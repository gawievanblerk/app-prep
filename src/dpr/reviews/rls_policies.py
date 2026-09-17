"""Review 2, database lock check: policy defects."""

from __future__ import annotations

import re
from collections.abc import Iterator

from dpr.model import Finding, Tag
from dpr.parsing.sqlschema import TableDef
from dpr.reviews.rls_common import (
    AUTH_REF,
    MEMBERSHIP_WORDS,
    client_facing,
    has_owner_or_unknown,
    owner_column,
    predicate_text,
    public_tables,
    replacement_sql,
    sql_block,
    state_for,
    tenant_column,
)
from dpr.rules import Context, make_finding, rule

AUTH_ROLE = re.compile(r"auth\.role\s*\(\s*\)\s*=\s*'authenticated'")
CLIENT_CLAIM = re.compile(r"user_metadata|current_setting\s*\(\s*'request\.headers'")
UID_REF = re.compile(r"auth\.uid\s*\(")
WRITE_COMMANDS = ("insert", "update", "delete", "all")


def _policies(ctx: Context):
    """Every policy on a public table. Tables known only from a dump get an empty column list."""
    if not client_facing(ctx):
        return
    state = state_for(ctx)
    tables = {t.key: t for t in public_tables(ctx)}
    ordered = sorted(
        state.policies.values(), key=lambda p: (p.location.file, p.location.line, p.name)
    )
    for policy in ordered:
        if policy.table.startswith("public."):
            table = tables.get(policy.table) or TableDef(policy.table, [], policy.location)
            yield state, table, policy


def _fix(state, policy) -> str:
    return sql_block(replacement_sql(state, policy))


@rule("RLS-POLICY-TRUE", review="rls", severity="high", exploitability="high")
def policy_true(ctx: Context) -> Iterator[Finding]:
    for state, table, policy in _policies(ctx):
        if policy.using == "true" and has_owner_or_unknown(table):
            yield make_finding(
                "RLS-POLICY-TRUE",
                tag=Tag.CONFIRMED,
                locations=[policy.location],
                fix=_fix(state, policy),
                policy=policy.name,
                table=table.key,
            )


@rule("RLS-AUTHENTICATED-NOT-OWNER", review="rls", severity="high", exploitability="high")
def authenticated_not_owner(ctx: Context) -> Iterator[Finding]:
    for state, table, policy in _policies(ctx):
        text = predicate_text(policy)
        if not text or AUTH_REF.search(text) or not has_owner_or_unknown(table):
            continue
        signed_in_only = (
            policy.roles_explicit
            and set(policy.roles) == {"authenticated"}
            and "true" not in (policy.using, policy.with_check)
        )
        if AUTH_ROLE.search(text) or signed_in_only:
            yield make_finding(
                "RLS-AUTHENTICATED-NOT-OWNER",
                tag=Tag.CONFIRMED,
                locations=[policy.location],
                fix=_fix(state, policy),
                policy=policy.name,
                table=table.key,
            )


def _mentions(text: str | None, owner: str) -> bool:
    return bool(text) and bool(AUTH_REF.search(text) or re.search(rf"\b{re.escape(owner)}\b", text))


@rule("RLS-WEAK-WITH-CHECK", review="rls", severity="high", exploitability="high")
def weak_with_check(ctx: Context) -> Iterator[Finding]:
    state = state_for(ctx)
    for table in public_tables(ctx):
        owner = owner_column(table)
        if owner is None:
            continue
        policies = state.policies_for(table.key)
        select_scoped = any(
            p.command in ("select", "all")
            and p.using
            and (UID_REF.search(p.using) or re.search(rf"\b{re.escape(owner)}\b", p.using))
            for p in policies
        )
        for policy in policies:
            if policy.command not in ("insert", "update", "all") or policy.with_check is None:
                continue
            if _mentions(policy.with_check, owner):
                continue
            if policy.command == "insert":
                severity = "high"
                what = f"The insert policy {policy.name} lets a caller create rows for any {owner}."
            else:
                severity = "low" if select_scoped else "high"
                what = (
                    f"The {policy.command} policy {policy.name} lets a caller change {owner} "
                    "to another user. "
                )
                what += (
                    "A select policy scoped to the owner blocks this in practice."
                    if select_scoped
                    else "No select policy scoped to the owner blocks it."
                )
            yield make_finding(
                "RLS-WEAK-WITH-CHECK",
                tag=Tag.CONFIRMED,
                locations=[policy.location],
                severity=severity,
                fix=_fix(state, policy),
                policy=policy.name,
                table=table.key,
                owner=owner,
                what=what,
            )


@rule("RLS-WRONG-ROLE", review="rls", severity="high", exploitability="high")
def wrong_role(ctx: Context) -> Iterator[Finding]:
    for state, table, policy in _policies(ctx):
        if owner_column(table) is None or policy.command not in WRITE_COMMANDS:
            continue
        open_roles = {"anon", "public"} & set(policy.roles)
        if policy.roles_explicit and open_roles and not AUTH_REF.search(predicate_text(policy)):
            yield make_finding(
                "RLS-WRONG-ROLE",
                tag=Tag.CONFIRMED,
                locations=[policy.location],
                fix=_fix(state, policy),
                policy=policy.name,
                table=table.key,
                roles=", ".join(sorted(open_roles)),
                command=policy.command,
            )


@rule("RLS-CLIENT-OWNER", review="rls", severity="high", exploitability="high")
def client_owner(ctx: Context) -> Iterator[Finding]:
    for state, table, policy in _policies(ctx):
        if CLIENT_CLAIM.search(predicate_text(policy)):
            yield make_finding(
                "RLS-CLIENT-OWNER",
                tag=Tag.CONFIRMED,
                locations=[policy.location],
                fix=_fix(state, policy),
                policy=policy.name,
                table=table.key,
            )


@rule("RLS-TENANT-UNBOUND", review="rls", severity="high", exploitability="high")
def tenant_unbound(ctx: Context) -> Iterator[Finding]:
    for state, table, policy in _policies(ctx):
        tenant = tenant_column(table)
        text = predicate_text(policy)
        if tenant is None or not re.search(r"\b(select|exists)\b", text):
            continue
        if not any(word in text for word in MEMBERSHIP_WORDS) or not AUTH_REF.search(text):
            continue
        if re.search(rf"\b{re.escape(tenant)}\b", text):
            continue
        yield make_finding(
            "RLS-TENANT-UNBOUND",
            tag=Tag.INFERRED,
            locations=[policy.location],
            fix=_fix(state, policy),
            policy=policy.name,
            table=table.key,
            tenant=tenant,
        )

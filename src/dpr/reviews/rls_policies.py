"""Review 2, database lock check: policy defects."""

from __future__ import annotations

import re
from collections.abc import Iterator

from dpr.model import Finding, Tag
from dpr.parsing.sqlschema import TableDef
from dpr.reviews.rls_common import (
    AUTH_REF,
    HELPER_PROOF,
    MEMBERSHIP_WORDS,
    calls_helper,
    client_facing,
    grants_clients,
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


def _policies(ctx: Context, granting: bool = False):
    """Every policy on a public table. Tables known only from a dump get an empty column list.

    With granting=True, only permissive policies that apply to a client role are kept.
    """
    if not client_facing(ctx):
        return
    state = state_for(ctx)
    tables = {t.key: t for t in public_tables(ctx)}
    ordered = sorted(
        state.policies.values(), key=lambda p: (p.location.file, p.location.line, p.name)
    )
    for policy in ordered:
        if granting and not grants_clients(policy):
            continue
        if policy.table.startswith("public."):
            table = tables.get(policy.table) or TableDef(policy.table, [], policy.location)
            yield state, table, policy


def _fix(state, policy) -> str:
    return sql_block(replacement_sql(state, policy))


def _evidence(text: str | None) -> dict:
    """CONFIRMED, unless the predicate calls a helper function that could change the answer."""
    if calls_helper(text):
        return {"tag": Tag.INFERRED, "proof_needed": HELPER_PROOF}
    return {"tag": Tag.CONFIRMED}


@rule("RLS-POLICY-TRUE", review="rls", severity="high", exploitability="high")
def policy_true(ctx: Context) -> Iterator[Finding]:
    for state, table, policy in _policies(ctx, granting=True):
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
    for state, table, policy in _policies(ctx, granting=True):
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
                **_evidence(text),
                locations=[policy.location],
                fix=_fix(state, policy),
                policy=policy.name,
                table=table.key,
            )


def _mentions(text: str | None, owner: str) -> bool:
    return bool(text) and bool(AUTH_REF.search(text) or re.search(rf"\b{re.escape(owner)}\b", text))


def _owner_scoped(policy, owner: str) -> bool:
    using = policy.using or ""
    return bool(UID_REF.search(using) or re.search(rf"\b{re.escape(owner)}\b", using))


@rule("RLS-WEAK-WITH-CHECK", review="rls", severity="high", exploitability="high")
def weak_with_check(ctx: Context) -> Iterator[Finding]:
    state = state_for(ctx)
    for table in public_tables(ctx):
        owner = owner_column(table)
        if owner is None:
            continue
        policies = [p for p in state.policies_for(table.key) if grants_clients(p)]
        readers = [p for p in policies if p.command in ("select", "all")]
        select_scoped = bool(readers) and all(_owner_scoped(p, owner) for p in readers)
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
                    "Every select policy is scoped to the owner, which blocks this in practice."
                    if select_scoped
                    else "Not every select policy is scoped to the owner, so they do not block it."
                )
            yield make_finding(
                "RLS-WEAK-WITH-CHECK",
                **_evidence(policy.with_check),
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
    for state, table, policy in _policies(ctx, granting=True):
        if owner_column(table) is None or policy.command not in WRITE_COMMANDS:
            continue
        open_roles = {"anon", "public"} & set(policy.roles)
        text = predicate_text(policy)
        if policy.roles_explicit and open_roles and not AUTH_REF.search(text):
            yield make_finding(
                "RLS-WRONG-ROLE",
                **_evidence(text),
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
    for state, table, policy in _policies(ctx, granting=True):
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
            proof_needed=HELPER_PROOF if calls_helper(text) else None,
            locations=[policy.location],
            fix=_fix(state, policy),
            policy=policy.name,
            table=table.key,
            tenant=tenant,
        )

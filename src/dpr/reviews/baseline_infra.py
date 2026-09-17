"""Review 4, baseline: infrastructure as code, database network exposure and HTTPS enforcement."""

from __future__ import annotations

import re
from collections.abc import Iterator

from dpr.model import Finding, Location, Tag
from dpr.parsing import hcl
from dpr.redact import snippet
from dpr.rules import Context, make_finding, rule
from dpr.walk import line_of

AZURE_DB_FIREWALL = re.compile(
    r"azurerm_(?:postgresql|mysql|mariadb|mssql|sql|cosmosdb)\w*firewall_rule"
)
DB_PORTS = {5432, 3306, 1433, 27017, 6379, 9200, 5984, 26257}
PORT_NUMBER = re.compile(r"-?\d+")
OPEN_CIDR = re.compile(r'"(0\.0\.0\.0/0|::/0)"')
AZURE_WEB_APPS = re.compile(
    r"azurerm_(?:linux_web_app|windows_web_app|app_service|linux_function_app"
    r"|windows_function_app|function_app)"
)
ADMIN_URL = re.compile(
    r"://\$\{([^}]*(?:admin|master|root|superuser|administrator_login)[^}]*)\}:", re.IGNORECASE
)


def _terraform(ctx: Context) -> Iterator[tuple[str, str, hcl.Block]]:
    for entry in ctx.index.with_suffix(".tf"):
        text = ctx.index.text(entry.rel)
        for block in hcl.blocks(text):
            if block.kind == "resource" and len(block.labels) == 2:
                yield entry.rel, text, block


def _ports(block: hcl.Block) -> set[int]:
    """Database ports covered by this block's own from_port..to_port range.

    A port given as a variable or other non-numeric expression is skipped, not guessed.
    """
    attrs = hcl.attributes(block)
    low_raw = hcl.unquote(attrs.get("from_port", ("", 0))[0]).strip()
    high_raw = hcl.unquote(attrs.get("to_port", ("", 0))[0]).strip()
    if not (PORT_NUMBER.fullmatch(low_raw) and PORT_NUMBER.fullmatch(high_raw)):
        return set()
    low, high = sorted((int(low_raw), int(high_raw)))
    return {p for p in DB_PORTS if low <= p <= high}


def _port_list(ports: set[int]) -> str:
    return ", ".join(str(p) for p in sorted(ports))


def _open_cidr(body: str) -> re.Match[str] | None:
    """The first open CIDR (0.0.0.0/0 or ::/0) outside comments, so a commented-out rule
    never counts."""
    return OPEN_CIDR.search(hcl._strip_comments(body))


def _open_ingress_ports(block: hcl.Block) -> tuple[set[int], int, set[str]]:
    """Union of database ports this security group's own `ingress` blocks expose to an open
    CIDR, the line of the first exposing ingress, and the open CIDRs. `egress` blocks never
    count."""
    exposed: set[int] = set()
    cidrs: set[str] = set()
    first_line = 0
    for nested in hcl.blocks(block.body):
        match = _open_cidr(nested.body) if nested.kind == "ingress" else None
        ports = _ports(nested) if match else set()
        if ports:
            if not exposed:
                first_line = block.body_line + nested.line - 1
            exposed |= ports
            cidrs.add(match.group(1))
    return exposed, first_line, cidrs


def _open(rel: str, text: str, line: int, severity: str, what: str) -> Finding:
    return make_finding(
        "BASE-DB-NETWORK-OPEN",
        tag=Tag.CONFIRMED,
        locations=[Location(rel, line)],
        severity=severity,
        snippet=snippet(text, line),
        what=what,
    )


@rule(
    "BASE-DB-NETWORK-OPEN",
    review="baseline",
    severity="medium",
    exploitability="medium",
    owasp="A05",
)
def db_network_open(ctx: Context) -> Iterator[Finding]:
    for rel, text, block in _terraform(ctx):
        kind, name = block.labels
        attrs = hcl.attributes(block)
        if AZURE_DB_FIREWALL.fullmatch(kind):
            start = hcl.unquote(attrs.get("start_ip_address", ("", 0))[0])
            end = hcl.unquote(attrs.get("end_ip_address", ("", 0))[0])
            if start == "0.0.0.0" and end == "0.0.0.0":
                what = (
                    f"Firewall rule {name} opens 0.0.0.0 to 0.0.0.0, which admits connections "
                    "from any Azure-hosted service, including other customers' tenants."
                )
                yield _open(rel, text, block.line, "medium", what)
            elif start == "0.0.0.0" and end == "255.255.255.255":
                what = f"Firewall rule {name} admits every IPv4 address on the internet."
                yield _open(rel, text, block.line, "high", what)
        elif kind == "aws_security_group":
            ports, line, cidrs = _open_ingress_ports(block)
            if ports:
                what = (
                    f"Security group {name} allows {' and '.join(sorted(cidrs))} to database "
                    f"port(s) {_port_list(ports)}."
                )
                yield _open(rel, text, line, "high", what)
        elif kind in ("aws_security_group_rule", "aws_vpc_security_group_ingress_rule"):
            is_ingress = kind == "aws_vpc_security_group_ingress_rule" or (
                hcl.unquote(attrs.get("type", ("", 0))[0]) == "ingress"
            )
            match = _open_cidr(block.body) if is_ingress else None
            ports = _ports(block) if match else set()
            if ports:
                what = (
                    f"Security group rule {name} allows {match.group(1)} to database "
                    f"port(s) {_port_list(ports)}."
                )
                yield _open(rel, text, block.line, "high", what)
        elif kind in ("aws_db_instance", "aws_rds_cluster_instance"):
            value, line = attrs.get("publicly_accessible", ("", 0))
            if value.strip() == "true":
                what = f"Database instance {name} is publicly accessible."
                yield _open(rel, text, line, "medium", what)
        elif kind == "google_sql_database_instance" and (match := _open_cidr(block.body)):
            line = block.body_line + block.body[: match.start()].count("\n")
            what = f"Cloud SQL instance {name} has {match.group(1)} as an authorized network."
            yield _open(rel, text, line, "high", what)


@rule(
    "BASE-DB-ADMIN-LOGIN",
    review="baseline",
    severity="medium",
    exploitability="medium",
    owasp="A05",
)
def db_admin_login(ctx: Context) -> Iterator[Finding]:
    for entry in ctx.index.with_suffix(".tf"):
        text = ctx.index.text(entry.rel)
        for match in ADMIN_URL.finditer(text):
            line = line_of(text, match.start())
            yield make_finding(
                "BASE-DB-ADMIN-LOGIN",
                tag=Tag.INFERRED,
                locations=[Location(entry.rel, line)],
                snippet=snippet(text, line),
                login=match.group(1),
            )


@rule(
    "BASE-HTTPS-NOT-ENFORCED",
    review="baseline",
    severity="low",
    exploitability="low",
    owasp="A02",
)
def https_not_enforced(ctx: Context) -> Iterator[Finding]:
    for rel, text, block in _terraform(ctx):
        kind, name = block.labels
        attrs = hcl.attributes(block)
        what = None
        line = block.line
        if AZURE_WEB_APPS.fullmatch(kind) and attrs.get("https_only", ("",))[0] != "true":
            what = f"{kind} {name} does not set https_only = true, so plain HTTP is served."
        elif kind == "aws_cloudfront_distribution" and re.search(
            r'viewer_protocol_policy\s*=\s*"allow-all"', block.body
        ):
            what = f"CloudFront distribution {name} allows plain HTTP viewers (allow-all)."
        elif kind == "aws_lb_listener" and re.search(r'protocol\s*=\s*"HTTP"', block.body):
            if "redirect" not in block.body:
                what = f"Load balancer listener {name} serves HTTP without a redirect to HTTPS."
        if what:
            yield make_finding(
                "BASE-HTTPS-NOT-ENFORCED",
                tag=Tag.CONFIRMED,
                locations=[Location(rel, line)],
                snippet=snippet(text, line),
                what=what,
            )

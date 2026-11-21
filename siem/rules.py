"""Detection rules loaded from rules.yaml.

A rule's condition is a Python-style expression checked against every flow:

    country_code in ["RU", "KP"] and remote_port != 443
    not signed and scope == "public"
    regex(hostname, r"\\.(xyz|top|zip)$")
    cidr(remote_ip, "185.220.0.0/16")

Conditions are parsed with `ast` and only a small set of node types, field
names and helpers is allowed, so a rule can't run arbitrary Python.
"""
from __future__ import annotations

import ast
import functools
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

SEVERITIES = ["info", "low", "medium", "high", "critical"]

FIELDS = {
    "app": "Application (outermost .app bundle, e.g. 'Google Chrome')",
    "process": "Executable name, e.g. 'Google Chrome Helper'",
    "path": "Full executable path",
    "pid": "Process ID",
    "user": "User owning the process",
    "proto": "tcp | udp | quic",
    "local_ip": "Local address", "local_port": "Local port",
    "remote_ip": "Remote address", "remote_port": "Remote port",
    "service": "Service name for remote port (https, ssh, dns...)",
    "scope": "public | private | loopback | link-local | multicast | cgnat",
    "country": "Country name", "country_code": "ISO-3166 alpha-2 (US, DE, IN...)",
    "city": "City", "asn": "Autonomous system number", "org": "AS owner (Google LLC...)",
    "hostname": "Domain the app looked up (DNS sniff) or reverse DNS",
    "state": "TCP state (Established, SynSent...)", "interface": "en0, utun3...",
    "bytes_in": "Bytes received on this flow", "bytes_out": "Bytes sent on this flow",
    "rate_in": "Current receive rate (bytes/s)", "rate_out": "Current send rate (bytes/s)",
    "rtt_ms": "Average round-trip time (ms)", "duration": "Seconds since first seen",
    "signed": "True if binary has a valid code signature", "apple": "True if signed by Apple",
    "signer": "Signing authority", "team_id": "Developer team ID",
    "new_app": "True the first time this app is ever seen on the network",
    "new_dest": "True the first time this app talks to this org/IP",
}


def _cidr(ip, net):
    try:
        return ipaddress.ip_address(ip) in _net(net)
    except ValueError:
        return False


@functools.lru_cache(maxsize=512)
def _net(net):
    return ipaddress.ip_network(net, strict=False)


@functools.lru_cache(maxsize=512)
def _re(p):
    return re.compile(p, re.I)


def _regex(value, pattern):
    return bool(_re(pattern).search(str(value or "")))


FUNCS = {
    "cidr": _cidr,                                  # cidr(remote_ip, "10.0.0.0/8")
    "regex": _regex,                                # regex(hostname, "evil")
    "lower": lambda s: str(s or "").lower(),
    "startswith": lambda s, p: str(s or "").startswith(p),
    "endswith": lambda s, p: str(s or "").endswith(p),
    "contains": lambda s, p: p.lower() in str(s or "").lower(),
    "any_of": lambda s, *ps: any(p.lower() in str(s or "").lower() for p in ps),
    "len": lambda s: len(s or ""),
}

_ALLOWED = (
    ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not, ast.USub,
    ast.Compare, ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn,
    ast.Name, ast.Load, ast.Constant, ast.List, ast.Tuple, ast.Set, ast.Call,
    ast.BinOp, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.IfExp,
)


class RuleError(ValueError):
    pass


def compile_condition(expr: str):
    if not isinstance(expr, str) or not expr.strip():
        raise RuleError("condition is empty")
    if len(expr) > 2000:
        raise RuleError("condition too long")
    try:
        tree = ast.parse(expr.strip(), mode="eval")
    except SyntaxError as e:
        raise RuleError(f"syntax error: {e.msg} (col {e.offset})") from None
    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED):
            raise RuleError(f"'{type(node).__name__}' is not allowed in rules")
        if isinstance(node, ast.Name) and node.id not in FIELDS and node.id not in FUNCS \
                and node.id not in ("True", "False", "None"):
            raise RuleError(f"unknown field '{node.id}'")
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.func.id not in FUNCS:
                raise RuleError("only these functions are allowed: " + ", ".join(FUNCS))
            if node.keywords:
                raise RuleError("keyword arguments are not allowed")
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            # allow 50*1024*1024, but not "x" * 10**9 style memory blowups
            for side in ast.walk(node):
                if isinstance(side, ast.Name) or (isinstance(side, ast.Constant)
                                                  and not isinstance(side.value, (int, float))):
                    raise RuleError("'*' is only allowed between numbers")
        if isinstance(node, ast.Constant) and not isinstance(
                node.value, (str, int, float, bool, type(None))):
            raise RuleError("unsupported constant")
    code = compile(tree, "<rule>", "eval")
    env = {"__builtins__": {}, **FUNCS}

    def run(ctx: dict) -> bool:
        try:
            return bool(eval(code, env, ctx))  # safe: tree was validated above
        except Exception:
            return False
    return run


@dataclass
class Rule:
    id: str
    name: str
    condition: str
    severity: str = "medium"
    description: str = ""
    enabled: bool = True
    fn: object = field(default=None, repr=False)


def parse_rules(text: str) -> list[Rule]:
    try:
        data = yaml.safe_load(text) or []
    except yaml.YAMLError as e:
        raise RuleError(f"YAML error: {e}") from None
    if isinstance(data, dict):
        data = data.get("rules", [])
    if not isinstance(data, list):
        raise RuleError("rules file must be a list of rules")
    rules, seen = [], set()
    for i, r in enumerate(data):
        if not isinstance(r, dict):
            raise RuleError(f"rule #{i + 1} is not a mapping")
        rid = str(r.get("id") or f"rule-{i + 1}")
        if rid in seen:
            raise RuleError(f"duplicate rule id '{rid}'")
        seen.add(rid)
        sev = str(r.get("severity", "medium")).lower()
        if sev not in SEVERITIES:
            raise RuleError(f"{rid}: severity must be one of {SEVERITIES}")
        try:
            fn = compile_condition(r.get("condition", ""))
        except RuleError as e:
            raise RuleError(f"{rid}: {e}") from None
        rules.append(Rule(id=rid, name=str(r.get("name", rid)), condition=r["condition"],
                          severity=sev, description=str(r.get("description", "")),
                          enabled=bool(r.get("enabled", True)), fn=fn))
    return rules


class RuleSet:
    def __init__(self, path: Path):
        self.path = path
        self.rules: list[Rule] = []
        self.error = ""
        self.load()

    def load(self):
        try:
            self.rules = parse_rules(self.path.read_text())
            self.error = ""
        except (OSError, RuleError) as e:
            self.error = str(e)

    def text(self) -> str:
        try:
            return self.path.read_text()
        except OSError:
            return ""

    def save(self, text: str) -> list[Rule]:
        rules = parse_rules(text)  # raises RuleError on any problem
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(text)
        tmp.replace(self.path)
        self.rules, self.error = rules, ""
        return rules

    def evaluate(self, ctx: dict) -> list[Rule]:
        return [r for r in self.rules if r.enabled and r.fn(ctx)]

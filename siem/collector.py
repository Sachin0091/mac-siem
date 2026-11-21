"""Reads live flows from nettop.

nettop prints a process line ("name.pid") followed by one line per socket
("tcp4 1.2.3.4:5<->6.7.8.9:443"). Byte counts are cumulative, so the engine
diffs two samples to get a rate. Works without root.
"""
from __future__ import annotations

import csv
import io
import os
import re
import subprocess
import time
from dataclasses import dataclass, field

NETTOP_CMD = [
    "/usr/bin/nettop", "-L", "1", "-n", "-x",
    "-J", "interface,state,bytes_in,bytes_out,rtt_avg",
]

PROC_RE = re.compile(r"^(?P<name>.+)\.(?P<pid>\d+)$")
FLOW_RE = re.compile(r"^(?P<proto>tcp|udp|quic)(?P<ver>[46]) (?P<local>\S+)<->(?P<remote>\S+)$")


def split_endpoint(ep: str, ver: str) -> tuple[str, str]:
    """'1.2.3.4:443' (v4) or 'fe80::1%en0.443' (v6) -> (ip, port)."""
    sep = ":" if ver == "4" else "."
    ip, _, port = ep.rpartition(sep)
    if not ip:  # '*' style wildcard
        return ep, "*"
    return ip, port


@dataclass
class Flow:
    key: tuple
    pid: int
    pname: str
    proto: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    interface: str
    state: str
    bytes_in: int
    bytes_out: int
    rtt_ms: float | None
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    rate_in: float = 0.0
    rate_out: float = 0.0


@dataclass
class Listener:
    pid: int
    pname: str
    proto: str
    local_ip: str
    local_port: int


def _int(s: str) -> int:
    try:
        return int(s)
    except (TypeError, ValueError):
        return 0


def _port(s: str) -> int:
    return int(s) if s.isdigit() else 0


def sample_nettop() -> tuple[list[dict], list[Listener]]:
    out = subprocess.run(NETTOP_CMD, capture_output=True, text=True, timeout=15).stdout
    flows: list[dict] = []
    listeners: list[Listener] = []
    cur_name, cur_pid = "?", 0
    for row in csv.reader(io.StringIO(out)):
        if not row or row[0] == "":
            continue  # header
        head = row[0]
        fm = FLOW_RE.match(head)
        if not fm:
            pm = PROC_RE.match(head)
            if pm:
                cur_name, cur_pid = pm.group("name"), int(pm.group("pid"))
            continue
        cols = (row + [""] * 6)[1:6]
        iface, state, b_in, b_out, rtt = cols
        ver = fm.group("ver")
        lip, lport = split_endpoint(fm.group("local"), ver)
        rip, rport = split_endpoint(fm.group("remote"), ver)
        lip = lip.split("%")[0]
        rip = rip.split("%")[0]
        proto = fm.group("proto")
        if rip in ("*", "") or rport == "*":
            if state == "Listen" or (proto == "udp" and lport not in ("*", "0")):
                listeners.append(Listener(cur_pid, cur_name, proto, lip, _port(lport)))
            continue
        rtt_ms = None
        if rtt.endswith(" ms"):
            try:
                rtt_ms = float(rtt[:-3])
            except ValueError:
                pass
        flows.append({
            "key": (cur_pid, proto + ver, lip, lport, rip, rport),
            "pid": cur_pid, "pname": cur_name, "proto": proto,
            "local_ip": lip, "local_port": _port(lport),
            "remote_ip": rip, "remote_port": _port(rport),
            "interface": iface, "state": state or ("Active" if proto != "tcp" else ""),
            "bytes_in": _int(b_in), "bytes_out": _int(b_out), "rtt_ms": rtt_ms,
        })
    return flows, listeners


# process info
_proc_cache: dict[int, dict] = {}


def app_from_path(path: str, fallback: str) -> str:
    """Outermost .app bundle name, so 'Google Chrome Helper' rolls up to 'Google Chrome'."""
    m = re.search(r"/([^/]+)\.app/", path + "/")
    if m:
        return m.group(1)
    if "WebKit.Networking" in path:
        return "WebKit (Safari/WebViews)"
    base = os.path.basename(path) if path else ""
    return base or fallback


def process_info(pid: int, pname: str) -> dict:
    info = _proc_cache.get(pid)
    if info and info["pname_hint"] == pname:
        return info
    path = ""
    user = ""
    try:
        r = subprocess.run(["/bin/ps", "-o", "user=,comm=", "-p", str(pid)],
                           capture_output=True, text=True, timeout=5)
        line = r.stdout.strip()
        if line:
            user, _, path = line.partition(" ")
            path = path.strip()
    except Exception:
        pass
    info = {
        "pname_hint": pname,
        "path": path,
        "user": user,
        "process": os.path.basename(path) if path else pname,
        "app": app_from_path(path, pname),
    }
    _proc_cache[pid] = info
    return info


def prune_proc_cache(live_pids: set[int]) -> None:
    for pid in list(_proc_cache):
        if pid not in live_pids:
            _proc_cache.pop(pid, None)

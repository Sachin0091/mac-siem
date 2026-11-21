"""Adds context to a raw flow: geo/ASN, address scope, hostname, code signature.

Anything slow (reverse DNS, codesign) runs in a small thread pool and is cached.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import shutil
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

log = logging.getLogger("siem.enrich")

try:
    import maxminddb
except ImportError:  # pragma: no cover
    maxminddb = None

_pool = ThreadPoolExecutor(max_workers=6, thread_name_prefix="enrich")

COMMON_PORTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3", 123: "ntp", 137: "netbios",
    143: "imap", 443: "https", 445: "smb", 465: "smtps", 514: "syslog",
    587: "submission", 853: "dns-over-tls", 993: "imaps", 995: "pop3s",
    1194: "openvpn", 1900: "ssdp", 3074: "xbox", 3306: "mysql", 3389: "rdp",
    3478: "stun", 4500: "ipsec-nat", 5000: "airplay", 7000: "airplay", 5222: "xmpp", 5223: "apns", 5228: "gcm",
    5353: "mdns", 5432: "postgres", 5900: "vnc", 6379: "redis", 6881: "bittorrent",
    8080: "http-alt", 8443: "https-alt", 9001: "tor", 9050: "tor-socks",
    51820: "wireguard",
}


def service_name(port: int, proto: str) -> str:
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        return socket.getservbyport(port, "udp" if proto in ("udp", "quic") else "tcp")
    except (OSError, OverflowError):
        return ""


def scope_of(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if a.is_loopback:
        return "loopback"
    if a.is_link_local:
        return "link-local"
    if a.is_multicast:
        return "multicast"
    if isinstance(a, ipaddress.IPv4Address) and a in ipaddress.ip_network("100.64.0.0/10"):
        return "cgnat"
    if a.is_private:
        return "private"
    if a.is_global:
        return "public"
    return "reserved"


# GeoIP
class Geo:
    def __init__(self, data_dir: Path):
        self.city = self.asn = None
        if maxminddb is None:
            log.warning("maxminddb not installed; geo lookups disabled")
            return
        for attr, pattern in (("city", "*city*.mmdb"), ("asn", "*asn*.mmdb")):
            files = sorted(data_dir.glob(pattern))
            if files:
                setattr(self, attr, maxminddb.open_database(str(files[-1])))
                log.info("loaded %s", files[-1].name)
        if not self.city:
            log.warning("no city/country .mmdb in %s - run ./setup_geoip.sh", data_dir)
        self._cache: dict[str, dict] = {}

    def lookup(self, ip: str) -> dict:
        if ip in getattr(self, "_cache", {}):
            return self._cache[ip]
        out = {"country": "", "country_code": "", "city": "", "lat": None, "lon": None,
               "asn": 0, "org": ""}
        try:
            if self.city:
                r = self.city.get(ip) or {}
                c = r.get("country") or {}
                out["country"] = (c.get("names") or {}).get("en", "")
                out["country_code"] = c.get("iso_code", "")
                out["city"] = ((r.get("city") or {}).get("names") or {}).get("en", "")
                loc = r.get("location") or {}
                out["lat"], out["lon"] = loc.get("latitude"), loc.get("longitude")
            if self.asn:
                r = self.asn.get(ip) or {}
                out["asn"] = r.get("autonomous_system_number", 0)
                out["org"] = r.get("autonomous_system_organization", "")
        except ValueError:
            pass
        if len(self._cache) > 50000:
            self._cache.clear()
        self._cache[ip] = out
        return out


# hostnames
class Hostnames:
    """ip -> name. Prefers names learned from sniffed DNS answers (what the app
    actually asked for), falls back to reverse DNS (PTR)."""

    def __init__(self, sniff: str = "auto"):
        self.dns: dict[str, str] = {}
        self.ptr: dict[str, str | None] = {}
        self._lock = threading.Lock()
        self.sniffing = False
        self.sniff_error = ""
        if sniff != "off":
            threading.Thread(target=self._sniff_dns, daemon=True, name="dns-sniff").start()

    def get(self, ip: str) -> tuple[str, str]:
        """Returns (hostname, source)."""
        if ip in self.dns:
            return self.dns[ip], "dns"
        if ip in self.ptr:
            return self.ptr[ip] or "", "ptr"
        with self._lock:
            if ip not in self.ptr:
                self.ptr[ip] = None
                _pool.submit(self._rdns, ip)
        return "", ""

    def _rdns(self, ip: str) -> None:
        try:
            socket.setdefaulttimeout(3)
            name = socket.gethostbyaddr(ip)[0]
        except Exception:
            name = ""
        self.ptr[ip] = name

    # tcpdump needs read access to /dev/bpf* (root, or Wireshark's ChmodBPF).
    _Q = re.compile(r": (\d+)\+?\s+(?:\[\w+\]\s+)?(?:A|AAAA)\? (\S+?)\.? \(")
    _R = re.compile(r": (\d+)[\*\-\|\$]* +\d+/\d+/\d+ (.*)$")
    _ANS = re.compile(r"\b(?:A|AAAA) ([0-9a-fA-F:.]+)")

    def _sniff_dns(self) -> None:
        exe = shutil.which("tcpdump")
        if not exe:
            self.sniff_error = "tcpdump not found"
            return
        try:
            p = subprocess.Popen([exe, "-l", "-n", "-i", "any", "udp", "port", "53"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, bufsize=1)
        except OSError as e:
            self.sniff_error = str(e)
            return
        pending: dict[str, str] = {}
        assert p.stdout is not None
        for line in p.stdout:
            self.sniffing = True
            q = self._Q.search(line)
            if q:
                pending[q.group(1)] = q.group(2).lower()
                if len(pending) > 5000:
                    pending.clear()
                continue
            r = self._R.search(line)
            if r and r.group(1) in pending:
                qname = pending.pop(r.group(1))
                for ip in self._ANS.findall(r.group(2)):
                    self.dns[ip.rstrip(".,")] = qname
                if len(self.dns) > 100000:
                    self.dns.clear()
        err = (p.stderr.read() if p.stderr else "").strip()
        self.sniffing = False
        self.sniff_error = err.splitlines()[-1] if err else "tcpdump exited"
        log.info("DNS sniffing unavailable (%s). Hostnames fall back to reverse DNS.",
                 self.sniff_error)


# code signing
class CodeSign:
    def __init__(self):
        self.cache: dict[str, dict] = {}
        self._lock = threading.Lock()

    def get(self, path: str) -> dict:
        if not path or not path.startswith("/"):
            return {"signed": None, "signer": "", "team_id": "", "apple": False}
        if path in self.cache:
            return self.cache[path]
        with self._lock:
            if path not in self.cache:
                self.cache[path] = {"signed": None, "signer": "checking…", "team_id": "",
                                    "apple": False}
                _pool.submit(self._check, path)
        return self.cache[path]

    def _check(self, path: str) -> None:
        res = {"signed": False, "signer": "unsigned", "team_id": "", "apple": False}
        try:
            r = subprocess.run(["/usr/bin/codesign", "-dv", "--verbose=2", path],
                               capture_output=True, text=True, timeout=20)
            txt = r.stderr
            if "not signed at all" not in txt and r.returncode == 0:
                auth = re.findall(r"^Authority=(.+)$", txt, re.M)
                team = re.search(r"^TeamIdentifier=(.+)$", txt, re.M)
                res["signed"] = True
                res["signer"] = auth[0] if auth else ("ad-hoc" if "adhoc" in txt else "signed")
                res["team_id"] = team.group(1) if team and team.group(1) != "not set" else ""
                platform = "Platform identifier=" in txt  # sealed OS binary
                res["apple"] = platform or (bool(auth) and auth[0] == "Software Signing")
                if platform:
                    res["signer"] = "Apple (platform binary)"
                    self.cache[path] = res
                    return
                v = subprocess.run(["/usr/bin/codesign", "--verify", path],
                                   capture_output=True, text=True, timeout=30)
                if v.returncode != 0 and "resource envelope is obsolete" not in v.stderr:
                    res["signed"] = False
                    res["signer"] = "INVALID signature: " + res["signer"]
        except Exception as e:
            res["signer"] = f"error: {e}"
            res["signed"] = None
        self.cache[path] = res

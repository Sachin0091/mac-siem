"""Main loop: sample nettop, diff against last sample, enrich, run rules, save."""
from __future__ import annotations

import collections
import logging
import threading
import time
from pathlib import Path

from . import collector
from .enrich import CodeSign, Geo, Hostnames, scope_of, service_name
from .rules import SEVERITIES, RuleSet
from .store import Store

log = logging.getLogger("siem.engine")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


class Engine:
    def __init__(self, cfg: dict, root: Path):
        self.cfg = cfg
        data = root / "data"
        data.mkdir(exist_ok=True)
        self.geo = Geo(data)
        self.hosts = Hostnames(cfg.get("dns_sniff", "auto"))
        self.codesign = CodeSign()
        self.rules = RuleSet(root / cfg.get("rules_file", "rules.yaml"))
        self.store = Store(data / "siem.db")
        self.baseline = self.store.load_baseline()
        self.started = time.time()
        # learning window starts at the very first run (persisted via baseline timestamps)
        self.learning_until = ((self.store.first_baseline_ts() or self.started)
                               + 60 * float(cfg.get("learning_minutes", 10)))
        self.flows: dict[tuple, dict] = {}
        self.listeners: list[dict] = []
        self.series = collections.deque(maxlen=int(cfg.get("series_points", 450)))
        self.app_totals: dict[str, list[int]] = collections.defaultdict(lambda: [0, 0])
        self.alert_cooldown: dict[tuple, float] = {}
        self.home = cfg.get("home") or None
        self.lock = threading.Lock()
        self.last_poll = 0.0
        self.poll_error = ""
        self.paused = False

    # loop
    def run_forever(self):
        interval = float(self.cfg.get("poll_interval", 2))
        last_prune = 0.0
        while True:
            t0 = time.time()
            if not self.paused:
                try:
                    self.poll()
                    self.poll_error = ""
                except Exception as e:
                    log.exception("poll failed")
                    self.poll_error = str(e)
            if t0 - last_prune > 3600:
                self.store.prune(float(self.cfg.get("retention_days", 14)))
                last_prune = t0
            time.sleep(max(0.2, interval - (time.time() - t0)))

    def poll(self):
        raw, listeners = collector.sample_nettop()
        now = time.time()
        dt = max(0.5, now - self.last_poll) if self.last_poll else 0
        self.last_poll = now
        learning = now < self.learning_until
        seen, opened, closed, new_base = set(), [], [], []
        tot_in = tot_out = 0.0

        with self.lock:
            for r in raw:
                k = r["key"]
                seen.add(k)
                f = self.flows.get(k)
                if f is None:
                    f = self._new_flow(r, now, learning, new_base)
                    self.flows[k] = f
                    opened.append(f)
                else:
                    d_in = max(0, r["bytes_in"] - f["bytes_in"])
                    d_out = max(0, r["bytes_out"] - f["bytes_out"])
                    f["rate_in"] = d_in / dt if dt else 0
                    f["rate_out"] = d_out / dt if dt else 0
                    tot_in += f["rate_in"]
                    tot_out += f["rate_out"]
                    t = self.app_totals[f["app"]]
                    t[0] += d_in
                    t[1] += d_out
                    for c in ("bytes_in", "bytes_out", "state", "rtt_ms", "interface"):
                        if r[c] is not None and r[c] != "":
                            f[c] = r[c]
                f["last_seen"] = now
                f["duration"] = now - f["first_seen"]
                # signing info arrives asynchronously
                cs = self.codesign.get(f["path"])
                f.update(signed=cs["signed"], signer=cs["signer"], team_id=cs["team_id"],
                         apple=cs["apple"])
                if not f["hostname"]:
                    f["hostname"], f["host_src"] = self.hosts.get(f["remote_ip"])

            for k in list(self.flows):
                if k not in seen:
                    closed.append(self.flows.pop(k))

            uniq = {}
            for l in listeners:
                exposed = l.local_ip in ("*", "0.0.0.0", "::")
                k = (l.pid, l.proto, l.local_port, exposed or l.local_ip)
                if k not in uniq:
                    uniq[k] = {"pid": l.pid, "app": collector.process_info(l.pid, l.pname)["app"],
                               "process": l.pname, "proto": l.proto, "ip": l.local_ip,
                               "port": l.local_port, "exposed": exposed,
                               "service": service_name(l.local_port, l.proto)}
            self.listeners = sorted(uniq.values(), key=lambda x: (not x["exposed"], x["port"]))
            self.series.append((now, round(tot_in), round(tot_out)))
            alerts = self._detect(now)

        collector.prune_proc_cache({k[0] for k in seen})
        if new_base:
            self.store.add_baseline(new_base)
        self.store.add_events([self._event(f, "open", now) for f in opened] +
                              [self._event(f, "close", now) for f in closed])
        for a in alerts:
            a["id"] = self.store.add_alert(a)
        if self.home is None:
            self._guess_home(raw)

    def _new_flow(self, r: dict, now: float, learning: bool, new_base: list) -> dict:
        p = collector.process_info(r["pid"], r["pname"])
        rip = r["remote_ip"]
        g = self.geo.lookup(rip)
        scope = scope_of(rip)
        host, src = self.hosts.get(rip)
        dest = g["org"] or rip
        new_app = (p["app"], "") not in self.baseline
        new_dest = (p["app"], dest) not in self.baseline
        for pair, is_new in (((p["app"], ""), new_app), ((p["app"], dest), new_dest)):
            if is_new and scope == "public":
                self.baseline.add(pair)
                new_base.append(pair)
        f = dict(r)
        f.pop("key")
        f.update(
            id="%d-%s-%s-%s-%s-%s" % r["key"], app=p["app"], process=p["process"],
            path=p["path"], user=p["user"], scope=scope,
            service=service_name(r["remote_port"], r["proto"]),
            hostname=host, host_src=src, first_seen=now, last_seen=now, duration=0,
            rate_in=0.0, rate_out=0.0, signed=None, signer="", team_id="", apple=False,
            new_app=new_app and scope == "public" and not learning,
            new_dest=new_dest and scope == "public" and not learning,
            alerts=[], max_sev="", **g)
        return f

    def _detect(self, now: float) -> list[dict]:
        out = []
        for f in self.flows.values():
            hits = self.rules.evaluate(f)
            f["alerts"] = [h.id for h in hits]
            f["max_sev"] = max((h.severity for h in hits), key=SEV_RANK.get, default="")
            for h in hits:
                key = (h.id, f["app"], f["hostname"] or f["remote_ip"])
                if now - self.alert_cooldown.get(key, 0) < float(
                        self.cfg.get("alert_cooldown_minutes", 30)) * 60:
                    continue
                self.alert_cooldown[key] = now
                out.append({
                    "ts": now, "rule_id": h.id, "rule_name": h.name, "severity": h.severity,
                    "app": f["app"], "process": f["process"], "remote_ip": f["remote_ip"],
                    "remote_port": f["remote_port"], "hostname": f["hostname"],
                    "country_code": f["country_code"], "org": f["org"], "acked": 0,
                    "details": {k: f.get(k) for k in (
                        "path", "pid", "proto", "local_port", "country", "city", "asn",
                        "scope", "bytes_in", "bytes_out", "signer", "team_id", "condition")}
                    | {"condition": h.condition, "description": h.description},
                })
        if len(self.alert_cooldown) > 20000:
            cutoff = now - 86400
            self.alert_cooldown = {k: v for k, v in self.alert_cooldown.items() if v > cutoff}
        return out

    @staticmethod
    def _event(f: dict, kind: str, now: float) -> dict:
        e = {c: f.get(c) for c in ("app", "process", "pid", "proto", "local_port", "remote_ip",
                                   "remote_port", "hostname", "country_code", "country", "city",
                                   "org", "scope", "bytes_in", "bytes_out")}
        e.update(ts=now, kind=kind, duration=now - f["first_seen"] if kind == "close" else 0)
        return e

    def _guess_home(self, raw: list[dict]):
        """Use our own public IPv6 (if any) to place 'home' on the map, offline."""
        for r in raw:
            if scope_of(r["local_ip"]) == "public":
                g = self.geo.lookup(r["local_ip"])
                if g["lat"] is not None:
                    self.home = {"lat": g["lat"], "lon": g["lon"],
                                 "label": ", ".join(x for x in (g["city"], g["country"]) if x)}
                    return

    # output
    def snapshot(self) -> dict:
        with self.lock:
            flows = [dict(f) for f in self.flows.values()]
            listeners = list(self.listeners)
            series = list(self.series)
            totals = {a: list(v) for a, v in self.app_totals.items()}

        public = [f for f in flows if f["scope"] == "public"]
        apps: dict[str, dict] = {}
        for f in flows:
            a = apps.setdefault(f["app"], {"app": f["app"], "flows": 0, "rate_in": 0, "rate_out": 0,
                                           "remotes": set(), "countries": set(), "max_sev": ""})
            a["flows"] += 1
            a["rate_in"] += f["rate_in"]
            a["rate_out"] += f["rate_out"]
            if f["scope"] == "public":
                a["remotes"].add(f["remote_ip"])
                if f["country_code"]:
                    a["countries"].add(f["country_code"])
            if SEV_RANK.get(f["max_sev"], -1) > SEV_RANK.get(a["max_sev"], -1):
                a["max_sev"] = f["max_sev"]
        for a in apps.values():
            t = totals.get(a["app"], [0, 0])
            a.update(bytes_in=t[0], bytes_out=t[1], remotes=len(a["remotes"]),
                     countries=sorted(a["countries"]))
        counts = self.store.unacked_counts()
        return {
            "ts": time.time(),
            "status": {
                "uptime": time.time() - self.started,
                "paused": self.paused,
                "poll_error": self.poll_error,
                "geo": bool(self.geo.city),
                "asn": bool(self.geo.asn),
                "dns_sniffing": self.hosts.sniffing,
                "dns_error": self.hosts.sniff_error,
                "rules_error": self.rules.error,
                "rules": len(self.rules.rules),
                "learning_left": max(0, self.learning_until - time.time()),
            },
            "home": self.home,
            "kpis": {
                "flows": len(flows),
                "public_flows": len(public),
                "remotes": len({f["remote_ip"] for f in public}),
                "countries": len({f["country_code"] for f in public if f["country_code"]}),
                "apps": len(apps),
                "rate_in": series[-1][1] if series else 0,
                "rate_out": series[-1][2] if series else 0,
                "listeners_exposed": sum(1 for l in listeners if l["exposed"]),
                "alerts_open": sum(counts.values()),
            },
            "alert_counts": counts,
            "flows": flows,
            "apps": sorted(apps.values(), key=lambda a: -(a["bytes_in"] + a["bytes_out"])),
            "listeners": listeners,
            "series": series,
            "alerts_recent": self.store.alerts(limit=30, include_acked=False),
        }

    def test_condition(self, expr: str) -> list[dict]:
        from .rules import compile_condition
        fn = compile_condition(expr)
        with self.lock:
            return [dict(f) for f in self.flows.values() if fn(f)]

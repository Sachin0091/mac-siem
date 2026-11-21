#!/usr/bin/env python3
"""MAC SIEM - local network monitoring dashboard for macOS.

    ./run.sh          # run as your user
    sudo ./run.sh     # also capture DNS to get real domain names
"""
from __future__ import annotations

import argparse
import logging
import threading
import webbrowser
from pathlib import Path

import yaml

from siem.engine import Engine
from siem.server import make_server

ROOT = Path(__file__).resolve().parent


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--config", default=str(ROOT / "config.yaml"))
    ap.add_argument("--port", type=int)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    cfg = {}
    if Path(args.config).exists():
        cfg = yaml.safe_load(Path(args.config).read_text()) or {}
    port = args.port or int(cfg.get("port", 8765))

    engine = Engine(cfg, ROOT)
    threading.Thread(target=engine.run_forever, daemon=True, name="poller").start()
    srv = make_server(engine, ROOT, "127.0.0.1", port)
    url = f"http://127.0.0.1:{port}/"
    logging.info("MAC SIEM running at %s (Ctrl-C to stop)", url)
    if not args.no_browser:
        threading.Timer(1.0, webbrowser.open, (url,)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

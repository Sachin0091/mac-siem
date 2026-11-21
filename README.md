# MAC SIEM

A small SIEM-style dashboard that shows what your Mac is talking to on the network.

For every connection you can see which app opened it, the IP and hostname on the
other end, which country and company that IP belongs to, and how much data is
going through it. You can write your own detection rules and get alerts when
something matches.

It runs entirely on your machine. There's no cloud service, no account, and no
agent to install. It uses tools that already ship with macOS plus a free offline
GeoIP database.

## Features

- Live world map with lines from your location to every server your Mac is connected to
- Per-app view of connections: process, PID, remote IP/port, hostname, country, city, ASN/organisation, TCP state, bytes, speed, latency
- Code signature check for each app (Apple, signed third party, unsigned)
- Custom detection rules in YAML with a simple expression syntax
- Alerts with severity levels and acknowledge
- Baseline learning that flags new apps and new destinations
- Connection history stored in SQLite and searchable from the UI
- List of listening ports, so you can see what's exposed on your network
- Light on dependencies: Python standard library, `maxminddb` and `PyYAML`

## Requirements

- macOS (tested on recent releases with Apple Silicon)
- Python 3.10 or newer (`brew install python` if you don't have it)
- About 150 MB of disk space for the GeoIP databases

## Installation

```bash
git clone https://github.com/Sachin0091/mac-siem.git
cd mac-siem
./setup_geoip.sh
./run.sh
```

The dashboard opens at <http://127.0.0.1:8765>.

What each step does:

1. `setup_geoip.sh` downloads the DB-IP Lite City and ASN databases into `data/`.
   Without them the app still works, but there's no map and no country or organisation info.
2. `run.sh` creates a virtualenv in `.venv` on the first run, installs the two
   Python packages from `requirements.txt`, then starts the server.

### Seeing real domain names (optional)

```bash
sudo ./run.sh
```

When it runs as root, the app also watches DNS traffic with `tcpdump`, so it can
show the domain an app actually looked up (for example `api.github.com`). Without
root you only get reverse DNS, which for cloud servers usually looks like
`ec2-54-12-34-56.compute-1.amazonaws.com`.

If you have Wireshark installed with its ChmodBPF helper, DNS capture works
without sudo too.

### Command line options

```
./run.sh --port 9000       # use another port
./run.sh --no-browser      # don't open the browser automatically
./run.sh -v                # debug logging
```

## How it works

```
                 every 2 seconds
   nettop  ──────────────────────►  collector.py
 (built into macOS)                     │  list of flows: pid, process, local/remote
                                        │  address, state, bytes, RTT
                                        ▼
                                    engine.py
                                        │  compares with the previous sample:
                                        │  new flows, closed flows, bytes/sec
                                        ▼
                                    enrich.py
                     ┌──────────────────┼──────────────────┬───────────────────┐
                     ▼                  ▼                  ▼                   ▼
              DB-IP .mmdb files    reverse DNS or      ps + codesign      service name
              (country, city,      sniffed DNS         (app bundle,       for the port
               lat/lon, ASN)       (hostname)          signer, team ID)
                     └──────────────────┬──────────────────┴───────────────────┘
                                        ▼
                                    rules.py  ── evaluates rules.yaml against each flow
                                        │
                                        ▼
                                    store.py  ── SQLite: events, alerts, baseline
                                        │
                                        ▼
                                    server.py ── JSON API on 127.0.0.1
                                        │
                                        ▼
                               browser dashboard (static/)
                          polls /api/snapshot every 2 seconds
                         and draws the map and tables with d3
```

### Step by step

1. **Collecting.** `nettop -L 1 -n -x` prints every open socket on the system,
   grouped by process, with byte counters, TCP state, interface and round-trip
   time. It doesn't need root and it sees system processes too. The collector
   parses this CSV output every couple of seconds.
2. **Diffing.** The engine keeps the previous sample in memory. A connection that
   appears is logged as `open`, and one that disappears is logged as `close` with
   its total bytes and duration. Byte counters are compared to work out the
   current speed.
3. **Enriching.** Each new connection gets extra context:
   - GeoIP and ASN from the local DB-IP files, read with `maxminddb`
   - hostname from DNS capture if it's running, otherwise a reverse DNS lookup
   - app name from the process path, so `Google Chrome Helper` is grouped under `Google Chrome`
   - code signature from `codesign -dv`, cached per binary
   - scope: public, private, loopback, link-local, multicast
4. **Detecting.** Every rule in `rules.yaml` is checked against every live
   connection. A match creates an alert. The same rule, app and destination
   won't alert again for 30 minutes.
5. **Storing.** Events, alerts and the baseline of known app/destination pairs go
   into `data/siem.db`. Old history is cleaned up after 14 days.
6. **Showing.** `server.py` serves the dashboard and a small JSON API. The page
   polls it and redraws the map, charts and tables.

### Tech used

| Part | What | Why |
|---|---|---|
| Flow source | `nettop` (macOS) | Per-process sockets with byte counts, no root needed |
| DNS names | `tcpdump` (macOS) | Optional, maps IPs back to the domains that were looked up |
| Signatures | `codesign` (macOS) | Tells Apple, third-party and unsigned binaries apart |
| GeoIP | DB-IP Lite City + ASN, `maxminddb` | Free, offline, monthly updates |
| Backend | Python 3, `http.server`, `sqlite3` | No web framework, no database server |
| Rules | YAML + Python `ast` | Readable rules, validated so they can't run arbitrary code |
| Frontend | Plain JavaScript, d3 v7, topojson | No build step |
| Map | Natural Earth via `world-atlas` | Country outlines |

## Project structure

```
mac-siem/
├── mac_siem.py          entry point: loads config, starts the poller and web server
├── run.sh               creates the venv on first run and starts the app
├── setup_geoip.sh       downloads the GeoIP databases
├── config.yaml          settings
├── rules.yaml           detection rules
├── requirements.txt
├── siem/
│   ├── collector.py     runs and parses nettop, looks up process info
│   ├── engine.py        main loop, diffing, alerts, snapshot for the UI
│   ├── enrich.py        GeoIP, hostnames, DNS capture, codesign, port names
│   ├── rules.py         rule parser and safe expression evaluator
│   ├── store.py         SQLite tables and queries
│   └── server.py        HTTP API and static files
├── static/
│   ├── index.html
│   ├── app.js           dashboard logic, map, charts, tables
│   ├── style.css
│   └── countries.js     ISO country code lookup for the map
└── data/                created at runtime: GeoIP files, siem.db, API token
```

## Using the dashboard

**Overview** has the summary numbers, the map, open alerts, throughput, and top
apps, countries and organisations. Click a dot or a country on the map to jump
to those connections.

**Connections** lists every live connection. Click a row for the full details,
with links to look the IP up on bgp.he.net, AbuseIPDB and Shodan. The search
box supports filters:

```
app:chrome
cc:US port:443
org:"amazon"
ip:17.57.145.26
sev:high
```

**Alerts** shows rule matches. Filter by severity and acknowledge them once you've looked.

**Rules** lets you edit `rules.yaml` in the browser. It's validated before
saving, so a typo won't break detection. The tester on the right runs any
condition against current traffic so you can see what it would match.

**History** lets you search past connections by app, IP, host, organisation or
country, over the last hour up to the last 30 days.

## Writing rules

Rules are in `rules.yaml`:

```yaml
- id: unsigned-to-russia
  name: Unsigned binary talking to Russia
  severity: critical
  condition: country_code == "RU" and not signed

- id: zoom-elsewhere
  name: Zoom connecting outside Zoom's network
  severity: medium
  condition: app == "zoom.us" and not contains(org, "zoom") and scope == "public"

- id: big-upload
  name: Large upload from a non-Apple app
  severity: high
  condition: bytes_out > 200 * 1024 * 1024 and not apple
```

Severity is one of `info`, `low`, `medium`, `high`, `critical`. Add
`enabled: false` to turn a rule off without deleting it.

**Fields you can use**

| Field | Example |
|---|---|
| `app`, `process`, `path`, `pid`, `user` | `app == "Slack"` |
| `proto` | `"tcp"`, `"udp"`, `"quic"` |
| `remote_ip`, `remote_port`, `local_ip`, `local_port` | `remote_port == 22` |
| `service` | `"https"`, `"ssh"`, `"dns"` |
| `scope` | `"public"`, `"private"`, `"loopback"`, `"link-local"`, `"multicast"` |
| `country`, `country_code`, `city` | `country_code in ["CN", "RU"]` |
| `asn`, `org` | `contains(org, "digitalocean")` |
| `hostname` | `endswith(hostname, ".onion")` |
| `state`, `interface` | `state == "SynSent"` |
| `bytes_in`, `bytes_out`, `rate_in`, `rate_out` | `rate_out > 1000000` |
| `rtt_ms`, `duration` | `duration > 3600` |
| `signed`, `apple`, `signer`, `team_id` | `not signed` |
| `new_app`, `new_dest` | `new_dest and not apple` |

**Helpers:** `cidr(ip, "10.0.0.0/8")`, `regex(value, "pattern")`,
`contains(value, "text")`, `any_of(value, "a", "b")`, `startswith(value, "x")`,
`endswith(value, "x")`, `lower(value)`, `len(value)`

`new_app` and `new_dest` depend on the baseline. For the first 10 minutes after
the first run the app only records what's normal. After that, `new_app` is true
the first time an app reaches the internet, and `new_dest` is true the first
time an app talks to a new organisation.

## Configuration

`config.yaml`:

```yaml
port: 8765
poll_interval: 2            # seconds between samples
retention_days: 14          # how long history is kept
rules_file: rules.yaml
alert_cooldown_minutes: 30
learning_minutes: 10
dns_sniff: auto             # auto or off
# home: {lat: 28.61, lon: 77.21, label: "New Delhi"}
```

`home` sets where the map lines start. If you leave it out, the app tries to
work it out from your public IPv6 address using the local GeoIP data.

## Security

The app shows sensitive information, so the server is locked down:

- it only listens on `127.0.0.1`
- requests with a `Host` header other than localhost are rejected, which blocks DNS rebinding
- any request that changes something (saving rules, acknowledging alerts, pausing)
  needs a random token stored in `data/.token` (file mode 600)
- static files come from a fixed list, so there's no path traversal
- strings from the network such as hostnames are escaped before they're put on the page
- rule conditions are parsed and checked against a whitelist before running

## Limitations

- Connections that open and close in under 2 seconds can be missed. Lower
  `poll_interval` if you care about those.
- Safari and apps using WebKit views share one networking process, so they show
  up together as "WebKit (Safari/WebViews)".
- DNS capture can't see encrypted DNS (DNS over HTTPS inside browsers).
- The map outline is loaded from the jsDelivr CDN. Everything else is local.
- macOS only, since it depends on `nettop`.

## Updating GeoIP data

DB-IP publishes new files every month. Run `./setup_geoip.sh` again and restart the app.

## Credits

- IP geolocation by [DB-IP](https://db-ip.com), licensed under CC BY 4.0
- Map data from [Natural Earth](https://www.naturalearthdata.com) via [world-atlas](https://github.com/topojson/world-atlas)
- Charts and map rendering with [d3](https://d3js.org)

## License

MIT, see [LICENSE](LICENSE).

# Running Argus on Ubuntu

Argus is a single Python process backed by a SQLite file. **Ubuntu itself is the
application/monitoring server** — no nginx, Apache, PostgreSQL, or Docker is
required, and Argus does **not** use `dig` or `delv` (it speaks DNS directly via
`dnspython`).

Tested target: Ubuntu 20.04+ with Python 3.10+.

---

## 1. Install prerequisites (once)

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
```

Optional, for *manual* cross-checking only (Argus does not need them):

```bash
sudo apt install -y dnsutils bind9-dnsutils    # provides dig, delv
```

## 2. Get the project and set it up

```bash
git clone https://github.com/Buddika13/argus.git   # or copy your project folder
cd argus
bash scripts/setup_ubuntu.sh        # creates .venv, installs deps, inits the DB
```

(Or `make setup`.)

## 3. Run it

Activate the environment first:

```bash
source .venv/bin/activate
```

Then:

```bash
python -m argus status         # configuration + database readiness
python -m argus run-once       # one monitoring sweep (writes to the database)
python -m argus report         # write report.html
python -m argus dashboard      # live dashboard at http://127.0.0.1:8080
python -m argus serve          # continuous monitoring (Ctrl+C to stop)
```

Equivalent `make` targets: `make status`, `make sweep`, `make dashboard`,
`make serve`, `make report`.

## 4. Live workflow demo (for a supervisor)

```bash
python scripts/demo_workflow.py www.google.com 8.8.8.8
```

Shows, for a real domain: the DNS query, returned A/AAAA records, TTL, response
time, RCODE, independent authoritative verification, DNSSEC posture, the
comparison result, and the final health/integrity verdict. Try other domains and
resolvers, e.g. `python scripts/demo_workflow.py cloudflare.com 1.1.1.1`.

## 5. Run continuously as a service (make Ubuntu the monitoring server)

```bash
sudo cp deploy/argus.service /etc/systemd/system/argus.service
sudo nano /etc/systemd/system/argus.service     # set User= and the two paths
sudo systemctl daemon-reload
sudo systemctl enable --now argus
systemctl status argus
journalctl -u argus -f                           # follow the logs
```

Optionally serve the dashboard continuously too with
`deploy/argus-dashboard.service`. To view it from your laptop over SSH:

```bash
ssh -L 8080:127.0.0.1:8080 user@your-server      # then open http://127.0.0.1:8080
```

## 6. Configuration

Edit the files in `config/`:

- `config/resolvers.yaml` — add your resolvers. **ISP IP addresses are
  placeholders**; replace them with the real resolver IPs and set
  `enabled: true`.
- `config/watchlist.txt` — the domains to monitor.
- `config/config.yaml` — sweep interval, timeouts, DNSSEC toggle, database path.

## 7. Tests and evaluation

```bash
python -m unittest discover -s tests -p "test_*.py"   # or: make test
python scripts/collect_eval.py --sweeps 6 --interval 10  # clean dataset
python -m pip install matplotlib
python scripts/graph_eval.py                             # graphs/ (PNG figures)
```

## Troubleshooting

- **`python: command not found`** — use `python3`, or activate the venv
  (`source .venv/bin/activate`) which provides `python`.
- **`ModuleNotFoundError: No module named 'argus'`** — run from the project root
  (the folder containing the `argus/` directory), or use `.venv/bin/python`.
- **`No module named 'dns'`** — dependencies not installed; run
  `pip install -r requirements.txt` inside the activated venv.
- **Dashboard not reachable remotely** — it binds to loopback by design; use the
  SSH tunnel above rather than exposing it.

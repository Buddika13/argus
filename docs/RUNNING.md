# How to Run Argus

## Prerequisites

- **Python 3.10 or newer** (developed on 3.12).
- Confirm it works: `python --version`.

## One-time setup

From the project folder:

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

On Linux use `source .venv/bin/activate` then `pip install -r requirements.txt`.

### Windows note

If `.venv\Scripts\activate` is blocked ("running scripts is disabled"), either
call the venv Python directly (as below) or allow scripts once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

Below, `python` means `.venv\Scripts\python.exe` if you have not activated the venv.

## Commands

```powershell
python -m argus status        # show configuration, database and readiness
python -m argus run-once      # one full monitoring sweep (writes to the database)
python -m argus report        # write report.html and open it in the browser
python -m argus dashboard     # serve a live, auto-refreshing dashboard (Ctrl+C to stop)
python -m argus serve         # continuous monitoring on the configured interval
```

- `report` writes a one-off static snapshot (`--no-open` to skip opening it).
- `dashboard` serves `http://127.0.0.1:8080`, re-reading the database on every
  request so it always shows live data (`--host`, `--port`, `--refresh`).

## Database

```powershell
python scripts\init_db.py                    # create schema + seed resolvers/domains from config
python scripts\init_db.py --with-sample-data # also load sample rows (testing only)
```

The database is `data/argus.sqlite3` (path configurable in `config/config.yaml`).
Schema creation is idempotent and never deletes existing data.

## Evaluation (research graphs)

```powershell
.venv\Scripts\python.exe -m pip install matplotlib   # analysis-only dependency
python scripts\collect_eval.py --sweeps 6 --interval 10   # clean dataset -> data/eval.sqlite3
python scripts\graph_eval.py                              # PNG graphs -> graphs/
```

## Tests

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

## Configuration files

| File | Purpose |
| --- | --- |
| `config/config.yaml` | Interval, timeouts, DNSSEC toggle, thresholds, database path. |
| `config/resolvers.yaml` | Monitored resolvers + controls. Set real ISP IPs and `enabled: true`. |
| `config/watchlist.txt` | Monitored domains. |
| `.env` (from `.env.example`) | Optional `ARGUS_VANTAGE` for this probe node. |

# Argus — convenience targets for Ubuntu/Linux.
# Usage:  make setup   then   make sweep / make dashboard / make demo / make test
#
# PY points at the venv interpreter created by `make setup`.

PY := .venv/bin/python

.PHONY: help setup status sweep serve report dashboard demo test collect graphs clean

help:
	@echo "Argus targets:"
	@echo "  make setup      - create venv, install deps, init database"
	@echo "  make status     - show configuration and readiness"
	@echo "  make sweep      - run one monitoring sweep"
	@echo "  make serve      - continuous monitoring (Ctrl+C to stop)"
	@echo "  make dashboard  - live dashboard at http://127.0.0.1:8080"
	@echo "  make report     - write a static report.html"
	@echo "  make demo       - live workflow demo for www.google.com"
	@echo "  make test       - run the unit test suite"
	@echo "  make collect    - collect a clean evaluation dataset"
	@echo "  make graphs     - generate evaluation graphs (needs matplotlib)"

setup:
	bash scripts/setup_ubuntu.sh

status:
	$(PY) -m argus status

sweep:
	$(PY) -m argus run-once

serve:
	$(PY) -m argus serve

report:
	$(PY) -m argus report --no-open

dashboard:
	$(PY) -m argus dashboard

demo:
	$(PY) scripts/demo_workflow.py www.google.com 8.8.8.8

test:
	$(PY) -m unittest discover -s tests -p "test_*.py"

collect:
	$(PY) scripts/collect_eval.py --sweeps 6 --interval 10

graphs:
	$(PY) -m pip install matplotlib >/dev/null && $(PY) scripts/graph_eval.py

clean:
	rm -rf __pycache__ argus/__pycache__ tests/__pycache__ scripts/__pycache__

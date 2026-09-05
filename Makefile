# VulnIntel AI
#
# The venv deliberately lives outside the project. This repository is often kept
# on an external drive, and macOS writes AppleDouble sidecar files (._name) on
# any filesystem that cannot store extended attributes — exFAT, FAT32, most USB
# disks. Those sidecars break pip: a ._pip-24.0.dist-info matches the *.dist-info
# glob, is binary, and fails to decode. Keeping the environment on the system
# disk avoids the whole class of problem.

VENV        ?= $(HOME)/.venvs/vulnintel-ai
PY          := $(VENV)/bin/python
PIP         := $(PY) -m pip
export PYTHONPATH := src:apps

HOST ?= 127.0.0.1
PORT ?= 8000

.DEFAULT_GOAL := help
.PHONY: help venv install install-dev clean-osx db generate ingest ingest-nvd rag \
        match score bootstrap demo serve serve-reload rank ask status test test-cov \
        lint fmt eval mcp-demo report up down logs psql reset

help:  ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- environment

venv:  ## Create the virtualenv (outside the repo, see header)
	@test -d $(VENV) || python3 -m venv $(VENV)
	@$(PIP) install -q --upgrade pip
	@echo "venv ready at $(VENV)"

install: venv  ## Install the package and runtime dependencies
	@$(PIP) install -q -e .
	@echo "installed"

install-dev: venv  ## Install with dev, docs and postgres extras
	@$(PIP) install -q -e ".[dev,docs]"
	@echo "installed (dev)"

clean-osx:  ## Delete macOS AppleDouble sidecars and .DS_Store
	@find . -name '._*' -type f -delete 2>/dev/null || true
	@find . -name '.DS_Store' -type f -delete 2>/dev/null || true
	@echo "cleaned"

# ---------------------------------------------------------------- pipeline

db:  ## Create the schema and serving views
	@$(PY) -m vulnintel.cli db init

generate:  ## Generate the synthetic estate from a fixed seed
	@$(PY) -m vulnintel.cli generate

ingest:  ## Ingest the fast feeds (KEV, EPSS, OSV, ATT&CK)
	@$(PY) -m vulnintel.cli ingest kev epss osv attack

ingest-nvd:  ## Backfill the full NVD corpus (~30 min; set NVD_API_KEY to speed it up)
	@$(PY) -m vulnintel.cli ingest nvd --backfill

rag:  ## Generate the policy corpus, chunk, embed and index it
	@$(PY) -m vulnintel.cli rag build

match:  ## Match inventory against advisories
	@$(PY) -m vulnintel.cli match

score:  ## Compute enterprise priority scores
	@$(PY) -m vulnintel.cli score

bootstrap:  ## Everything except the NVD backfill, in order
	@$(PY) -m vulnintel.cli bootstrap

demo: bootstrap  ## Bootstrap then show the ranked queue with no model involved
	@$(PY) -m vulnintel.cli rank --limit 5 --by-cve

reset:  ## Drop every table and rebuild the schema
	@$(PY) -m vulnintel.cli db reset --yes

# ---------------------------------------------------------------- running

serve:  ## Run the API and UI
	@$(PY) -m uvicorn api.main:app --host $(HOST) --port $(PORT)

serve-reload:  ## Run with autoreload for development
	@$(PY) -m uvicorn api.main:app --host $(HOST) --port $(PORT) --reload

rank:  ## Ranked findings, deterministic, no model call
	@$(PY) -m vulnintel.cli rank --limit 10 --explain

ask:  ## Ask a question (make ask Q="are we exposed to CVE-2023-44487?")
	@$(PY) -m vulnintel.cli ask "$(Q)"

status:  ## What is loaded and what is missing
	@$(PY) -m vulnintel.cli status

mcp-demo:  ## Prove the MCP servers over a real stdio client
	@$(PY) -m vulnintel.mcp_servers.client_demo

# ---------------------------------------------------------------- quality

test:  ## Run the test suite
	@$(PY) -m pytest

test-cov:  ## Run tests with a coverage report
	@$(PY) -m pytest --cov --cov-report=term-missing

lint:  ## Check formatting and lint rules
	@$(VENV)/bin/ruff check .
	@$(VENV)/bin/ruff format --check .

fmt:  ## Apply formatting and safe lint fixes
	@$(VENV)/bin/ruff check --fix .
	@$(VENV)/bin/ruff format .

eval:  ## Run every evaluation suite
	@$(PY) -m vulnintel.cli eval all

report:  ## Rebuild the optimisation report (docx, gitignored)
	@$(PY) scripts/build_optimisation_report.py

# ---------------------------------------------------------------- docker

up:  ## Start Postgres and the app in containers
	@docker compose up -d --build
	@echo "UI on http://localhost:8000"

down:  ## Stop the containers
	@docker compose down

logs:  ## Follow the app logs
	@docker compose logs -f app

psql:  ## Open a psql shell against the container
	@docker compose exec postgres psql -U vulnintel -d vulnintel

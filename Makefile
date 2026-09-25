.PHONY: install test lint run-dashboard clean

# ── Virtualenv helpers ────────────────────────────────────────────────────────
VENV       := .venv
PYTHON     := $(VENV)/bin/python
PIP        := $(VENV)/bin/pip
PYTEST     := $(VENV)/bin/pytest
RUFF       := $(VENV)/bin/ruff
UVICORN    := $(VENV)/bin/uvicorn

$(VENV)/bin/activate:
	python3 -m venv $(VENV)

## install: create venv and install all dependencies
install: $(VENV)/bin/activate
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	$(PIP) install -e .
	@echo "\n✅  Sieve installed. Activate with: source $(VENV)/bin/activate"

## test: run the full pytest suite
test:
	$(PYTEST) tests/ -v

## test-sanity: run only the sanity / bootstrap tests
test-sanity:
	$(PYTEST) tests/test_sanity.py -v

## lint: run ruff linter
lint:
	$(RUFF) check sieve/ tests/

## lint-fix: run ruff with auto-fix
lint-fix:
	$(RUFF) check --fix sieve/ tests/

## run-dashboard: start the FastAPI dashboard (development mode)
run-dashboard:
	$(UVICORN) sieve.dashboard.api:app \
		--host $${DASHBOARD_HOST:-127.0.0.1} \
		--port $${DASHBOARD_PORT:-8000} \
		--reload

## run-mcp: start the MCP server (stdio transport)
run-mcp:
	$(PYTHON) -m sieve.mcp.server

## clean: remove build artifacts and caches
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf dist/ build/ .pytest_cache/ .ruff_cache/ .mypy_cache/ htmlcov/ .coverage

## help: show this help
help:
	@grep -E '^## ' Makefile | sed 's/## /  /'

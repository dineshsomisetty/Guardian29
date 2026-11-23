PY ?= uv run python
REPO ?= targets/juice-shop

.PHONY: setup check lint test run serve-runs

setup:
	uv sync --extra dev

lint:
	uv run ruff check guardian tests
	$(PY) scripts/check_forbidden.py

test:
	uv run pytest -q

check: lint test

run:
	$(PY) -m guardian run --repo $(REPO)

serve-runs:
	$(PY) -m guardian serve-runs --port 8001

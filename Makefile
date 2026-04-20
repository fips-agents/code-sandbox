.DEFAULT_GOAL := help
PROFILE ?= minimal

.PHONY: help install test lint build build-profile run clean

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Create venv and install in editable mode with dev deps
	python3 -m venv .venv
	.venv/bin/pip install -e ".[dev]"
	@echo "\n  Activate: source .venv/bin/activate"

test:  ## Run tests
	.venv/bin/pytest -v --tb=short

lint:  ## Run linter
	.venv/bin/ruff check sandbox/ tests/

build:  ## Build container image (default: minimal profile)
	podman build --platform linux/amd64 -t code-sandbox:$(PROFILE) \
		--build-arg PROFILE=$(PROFILE) -f Containerfile . --no-cache

run:  ## Run sandbox locally (dev mode)
	SANDBOX_PROFILE=$(PROFILE) .venv/bin/uvicorn sandbox.app:app --host 0.0.0.0 --port 8000 --reload

clean:  ## Remove build artifacts
	rm -rf .venv __pycache__ .pytest_cache .ruff_cache dist/

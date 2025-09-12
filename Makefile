SHELL := /bin/bash

TOOL := threatlens.sh
BIN := threatlens

.PHONY: install run test clean deps-kali deps env

install:
	@echo "Installing $(TOOL) to /usr/local/bin/$(BIN)"
	@install -m 0755 $(TOOL) /usr/local/bin/$(BIN)

run:
	@if [ -x .venv/bin/threatlens ]; then \
		.venv/bin/threatlens --help || true; \
	else \
		./$(TOOL) --help || true; \
	fi

test:
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck -S style $(TOOL); \
	else \
		echo "shellcheck not found; skipping lint"; \
	fi

clean:
	@rm -rf output
	@echo "Cleaned outputs"

deps-kali:
	@bash scripts/install_kali.sh

deps:
	@bash scripts/install.sh

env:
	@bash scripts/bootstrap_env.sh

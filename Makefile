SHELL := /bin/bash

TOOL := threatlens.sh
BIN := threatlens

.PHONY: install run test clean

install:
	@echo "Installing $(TOOL) to /usr/local/bin/$(BIN)"
	@install -m 0755 $(TOOL) /usr/local/bin/$(BIN)

run:
	@./$(TOOL) --help || true

test:
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck -S style $(TOOL); \
	else \
		echo "shellcheck not found; skipping lint"; \
	fi

clean:
	@rm -rf output
	@echo "Cleaned outputs"


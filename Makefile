SHELL := /bin/bash
export BASH_ENV=
export ENV=
SRC := authforge.sh $(wildcard core/*.sh lib/*.sh modules/*.sh plugins/*.sh scripts/*.sh)
TESTSRC := tests/run.sh $(wildcard tests/lib/*.sh tests/unit/*.sh tests/integration/*.sh tests/regression/*.sh)

PREFIX ?= $(HOME)/.local

.PHONY: all check lint test test-unit test-integration test-regression test-compliance test-install install uninstall clean clean-data

all: check lint test

check: ## Bash syntax check (bash -n)
	@for f in $(SRC) $(TESTSRC); do bash -n "$$f" || exit 1; done; echo "syntax OK ($(words $(SRC) $(TESTSRC)) files)"

lint: ## ShellCheck: product code at style level, tests at warning level
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck -x -S style $(SRC) && \
		shellcheck -x -S warning $(TESTSRC) && \
		echo "shellcheck OK"; \
	else \
		echo "shellcheck not installed (skipped)"; \
	fi

test: ## All suites
	tests/run.sh all

test-unit:
	tests/run.sh unit

test-integration:
	tests/run.sh integration

test-regression:
	tests/run.sh regression

test-compliance: ## Run M5-P1 compliance and evidence unit suites
	bash tests/unit/test_compliance.sh && bash tests/unit/test_evidence.sh

test-install: ## Run M5-P2 installation and uninstallation unit suite
	bash tests/unit/test_install.sh

install: ## Install AUTHFORGE (default user-local under PREFIX=~/.local)
	./scripts/install.sh --prefix "$(PREFIX)"

uninstall: ## Uninstall AUTHFORGE code/launcher (preserves user data by default)
	./scripts/uninstall.sh --prefix "$(PREFIX)"

clean: clean-data ## Alias for clean-data (DESTRUCTIVE: removes generated sessions, logs, evidence, backups)

clean-data: ## Remove generated sessions, logs, evidence, backups, temp test data (keeps .gitkeep)
	find reports logs evidence -mindepth 1 ! -name .gitkeep -delete 2>/dev/null || true
	rm -rf backups .tmp-test

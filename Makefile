# Set the shell to bash
SHELL := /bin/bash

.SILENT: install clean format ruff-fix build publish test-publish show-package

APP_NAME ?= "DetectIQ"
PYTHON_FILES := $(shell git ls-files "*.py")

# Default target is help
.DEFAULT_GOAL := help

# ENSURE POETRY ENV
.PHONY: ensure-poetry-env
ensure-poetry-env: ## Ensure Poetry environment is properly set up
	@echo "\033[1;34m[i] Ensuring Poetry environment is available...\033[0m"
	@if ! poetry env info -p >/dev/null 2>&1; then \
		echo "\033[1;33m[*] Creating virtual environment...\033[0m"; \
		poetry env use python; \
	fi
	@echo "\033[1;32m[✓] Poetry environment: $$(poetry env info -p)\033[0m"

# HELP TARGET
.PHONY: help
help: ## Show this help message
	@echo "Usage:"
	@echo "  make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  help                     Show this help message"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_\/-]+:.*?## / {if ($$1 != "help") printf "  %-25s%s\n", $$1, $$2}' $(MAKEFILE_LIST) | sort
	@echo ""
	@echo "⚠️  IMPORTANT: Never commit or distribute .env files with API keys or secrets!"
	@echo "    Use .env.example as a template, but keep your .env files private."

# CLEAN TARGETS
.PHONY: clean/poetry-env
clean/poetry-env: ## Clean Poetry virtual environment
	@echo "\033[1;33m[*] Cleaning Poetry virtual environment\033[0m"
	@if poetry env info -p >/dev/null 2>&1; then \
		echo "Removing Poetry virtual environment for $(APP_NAME)..."; \
		poetry env remove $$(poetry env info -p) 2>/dev/null || true; \
	else \
		echo "No Poetry environment found for this project."; \
	fi
	@echo "\033[1;32m[✓] Poetry environment cleaned\033[0m"

.PHONY: clean
clean: clean/poetry-env ## Clean backend artifacts and Poetry virtual environment
	@echo "\033[1;33m[*] Cleaning backend artifacts\033[0m"
	@echo "Cleaning up Python cache files and build artifacts..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type f -name "*.pyd" -delete 2>/dev/null || true
	rm -rf dist/ build/ 2>/dev/null || true
	rm -rf .pytest_cache/ .ruff_cache/ .coverage htmlcov/ .mypy_cache/ .tox/ 2>/dev/null || true
	@echo "\033[1;32m[✓] Backend cleaned\033[0m"
	@echo "\033[1;33m[*] Deep cleaning project (backend & poetry env)\033[0m"
	@echo "\033[1;32m[✓] Project cleaned\033[0m"

# INSTALL TARGETS
.PHONY: update
update: ensure-poetry-env ## Update all backend dependencies to their latest versions
	@echo "\033[1;33m[*] Updating '$(APP_NAME)' backend dependencies\033[0m"
	@echo "Updating backend dependencies..."
	poetry update
	@echo "\033[1;32m[✓] Backend dependencies updated\033[0m"

.PHONY: initialize/rulesets
initialize/rulesets: ensure-poetry-env ## Initialize all rulesets (long-running operation)
	@echo "\033[1;33m[*] Initializing rulesets (this may take several minutes)\033[0m"
	# TODO: Update command to initialize rulesets without Django/manage.py.
	# The previous command was: poetry run python manage.py initialize_rulesets --rule_types snort --force
	# This needs to be replaced with a direct script call if the functionality is still required.
	@echo "\033[1;32m[✓] Rulesets initialization placeholder (command needs update)\033[0m"

.PHONY: install
install: ensure-poetry-env ## Install backend dependencies and extras
	@echo "\033[1;33m[*] Installing '$(APP_NAME)' backend dependencies and extras\033[0m"
	poetry install --all-extras
	@echo "\033[1;32m[✓] Backend dependencies installed\033[0m"
	@echo "\033[1;32m[!] Installing '${APP_NAME}' backend completed\033[0m"
	@echo "\033[1;34m[i] To initialize or update rulesets, run 'make initialize/rulesets'\033[0m"

# FORMAT TARGET
.PHONY: format
format: ensure-poetry-env ## Format Python code with Black
	@echo "Formatting Python files with Black..."
	poetry run black . # Use current directory for black, similar to original broader scope
	@echo "Formatting completed"

.PHONY: ruff
ruff: ensure-poetry-env ## Run Ruff linter
	@echo "Running Ruff linter..."
	poetry run ruff check --ignore E501,F401 $(PYTHON_FILES)

.PHONY: ruff-fix
ruff-fix: ensure-poetry-env ## Run Ruff linter with auto-fixes
	@echo "Running Ruff linter with auto-fixes..."
	poetry run ruff check --fix --ignore E501,F401 $(PYTHON_FILES) # Aligned ignored rules with SigmaIQ

# TEST TARGET
.PHONY: test
test: ensure-poetry-env ## Run backend tests with coverage (installs test dependencies if needed)
	@echo "Installing test dependencies..."
	poetry install --with dev
	@echo "Running tests with coverage..."
	poetry run pytest tests/ --cov=detectiq --cov-report=term-missing

# TOKEN TARGETS
.PHONY: token-check
token-check: ensure-poetry-env ## Check if PyPI token is configured
	@echo "Checking PyPI token configuration..."
	@# First check using poetry config, but suppress error messages
	@if poetry config pypi-token.pypi 2>/dev/null | grep -q "."; then \
		echo "✓ PyPI token found"; \
	else \
		if poetry run python -c "import keyring; keyring.get_password('pypi-token', 'pypi') and print('Token found')" 2>/dev/null | grep -q "Token found"; then \
			echo "✓ PyPI token found (in keyring)"; \
		else \
			echo "PyPI token not configured. Please run:"; \
			echo "make token-set TOKEN=your-token-here"; \
			echo ""; \
			echo "If you encounter keyring errors, install keyrings.alt:"; \
			echo "pip install keyrings.alt"; \
			exit 1; \
		fi \
	fi

.PHONY: token-set
token-set: ensure-poetry-env ## Set PyPI token (Usage: make token-set TOKEN=your-token-here)
	@if [ -z "$(TOKEN)" ]; then \
		echo "Error: TOKEN is required. Usage: make token-set TOKEN=your-token-here"; \
		exit 1; \
	fi
	@echo "Setting PyPI token..."
	@poetry config pypi-token.pypi "$(TOKEN)"
	@# Try to store in keyring but don't fail if it doesn't work
	@poetry run python -c "import keyring; keyring.set_password('pypi-token', 'pypi', '$(TOKEN)')" 2>/dev/null || echo "Note: Token stored in poetry config only (keyring backend not available)"
	@echo "Token configured successfully"

.PHONY: token-remove
token-remove: ensure-poetry-env ## Remove PyPI token configuration
	@echo "Removing PyPI token..."
	@poetry config --unset pypi-token.pypi 2>/dev/null || true
	@# Try to remove from keyring but don't fail if it doesn't work
	@poetry run python -c "import keyring; keyring.delete_password('pypi-token', 'pypi')" 2>/dev/null || echo "Note: Keyring backend not available, token removed from poetry config only"
	@rm -f ~/.config/pypoetry/auth.toml 2>/dev/null || true
	@echo "Token removed successfully"

# VERSION TARGETS
.PHONY: version
version: ensure-poetry-env ## Display current version
	@poetry version

.PHONY: version-patch
version-patch: ensure-poetry-env ## Bump patch version (0.0.X)
	@poetry version patch
	@$(MAKE) _sync-version

.PHONY: version-minor
version-minor: ensure-poetry-env ## Bump minor version (0.X.0)
	@poetry version minor
	@$(MAKE) _sync-version

.PHONY: version-major
version-major: ensure-poetry-env ## Bump major version (X.0.0)
	@poetry version major
	@$(MAKE) _sync-version

.PHONY: _sync-version
_sync-version: ensure-poetry-env
	@echo "Syncing versions..."
	@VERSION=$$(poetry version -s) && \
	echo "New version: $$VERSION" && \
	sed -i.bak "s/__version__ = .*/__version__ = \"$$VERSION\"/" detectiq/__init__.py && \
	rm -f detectiq/__init__.py.bak

.PHONY: _lock
_lock: ensure-poetry-env
	@echo "Updating poetry.lock file..."
	poetry lock

# BUILD TARGET
.PHONY: build
build: ensure-poetry-env clean ## Build the package
	@echo "\033[1;33m[*] Building '$(APP_NAME)' package\033[0m"
	poetry build
	@echo "\033[1;32m[✓] Package built successfully to dist/\033[0m"

# TEST PUBLISH TARGET
.PHONY: test-publish
test-publish: ensure-poetry-env token-check build ## Build and publish package to TestPyPI
	@echo "\033[1;33m[*] Publishing '$(APP_NAME)' to TestPyPI\033[0m"
	@# Ensure twine is available (it's a dev dependency)
	@if ! poetry run twine --version >/dev/null 2>&1; then \
		echo "\033[1;31m[!] Twine is not installed or not found in poetry env. Please install dev dependencies (make install or ensure twine is in dev group).\033[0m"; \
		exit 1; \
	fi
	twine upload --repository testpypi dist/*
	@echo "\033[1;32m[✓] Published to TestPyPI successfully\033[0m"

# PUBLISH TARGET
.PHONY: publish
publish: ensure-poetry-env token-check build ## Publish package to PyPI (requires prior build)
	@echo "\033[1;33m[*] Publishing '$(APP_NAME)' to PyPI\033[0m"
	@# Verify keyring is installed
	@if ! poetry run pip show keyring >/dev/null 2>&1; then \
		echo "\033[1;33m[*] Installing keyring...\033[0m"; \
		poetry run pip install keyring keyrings.alt; \
	fi
	poetry publish
	@echo "\033[1;32m[✓] Published to PyPI successfully\033[0m"

# SHOW PACKAGE CONTENTS TARGET
.PHONY: show-package
show-package: ensure-poetry-env build ## Show contents of the built package files
	@echo "\033[1;33m[*] Showing contents of built packages in dist/\033[0m"
	@if [ -z "$$(ls -A dist/*.tar.gz 2>/dev/null)" ] || [ -z "$$(ls -A dist/*.whl 2>/dev/null)" ]; then \
		echo "\033[1;31m[!] No built packages found in dist/. Run 'make build' first.\033[0m"; \
		exit 1; \
	fi
	@echo "\n--- Contents of .tar.gz file ---"
	@for tarball in dist/*.tar.gz; do \
		if [ -f "$$tarball" ]; then \
			echo "Contents of $$tarball:"; \
			tar tzf "$$tarball"; \
			echo ""; \
		fi; \
	done
	@echo "\n--- Contents of .whl file (archive listing) ---"
	@for wheel in dist/*.whl; do \
		if [ -f "$$wheel" ]; then \
			echo "Contents of $$wheel:"; \
			unzip -l "$$wheel"; \
			echo ""; \
		fi; \
	done
	@echo "\033[1;32m[✓] Finished showing package contents\033[0m"

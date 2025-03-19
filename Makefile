# Set the shell to bash
SHELL := /bin/bash

.SILENT: install/backend/dependencies install/frontend/dependencies install/backend start/backend start/frontend run/local

APP_NAME ?= "DetectIQ"

# Define source directories
SRC_DIRS := detectiq tests
# Explicitly filter out node_modules from Python files list
PYTHON_FILES := $(shell find $(SRC_DIRS) -type f -name "*.py" 2>/dev/null | grep -v "node_modules")

# Default target is help
.DEFAULT_GOAL := help

# Help target - only shows available commands, doesn't execute anything
.PHONY: help
help: ## Show this help message
	@echo "Usage:"
	@echo "  make <target>"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_\/-]+:.*?## / {printf "  %-25s%s\n", $$1, $$2}' $(MAKEFILE_LIST) | sort
	@echo ""
	@echo "⚠️  IMPORTANT: Never commit or distribute .env files with API keys or secrets!"
	@echo "    Use .env.example as a template, but keep your .env files private."

install/backend/dependencies: ## Install backend dependencies using Poetry
	@echo "\033[1;33m[*] Installing '$(APP_NAME)' backend dependencies\033[0m"
	poetry install --all-extras

install/backend: install/backend/dependencies ## Build backend and initialize databases and rulesets
	@echo "\033[1;33m[*] Building '$(APP_NAME)' backend\033[0m"
	cd detectiq/ &&\
	poetry run python manage.py migrate &&\
	poetry run python manage.py initialize_rulesets --create_vectorstores &&\
	poetry run python manage.py initialize_rulesets --rule_types sigma yara &&\
	poetry run python manage.py initialize_rulesets --rule_types snort --force 

install/frontend/dependencies: ## Install frontend dependencies using npm
	@echo "\033[1;33m[*] Installing '$(APP_NAME)' frontend dependencies\033[0m"
	cd detectiq/webapp/frontend &&\
	npm install

install/local: install/backend install/frontend/dependencies ## Complete local installation of both backend and frontend
	@echo "\033[1;32m[!] Installing '${APP_NAME}'\033[0m"

start/backend: ## Start the Django backend server
	@echo "\033[1;33m[*] Starting '$(APP_NAME)' backend\033[0m"
	cd detectiq/webapp/backend &&\
	poetry run python manage.py runserver &
	sleep 10

start/frontend: ## Start the frontend development server 
	@echo "\033[1;33m[*] Starting '$(APP_NAME)' frontend\033[0m"
	cd detectiq/webapp/frontend &&\
	npm run dev

run/local: start/backend start/frontend ## Run both backend and frontend servers
	@echo "\033[1;33m[*] Running '$(APP_NAME)'\033[0m"

.PHONY: format
format: ## Format Python files using black
	@echo "Formatting Python files..."
	poetry run black $(PYTHON_FILES)

.PHONY: ruff
ruff: ## Run Ruff linter
	@echo "Running Ruff linter..."
	@# Use the pre-filtered PYTHON_FILES list that excludes node_modules
	poetry run ruff check $(PYTHON_FILES) || true
	@echo "Note: Linting only checks project files, not third-party code."

.PHONY: install-dev
install-dev: lock ## Install development dependencies
	@echo "Installing development dependencies..."
	poetry install --with dev

.PHONY: test
test: install-dev ## Run tests (with coverage)
	@echo "Running tests with coverage..."
	poetry run pytest tests/ --cov=detectiq --cov-report=term-missing

.PHONY: clean
clean: ## Clean up python cache files and build artifacts
	@echo "Cleaning up cache files and build artifacts..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type f -name "*.pyd" -delete 2>/dev/null || true
	rm -rf dist/ build/ 2>/dev/null || true
	rm -rf .pytest_cache/ .ruff_cache/ .coverage htmlcov/ .mypy_cache/ .tox/ 2>/dev/null || true

.PHONY: build
build: ## Build the package using poetry
	@echo "Building package..."
	poetry build

.PHONY: token-check
token-check: ## Check if PyPI token is configured
	@echo "Checking PyPI token configuration..."
	@if ! python -c "import keyring; token = keyring.get_password('pypi-token', 'pypi'); exit(0 if token else 1)"; then \
		echo "PyPI token not configured. Please run:"; \
		echo "make token-set TOKEN=your-token-here"; \
		exit 1; \
	else \
		echo "✓ PyPI token found"; \
	fi

.PHONY: token-set
token-set: ## Set PyPI token (Usage: make token-set TOKEN=your-token-here)
	@if [ -z "$(TOKEN)" ]; then \
		echo "Error: TOKEN is required. Usage: make token-set TOKEN=your-token-here"; \
		exit 1; \
	fi
	@echo "Setting PyPI token..."
	@poetry config pypi-token.pypi "$(TOKEN)"
	@python -c "import keyring; keyring.set_password('pypi-token', 'pypi', '$(TOKEN)')" 2>/dev/null || echo "Warning: Could not store in keyring"
	@echo "Token configured successfully"

.PHONY: token-remove
token-remove: ## Remove PyPI token configuration
	@echo "Removing PyPI token..."
	@poetry config --unset pypi-token.pypi 2>/dev/null || true
	@python -c "import keyring; keyring.delete_password('pypi-token', 'pypi')" 2>/dev/null || true
	@rm -f ~/.config/pypoetry/auth.toml 2>/dev/null || true
	@echo "Token removed successfully"

.PHONY: publish
publish: token-check safety-check ## Publish to PyPI
	@echo "Publishing package to PyPI..."
	poetry publish

.PHONY: format-ruff
format-ruff: format ruff ## Run format and ruff commands 

.PHONY: format-all
format-all: format ruff ## Run all code formatting and linting commands (alias for format-ruff)
	@echo "All formatting and linting completed"

.PHONY: version
version: ## Display current version
	@poetry version

.PHONY: version-patch
version-patch: ## Bump patch version (0.0.X)
	@poetry version patch
	@$(MAKE) sync-version

.PHONY: version-minor
version-minor: ## Bump minor version (0.X.0)
	@poetry version minor
	@$(MAKE) sync-version

.PHONY: version-major
version-major: ## Bump major version (X.0.0)
	@poetry version major
	@$(MAKE) sync-version

.PHONY: sync-version
sync-version: ## Sync version between pyproject.toml and __init__.py
	@echo "Syncing versions..."
	@VERSION=$$(poetry version -s) && \
	echo "New version: $$VERSION" && \
	sed -i.bak "s/__version__ = .*/__version__ = \"$$VERSION\"/" detectiq/__init__.py && \
	rm -f detectiq/__init__.py.bak

.PHONY: lock
lock: ## Update poetry.lock to match pyproject.toml
	@echo "Updating poetry.lock file..."
	poetry lock

.PHONY: update
update: ## Update dependencies to their latest versions
	@echo "Updating dependencies..."
	poetry update 

.PHONY: show-package-contents
show-package-contents: build ## Show contents of the built package
	@echo "Package contents:"
	@tar -tvf dist/*.tar.gz || echo "No tar.gz file found"
	@echo "\nWheel contents:"
	@unzip -l dist/*.whl || echo "No wheel file found" 

.PHONY: pypi-build
pypi-build: safety-check clean ## Build using setuptools for PyPI
	@echo "Building package for PyPI..."
	python -m build

.PHONY: pypi-check
pypi-check: pypi-build ## Check PyPI package with twine
	@echo "Checking package with twine..."
	twine check dist/*

.PHONY: pypi-publish
pypi-publish: token-check pypi-check ## Publish to PyPI using twine
	@echo "Publishing to PyPI..."
	twine upload dist/*

.PHONY: pypi-test-publish
pypi-test-publish: token-check pypi-check ## Publish to TestPyPI
	@echo "Publishing to TestPyPI..."
	twine upload --repository-url https://test.pypi.org/legacy/ dist/*

.PHONY: safety-check
safety-check: ## Check for .env files that shouldn't be committed or packaged
	@echo "Checking for .env files that shouldn't be committed or packaged..."
	@if find . -type f -path "**/.env" ! -path "./.venv/**" | grep -q .; then \
		echo "⚠️ WARNING: .env files found outside of .venv:"; \
		find . -type f -path "**/.env" ! -path "./.venv/**"; \
		echo "These files may contain secrets and should not be committed or packaged."; \
		echo "Make sure they are in .gitignore and excluded in MANIFEST.in and pyproject.toml."; \
	else \
		echo "✓ No problematic .env files found."; \
	fi
	@if find . -type f -name ".env.*" ! -name ".env.example" | grep -q .; then \
		echo "⚠️ WARNING: .env.* files (other than .env.example) found:"; \
		find . -type f -name ".env.*" ! -name ".env.example"; \
		echo "These files may contain secrets and should not be committed or packaged."; \
	else \
		echo "✓ No problematic .env.* files found."; \
	fi

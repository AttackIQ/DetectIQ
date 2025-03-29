# Set the shell to bash
SHELL := /bin/bash

.SILENT: install/backend/dependencies install/frontend/dependencies install/backend start/backend start/frontend run/local dev restart restart/frontend restart/backend clean/backend clean/frontend clean

APP_NAME ?= "DetectIQ"

# Define Python files using git ls-files instead of find
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

.PHONY: clean/backend
clean/backend: ## Clean Python-related files and backend build artifacts
	@echo "\033[1;33m[*] Cleaning backend artifacts\033[0m"
	@echo "Cleaning up Python cache files and build artifacts..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type f -name "*.pyd" -delete 2>/dev/null || true
	rm -rf dist/ build/ 2>/dev/null || true
	rm -rf .pytest_cache/ .ruff_cache/ .coverage htmlcov/ .mypy_cache/ .tox/ 2>/dev/null || true
	@echo "\033[1;32m[✓] Backend cleaned\033[0m"

.PHONY: clean/frontend
clean/frontend: ## Clean frontend build artifacts and dependencies
	@echo "\033[1;33m[*] Cleaning frontend artifacts\033[0m"
	@if [ -d "detectiq/webapp/frontend/node_modules" ]; then \
		echo "Cleaning frontend node_modules..."; \
		rm -rf detectiq/webapp/frontend/node_modules; \
	fi
	@if [ -d "detectiq/webapp/frontend/.next" ]; then \
		echo "Cleaning frontend .next..."; \
		rm -rf detectiq/webapp/frontend/.next; \
	fi
	@echo "\033[1;32m[✓] Frontend cleaned\033[0m"

.PHONY: clean
clean: stop clean/backend clean/frontend clean/poetry-env ## Stop servers and clean both backend and frontend
	@echo "\033[1;33m[*] Deep cleaning entire project\033[0m"
	@echo "\033[1;32m[✓] Project cleaned\033[0m"

# INSTALL TARGETS
install/backend/dependencies: ensure-poetry-env
	@echo "\033[1;33m[*] Installing '$(APP_NAME)' backend dependencies\033[0m"
	poetry install --all-extras

.PHONY: initialize/rulesets
initialize/rulesets: ensure-poetry-env ## Initialize all rulesets (long-running operation)
	@echo "\033[1;33m[*] Initializing rulesets (this may take several minutes)\033[0m"
	cd detectiq/ &&\
	poetry run python manage.py initialize_rulesets --create_vectorstores &&\
	poetry run python manage.py initialize_rulesets --rule_types sigma yara &&\
	poetry run python manage.py initialize_rulesets --rule_types snort --force
	@echo "\033[1;32m[✓] Rulesets initialized\033[0m"

install/backend: install/backend/dependencies ## Install backend with all dependencies and run migrations
	@echo "\033[1;33m[*] Building '$(APP_NAME)' backend\033[0m"
	cd detectiq/ &&\
	poetry run python manage.py migrate
	@echo "\033[1;32m[✓] Backend installed (run 'make initialize/rulesets' to initialize or update ruleset data)\033[0m"

install/frontend/dependencies: 
	@echo "\033[1;33m[*] Installing '$(APP_NAME)' frontend dependencies\033[0m"
	@if ! command -v npm &> /dev/null; then \
		echo "\033[1;31m[!] npm is not installed. Please install Node.js and npm first.\033[0m"; \
		exit 1; \
	fi
	@if [ ! -d "detectiq/webapp/frontend" ]; then \
		echo "\033[1;31m[!] Frontend directory not found at detectiq/webapp/frontend\033[0m"; \
		exit 1; \
	fi
	cd detectiq/webapp/frontend && \
	npm install && \
	npm audit fix --force || true && \
	npm install

install/frontend: install/frontend/dependencies ## Build frontend (Next.js)
	@echo "\033[1;33m[*] Building '$(APP_NAME)' frontend\033[0m"
	@if [ ! -d "detectiq/webapp/frontend" ]; then \
		echo "\033[1;31m[!] Frontend directory not found at detectiq/webapp/frontend\033[0m"; \
		exit 1; \
	fi
	cd detectiq/webapp/frontend && \
	npm run build

.PHONY: install
install: install/backend install/frontend/dependencies ## Install both backend (Django) and frontend (Next.js) dependencies
	@echo "\033[1;32m[!] Installing '${APP_NAME}' completed\033[0m"
	@echo "\033[1;34m[i] To initialize or update rulesets, run 'make initialize/rulesets'\033[0m"

# RESTART TARGETS
.PHONY: restart
restart: ## Restart both servers (faster than stop+start)
	@echo "\033[1;33m[*] Fast-restarting both servers\033[0m"
	@$(MAKE) restart/backend
	@$(MAKE) restart/frontend
	@echo "\033[1;32m[✓] All servers restarted\033[0m"
	@echo "\033[1;32m[✓] Backend server running at http://localhost:8000\033[0m"
	@echo "\033[1;32m[✓] Frontend server running at http://localhost:3000\033[0m"

.PHONY: restart/frontend
restart/frontend: ## Restart only the frontend server
	@echo "\033[1;33m[*] Restarting frontend server\033[0m"
	@if lsof -ti:3000 >/dev/null 2>&1; then \
		echo "Stopping frontend server..."; \
		lsof -ti:3000 | xargs kill -9 2>/dev/null || true; \
		sleep 1; \
	fi
	@$(MAKE) start/frontend

.PHONY: restart/backend
restart/backend: ## Restart only the backend server
	@echo "\033[1;33m[*] Restarting backend server\033[0m"
	@if lsof -ti:8000 >/dev/null 2>&1; then \
		echo "Stopping backend server..."; \
		lsof -ti:8000 | xargs kill -9 2>/dev/null || true; \
		sleep 1; \
	fi
	@cd detectiq/webapp/backend &&\
	poetry run python manage.py runserver 2>&1 &
	@# Wait for server to start and check if it's running
	@for i in {1..5}; do \
		if curl -s http://localhost:8000/ >/dev/null 2>&1; then \
			echo "\033[1;32m[✓] Backend server restarted successfully\033[0m"; \
			break; \
		fi; \
		if [ $$i -eq 5 ]; then \
			echo "\033[1;31m[!] Backend server taking longer than expected to restart\033[0m"; \
		fi; \
		sleep 0.5; \
	done

# START TARGETS
start/backend: 
	@echo "\033[1;33m[*] Starting '$(APP_NAME)' backend\033[0m"
	@# Check if port 8000 is already in use
	@if lsof -i:8000 >/dev/null 2>&1; then \
		echo "\033[1;31m[!] Port 8000 is already in use. Attempting to kill the process...\033[0m"; \
		lsof -ti:8000 | xargs kill -9 2>/dev/null || true; \
		sleep 1; \
	fi
	@# Start the backend server
	cd detectiq/webapp/backend &&\
	poetry run python manage.py runserver 2>&1 &
	@# Wait for server to start and check if it's running
	@for i in {1..10}; do \
		if curl -s http://localhost:8000/ >/dev/null 2>&1; then \
			echo "\033[1;32m[✓] Backend server started successfully\033[0m"; \
			break; \
		fi; \
		if [ $$i -eq 10 ]; then \
			echo "\033[1;31m[!] Failed to start backend server\033[0m"; \
			exit 1; \
		fi; \
		sleep 1; \
	done

start/frontend: 
	@echo "\033[1;33m[*] Starting '$(APP_NAME)' frontend\033[0m"
	@if ! command -v npm &> /dev/null; then \
		echo "\033[1;31m[!] npm is not installed. Please install Node.js and npm first.\033[0m"; \
		exit 1; \
	fi
	@if [ ! -d "detectiq/webapp/frontend" ]; then \
		echo "\033[1;31m[!] Frontend directory not found at detectiq/webapp/frontend\033[0m"; \
		exit 1; \
	fi
	@if [ ! -f "detectiq/webapp/frontend/node_modules/.bin/next" ]; then \
		echo "\033[1;31m[!] Next.js not found. Please run 'make install/frontend/dependencies' first.\033[0m"; \
		exit 1; \
	fi
	@# Start the frontend server with better error handling - now runs in background
	cd detectiq/webapp/frontend && \
	(npm run dev > /tmp/frontend-server.log 2>&1 &) 
	@# Wait for server to start
	@echo "Waiting for frontend server to start..."
	@for i in {1..10}; do \
		if curl -s http://localhost:3000/ >/dev/null 2>&1; then \
			echo "\033[1;32m[✓] Frontend server started successfully\033[0m"; \
			break; \
		fi; \
		if [ $$i -eq 10 ]; then \
			echo "\033[1;31m[!] Warning: Could not confirm frontend server started (still starting?)\033[0m"; \
		fi; \
		sleep 1; \
	done

.PHONY: start
start: install stop start/backend start/frontend ## Start both backend (Django:8000) and frontend (Next.js:3000) servers
	@echo "\033[1;33m[*] Running '$(APP_NAME)'\033[0m"
	@echo "\033[1;32m[✓] Backend server running at http://localhost:8000\033[0m"
	@echo "\033[1;32m[✓] Frontend server running at http://localhost:3000\033[0m"
	@echo "\033[1;34m[i] Use 'make logs' to view server logs\033[0m"
	@echo "\033[1;34m[i] Use 'make status' to check server status\033[0m"
	@echo "\033[1;34m[i] Use 'make stop' to stop servers\033[0m"

# STATUS TARGET
.PHONY: status
status: ## Check status of both backend (Django:8000) and frontend (Next.js:3000) servers
	@echo "\033[1;33m[*] Checking server status\033[0m"
	@echo "\nBackend server (port 8000):"
	@if lsof -ti:8000 >/dev/null 2>&1; then \
		echo "\033[1;32m[✓] Running\033[0m"; \
	else \
		echo "\033[1;31m[✗] Not running\033[0m"; \
	fi
	@echo "\nFrontend server (port 3000):"
	@if lsof -ti:3000 >/dev/null 2>&1; then \
		echo "\033[1;32m[✓] Running\033[0m"; \
	else \
		echo "\033[1;31m[✗] Not running\033[0m"; \
	fi

# STOP TARGET
.PHONY: stop
stop: ## Stop both backend (Django:8000) and frontend (Next.js:3000) servers
	@echo "\033[1;33m[*] Stopping all servers\033[0m"
	@# Kill Django backend server
	@if lsof -ti:8000 >/dev/null 2>&1; then \
		echo "Stopping backend server..."; \
		lsof -ti:8000 | xargs kill -9 2>/dev/null || true; \
	fi
	@# Kill Next.js frontend server
	@if lsof -ti:3000 >/dev/null 2>&1; then \
		echo "Stopping frontend server..."; \
		lsof -ti:3000 | xargs kill -9 2>/dev/null || true; \
	fi
	@echo "\033[1;32m[✓] All servers stopped\033[0m"

# LOGS TARGET
.PHONY: logs
logs: ## Show real-time logs for both backend and frontend (Ctrl+C to exit)
	@echo "\033[1;33m[*] Showing server logs (Ctrl+C to exit)\033[0m"
	@# Check if any servers are running
	@if ! lsof -ti:8000 >/dev/null 2>&1 && ! lsof -ti:3000 >/dev/null 2>&1; then \
		echo "\033[1;33m[!] Warning: No servers are currently running\033[0m"; \
		echo "\033[1;34m[i] Start servers with 'make start'\033[0m"; \
	fi
	@# Backend logs
	@echo "\033[1;34m[i] Backend (Django) logs:\033[0m"
	@if lsof -ti:8000 >/dev/null 2>&1; then \
		BACKEND_PID=$$(lsof -ti:8000); \
		echo "\033[1;32m[✓] Backend server is running\033[0m"; \
		tail -n 50 -f "/proc/$${BACKEND_PID}/fd/1" 2>/dev/null || echo "Cannot access backend logs directly"; \
	else \
		echo "\033[1;33m[!] Backend server is not running\033[0m"; \
	fi
	@# Frontend logs
	@echo "\033[1;34m[i] Frontend (Next.js) logs:\033[0m"
	@if lsof -ti:3000 >/dev/null 2>&1; then \
		echo "\033[1;32m[✓] Frontend server is running\033[0m"; \
		if [ -f "/tmp/frontend-server.log" ]; then \
			tail -n 50 -f "/tmp/frontend-server.log"; \
		else \
			echo "Frontend log file not found"; \
		fi; \
	else \
		echo "\033[1;33m[!] Frontend server is not running\033[0m"; \
	fi

# FORMAT TARGET
.PHONY: format/backend
format/backend: ensure-poetry-env ## Format and lint backend Python code using black and ruff
	@echo "Formatting Python files..."
	poetry run black $(PYTHON_FILES)
	@echo "Running Ruff linter..."
	poetry run ruff check --ignore I001 $(PYTHON_FILES) || true
	@echo "Formatting and linting completed"

.PHONY: ruff-fix
ruff-fix: ensure-poetry-env ## Run Ruff linter with auto-fixes
	@echo "Running Ruff linter with auto-fixes..."
	poetry run ruff check --fix --ignore E501,F401,E402 $(PYTHON_FILES)

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

# PUBLISH TARGET
.PHONY: publish
publish: ensure-poetry-env token-check clean ## Build and publish package to PyPI
	@echo "\033[1;33m[*] Building and publishing '$(APP_NAME)' to PyPI\033[0m"
	@# Verify keyring is installed
	@if ! poetry run pip show keyring >/dev/null 2>&1; then \
		echo "\033[1;33m[*] Installing keyring...\033[0m"; \
		poetry run pip install keyring keyrings.alt; \
	fi
	poetry build
	poetry publish
	@echo "\033[1;32m[✓] Published to PyPI successfully\033[0m"

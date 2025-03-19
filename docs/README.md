# DetectIQ: Docs
* [Getting Started](#getting-started)
    * [Prerequisites](#prerequisites)
    * [Project Structure](#project-structure)
    * [Installation](#installation)
* [Configuration](#configuration)
    * [Required Environment Variables](#required-environment-variables)
    * [Optional Environment Variables](#optional-environment-variables)
* [Starting the Development Servers](#starting-the-development-servers)
    * [Using VS Code](#using-vscode)
    * [Using the Terminal](#using-the-terminal)
* [Maintenance Commands](#maintenance-commands)

## Getting Started
### Prerequisites
* Python 3.9 or higher
* Node.js 16+
* Poetry for dependency management

### Project Structure
```
DetectIQ/
├── detectiq/
│   ├── core/               # Core functionality
│   ├── licenses/           # License files
│   ├── llm/                # LLM integration
│   │   ├── agents/         # LangChain agents
│   │   └── tools/          # Custom tools
│   └── webapp/             # Web application
│       ├── frontend/       # Next.js frontend
│       └── backend/        # Django backend
├── tests/                  # Test suite
└── poetry.lock            # Dependency lock file
```

### Installation
**Step 1.** Clone the repository.
```bash
git clone https://github.com/AttackIQ/DetectIQ.git
```

**Step 2.** Set your environment variables (using [`.env.example`](./env.example) as a template).
```bash
cp .env.example .env
```

**Step 3.** Run the provided `start.sh` script and pass `install` as an argument.
```bash
bash start.sh install
```

The initialization process will:
1. Set up the database schema
2. Download official rule repositories
3. Create necessary directories
4. Generate embeddings for rule search (if `--create_vectorstores` is used)
5. Normalize rule metadata

> **Note**: Initial vector store creation may take some time depending on the number of rules and your hardware. Use the `--rule_types` flag to initialize specific rulesets if you don't need all of them.

## Configuration
Set the required environment variables in the `.env` file. See the `.env.example` file for more information. You can also set the optional environment variables to customize the behavior of the application, or rely on the defaults in `detectiq/globals.py`.  You can also set and update settings in the webapp UI, if using the webapp.

### Required Environment Variables
```bash
OPENAI_API_KEY="your-api-key"
DEBUG=True
DJANGO_SECRET_KEY=django-insecure-your-secret-key-here
```

### Optional Environment Variables
```bash
# Rule Directories, defaults to $PROJECT_ROOT/data/rules if not specified
SIGMA_RULE_DIR="path/to/sigma/rules"             # Directory for Sigma rules
YARA_RULE_DIR="path/to/yara/rules"              # Directory for YARA rules
SNORT_RULE_DIR="path/to/snort/rules"            # Directory for Snort rules
GENERATED_RULE_DIR="path/to/generated/rules"     # Directory for AI-generated rules

# Vector Store Directories, defaults to $PROJECT_ROOT/data/vector_stores if not specified
SIGMA_VECTOR_STORE_DIR="path/to/sigma/vectors"   # Vector store for Sigma rules
YARA_VECTOR_STORE_DIR="path/to/yara/vectors"     # Vector store for YARA rules
SNORT_VECTOR_STORE_DIR="path/to/snort/vectors"   # Vector store for Snort rules

# LLM Configuration
LLM_MODEL="gpt-4o"                              # LLM model to use (default: gpt-4o)
LLM_TEMPERATURE=0.10                            # Temperature for LLM responses
EMBEDDING_MODEL="text-embedding-3-small"         # Model for text embeddings

# Package Configuration
SIGMA_PACKAGE_TYPE="core"                       # Sigma ruleset type (default: core)
YARA_PACKAGE_TYPE="core"                        # YARA ruleset type (default: core)
```

## Starting the Development Servers
> **Note**: You must have both the frontend and backend servers running to use the webapp.
> 
> Navigate to http://localhost:3000/ to access the webapp UI after starting the servers.

### Using VSCode
Under Run/Debug, select the "Full Stack" configuration and click the green play button.

### Using the Terminal
```bash
# Start frontend development server
cd detectiq/webapp/frontend
npm run dev

# Start backend development server
cd detectiq/
python manage.py runserver
```

## Maintenance Commands
```bash
# Delete all rules (use with caution)
python manage.py delete_all_rules --dry-run  # Preview what will be deleted
python manage.py delete_all_rules --rule-type sigma  # Delete specific rule type
python manage.py delete_all_rules  # Delete all rules

# Delete only LLM-generated rules
python manage.py delete_llm_rules --dry-run  # Preview
python manage.py delete_llm_rules  # Execute deletion
```
# DetectIQ: Docs
* [Getting Started](#getting-started)
    * [Prerequisites](#prerequisites)
    * [Project Structure](#project-structure)
    * [Installation](#installation)
* [Configuration](#configuration)
    * [Required Environment Variables](#required-environment-variables)
    * [Optional Environment Variables](#optional-environment-variables)

## Getting Started
### Prerequisites
* Python 3.9 or higher
* Poetry for dependency management (recommended)

### Project Structure
```
DetectIQ/
├── detectiq/
│   ├── core/               # Core functionality
│   ├── sigmaiq/            # Sigma specific features
│   │   └── llm/            # LLM integration for Sigma
├── examples/               # Usage examples
├── tests/                  # Test suite
└── poetry.lock            # Dependency lock file
```

### Installation
**Option 1:** Install from PyPI
```bash
pip install detectiq
```

**Option 2:** Install from source
```bash
# Clone the repository
git clone https://github.com/AttackIQ/DetectIQ.git
cd DetectIQ

# Install using poetry (recommended)
poetry install --all-extras

# Or using pip
# pip install .
```

**Step 2.** Set your environment variables (using [`.env.example`](./env.example) as a template).
```bash
cp .env.example .env
# Edit .env with your API keys and configuration
```

When using as a library, you'll need to initialize:
1. Create necessary directories for rules and vector stores
2. Download official rule repositories (if needed)
3. Generate embeddings for rule search

> **Note**: Initial vector store creation may take some time depending on the number of rules and your hardware. Use the `--rule_types` flag to initialize specific rulesets if you don't need all of them.

## Configuration
Set the required environment variables in the `.env` file. See the `.env.example` file for more information. You can also set the optional environment variables to customize the behavior of the library, or rely on the defaults in `detectiq/globals.py`.

### Required Environment Variables
```bash
OPENAI_API_KEY="your-api-key"
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

## Using the Library

Refer to the examples in the `examples/` directory for detailed usage patterns. Here's a basic example of using DetectIQ to create a YARA rule:

```python
import asyncio
from typing import cast
import os

# Set OpenAI API key
os.environ["OPENAI_API_KEY"] = "your-api-key"

from langchain.schema.language_model import BaseLanguageModel
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from detectiq.core.llm.yara_rules import YaraLLM
from detectiq.core.llm.toolkits.base import create_rule_agent
from detectiq.core.llm.toolkits.yara_toolkit import YaraToolkit
from detectiq.core.llm.toolkits.prompts import YARA_AGENT_PROMPT

async def main():
    # Initialize LLMs
    agent_llm = cast(BaseLanguageModel, ChatOpenAI(temperature=0, model="gpt-4o"))
    rule_creation_llm = cast(BaseLanguageModel, ChatOpenAI(temperature=0, model="gpt-4o"))
    
    # Initialize YARA tools
    yara_llm = YaraLLM(
        embedding_model=OpenAIEmbeddings(model="text-embedding-3-small"),
        agent_llm=agent_llm,
        rule_creation_llm=rule_creation_llm,
        rule_dir="./rules",
        vector_store_dir="./vectorstore",
    )
    
    # Create agent
    yara_agent = create_rule_agent(
        vectorstore=yara_llm.vectordb,
        rule_creation_llm=yara_llm.rule_creation_llm,
        agent_llm=yara_llm.agent_llm,
        toolkit_class=YaraToolkit,
        prompt=YARA_AGENT_PROMPT,
    )
    
    # Create a rule
    result = await yara_agent.ainvoke({"input": "Create a YARA rule to detect ransomware"})
    print(result.get("output"))

if __name__ == "__main__":
    asyncio.run(main())
```

## Rule Management

To manage your rules, use the provided library methods rather than command-line tools. For example:

```python
from detectiq.core.rules.sigma_rules import SigmaRuleManager

# Initialize rule manager
rule_manager = SigmaRuleManager(rule_dir="./rules")

# Delete all rules
rule_manager.delete_all_rules()

# Delete only LLM-generated rules
rule_manager.delete_generated_rules()
```
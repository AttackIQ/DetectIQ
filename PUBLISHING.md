# Publishing DetectIQ to PyPI

This document provides instructions for publishing the DetectIQ package to PyPI and using it in other projects.

## Prerequisites

Before publishing to PyPI, ensure you have the following:

1. A PyPI account (create one at [pypi.org](https://pypi.org/account/register/))
2. The necessary tools:
   ```bash
   pip install --upgrade pip setuptools wheel twine build keyring keyrings.alt
   ```
   Alternatively, use the development dependencies:
   ```bash
   make install-dev
   ```
   
3. A PyPI token configured for authentication:
   ```bash
   make token-set TOKEN=your-pypi-token
   ```

> **Note**: The `keyrings.alt` package provides fallback keyring backends for various environments and prevents token-related errors when keyring backends aren't available by default.

## Publishing Steps

### Option 1: Using the Makefile (Recommended)

1. Configure your PyPI token (one-time setup):
   ```bash
   make token-set TOKEN=your-pypi-token
   ```

2. Versioning:
   ```bash
   # Show current version
   make version
   
   # Bump version (choose one)
   make version-patch  # for 0.0.X
   make version-minor  # for 0.X.0
   make version-major  # for X.0.0
   ```

3. Build and publish:
   ```bash
   # Build, check and publish to PyPI
   make pypi-publish
   
   # Or test on TestPyPI first
   make pypi-test-publish
   ```

4. Additional helpful commands:
   ```bash
   # Show all available commands
   make help
   
   # Clean up build artifacts
   make clean
   
   # Show package contents
   make show-package-contents
   ```

### Option 2: Using the publish.py script

1. Run the publish script:
   ```bash
   ./publish.py
   ```
2. Follow the prompts to build and upload the package.

### Option 3: Manual publishing

1. Clean previous builds:
   ```bash
   rm -rf dist/* build/*
   ```

2. Build the package:
   ```bash
   python -m build
   ```

3. Check the distribution:
   ```bash
   twine check dist/*
   ```

4. Upload to TestPyPI (optional, for testing):
   ```bash
   twine upload --repository-url https://test.pypi.org/legacy/ dist/*
   ```

5. Upload to PyPI:
   ```bash
   twine upload dist/*
   ```

## Using the Package

### Installation

Once published, you can install the package using pip:

```bash
pip install detectiq
```

Or install with specific extras:

```bash
pip install detectiq[all]  # Install with all optional dependencies
pip install detectiq[analysis]  # Just the analysis tools
```

### Example Usage

Here's a basic example of using DetectIQ in your project:

```python
import asyncio
from typing import cast
import os

# Set API key if not already set in environment
os.environ["OPENAI_API_KEY"] = "your-api-key"

from langchain.schema.language_model import BaseLanguageModel
from langchain_openai import ChatOpenAI, OpenAIEmbeddings

# Import from DetectIQ
from detectiq.core.llm.yara_rules import YaraLLM
from detectiq.core.llm.toolkits.base import create_rule_agent
from detectiq.core.llm.toolkits.yara_toolkit import YaraToolkit
from detectiq.globals import DEFAULT_DIRS

async def create_yara_rule():
    # Initialize models
    agent_llm = cast(BaseLanguageModel, ChatOpenAI(temperature=0, model="gpt-4o"))
    rule_creation_llm = cast(BaseLanguageModel, ChatOpenAI(temperature=0, model="gpt-4o"))
    
    # Initialize YARA LLM
    yara_llm = YaraLLM(
        embedding_model=OpenAIEmbeddings(model="text-embedding-3-small"),
        agent_llm=agent_llm,
        rule_creation_llm=rule_creation_llm,
        rule_dir="./my_rules",  # Your rules directory
        vector_store_dir="./vectorstore",  # Your vector store directory
    )
    
    # Create or load vector store
    try:
        yara_llm.load_vectordb()
    except FileNotFoundError:
        await yara_llm.update_rules()
        await yara_llm.create_vectordb()
    
    # Create agent
    yara_agent = create_rule_agent(
        rule_type="yara",
        vectorstore=yara_llm.vectordb,
        rule_creation_llm=yara_llm.rule_creation_llm,
        agent_llm=yara_llm.agent_llm,
        toolkit_class=YaraToolkit,
    )
    
    # Use the agent
    prompt = "Create a YARA rule to detect ransomware"
    result = await yara_agent.ainvoke({"input": prompt})
    print(result.get("output"))

# Run the example
if __name__ == "__main__":
    asyncio.run(create_yara_rule())
```

See the included `usage_example.py` for a more detailed example.

## Configuration

Ensure you have set up your API credentials properly. For OpenAI models, set your API key in an environment variable:

```bash
export OPENAI_API_KEY="your-api-key"
```

Or in your Python code:

```python
import os
os.environ["OPENAI_API_KEY"] = "your-api-key"
``` 
# DetectIQ Examples

This directory contains examples demonstrating how to use the DetectIQ package.

## Getting Started

### Setup Environment

1. Create a Python virtual environment (Python 3.9+ required):
   ```bash
   # Create virtual environment
   python -m venv venv
   
   # Activate virtual environment
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   # If you want to install from PyPI:
   pip install detectiq
   
   # Or if you want to install from local repository (development):
   cd .. # Navigate to the root directory of the repo
   pip install -e .
   ```

3. Set up your environment variables:
   ```bash
   # Copy the example environment file and edit it with your API keys
   cp ../.env.example .env
   # Edit the .env file with your OpenAI API key
   nano .env
   ```

4. Run an example:
   ```bash
   # Run the basic example
   python basic_usage.py
   ```

> **Note**: All examples in subdirectories use the same `.env` file in this directory.
> You only need to set up one `.env` file for all examples.

## Examples Structure

### Basic Usage

- [basic_usage.py](basic_usage.py) - Comprehensive example showing how to use the core functionality of DetectIQ

### LLM Rule Creation

Examples demonstrating how to use the LLM-powered rule creation capabilities:

- [llm/sigma_rule_translation_and_creation.py](llm/sigma_rule_translation_and_creation.py) - Create and translate Sigma rules
- [llm/yara_rule_creation.py](llm/yara_rule_creation.py) - Create YARA rules and analyze files
- [llm/snort_rule_creation.py](llm/snort_rule_creation.py) - Create Snort rules and analyze network traffic

### Static Analysis

Examples showing how to analyze files and network traffic for rule creation:

- [analysis/analyze_file_for_yara.py](analysis/analyze_file_for_yara.py) - Analyze a file for YARA rule creation
- [analysis/analyze_pcap_for_snort.py](analysis/analyze_pcap_for_snort.py) - Analyze a PCAP file for Snort rule creation

## Dependencies

All examples require the following dependencies, which are **automatically installed** when you install the DetectIQ package:
- langchain, langchain-openai, langchain-community
- openai
- faiss-cpu
- yara-python
- sigmaiq
- and other dependencies

You only need to run `pip install detectiq` (or `pip install -e .` for development) and everything will be set up automatically.

## Usage with Installed Package

If you've installed DetectIQ via pip, you can adapt these examples by changing the imports:

```python
# When using the installed package
from detectiq.core.llm.sigma_rules import SigmaLLM
from detectiq.core.llm.toolkits.base import create_rule_agent
# ... other imports
```

## Documentation Images

You can view the DetectIQ rules page here:

![DetectIQ Rules Page](https://raw.githubusercontent.com/AttackIQ/DetectIQ/feature/ava/docs/images/detectiq_rules_page.png) 
# DetectIQ Examples

This directory contains examples demonstrating how to use the DetectIQ package.

## Getting Started

The simplest way to get started is with the basic usage example:

```bash
# Copy the example environment file and edit it with your API keys
cp .env.example .env
# Edit the .env file with your OpenAI API key
nano .env

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

## Usage with Installed Package

If you've installed DetectIQ via pip, you can adapt these examples by changing the imports:

```python
# When using the installed package
from detectiq.core.llm.sigma_rules import SigmaLLM
from detectiq.core.llm.toolkits.base import create_rule_agent
# ... other imports
```

## Requirements

All examples require:
- Python 3.9+
- DetectIQ package
- OpenAI API key 
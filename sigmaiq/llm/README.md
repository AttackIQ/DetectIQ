<div align="center">
    <a href="https://www.attackiq.com" target="_blank">
        <img src="https://www.attackiq.com/wp-content/uploads/2021/10/col-dflt.png" height="300" alt="AttackIQ">
    </a>
</div>
<h1 align="center">SigmAIQ: LLM</h1>

# Table of Contents
- [Table of Contents](#table-of-contents)
- [Overview](#overview)
- [Features](#features)
  - [Embedding Creation and Storage](#embedding-creation-and-storage)
  - [Sigma Rule Similarity Searching](#sigma-rule-similarity-searching)
  - [Agent/Bot for Sigma Rule Translation and Creation](#agentbot-for-sigma-rule-translation-and-creation)
  - [Converting Backend Queries to Sigma Rules](#converting-backend-queries-to-sigma-rules)
- [Installation](#installation)
- [Usage](#usage)
- [Example Q\&A](#example-qa)
- [Known Issues](#known-issues)
- [TODO](#todo)
- [License](#license)
- [Contributing](#contributing)
- [Acknowledgements](#acknowledgements)

# Overview

SigmAIQ LLM is an experimental feature that leverages the power of Large Language Models (LLMs) and Vector Databases to enhance Sigma Rule creation, translation, and searching. This feature integrates [langchain](https://github.com/langchain-ai/langchain) and [pySigma](https://github.com/SigmaHQ/pySigma) to provide advanced capabilities for working with Sigma Rules.

**Note:** This feature is under active development and not recommended for production use. By default, it uses OpenAI embeddings and LLM models (gpt-4), which require an OpenAI API key set in the environmental variable `OPENAI_API_KEY`.

# Features

1. **Embedding Creation and Storage**: Automatically download and create embeddings for the latest Sigma Rules.
2. **Sigma Rule Similarity Searching**: Efficiently search for similar Sigma Rules using vector similarity.
3. **Agent/Bot for Sigma Rule Translation and Creation**: Utilize LLM agents for advanced rule translation and creation.
4. **Converting Backend Queries to Sigma Rules**: Transform existing backend queries into Sigma Rules.

## Embedding Creation and Storage
The `sigmaiq.llm.base.SigmaLLM` class automates the process of downloading the latest Sigma Rules from [SigmaHQ](https://github.com/SigmaHQ/sigma/releases/latest), creating embeddings, and storing them in a Vector Database. By default, it uses `OpenAIEmbeddings` and `FAISS`, but can be extended to use different implementations.

## Sigma Rule Similarity Searching
Leverage the power of vector databases to find similar Sigma Rules quickly. This feature doesn't require LLM model training and can be a cost-effective option for rule searching.

## Agent/Bot for Sigma Rule Translation and Creation
The `create_sigma_agent()` function in `sigmaiq.llm.toolkits.base` creates a `langchain` `Agent` that can:
- Automatically determine the appropriate backend, pipeline, and output format for rule translation.
- Create new Sigma Rules based on user queries and similar existing rules.

## Converting Backend Queries to Sigma Rules
Transform existing backend-specific queries into standardized Sigma Rules for better portability and management.

# Installation

Clone this repository and install SigmAIQ dependencies along with the `llm` group:

Using pip:
```bash
pip install -e .
pip install -r requirements/llm.txt
```

Using poetry:
```bash
poetry install --with llm
```

# Usage

For detailed usage examples, please refer to the `examples` directory in the repository. Here's a basic example:

```python
from sigmaiq.llm.base import SigmaLLM
from langchain_openai import OpenAIEmbeddings

# Initialize SigmaLLM
sigma_llm = SigmaLLM(embedding_model=OpenAIEmbeddings(model="text-embedding-3-large"))

# Create and save vector database
sigma_llm.create_sigma_vectordb(save=True)

# Perform similarity search
query = "Encoded powershell commands"
results = sigma_llm.similarity_search(query)
```

# Example Q&A

This example demonstrates how the agent can use multiple tools in succession:

**Question:** "Create a Windows process creation Sigma Rule for certutil downloading a file from definitely-not-malware.com, then translate it to a Microsoft XDR query."

**Answer:**

Intermediate Step (Rule Creation):
```yaml
title: Windows Process Creation Event with certutil.exe Downloading from definitely-not-malware.com
description: Detects a Windows process creation event where certutil.exe downloads a file from definitely-not-malware.com
references:
    - https://github.com/AttackIQ/SigmAIQ
author: SigmAIQ (AttackIQ)
date: 2022/12/06
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\certutil.exe'
        CommandLine|contains: 'definitely-not-malware.com'
    condition: selection
falsepositives:
    - Unknown
level: high
```

Final Output (Microsoft XDR KQL query):
```
DeviceProcessEvents
| where FolderPath endswith "\\certutil.exe" and ProcessCommandLine contains "definitely-not-malware.com"
```

# Known Issues

- Agent parsing issues may occur when invalid JSON is passed between agent steps.

# TODO

- [ ] Add example for using custom (and free) embeddings and LLM models
- [ ] Add example for using custom Vector Databases
- [ ] Add ability to easily customize prompts for tools/agents
- [ ] Implement Sigma Rule Creation Tool without Vector Databases
- [ ] Add metadata to Vector Database entries for advanced filtering on Sigma Rule fields (e.g., category, product, level, status)

# License

This project is licensed under the terms of the GNU LGPL, version 2.1. Please see the `LICENSE` file for full details.

# Contributing

Contributions and use cases are welcome! Please submit a PR or issue if you would like to contribute or have any questions.

# Acknowledgements

We'd like to acknowledge:
- The creators, maintainers, and contributors of the [Sigma](https://github.com/SigmaHQ/sigma/) and [pySigma](https://github.com/SigmaHQ/pySigma) projects.
- The [langchain](https://github.com/langchain-ai/langchain) project for making LLMs more accessible and easier to use.
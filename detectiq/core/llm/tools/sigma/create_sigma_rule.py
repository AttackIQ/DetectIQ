import asyncio
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Type

import yaml
from langchain.prompts import ChatPromptTemplate
from langchain.schema.language_model import BaseLanguageModel
from langchain.schema.output_parser import StrOutputParser
from langchain.schema.runnable import RunnablePassthrough
from langchain.schema.vectorstore import VectorStore
from langchain_core.callbacks import BaseCallbackManager, Callbacks
from langchain_core.tools import BaseTool
from pydantic import BaseModel, ConfigDict, field_validator

from detectiq.core.utils.logging import get_logger

# Initialize logger
logger = get_logger(__name__)


# Define BaseCache first, before any imports or other classes
class BaseCache(BaseModel):
    """Base cache class for tools."""

    data: Dict[str, Any] = {}
    model_config = ConfigDict(arbitrary_types_allowed=True)


class CreateSigmaRuleInput(BaseModel):
    """Input for CreateSigmaRuleTool."""

    description: str
    rule_context: Optional[str] = None
    model_config = ConfigDict(arbitrary_types_allowed=True)


def _check_sigmadb(cls, v):
    """Validate sigmadb has required methods."""
    if v is None:
        return None
    if not hasattr(v, "as_retriever"):
        raise ValueError("sigmadb must have 'as_retriever' method")
    return v


class CreateSigmaRuleTool(BaseTool):
    """Class for creating Sigma rules based on log analysis or description"""

    name: str = "create_sigma_rule"
    description: str = """Use this tool to create Sigma rules based on either:
        1. Log analysis results
        2. A description of what you want to detect"""
    args_schema: Type[BaseModel] = CreateSigmaRuleInput
    llm: BaseLanguageModel
    sigmadb: Optional[VectorStore] = None
    k: int = 3
    verbose: bool = False
    callback_manager: Optional[BaseCallbackManager] = None
    callbacks: Optional[Callbacks] = None
    cache: Optional[BaseCache] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @field_validator("sigmadb")
    def validate_sigmadb(cls, v):
        return _check_sigmadb(cls, v)

    async def _arun(
        self,
        description: str,
        rule_context: Optional[str] = None,
        chat_history: Optional[List[Any]] = None,
    ) -> Dict[str, Any]:
        try:
            if self.sigmadb is None:
                raise ValueError("sigmadb is required but not initialized")

            if not description:
                raise ValueError("Description is required")

            # Get current date
            current_date = datetime.now().strftime("%Y-%m-%d")

            # Get similar rules silently
            retriever = self.sigmadb.as_retriever(search_kwargs={"k": self.k})
            similar_rules = await retriever.ainvoke(description)

            # Format similar rules context
            context_text = "\n".join(doc.page_content for doc in similar_rules)

            # Format chat history for prompt
            formatted_chat_history = "N/A"
            if chat_history:
                history_lines = []
                for msg in chat_history:
                    role = "User" if msg.type == "human" else "Assistant"
                    history_lines.append(f"{role}: {msg.content}")
                formatted_chat_history = "\n".join(history_lines)

            template = """You are an expert in creating Sigma rules.

Given the following description, conversation history, and context, produce a Sigma rule that effectively detects the specified threat while minimizing false positives.

Conversation History:
{formatted_chat_history}

Context (Similar Rules):
{context_text}

Description:
{description}

Additional Context (from file analysis or other sources):
{rule_context}

Ensure your Sigma rule includes:

- A unique 'id' (UUID) (REQUIRED)
- Clear 'title' and 'description' based on what you are detecting (REQUIRED)
- Appropriate 'author', 'date', 'references', 'tags', and 'level'
- Correct 'logsource' definition
- Add authors of any rules used as context for rule creation
- Well-defined 'detection' section with selections and conditions
- 'falsepositives' section listing potential false positives
- 'related' field if similar rules are used

Example:

```yaml
title: <Title of the rule>
id: <unique UUID>
description: <Description of the rule>
author: <DetectIQ, and any other authors>
date: {current_date}
related:
  - id: <UUID>
    type: <derived, similar, obsolete, renamed, or merged>
references:
  - <URLs or documents>
logsource:
  category: <category>
  product: <product>
  service: <service>
detection:
  selections:
    field: value
  filters:
    field: value
  condition: <logical condition>
falsepositives:
  - <Possible false positives>
level: <informational, low, medium, high, critical>
tags:
  - <MITRE ATT&CK tags>
```

Follow the Sigma documentation for proper formatting: https://sigmahq.io/docs/basics/rules.html

The Analysis Summary and Detection Strategy sections are required and must be detailed.

+ IMPORTANT: Ensure all analysis text uses standard Markdown formatting. Use double newlines ('\n\n') between paragraphs and list items for proper rendering.

You MUST provide your response in the following format, using standard markdown headings:

#### Analysis Summary
[Provide a detailed analysis of:
1. The attack technique or behavior being detected
2. Key indicators and patterns identified
3. Relevant log sources and fields
4. Potential variations of the attack]

#### Detection Strategy
[Explain in detail:
1. Why specific detection logic was chosen
2. How the conditions work together
3. Why certain fields were selected
4. How false positives are minimized
5. Any limitations or considerations]

#### Sigma Rule
[Provide the Sigma rule in valid YAML format, following best practices. Only put the Sigma rule in the YAML block.]
"""

            prompt = ChatPromptTemplate.from_template(template)
            chain = (
                {
                    "context_text": lambda x: context_text,
                    "description": RunnablePassthrough(),
                    "rule_context": lambda x: rule_context or "No additional context provided.",
                    "current_date": lambda x: current_date,
                    "formatted_chat_history": lambda x: formatted_chat_history,
                }
                | prompt
                | self.llm
                | StrOutputParser()
            )

            response = await chain.ainvoke(description)

            # First try to extract from code block
            yaml_block_match = re.search(r"```yaml\n(.*?)\n```", response, re.DOTALL)
            if yaml_block_match:
                rule_content = yaml_block_match.group(1).strip()
            else:
                # Fallback to section extraction
                yaml_match = re.search(r"#### Sigma Rule\n(.*?)(?=\n####|$)", response, re.DOTALL)
                if not yaml_match:
                    raise ValueError("Could not extract Sigma rule from response")
                rule_content = yaml_match.group(1).strip()

            # Extract the analysis sections
            analysis_summary = re.search(r"#### Analysis Summary\n(.*?)(?=\n####)", response, re.DOTALL)
            detection_strategy = re.search(r"#### Detection Strategy\n(.*?)(?=\n####)", response, re.DOTALL)

            if not analysis_summary or not detection_strategy:
                logger.warning("Missing required analysis sections in response")
                raise ValueError("Response missing required analysis sections")

            # Combine analysis sections for agent output
            agent_output = ""
            agent_output += "#### Analysis Summary\n" + analysis_summary.group(1).strip() + "\n\n"
            agent_output += "#### Detection Strategy\n" + detection_strategy.group(1).strip()

            if not agent_output.strip():
                logger.warning("Empty agent output generated")
                raise ValueError("Empty analysis sections in response")

            # Add before YAML extraction
            logger.debug(f"Raw rule content before extraction:\n{rule_content}")

            # Clean up the rule content - improved YAML extraction
            yaml_lines = []
            in_yaml = False
            for line in rule_content.split("\n"):
                stripped_line = line.strip()
                # Start capturing at title: or --- (YAML document start)
                if stripped_line.startswith("title:") or stripped_line == "---":
                    in_yaml = True
                if in_yaml:
                    # Stop if we hit explanatory text or empty lines after YAML
                    if (stripped_line and ":" not in stripped_line and not stripped_line.startswith("-")) or (
                        not stripped_line and len(yaml_lines) > 0 and not any(line.strip() for line in yaml_lines[-3:])
                    ):
                        break
                    yaml_lines.append(line)

            rule_content = "\n".join(yaml_lines).strip()

            # Add after YAML extraction
            logger.debug(f"Extracted YAML content:\n{rule_content}")

            # Validate the extracted rule content
            if not rule_content:
                raise ValueError("Failed to extract rule content from response")

            try:
                # Parse YAML to validate structure
                rule_yaml = yaml.safe_load(rule_content)
                if not rule_yaml or not isinstance(rule_yaml, dict):
                    raise ValueError("Invalid YAML structure in generated rule")

                # Ensure required fields are present
                required_fields = ["title", "description", "detection"]
                missing_fields = [field for field in required_fields if field not in rule_yaml]
                if missing_fields:
                    raise ValueError(f"Missing required fields in rule: {', '.join(missing_fields)}")

            except yaml.YAMLError as e:
                logger.error(f"YAML parsing error: {e}")
                raise ValueError(f"Invalid YAML in generated rule: {str(e)}")

            # Add after YAML parsing
            logger.debug(f"Parsed YAML fields: {rule_yaml.keys()}")

            return {
                "rule": rule_content,
                "agent_output": agent_output,
                "title": rule_yaml.get("title", "Untitled Rule"),
                "severity": rule_yaml.get("level", "medium"),
                "description": rule_yaml.get("description", ""),
            }

        except Exception as e:
            logger.error(f"Error in _arun: {str(e)}")
            raise e

    def _run(
        self,
        description: str,
        rule_context: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Synchronous run method required by BaseTool."""
        return asyncio.run(self._arun(description, rule_context))


# Rebuild the model at module level after all classes are defined
CreateSigmaRuleTool.model_rebuild()

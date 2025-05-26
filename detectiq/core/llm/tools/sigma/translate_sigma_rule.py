import asyncio
from typing import Type

from langchain.prompts import ChatPromptTemplate
from langchain.schema.language_model import BaseLanguageModel
from langchain.schema.output_parser import StrOutputParser
from langchain.tools import BaseTool
from pydantic import BaseModel


class TranslateSigmaRuleInput(BaseModel):
    """Input for TranslateSigmaRuleTool."""

    rule: str
    backend: str


class TranslateSigmaRuleTool(BaseTool):
    """Tool for translating Sigma rules to specific SIEM/backend queries."""

    name: str = "translate_sigma_rule"
    args_schema: Type[BaseModel] = TranslateSigmaRuleInput
    description: str = """
Use this tool to translate a Sigma rule into a query for a specific SIEM/backend.
The input should be a valid Sigma rule and the target backend (e.g., 'splunk', 'elasticsearch').
"""
    llm: BaseLanguageModel

    async def _arun(
        self,
        rule: str,
        backend: str,
    ) -> str:
        template = """You are a security analyst specializing in Sigma rule translation.
Convert the provided Sigma rule to a query for the specified backend while maintaining detection accuracy.

Sigma Rule:
{rule}

Target Backend:
{backend}

Provide the translation in the following format:

### Translation Summary
[Brief explanation of the translation process and any important considerations]

### Translated Query
[The complete, properly formatted query for the target backend]

### Implementation Notes
[Any important notes about:
1. Field mappings used
2. Backend-specific optimizations
3. Any limitations or considerations
4. Required permissions or configurations]
"""

        prompt = ChatPromptTemplate.from_template(template)
        chain = prompt | self.llm | StrOutputParser()
        return await chain.ainvoke({"rule": rule, "backend": backend})

    def _run(
        self,
        rule: str,
        backend: str,
    ) -> str:
        """Synchronous run method required by BaseTool."""
        return asyncio.run(self._arun(rule, backend))

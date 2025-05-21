# stdlib
import asyncio
from typing import Type

# langchain
from langchain.prompts import ChatPromptTemplate

# langchain typing
from langchain.schema.language_model import BaseLanguageModel
from langchain.schema.output_parser import StrOutputParser
from langchain.schema.runnable import RunnablePassthrough
from langchain.schema.vectorstore import VectorStore
from langchain.tools import BaseTool

# pydantic
from pydantic import BaseModel, Field


class CreateSigmaRuleInput(BaseModel):
    """Input for TranslateSigmaRule tool, which uses SigmAIQ backend factory to convert a Sigma Rule into
    a query for a specific backend."""

    query: str = Field(
        description="The users question, used to search through the Sigma VectorStore and create a Sigma Rule."
    )

    # No need for Config class inheritance with pydantic v2


class CreateSigmaRuleVectorStoreTool(BaseTool):
    """Class for translating Sigma rules via SigmAIQ Backend Factory"""

    name: str = "create_sigma_rule_vectorstore"
    args_schema: Type[BaseModel] = CreateSigmaRuleInput
    description: str = """Use this tool to take the users input, find similar Sigma Rules from the vectorstore,
then create a brand new Sigma Rule based on the users input and the similar Sigma Rules returned from the vectorstore
to use as context. The output is a Sigma Rule in YAML format.
"""
    sigmadb: VectorStore
    llm: BaseLanguageModel
    k: int = 3
    verbose: bool = False

    def _run(self, query: str) -> str:
        """Run the tool"""
        return asyncio.run(self._arun(query))

    async def _arun(self, query: str) -> str:
        """Async run the tool"""
        template = """You are a cybersecurity detection engineering assistant bot specializing in Sigma Rule creation.
You are assisting a user in creating a new Sigma Rule based on the users question.  
The users question is first used to find similar Sigma Rules from the a vectorstore containing official 
Sigma Rules. The official Sigma Rules can be used as context as needed in conjunction with the detection specified
in the users question to create a new Sigma Rule.  
The created Sigma Rule should be in YAML format and use the official Sigma schema.  The detection field
can contain multiple 'selection' identifiers and multiple 'filter' identifiers as needed, 
which can be used in the condition field to select criteria and filter out criteria respectively.
Set the 'author' to 'SigmAIQ (AttackIQ)', the date to today's date, and the reference to 'https://github.com/AttackIQ/SigmAIQ'.
If you use other rules as context and derive the created Sigma Rules from the context rules, you must
include the original authors under the 'author' field in the new rule in addition to "SigmAIQ (AttackIQ),
and add the original rule IDs under the 'related' field. The valid 'types' under 'related' are the following:

    derived: The rule was derived from the referred rule or rules, which may remain active.
    obsoletes: The rule obsoletes the referred rule or rules, which aren't used anymore.
    merged: The rule was merged from the referred rules. The rules may be still existing and in use.
    renamed: The rule had previously the referred identifier or identifiers but was renamed for whatever reason, e.g. from a private naming scheme to UUIDs, to resolve collisions etc. It's not expected that a rule with this id exists anymore.
    similar: Use to relate similar rules to each other (e.g. same detection content applied to different log sources, rule that is a modified version of another rule with a different level)

If you are unsure about the Sigma rule schema, you can get the information from the official
Sigma specification here first: https://raw.githubusercontent.com/SigmaHQ/sigma-specification/main/Sigma_specification.md

------------

Sigma Rule Schema:

title
id [optional]
related [optional]
   - id {{rule-id}}
     type {{type-identifier}}
status [optional]
description [optional]
references [optional]
author [optional]
date [optional]
modified [optional]
tags [optional]
logsource
   category [optional]
   product [optional]
   service [optional]
   definition [optional]
   ...
detection
   {{search-identifier}} [optional]
      {{string-list}} [optional]
      {{map-list}} [optional]
      {{field: value}}> [optional]
   ... # Multiple search identifiers can be specified as needed and used in the condition
   condition
fields [optional]
falsepositives [optional]
level [optional]:


------------

Vectorstore Search Results:

{context}

------------

User's Question: 
{query}
"""

        prompt = ChatPromptTemplate.from_template(template)
        retriever = self.sigmadb.as_retriever(search_kwargs={"k": self.k})
        chain = {"context": retriever, "query": RunnablePassthrough()} | prompt | self.llm | StrOutputParser()
        return await chain.ainvoke(query)

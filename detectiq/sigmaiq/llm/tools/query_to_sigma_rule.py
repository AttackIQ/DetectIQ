import asyncio
import json
from typing import Optional, Type, Union

from langchain.prompts import ChatPromptTemplate
from langchain.schema.language_model import BaseLanguageModel
from langchain.schema.output_parser import StrOutputParser
from langchain.schema.runnable import RunnablePassthrough
from langchain.tools import BaseTool
from pydantic import BaseModel, Extra, Field

from detectiq.sigmaiq.sigmaiq_backend_factory import AVAILABLE_BACKENDS


class QueryToSigmaRuleInput(BaseModel):
    """Input for QueryToSigmaRule tool, which converts a backend query to a Sigma Rule, and
    uses SigmAIQ backend factory for validation.
    """

    query: Union[str, dict] = Field(
        default=None,
        description="""A query string for a backend, which should be converted to a Sigma Rule YAML string.""",
    )
    backend: str = Field(
        default=None,
        description="""The backend that the query is for, and what should be used for validation. Backend options their descriptions are as 
        follows:\n"""
        + f"{json.dumps(AVAILABLE_BACKENDS, indent=2)}",
    )


class QueryToSigmaRuleTool(BaseTool):
    """Class for converting a backend query to a Sigma Rule"""

    name: str = "query_to_sigma_rule"
    args_schema: Type[BaseModel] = QueryToSigmaRuleInput
    description: str = """
Use this tool to take an already existing query for a backend and convert it to a Sigma Rule.
Use the translate_sigma_rule tool to take the created Sigma Rule and convert it back to a query to 
determine if the queries are the same and the conversion is successful. Fix any errors if necessary.
The input must be a query string for a backend, and the backend must be specified.
The output is a Sigma Rule YAML string, or an error message if the conversion fails.
"""
    # return_direct = True  # We don't need an agent LLM to think about the output, it is what it is.
    llm: BaseLanguageModel
    verbose: bool = False

    class Config:
        """Configuration for this pydantic object."""

        extra = Extra.forbid

    def _run(self, query: Optional[str] = None, backend: Optional[str] = None) -> str:
        return asyncio.run(self._arun(query, backend))

    async def _arun(self, query: Optional[str] = None, backend: Optional[str] = None) -> str:
        template = """You are a cybersecurity detection engineering assistant bot specializing in Sigma Rule creation.
You are assisting a user in taking a query for a security/SIEM product, and converting it to a Sigma Rule.
The backend is used to validate the query and ensure it is compatible with the backend.
The created Sigma Rule should be in YAML format and use the official Sigma schema.  The detection field
can contain multiple 'selection' identifiers and multiple 'filter' identifiers as needed, 
which can be used in the condition field to select criteria and filter out criteria respectively.  
The fields should be Sysmon field names if possible, or Windows Event Log field names if possible.  

-----------

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
      {{field: valu}}> [optional]
   ... # Multiple search identifiers can be specified as needed and used in the condition
   condition
fields [optional]
falsepositives [optional]
level [optional]:

-----------

User's Query: {query}
Backend: {backend}
"""

        prompt = ChatPromptTemplate.from_template(template)
        chain = (
            {"query": RunnablePassthrough(), "backend": RunnablePassthrough()} | prompt | self.llm | StrOutputParser()
        )
        return await chain.ainvoke({"query": query, "backend": backend})

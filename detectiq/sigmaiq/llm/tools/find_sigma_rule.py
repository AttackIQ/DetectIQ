import asyncio
from typing import Type, Union

from langchain.prompts import ChatPromptTemplate
from langchain.schema.language_model import BaseLanguageModel
from langchain.schema.output_parser import StrOutputParser
from langchain.schema.runnable import RunnablePassthrough
from langchain.schema.vectorstore import VectorStore
from langchain.tools import BaseTool
from pydantic import BaseModel, Extra, Field


class FindSigmaRuleInput(BaseModel):
    """Input for FindSigmaRule tool, which searches for Sigma Rules in a vector database."""

    query: Union[str, dict] = Field(
        ...,  # This makes the field required
        description="""A query string or dictionary to search for Sigma Rules in the vector database.""",
    )


class FindSigmaRuleTool(BaseTool):
    """Class for searching Sigma rules in the vector database"""

    name: str = "find_sigma_rule"
    args_schema: Type[BaseModel] = FindSigmaRuleInput
    description: str = """
Use this tool to search for a Sigma Rule in the vector database. The input should be relevant information, such as
log artifacts, event IDs, operating systems, categories, indicators of compromise, MITRE ATT&CK information, or other relevant information to use
to search the vector store. If multiple rules are returned from the vector store, select the most similar Sigma Rule and return it in YAML format.
"""
    llm: BaseLanguageModel
    sigmadb: VectorStore
    k: int = 3
    verbose: bool = False

    class Config:
        """Configuration for this pydantic object."""

        extra = Extra.forbid

    def _run(self, query: Union[str, dict]) -> str:
        return asyncio.run(self._arun(query))

    async def _arun(self, query: Union[str, dict]) -> str:
        template = """You are a cybersecurity detection engineering assistant bot specializing in Sigma Rules.
You are assisting a user searching for Sigma Rules stored in a vectorstore.
Based on the user's question, extract the relevant information, such as
log artifacts, event IDs, operating systems, categories, indicators of compromise, 
MITRE ATT&CK information, or other relevant information to use
to search the vector store. If multiple rules are returned from the 
vector store, select the most similar Sigma Rule and return it in YAML format. Output the entire rule.
-------
Vectorstore Search Results:

{context}
------
User's Question: 
{question}
"""

        prompt = ChatPromptTemplate.from_template(template)
        retriever = self.sigmadb.as_retriever(search_kwargs={"k": self.k})
        chain = {"context": retriever, "question": RunnablePassthrough()} | prompt | self.llm | StrOutputParser()
        return await chain.ainvoke(query)

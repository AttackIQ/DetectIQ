# stdlib
import json
from json import JSONDecodeError
from typing import Any, Dict, Optional, Union

# langchain
from langchain.agents.agent import AgentExecutor
from langchain.agents.format_scratchpad import format_to_openai_function_messages
from langchain.agents.output_parsers import OpenAIFunctionsAgentOutputParser
from langchain.prompts import ChatPromptTemplate

# langchain typing
from langchain.schema import (
    AgentAction,
    AgentFinish,
    OutputParserException,
)
from langchain.schema.agent import AgentActionMessageLog
from langchain.schema.language_model import BaseLanguageModel
from langchain.schema.messages import (
    AIMessage,
    BaseMessage,
)
from langchain.schema.vectorstore import VectorStore
from langchain_core.utils.function_calling import convert_to_openai_function
from langchain_openai import ChatOpenAI

from detectiq.sigmaiq.llm.toolkits.prompts import SIGMA_AGENT_PROMPT

# sigmaiq
from detectiq.sigmaiq.llm.toolkits.sigma_toolkit import SigmaToolkit


def create_sigma_agent(
    sigma_vectorstore: Optional[VectorStore] = None,
    rule_creation_llm: Optional[BaseLanguageModel] = None,
    prompt: Optional[ChatPromptTemplate] = SIGMA_AGENT_PROMPT,
    verbose: bool = False,
    return_intermediate_steps: bool = False,
    agent_executor_kwargs: Optional[Dict[str, Any]] = None,
) -> AgentExecutor:
    if sigma_vectorstore is None:
        raise ValueError("sigma_vectorstore must be provided")

    if rule_creation_llm is None:
        rule_creation_llm = ChatOpenAI(model="gpt-4o")

    toolkit = SigmaToolkit(sigmadb=sigma_vectorstore, rule_creation_llm=rule_creation_llm)
    tools = toolkit.get_tools()

    # Assert if any of the tools does not have arun
    for tool in tools:
        assert hasattr(tool, "arun"), f"Tool {tool.name} does not have an 'arun' method"

    # Create OpenAI Function for each tool for the agent LLM, so we can create an OpenAI Function AgentExecutor
    llm_with_tools = rule_creation_llm.bind(functions=[convert_to_openai_function(t) for t in tools])

    agent = (
        {
            "input": lambda x: x["input"],
            "chat_history": lambda x: x.get("chat_history", []),
            "agent_scratchpad": lambda x: format_to_openai_function_messages(x["intermediate_steps"]),
        }
        | prompt
        | llm_with_tools
        | CustomOpenAIFunctionsAgentOutputParser()
    )

    # Create and return the AgentExecutor
    agent_executor = AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=verbose,
        return_intermediate_steps=return_intermediate_steps,
        handle_parsing_errors=True,
        **(agent_executor_kwargs or {}),
    )

    return agent_executor


class CustomOpenAIFunctionsAgentOutputParser(OpenAIFunctionsAgentOutputParser):
    """Custom OpenAIFunctionsAgentOutputParser to overcome the JSON parsing error on some agent
    intermediate step inputs. This occurs because the `json.load()` method needs the arg `strict=False` to
    parse the JSON. This is a hacky way to do this, but it works for now.
    """

    def parse(self, message: Union[str, BaseMessage]) -> Union[AgentAction, AgentFinish]:
        """Parse an AI message."""
        if isinstance(message, str):
            raise ValueError("Expected an AIMessage object, got a string")
        if not isinstance(message, AIMessage):
            raise TypeError(f"Expected an AI message got {type(message)}")

        return self._parse_ai_message(message)

    @staticmethod
    def _parse_ai_message(message: AIMessage) -> Union[AgentAction, AgentFinish]:
        """Parse an AI message."""
        function_call = message.additional_kwargs.get("function_call", {})

        if function_call:
            function_name = function_call["name"]
            try:
                _tool_input = json.loads(function_call["arguments"].strip(), strict=False)  # HACK
            except JSONDecodeError:
                raise OutputParserException(
                    f"Could not parse tool input: {function_call} because " f"the `arguments` is not valid JSON."
                )

            # HACK HACK HACK:
            # The code that encodes tool input into Open AI uses a special variable
            # name called `__arg1` to handle old style tools that do not expose a
            # schema and expect a single string argument as an input.
            # We unpack the argument here if it exists.
            # Open AI does not support passing in a JSON array as an argument.
            if "__arg1" in _tool_input:
                tool_input = _tool_input["__arg1"]
            else:
                tool_input = _tool_input

            content_msg = f"responded: {message.content}\n" if message.content else "\n"
            log = f"\nInvoking: `{function_name}` with `{tool_input}`\n{content_msg}\n"
            return AgentActionMessageLog(tool=function_name, tool_input=tool_input, log=log, message_log=[message])

        return AgentFinish(return_values={"output": message.content}, log=str(message.content))

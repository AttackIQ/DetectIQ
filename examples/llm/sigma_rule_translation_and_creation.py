# %% This example will demonstrate how to create a Sigma langchain agent chatbot, which can perform various tasks like
# %% automatically translate a rule for you, and create new rules from a users input.
import asyncio
from langchain.schema.language_model import BaseLanguageModel
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from typing import cast

from detectiq.core.llm.sigma_rules import SigmaLLM
from detectiq.core.llm.toolkits.base import create_rule_agent
from detectiq.core.llm.toolkits.sigma_toolkit import SigmaToolkit
from detectiq.core.utils.logging import get_logger
from detectiq.globals import DEFAULT_DIRS, Config

logger = get_logger(__name__, log_file="sigma_rule_creation.log")


async def initialize_sigma_llm():
    """Initialize Sigma LLM and vector store."""
    # Initialize LLMs with explicit typing
    agent_llm = cast(BaseLanguageModel, ChatOpenAI(temperature=0, model="gpt-4o"))
    rule_creation_llm = cast(BaseLanguageModel, ChatOpenAI(temperature=0, model="gpt-4o"))

    # Initialize Sigma LLM with embeddings and LLMs
    sigma_llm = SigmaLLM(
        embedding_model=OpenAIEmbeddings(model=Config.EMBEDDING_MODEL),
        agent_llm=agent_llm,
        rule_creation_llm=rule_creation_llm,
        rule_dir=str(DEFAULT_DIRS.SIGMA_RULE_DIR),
        vector_store_dir=str(DEFAULT_DIRS.SIGMA_VECTOR_STORE_DIR),
    )

    # Try to load existing vectordb first
    try:
        logger.info("Attempting to load existing Sigma vectorstore...")
        sigma_llm.load_vectordb()
        logger.info("Successfully loaded existing Sigma vectorstore")
    except FileNotFoundError:
        logger.info("No existing vectorstore found. Creating new vectorstore...")
        await sigma_llm.update_rules()
        await sigma_llm.create_vectordb()
        logger.info("Successfully created new Sigma vectorstore")
    except Exception as e:
        logger.error(f"Error loading vectorstore: {str(e)}")
        raise

    return sigma_llm


async def main():
    """Main entry point."""
    # Initialize Sigma LLM
    sigma_llm = await initialize_sigma_llm()

    if sigma_llm.vectordb is None:
        raise ValueError("Failed to initialize vector store")

    if sigma_llm.rule_creation_llm is None or sigma_llm.agent_llm is None:
        raise ValueError("LLM models not properly initialized")

    # Create a Sigma Agent Executor
    sigma_agent_executor = create_rule_agent(
        rule_type="sigma",
        vectorstore=sigma_llm.vectordb,
        rule_creation_llm=sigma_llm.rule_creation_llm,
        agent_llm=sigma_llm.agent_llm,
        toolkit_class=SigmaToolkit,
    )

    # Example prompts and operations...
    print("\n--------\nRULE TRANSLATION\n--------\n")
    user_input = (
        "Convert this Sigma rule to a Splunk query using the 'splunk_cim_dm' pipeline: \n\n"
        + "title: whoami Command\n"
        + "description: Detects a basic whoami commandline execution\n"
        + "logsource:\n"
        + "    product: windows\n"
        + "    category: process_creation\n"
        + "detection:\n"
        + "    selection1:\n"
        + "        - CommandLine|contains: 'whoami.exe'\n"
        + "    condition: selection1"
    )

    answer = await sigma_agent_executor.ainvoke({"input": user_input})
    print(f"\n\nQUESTION:\n {user_input}", end="\n\n")
    print("ANSWER: \n")
    print(answer.get("output"), end="\n\n")

    print("\n--------\nRULE CREATION\n--------\n")
    user_input = "Create a Sigma rule to detect suspicious activity in the Windows Registry."
    answer = await sigma_agent_executor.ainvoke({"input": user_input})
    print(f"\n\nQUESTION:\n {user_input}", end="\n\n")
    print("ANSWER: \n")
    print(answer.get("output"), end="\n\n")


if __name__ == "__main__":
    asyncio.run(main())

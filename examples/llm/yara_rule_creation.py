# This example will demonstrate how to create a YARA langchain agent chatbot, which can perform various tasks like
# creating new rules from a user's description of what to detect.
# To analyze a file, you can run this script with the --file flag followed by the path to the file.
# e.g. python llm_yara_rule_creation.py --file /path/to/file.exe

import argparse
import asyncio
from typing import cast

from langchain.schema.language_model import BaseLanguageModel
from langchain_openai import ChatOpenAI, OpenAIEmbeddings

from detectiq.core.llm.toolkits.base import create_rule_agent
from detectiq.core.llm.toolkits.yara_toolkit import YaraToolkit
from detectiq.core.llm.yara_rules import YaraLLM
from detectiq.core.utils.logging import get_logger
from detectiq.globals import DEFAULT_DIRS, Config

logger = get_logger(__name__, log_file="yara_rule_creation.log")


async def initialize_yara_llm():
    """Initialize YARA LLM and vector store."""
    # Initialize LLMs with explicit typing
    agent_llm = cast(BaseLanguageModel, ChatOpenAI(temperature=0, model="gpt-4o"))
    rule_creation_llm = cast(BaseLanguageModel, ChatOpenAI(temperature=0, model="gpt-4o"))

    # Initialize YARA LLM with embeddings and LLMs
    yara_llm = YaraLLM(
        embedding_model=OpenAIEmbeddings(model=Config.EMBEDDING_MODEL),
        agent_llm=agent_llm,
        rule_creation_llm=rule_creation_llm,
        rule_dir=str(DEFAULT_DIRS.YARA_RULE_DIR),
        vector_store_dir=str(DEFAULT_DIRS.YARA_VECTOR_STORE_DIR),
    )

    # Try to load existing vectordb first
    try:
        logger.info("Attempting to load existing YARA vectorstore...")
        yara_llm.load_vectordb()
        logger.info("Successfully loaded existing YARA vectorstore")
    except FileNotFoundError or RuntimeError:
        logger.info("No existing vectorstore found. Downloading YARA rules and creating new vectorstore...")
        # Download latest YARA rules and create vectorstore
        await yara_llm.update_rules()
        await yara_llm.create_vectordb()
        logger.info("Successfully created new YARA vectorstore")
    except Exception as e:
        logger.error(f"Error loading vectorstore: {str(e)}")
        raise

    return yara_llm


async def main():
    """Main entry point."""
    # Initialize YARA LLM
    yara_llm = await initialize_yara_llm()

    if yara_llm.vectordb is None:
        raise ValueError("Failed to initialize vector store")

    if yara_llm.rule_creation_llm is None or yara_llm.agent_llm is None:
        raise ValueError("LLM models not properly initialized")

    # Create a YARA Agent Executor
    yara_agent_executor = create_rule_agent(
        rule_type="yara",
        vectorstore=yara_llm.vectordb,
        rule_creation_llm=yara_llm.rule_creation_llm,
        agent_llm=yara_llm.agent_llm,
        toolkit_class=YaraToolkit,
    )

    # Add argument parsing
    parser = argparse.ArgumentParser(description="Create YARA rules from file analysis or descriptions")
    parser.add_argument("--file", "-f", help="Path to file for analysis")
    args = parser.parse_args()

    if args.file:
        print(f"\n--------\nANALYZING FILE: {args.file}\n--------\n")
        user_input = f"Analyze this file and create a YARA rule to detect similar files: {args.file}"
        answer = await yara_agent_executor.ainvoke({"input": user_input})
        print(f"QUESTION:\n {user_input}", end="\n\n")
        print("ANSWER: \n")
        print(answer.get("output"), end="\n\n")

    else:
        print("\n--------\nDESCRIPTION-BASED RULE CREATION\n--------\n")
        # Example rule creation prompts...
        user_input = (
            "Create a YARA rule to detect cryptocurrency mining malware. "
            "The rule should look for common cryptocurrency mining-related strings "
            "and patterns, such as mining pool URLs, wallet addresses, and "
            "common miner configuration strings. Focus on detecting both binary "
            "and configuration files."
        )
        answer = await yara_agent_executor.ainvoke({"input": user_input})
        print(f"QUESTION:\n {user_input}", end="\n\n")
        print("ANSWER: \n")
        print(answer.get("output"), end="\n\n")


if __name__ == "__main__":
    asyncio.run(main())

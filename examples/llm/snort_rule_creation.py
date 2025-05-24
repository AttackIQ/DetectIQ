import argparse
import asyncio
from typing import cast

from langchain.schema.language_model import BaseLanguageModel
from langchain_openai import ChatOpenAI, OpenAIEmbeddings

from detectiq.core.llm.snort_rules import SnortLLM
from detectiq.core.llm.toolkits.base import create_rule_agent
from detectiq.core.llm.toolkits.prompts import SNORT_AGENT_PROMPT
from detectiq.core.llm.toolkits.snort_toolkit import SnortToolkit
from detectiq.core.utils.logging import get_logger
from detectiq.globals import DEFAULT_DIRS, Config

# This example will demonstrate how to create a Snort langchain agent chatbot, which can perform various tasks like
# creating new rules from PCAP analysis or descriptions of network behavior to detect.
# To analyze PCAPs, use the --pcap flag and provide the path to the PCAP file.
# e.g. python llm_snort_rule_creation.py --pcap /path/to/pcap/file.pcap

logger = get_logger(__name__, log_file="snort_rule_creation.log")


async def initialize_snort_llm():
    """Initialize Snort LLM and vector store."""
    # Initialize LLMs with explicit typing
    agent_llm = cast(BaseLanguageModel, ChatOpenAI(temperature=0, model="gpt-4o"))
    rule_creation_llm = cast(BaseLanguageModel, ChatOpenAI(temperature=0, model="gpt-4o"))

    # Initialize Snort LLM with embeddings and LLMs
    snort_llm = SnortLLM(
        embedding_model=OpenAIEmbeddings(model=Config.EMBEDDING_MODEL),
        agent_llm=agent_llm,
        rule_creation_llm=rule_creation_llm,
        rule_dir=str(DEFAULT_DIRS.SNORT_RULE_DIR),
        vector_store_dir=str(DEFAULT_DIRS.SNORT_VECTOR_STORE_DIR),
    )

    # Try to load existing vectordb first
    try:
        logger.info("Attempting to load existing Snort vectorstore...")
        snort_llm.load_vectordb()
        logger.info("Successfully loaded existing Snort vectorstore")
    except FileNotFoundError:
        logger.info("No existing vectorstore found. Downloading Snort rules and creating new vectorstore...")
        # Download latest Snort rules and create vectorstore
        await snort_llm.update_rules()
        await snort_llm.create_vectordb()
        logger.info("Successfully created new Snort vectorstore")
    except Exception as e:
        logger.error(f"Error loading vectorstore: {str(e)}")
        raise

    return snort_llm


async def main():
    """Main entry point."""
    # Initialize Snort LLM
    snort_llm = await initialize_snort_llm()

    if snort_llm.vectordb is None:
        raise ValueError("Failed to initialize vector store")

    if snort_llm.rule_creation_llm is None or snort_llm.agent_llm is None:
        raise ValueError("LLM models not properly initialized")

    # Create a Snort Agent Executor
    snort_agent_executor = create_rule_agent(
        vectorstore=snort_llm.vectordb,
        rule_creation_llm=snort_llm.rule_creation_llm,
        agent_llm=snort_llm.agent_llm,
        toolkit_class=SnortToolkit,
        prompt=SNORT_AGENT_PROMPT,
    )

    # Add argument parsing
    parser = argparse.ArgumentParser(description="Create Snort rules from PCAP analysis or descriptions")
    parser.add_argument("--pcap", "-p", help="Path to PCAP file for analysis")
    args = parser.parse_args()

    if args.pcap:
        print(f"\n--------\nANALYZING PCAP: {args.pcap}\n--------\n")
        user_input = f"Analyze this PCAP file and create Snort rules to detect similar traffic patterns: {args.pcap}"
        answer = await snort_agent_executor.ainvoke({"input": user_input})
        print(f"QUESTION:\n {user_input}", end="\n\n")
        print("ANSWER: \n")
        print(answer.get("output"), end="\n\n")

    else:
        print("\n--------\nDESCRIPTION-BASED RULE CREATION\n--------\n")
        # Example rule creation prompts...
        user_input = (
            "Create a Snort rule to detect potential command and control (C2) traffic. "
            "The rule should look for HTTP traffic with suspicious patterns like: "
            "- Unusual User-Agent strings "
            "- Periodic beaconing behavior "
            "- Base64 encoded content in URIs "
            "- Communication with newly registered domains"
        )
        answer = await snort_agent_executor.ainvoke({"input": user_input})
        print(f"QUESTION:\n {user_input}", end="\n\n")
        print("ANSWER: \n")
        print(answer.get("output"), end="\n\n")


if __name__ == "__main__":
    asyncio.run(main())

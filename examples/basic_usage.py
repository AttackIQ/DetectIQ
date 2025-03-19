#!/usr/bin/env python3
"""
Basic example demonstrating how to use the DetectIQ API utilities.

This example demonstrates:
1. Initializing LLM components
2. Creating Sigma, YARA, and Snort rules
3. Translating Sigma rules to different formats

To use this example:
1. Copy this file to your project
2. Create a .env file with your OpenAI API key
3. Run: python basic_usage.py
"""
import os
import asyncio
from typing import cast

from langchain.schema.language_model import BaseLanguageModel
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from dotenv import load_dotenv

# Import DetectIQ components
from detectiq.core.llm.sigma_rules import SigmaLLM
from detectiq.core.llm.yara_rules import YaraLLM
from detectiq.core.llm.snort_rules import SnortLLM
from detectiq.core.llm.toolkits.base import create_rule_agent
from detectiq.core.llm.toolkits.sigma_toolkit import SigmaToolkit
from detectiq.core.llm.toolkits.yara_toolkit import YaraToolkit
from detectiq.core.llm.toolkits.snort_toolkit import SnortToolkit
from detectiq.core.utils.logging import get_logger

# Initialize logging
logger = get_logger(__name__)

# Load environment variables
load_dotenv()


async def demonstrate_sigma_rule_creation(agent_llm, rule_creation_llm):
    """Demonstrate creating a Sigma rule."""
    logger.info("Demonstrating Sigma rule creation...")
    
    # Initialize Sigma LLM
    sigma_llm = SigmaLLM(
        embedding_model=OpenAIEmbeddings(model="text-embedding-3-small"),
        agent_llm=agent_llm,
        rule_creation_llm=rule_creation_llm,
        rule_dir="./sigma_rules",
        vector_store_dir="./sigma_vectorstore",
    )
    
    # Create or load vector store
    try:
        sigma_llm.load_vectordb()
        logger.info("Successfully loaded existing Sigma vectorstore")
    except FileNotFoundError:
        logger.info("Creating new Sigma vectorstore...")
        await sigma_llm.update_rules()
        await sigma_llm.create_vectordb()
    
    # Create agent
    sigma_agent = create_rule_agent(
        rule_type="sigma",
        vectorstore=sigma_llm.vectordb,
        rule_creation_llm=sigma_llm.rule_creation_llm,
        agent_llm=sigma_llm.agent_llm,
        toolkit_class=SigmaToolkit,
    )
    
    # Example 1: Create a rule
    user_input = (
        "Create a Sigma rule to detect suspicious PowerShell commands that "
        "might be used for credential dumping"
    )
    logger.info(f"Creating Sigma rule with prompt: {user_input}")
    result = await sigma_agent.ainvoke({"input": user_input})
    logger.info("Sigma rule creation result:")
    print(result.get("output"))
    
    # Example 2: Translate a rule
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
    logger.info("Translating Sigma rule to Splunk query")
    result = await sigma_agent.ainvoke({"input": user_input})
    logger.info("Translation result:")
    print(result.get("output"))


async def demonstrate_yara_rule_creation(agent_llm, rule_creation_llm):
    """Demonstrate creating a YARA rule."""
    logger.info("Demonstrating YARA rule creation...")
    
    # Initialize YARA LLM
    yara_llm = YaraLLM(
        embedding_model=OpenAIEmbeddings(model="text-embedding-3-small"),
        agent_llm=agent_llm,
        rule_creation_llm=rule_creation_llm,
        rule_dir="./yara_rules",
        vector_store_dir="./yara_vectorstore",
    )
    
    # Create or load vector store
    try:
        yara_llm.load_vectordb()
        logger.info("Successfully loaded existing YARA vectorstore")
    except FileNotFoundError:
        logger.info("Creating new YARA vectorstore...")
        await yara_llm.update_rules()
        await yara_llm.create_vectordb()
    
    # Create agent
    yara_agent = create_rule_agent(
        rule_type="yara",
        vectorstore=yara_llm.vectordb,
        rule_creation_llm=yara_llm.rule_creation_llm,
        agent_llm=yara_llm.agent_llm,
        toolkit_class=YaraToolkit,
    )
    
    # Create a rule
    user_input = (
        "Create a YARA rule to detect cryptocurrency mining malware with "
        "common cryptomining strings and wallet addresses"
    )
    logger.info(f"Creating YARA rule with prompt: {user_input}")
    result = await yara_agent.ainvoke({"input": user_input})
    logger.info("YARA rule creation result:")
    print(result.get("output"))


async def demonstrate_snort_rule_creation(agent_llm, rule_creation_llm):
    """Demonstrate creating a Snort rule."""
    logger.info("Demonstrating Snort rule creation...")
    
    # Initialize Snort LLM
    snort_llm = SnortLLM(
        embedding_model=OpenAIEmbeddings(model="text-embedding-3-small"),
        agent_llm=agent_llm,
        rule_creation_llm=rule_creation_llm,
        rule_dir="./snort_rules",
        vector_store_dir="./snort_vectorstore",
    )
    
    # Create or load vector store
    try:
        snort_llm.load_vectordb()
        logger.info("Successfully loaded existing Snort vectorstore")
    except FileNotFoundError:
        logger.info("Creating new Snort vectorstore...")
        await snort_llm.update_rules()
        await snort_llm.create_vectordb()
    
    # Create agent
    snort_agent = create_rule_agent(
        rule_type="snort",
        vectorstore=snort_llm.vectordb,
        rule_creation_llm=snort_llm.rule_creation_llm,
        agent_llm=snort_llm.agent_llm,
        toolkit_class=SnortToolkit,
    )
    
    # Create a rule
    user_input = (
        "Create a Snort rule to detect potential command and control (C2) traffic. "
        "The rule should look for HTTP traffic with suspicious patterns like: "
        "- Unusual User-Agent strings "
        "- Periodic beaconing behavior "
        "- Base64 encoded content in URIs "
        "- Communication with newly registered domains"
    )
    logger.info(f"Creating Snort rule with prompt: {user_input}")
    result = await snort_agent.ainvoke({"input": user_input})
    logger.info("Snort rule creation result:")
    print(result.get("output"))


async def main():
    """Main entry point."""
    # Check for API key
    if not os.environ.get("OPENAI_API_KEY"):
        raise ValueError(
            "OPENAI_API_KEY not found in environment variables. "
            "Please set it in your .env file or environment."
        )
    
    # Initialize LLMs with explicit typing
    agent_llm = cast(BaseLanguageModel, ChatOpenAI(temperature=0, model="gpt-4o"))
    rule_creation_llm = cast(BaseLanguageModel, ChatOpenAI(temperature=0, model="gpt-4o"))
    
    # Run demonstrations
    logger.info("Starting DetectIQ demonstrations")
    
    # Uncomment the demonstrations you want to run:
    await demonstrate_sigma_rule_creation(agent_llm, rule_creation_llm)
    # await demonstrate_yara_rule_creation(agent_llm, rule_creation_llm)
    # await demonstrate_snort_rule_creation(agent_llm, rule_creation_llm)
    
    logger.info("All demonstrations completed")


if __name__ == "__main__":
    asyncio.run(main()) 
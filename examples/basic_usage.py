#!/usr/bin/env python3
# ruff: noqa: E402

"""
Basic example demonstrating how to use the DetectIQ API utilities.

This example demonstrates:
1. Initializing LLM components
2. Creating Sigma, YARA, and Snort rules from descriptions or files
3. Translating Sigma rules to different formats

To use this example:
1. Create and activate a virtual environment:
   python -m venv venv && source venv/bin/activate

2. Install DetectIQ:
   pip install -r requirements.txt

3. Configure OpenAI API key in .env file

4. Run: python main.py <command> [arguments]
   Available commands:
   - sigma <description> [--file/-f <file_path>]: Create a Sigma rule with optional file analysis
   - yara <description> [--file/-f <file_path>]: Create a YARA rule with optional file analysis
   - snort <description> [--file/-f <file_path>]: Create a Snort rule with optional file analysis
   - setup-embeddings: Create or update embeddings for all rule types
"""

import sys

import argparse
import asyncio
import os
from dotenv import load_dotenv, find_dotenv
from pathlib import Path
from typing import cast, Dict, Any, Union, Optional

# Load environment variables before importing detectiq modules
load_dotenv(find_dotenv())

from detectiq.core.llm.sigma_rules import SigmaLLM
from detectiq.core.llm.snort_rules import SnortLLM
from detectiq.core.llm.tools.sigma.create_sigma_rule import CreateSigmaRuleTool
from detectiq.core.llm.tools.snort.create_snort_rule import CreateSnortRuleTool
from detectiq.core.llm.tools.yara.create_yara_rule import CreateYaraRuleTool
from detectiq.core.llm.yara_rules import YaraLLM
from detectiq.core.utils.logging import get_logger
from detectiq.core.utils.snort.pcap_analyzer import PcapAnalyzer
from detectiq.core.utils.yara.file_analyzer import FileAnalyzer
from langchain.schema.language_model import BaseLanguageModel
from langchain_openai import ChatOpenAI, OpenAIEmbeddings

logger = get_logger(__name__)


class EmbeddingManager:
    """Manages embedding models and vector stores for different rule types."""

    def __init__(self, embedding_model_name: str = "text-embedding-3-small"):
        self.embedding_model_name = embedding_model_name
        self._embedding_model = None

    @property
    def embedding_model(self):
        if self._embedding_model is None:
            self._embedding_model = OpenAIEmbeddings(model=self.embedding_model_name)
        return self._embedding_model

    async def create_vector_store(self, llm_instance, llm_type: str) -> None:
        """Explicitly create or update a vector store"""
        logger.info(f"Creating new {llm_type} vector store...")
        os.makedirs(llm_instance.vector_store_dir, exist_ok=True)
        await llm_instance.update_rules()
        await llm_instance.create_vectordb()
        logger.info(f"Successfully created {llm_type} vector store")

    async def load_vector_store(self, llm_instance, llm_type: str) -> None:
        """Load an existing vector store without creating a new one"""
        try:
            llm_instance.load_vectordb()
            logger.info(f"Successfully loaded existing {llm_type} vector store")
        except (FileNotFoundError, RuntimeError) as e:
            logger.error(f"Failed to load vector store for {llm_type}: {str(e)}")
            raise RuntimeError(f"Vector store for {llm_type} not found. Run 'setup-embeddings' command first.")

    def verify_vector_store_exists(self, vector_store_dir: str, rule_type: str) -> None:
        """Verify that a vector store exists before attempting to use it"""
        if not os.path.exists(vector_store_dir) or not os.listdir(vector_store_dir):
            raise RuntimeError(f"Vector store for {rule_type} not found. Run 'setup-embeddings' command first.")


class DetectIQClient:
    """Client for interacting with DetectIQ API utilities."""

    def __init__(
        self,
        agent_model_name: str = "gpt-4o",
        rule_creation_model_name: str = "gpt-4o",
        embedding_model_name: str = "text-embedding-3-small",
        temperature: float = 0.0,
    ):
        self.temperature = temperature
        self.agent_model_name = agent_model_name
        self.rule_creation_model_name = rule_creation_model_name
        self.embedding_manager = EmbeddingManager(embedding_model_name)
        self._agent_llm = None
        self._rule_creation_llm = None

        self.rule_dirs = {
            "sigma": "./sigma_rules",
            "yara": "./yara_rules",
            "snort": "./snort_rules",
        }

        self.vector_store_dirs = {
            "sigma": "./sigma_vectorstore",
            "yara": "./yara_vectorstore",
            "snort": "./snort_vectorstore",
        }

    @property
    def agent_llm(self) -> BaseLanguageModel:
        if self._agent_llm is None:
            self._agent_llm = cast(
                BaseLanguageModel,
                ChatOpenAI(temperature=self.temperature, model=self.agent_model_name),
            )
        return self._agent_llm

    @property
    def rule_creation_llm(self) -> BaseLanguageModel:
        if self._rule_creation_llm is None:
            self._rule_creation_llm = cast(
                BaseLanguageModel,
                ChatOpenAI(temperature=self.temperature, model=self.rule_creation_model_name),
            )
        return self._rule_creation_llm

    async def _create_llm_instance(self, rule_type: str) -> Union[SigmaLLM, YaraLLM, SnortLLM]:
        rule_dir = self.rule_dirs.get(rule_type)
        vector_store_dir = self.vector_store_dirs.get(rule_type)

        # Verify that embeddings exist before attempting to create an LLM instance
        self.embedding_manager.verify_vector_store_exists(vector_store_dir, rule_type)

        llm_class_map = {
            "sigma": SigmaLLM,
            "yara": YaraLLM,
            "snort": SnortLLM,
        }

        llm_class = llm_class_map.get(rule_type)
        if not llm_class:
            raise ValueError(f"Unsupported rule type: {rule_type}")

        llm_instance = llm_class(
            embedding_model=self.embedding_manager.embedding_model,
            agent_llm=self.agent_llm,
            rule_creation_llm=self.rule_creation_llm,
            rule_dir=rule_dir,
            vector_store_dir=vector_store_dir,
        )

        await self.embedding_manager.load_vector_store(llm_instance, rule_type.capitalize())
        return llm_instance

    async def _create_llm_instance_without_store(self, rule_type: str) -> Union[SigmaLLM, YaraLLM, SnortLLM]:
        """Create an LLM instance without initializing vector store."""
        rule_dir = self.rule_dirs.get(rule_type)
        vector_store_dir = self.vector_store_dirs.get(rule_type)

        llm_class_map = {
            "sigma": SigmaLLM,
            "yara": YaraLLM,
            "snort": SnortLLM,
        }

        llm_class = llm_class_map.get(rule_type)
        if not llm_class:
            raise ValueError(f"Unsupported rule type: {rule_type}")

        llm_instance = llm_class(
            embedding_model=self.embedding_manager.embedding_model,
            agent_llm=self.agent_llm,
            rule_creation_llm=self.rule_creation_llm,
            rule_dir=rule_dir,
            vector_store_dir=vector_store_dir,
        )

        return llm_instance

    async def _analyze_file_for_sigma(self, file_path: Path) -> Dict[str, Any]:
        logger.info(f"Analyzing log file for Sigma rule: {file_path}")
        analyzer = FileAnalyzer()
        return await analyzer.analyze_file(file_path)

    async def _analyze_file_for_yara(self, file_path: Path) -> Dict[str, Any]:
        logger.info(f"Analyzing binary file for YARA rule: {file_path}")
        analyzer = FileAnalyzer()
        return await analyzer.analyze_file(file_path)

    async def _analyze_file_for_snort(self, file_path: Path) -> Dict[str, Any]:
        logger.info(f"Analyzing packet capture for Snort rule: {file_path}")
        analyzer = PcapAnalyzer()
        return await analyzer.analyze_file(file_path)

    async def _generate_sigma_rule(
        self,
        description: Optional[str] = None,
        file_analysis: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        try:
            llm_instance = await self._create_llm_instance("sigma")

            # Create sigma-specific description
            final_description = self._create_sigma_description(description, file_analysis or {})

            # Create sigma rule
            tool = CreateSigmaRuleTool(
                llm=self.rule_creation_llm,
                sigmadb=llm_instance.vectordb,
                verbose=True,
            )
            result = await tool._arun(final_description)

            return result
        except RuntimeError as e:
            if "Vector store" in str(e) and "not found" in str(e):
                logger.error(f"Cannot create Sigma rule: {str(e)}")
                raise RuntimeError(
                    "Cannot create Sigma rule: Embeddings not found. Run 'setup-embeddings' command first."
                )
            raise

    async def _generate_yara_rule(
        self,
        description: Optional[str] = None,
        file_analysis: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        try:
            llm_instance = await self._create_llm_instance("yara")

            # Create yara-specific description
            final_description = self._create_yara_description(description, file_analysis or {})

            # Create yara rule
            tool = CreateYaraRuleTool(
                llm=self.rule_creation_llm,
                yaradb=llm_instance.vectordb,
                verbose=True,
            )
            matching_rules = file_analysis.get("matching_rules", []) if file_analysis else []
            result = await tool._arun(
                final_description,
                file_analysis=file_analysis or {},
                matching_rules=matching_rules,
            )

            return result
        except RuntimeError as e:
            if "Vector store" in str(e) and "not found" in str(e):
                logger.error(f"Cannot create YARA rule: {str(e)}")
                raise RuntimeError(
                    "Cannot create YARA rule: Embeddings not found. Run 'setup-embeddings' command first."
                )
            raise

    async def _generate_snort_rule(
        self,
        description: Optional[str] = None,
        file_analysis: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        try:
            llm_instance = await self._create_llm_instance("snort")

            # Create snort-specific description
            final_description = self._create_snort_description(description, file_analysis or {})

            # Create snort rule
            tool = CreateSnortRuleTool(
                llm=self.rule_creation_llm,
                snortdb=llm_instance.vectordb,
                verbose=True,
            )
            result = await tool._arun(final_description, file_analysis=file_analysis or {})

            return result
        except RuntimeError as e:
            if "Vector store" in str(e) and "not found" in str(e):
                logger.error(f"Cannot create Snort rule: {str(e)}")
                raise RuntimeError(
                    "Cannot create Snort rule: Embeddings not found. Run 'setup-embeddings' command first."
                )
            raise

    def _create_sigma_description(
        self,
        description: Optional[str],
        file_analysis: Dict[str, Any],
    ) -> str:
        if not description:
            filename = file_analysis.get("file_info", {}).get("filename", "")
            if filename:
                description = f"Create a Sigma rule based on the log patterns in {filename}"
            else:
                description = "Create a SIGMA rule"

        enhanced_description = description

        # Add insights specific to log data
        if file_analysis.get("insights"):
            insights = "\n".join([f"- {insight}" for insight in file_analysis.get("insights", [])])
            enhanced_description += f"\n\nLog analysis insights:\n{insights}"

        # Add log-specific file information
        file_info = file_analysis.get("file_info", {})
        if file_info:
            file_info_str = "\n".join([f"- {k}: {v}" for k, v in file_info.items()])
            enhanced_description += f"\n\nLog file information:\n{file_info_str}"

        return enhanced_description

    def _create_yara_description(
        self,
        description: Optional[str],
        file_analysis: Dict[str, Any],
    ) -> str:
        if not description:
            filename = file_analysis.get("file_info", {}).get("filename", "")
            if filename:
                description = f"Create a YARA rule for the file {filename} based on its characteristics"
            else:
                description = "Create a YARA rule"

        enhanced_description = description

        # Add insights specifically for binary analysis
        if file_analysis.get("insights"):
            insights = "\n".join([f"- {insight}" for insight in file_analysis.get("insights", [])])
            enhanced_description += f"\n\nBinary analysis insights:\n{insights}"

        # Add binary-specific file information
        file_info = file_analysis.get("file_info", {})
        if file_info:
            file_info_str = "\n".join([f"- {k}: {v}" for k, v in file_info.items()])
            enhanced_description += f"\n\nBinary file information:\n{file_info_str}"

        # Add any matching rules found
        matching_rules = file_analysis.get("matching_rules", [])
        if matching_rules:
            rules_str = "\n".join([f"- {rule}" for rule in matching_rules])
            enhanced_description += f"\n\nMatching YARA rules:\n{rules_str}"

        return enhanced_description

    def _create_snort_description(
        self,
        description: Optional[str],
        file_analysis: Dict[str, Any],
    ) -> str:
        if not description:
            filename = file_analysis.get("file_info", {}).get("filename", "")
            if filename:
                description = f"Create a Snort rule based on the traffic patterns in {filename}"
            else:
                description = "Create a SNORT rule"

        enhanced_description = description

        # Add insights specifically for network traffic
        if file_analysis.get("insights"):
            insights = "\n".join([f"- {insight}" for insight in file_analysis.get("insights", [])])
            enhanced_description += f"\n\nNetwork traffic insights:\n{insights}"

        # Add network-specific information
        file_info = file_analysis.get("file_info", {})
        if file_info:
            file_info_str = "\n".join([f"- {k}: {v}" for k, v in file_info.items()])
            enhanced_description += f"\n\nPCAP file information:\n{file_info_str}"

        # Add any packet statistics if available
        packet_stats = file_analysis.get("packet_stats", {})
        if packet_stats:
            stats_str = "\n".join([f"- {k}: {v}" for k, v in packet_stats.items()])
            enhanced_description += f"\n\nPacket statistics:\n{stats_str}"

        return enhanced_description

    async def _process_rule_result(self, rule_type: str, result: Dict[str, Any]) -> Dict[str, Any]:
        rule_content = result.get("rule", "") or result.get("content", "") or result.get("output", "")
        title = result.get("title", "Untitled Rule")

        rule_file_path = await self._save_rule_to_file(rule_type, title, rule_content)

        return {
            "rule_type": rule_type,
            "title": title,
            "file_path": str(rule_file_path),
            "content": rule_content,
            "result": result,
        }

    async def _save_rule_to_file(self, rule_type: str, title: str, content: str) -> Path:
        rule_file_name = self._create_safe_filename(title)

        extensions = {"sigma": ".yml", "yara": ".yar", "snort": ".rules"}
        extension = extensions.get(rule_type, ".txt")

        rule_dir = Path(self.rule_dirs.get(rule_type, f"./{rule_type}_rules"))
        rule_dir.mkdir(parents=True, exist_ok=True)

        rule_file_path = rule_dir / f"{rule_file_name}{extension}"
        with open(rule_file_path, "w") as f:
            f.write(content)

        logger.info(f"Rule saved to: {rule_file_path}")
        return rule_file_path

    def _create_safe_filename(self, title: str) -> str:
        safe_name = "".join(c for c in title if c.isalnum() or c in (" ", "-", "_")).strip()
        safe_name = safe_name.replace(" ", "_").lower()
        return safe_name

    # Public API methods
    async def create_sigma_rule(self, description: str, file_path: Optional[str] = None) -> Dict[str, Any]:
        if file_path:
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                raise FileNotFoundError(f"File not found: {file_path}")

            file_analysis = await self._analyze_file_for_sigma(file_path_obj)
            result = await self._generate_sigma_rule(description, file_analysis)
        else:
            result = await self._generate_sigma_rule(description, None)

        return await self._process_rule_result("sigma", result)

    async def create_yara_rule(self, description: str, file_path: Optional[str] = None) -> Dict[str, Any]:
        if file_path:
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                raise FileNotFoundError(f"File not found: {file_path}")

            file_analysis = await self._analyze_file_for_yara(file_path_obj)
            result = await self._generate_yara_rule(description, file_analysis)
        else:
            result = await self._generate_yara_rule(description, None)

        return await self._process_rule_result("yara", result)

    async def create_snort_rule(self, description: str, file_path: Optional[str] = None) -> Dict[str, Any]:
        if file_path:
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                raise FileNotFoundError(f"File not found: {file_path}")

            file_analysis = await self._analyze_file_for_snort(file_path_obj)
            result = await self._generate_snort_rule(description, file_analysis)
        else:
            result = await self._generate_snort_rule(description, None)

        return await self._process_rule_result("snort", result)


async def create_rule(rule_type: str, description: str, file_path: Optional[str] = None):
    """Create a rule of specified type with optional file input."""
    client = DetectIQClient()

    if rule_type == "sigma":
        result = await client.create_sigma_rule(description, file_path)
    elif rule_type == "yara":
        result = await client.create_yara_rule(description, file_path)
    elif rule_type == "snort":
        result = await client.create_snort_rule(description, file_path)
    else:
        raise ValueError(f"Unsupported rule type: {rule_type}")

    print("\n=== Generated Rule ===")
    print(f"Type: {result['rule_type']}")
    print(f"Title: {result['title']}")
    print(f"Saved to: {result['file_path']}")
    print("\n=== Rule Content ===")
    print(result["content"])

    return result


async def setup_embeddings():
    """Initialize and create embeddings for all rule types."""
    client = DetectIQClient()

    print("Setting up embeddings for all rule types...")
    rule_types = ["sigma", "yara", "snort"]

    for rule_type in rule_types:
        print(f"\nInitializing {rule_type} embeddings...")
        llm_instance = await client._create_llm_instance_without_store(rule_type)
        await client.embedding_manager.create_vector_store(llm_instance, rule_type.capitalize())
        print(f"{rule_type.capitalize()} embeddings created successfully.")

    print("\nAll embeddings have been created successfully.")
    return True


def setup_argparse():
    parser = argparse.ArgumentParser(description="DetectIQ CLI for creating security detection rules")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Setup embeddings command
    subparsers.add_parser("setup-embeddings", help="Create or update embeddings for all rule types")

    # Sigma rule command
    sigma_parser = subparsers.add_parser("sigma", help="Create a Sigma rule")
    sigma_parser.add_argument("description", help="Description of the Sigma rule to create")
    sigma_parser.add_argument(
        "--file",
        "-f",
        dest="file_path",
        help="Optional file path to analyze for creating the Sigma rule",
    )

    # YARA rule command
    yara_parser = subparsers.add_parser("yara", help="Create a YARA rule")
    yara_parser.add_argument("description", help="Description of the YARA rule to create")
    yara_parser.add_argument(
        "--file",
        "-f",
        dest="file_path",
        help="Optional file path to analyze for creating the YARA rule",
    )

    # Snort rule command
    snort_parser = subparsers.add_parser("snort", help="Create a Snort rule")
    snort_parser.add_argument("description", help="Description of the Snort rule to create")
    snort_parser.add_argument(
        "--file",
        "-f",
        dest="file_path",
        help="Optional file path to analyze for creating the Snort rule",
    )

    return parser


async def main():
    """Run the appropriate command based on command-line arguments using argparse."""
    # Check for OPENAI_API_KEY only if we're not just showing help
    if "-h" not in sys.argv and "--help" not in sys.argv:
        if not os.environ.get("OPENAI_API_KEY"):
            raise ValueError(
                "OPENAI_API_KEY not found in environment variables. " "Please set it in your .env file or environment."
            )

    parser = setup_argparse()

    # Try/except to catch SystemExit from argparse help
    try:
        args = parser.parse_args()

        # If no command was specified, show help and exit
        if not args.command:
            parser.print_help()
            return
    except SystemExit:
        # This is expected when showing help
        return

    try:
        if args.command == "setup-embeddings":
            await setup_embeddings()
        elif args.command in ["sigma", "yara", "snort"]:
            file_path = args.file_path if hasattr(args, "file_path") else None
            await create_rule(args.command, args.description, file_path)
    except RuntimeError as e:
        print(f"Error: {str(e)}")
        if "Vector store" in str(e) and "not found" in str(e):
            print("\nYou need to run 'setup-embeddings' command first before creating rules.")
            print("Command: python main.py setup-embeddings")
    except Exception as e:
        print(f"Error: {str(e)}")


if __name__ == "__main__":
    asyncio.run(main())

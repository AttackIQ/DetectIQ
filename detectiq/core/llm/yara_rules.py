from typing import Any, Dict, List, Optional

from langchain.embeddings.base import Embeddings
from langchain.schema.document import Document
from langchain.schema.language_model import BaseLanguageModel

from detectiq.core.llm.base import BaseLLMRules
from detectiq.core.utils.logging import get_logger
from detectiq.core.utils.yara.rule_updater import YaraRuleUpdater
from detectiq.globals import DEFAULT_DIRS

logger = get_logger(__name__)


class YaraLLM(BaseLLMRules):
    """LLM-powered YARA rule operations."""

    def __init__(
        self,
        embedding_model: Optional[Embeddings] = None,
        agent_llm: Optional[BaseLanguageModel] = None,
        rule_creation_llm: Optional[BaseLanguageModel] = None,
        rule_dir: Optional[str] = None,
        vector_store_dir: Optional[str] = None,
        package_type: str = "core",
        auto_update: bool = True,
    ):
        """Initialize YaraLLM.

        Args:
            embedding_model: Model for creating embeddings
            agent_llm: LLM for agent operations
            rule_creation_llm: LLM for rule creation
            rule_dir: Directory for rules
            vector_store_dir: Directory for vector store
            package_type: Type of YARA rule package to use
            auto_update: Whether to automatically update rules
        """
        super().__init__(
            embedding_model=embedding_model,
            agent_llm=agent_llm,
            rule_creation_llm=rule_creation_llm,
            rule_dir=rule_dir or str(DEFAULT_DIRS.YARA_RULE_DIR),
            vector_store_dir=vector_store_dir,
            auto_update=auto_update,
        )

        # Initialize rule updater with string path
        self.rule_updater = YaraRuleUpdater(rule_dir=str(self.rule_dir), package_type=package_type)
        logger.info("Initialized YaraLLM")

    async def update_rules(self, force: bool = False) -> None:
        """Update YARA rules using the rule updater."""
        try:
            logger.info("Updating YARA rules...")
            await self.rule_updater.update_rules(force=force)
            logger.info("YARA rules updated successfully")
        except Exception as e:
            logger.error(f"Error updating YARA rules: {str(e)}")
            raise

    async def create_rule_docs(self) -> List[Document]:
        """Create Document objects from YARA rules."""
        try:
            logger.info("Creating document objects from YARA rules")
            rules = await self.rule_updater.load_rules()
            documents = []

            for rule in rules:
                doc = Document(page_content=rule["content"], metadata=rule["metadata"])
                documents.append(doc)

            logger.info(f"Created {len(documents)} document objects")
            return documents

        except Exception as e:
            logger.error(f"Error creating rule documents: {str(e)}")
            raise

    async def create_rule(self, description: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create a new YARA rule using LLM."""
        if not self.rule_creation_llm:
            raise ValueError("Rule creation LLM not provided")

        try:
            # TODO: Implement rule creation
            raise NotImplementedError("YARA rule creation not implemented yet")
        except Exception as e:
            logger.error(f"Error creating YARA rule: {e}")
            raise

    async def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze file for rule creation."""
        try:
            # TODO: Implement file analysis
            raise NotImplementedError("File analysis not implemented yet")
        except Exception as e:
            logger.error(f"Error analyzing file: {e}")
            raise

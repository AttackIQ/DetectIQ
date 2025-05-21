from typing import Any, Dict, List, Optional

from langchain.embeddings.base import Embeddings
from langchain.schema.document import Document
from langchain.schema.language_model import BaseLanguageModel

from detectiq.core.llm.base import BaseLLMRules
from detectiq.core.utils.logging import get_logger
from detectiq.core.utils.sigma.rule_updater import SigmaRuleUpdater
from detectiq.globals import DEFAULT_DIRS

logger = get_logger(__name__)


class SigmaLLM(BaseLLMRules):
    """LLM-powered Sigma rule operations."""

    def __init__(
        self,
        embedding_model: Optional[Embeddings] = None,
        agent_llm: Optional[BaseLanguageModel] = None,
        rule_creation_llm: Optional[BaseLanguageModel] = None,
        rule_dir: Optional[str] = None,
        vector_store_dir: Optional[str] = None,
        auto_update: bool = True,
    ):
        """Initialize SigmaLLM.

        Args:
            embedding_model: Model for creating embeddings
            agent_llm: LLM for agent operations
            rule_creation_llm: LLM for rule creation
            rule_dir: Directory for rules
            vector_store_dir: Directory for vector store
            auto_update: Whether to automatically update rules
        """
        super().__init__(
            embedding_model=embedding_model,
            agent_llm=agent_llm,
            rule_creation_llm=rule_creation_llm,
            rule_dir=rule_dir or str(DEFAULT_DIRS.SIGMA_RULE_DIR),
            vector_store_dir=vector_store_dir,
            auto_update=auto_update,
        )

        # Initialize rule updater with string path
        self.rule_updater = SigmaRuleUpdater(rule_dir=str(self.rule_dir))
        logger.info("Initialized SigmaLLM")

    async def update_rules(self, force: bool = False) -> None:
        """Update Sigma rules using the rule updater."""
        try:
            logger.info("Updating Sigma rules...")
            await self.rule_updater.update_rules(force=force)
            logger.info("Sigma rules updated successfully")
        except Exception as e:
            logger.error(f"Error updating Sigma rules: {str(e)}")
            raise

    async def create_rule_docs(self) -> List[Document]:
        """Create Document objects from Sigma rules."""
        try:
            logger.info("Creating document objects from Sigma rules")
            # Convert synchronous load_rules to async
            rules = await self._load_rules_async()
            documents = []

            for rule in rules:
                doc = Document(page_content=rule["content"], metadata=rule["metadata"])
                documents.append(doc)

            logger.info(f"Created {len(documents)} document objects")
            return documents

        except Exception as e:
            logger.error(f"Error creating rule documents: {str(e)}")
            raise

    async def _load_rules_async(self) -> List[Dict[str, Any]]:
        """Async wrapper for synchronous load_rules method."""
        return await self.rule_updater.load_rules()

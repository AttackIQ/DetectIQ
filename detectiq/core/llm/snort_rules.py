from typing import Any, Dict, List, Optional

from langchain.embeddings.base import Embeddings
from langchain.schema.document import Document
from langchain.schema.language_model import BaseLanguageModel

from detectiq.core.llm.base import BaseLLMRules
from detectiq.core.utils.logging import get_logger
from detectiq.core.utils.snort.rule_updater import SnortRuleUpdater
from detectiq.globals import DEFAULT_DIRS

logger = get_logger(__name__)


class SnortLLM(BaseLLMRules):
    """LLM-powered Snort rule operations."""

    def __init__(
        self,
        embedding_model: Optional[Embeddings] = None,
        agent_llm: Optional[BaseLanguageModel] = None,
        rule_creation_llm: Optional[BaseLanguageModel] = None,
        rule_dir: Optional[str] = None,
        vector_store_dir: Optional[str] = None,
        auto_update: bool = True,
    ):
        """Initialize SnortLLM."""
        super().__init__(
            embedding_model=embedding_model,
            agent_llm=agent_llm,
            rule_creation_llm=rule_creation_llm,
            rule_dir=rule_dir or str(DEFAULT_DIRS.SNORT_RULE_DIR),
            vector_store_dir=vector_store_dir,
            auto_update=auto_update,
        )

        # Initialize rule updater
        self.rule_updater = SnortRuleUpdater(rule_dir=str(self.rule_dir))
        logger.info("Initialized SnortLLM")

    async def update_rules(self, force: bool = False) -> None:
        """Update Snort rules using the rule updater."""
        try:
            logger.info("Updating Snort rules...")
            await self.rule_updater.update_rules(force=force)
            logger.info("Snort rules updated successfully")
        except Exception as e:
            logger.error(f"Error updating Snort rules: {str(e)}")
            raise

    async def create_rule_docs(self) -> List[Document]:
        """Create Document objects from Snort rules."""
        try:
            logger.info("Creating document objects from Snort rules")
            # Get rules asynchronously
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
        """Create a new Snort rule using LLM."""
        if not self.rule_creation_llm:
            raise ValueError("Rule creation LLM not provided")

        try:
            # TODO: Implement rule creation
            raise NotImplementedError("Snort rule creation not implemented yet")
        except Exception as e:
            logger.error(f"Error creating Snort rule: {e}")
            raise

    async def analyze_pcap(self, pcap_path: str) -> Dict[str, Any]:
        """Analyze PCAP file for rule creation."""
        try:
            # TODO: Implement PCAP analysis
            raise NotImplementedError("PCAP analysis not implemented yet")
        except Exception as e:
            logger.error(f"Error analyzing PCAP: {e}")
            raise

from langchain_openai import OpenAIEmbeddings
from pathlib import Path
from typing import Any, Dict, List, Optional

from detectiq.core.config import config
from detectiq.core.llm.yara_rules import YaraLLM
from detectiq.core.utils.logging import get_logger
from detectiq.core.utils.yara.rule_updater import YaraRuleUpdater
from detectiq.webapp.backend.services.rule_service import DjangoRuleRepository

logger = get_logger(__name__)


class YaraRulesetManager:
    def __init__(
        self,
        rule_dir: Optional[str] = None,
        vector_store_dir: Optional[str] = None,
        embedding_model: Optional[str] = None,
        package_type: Optional[str] = None,
    ):
        """Initialize the YARA ruleset manager."""
        self.rule_dir = Path(str(rule_dir or config.rule_directories.get("yara")))
        self.vector_store_dir = Path(str(vector_store_dir or config.vector_store_directories.get("yara")))
        self.rule_repository = DjangoRuleRepository()
        self.embedding_model = embedding_model or OpenAIEmbeddings(model=config.embedding_model)
        self.package_type = package_type or config.yara_package_type or "core"

        # Initialize rule updater
        self.updater = YaraRuleUpdater(rule_dir=str(self.rule_dir))

        # Initialize LLM handler
        self.llm = YaraLLM(
            rule_dir=str(self.rule_dir),
            auto_update=False,
            vector_store_dir=str(self.vector_store_dir),
            embedding_model=self.embedding_model,
        )

    async def verify_rule(self, rule_content: str, file_content: bytes):
        """Verify a YARA rule against file content."""
        try:
            # Implementation of rule verification
            pass
        except Exception as e:
            logger.error(f"Error verifying YARA rule: {e}")
            raise

    async def update_rules(self, force: bool = False) -> List[Dict[str, Any]]:
        """Update YARA rules and return loaded rules."""
        try:
            logger.info("Updating YARA rules...")

            # Clean rule directory if it exists
            if self.rule_dir.exists():
                await self._clean_rule_directory()

            # Update and load rules
            await self.updater.update_rules(force=force)
            rules = await self.updater.load_rules()

            logger.info(f"Successfully updated and loaded {len(rules)} YARA rules")
            return rules
        except Exception as e:
            logger.error(f"Error updating YARA rules: {e}")
            raise

    async def _clean_rule_directory(self):
        """Clean the rule directory."""
        try:
            import shutil

            shutil.rmtree(self.rule_dir)
            self.rule_dir.mkdir(parents=True, exist_ok=True)
            logger.info("Successfully cleaned YARA rule directory")
        except Exception as e:
            logger.error(f"Error cleaning YARA rule directory: {e}")
            raise

    async def create_vector_store(self) -> None:
        """Create vector store for YARA rules."""
        try:
            await self.llm.create_vectordb()
            logger.info("Successfully created YARA vector store")
        except Exception as e:
            logger.error(f"Error creating YARA vector store: {e}")
            raise

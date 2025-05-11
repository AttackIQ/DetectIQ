# stdlib
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

from langchain.embeddings.base import Embeddings
from langchain.schema.document import Document
from langchain.schema.language_model import BaseLanguageModel
from langchain_community.vectorstores import FAISS

from detectiq.core.utils.logging import get_logger
from detectiq.globals import DEFAULT_DIRS

logger = get_logger(__name__)

# Default batch size for processing documents - can be adjusted
DEFAULT_BATCH_SIZE = 500


class BaseLLMRules(ABC):
    """Base class for LLM-powered rule operations."""

    def __init__(
        self,
        embedding_model: Optional[Embeddings] = None,
        agent_llm: Optional[BaseLanguageModel] = None,
        rule_creation_llm: Optional[BaseLanguageModel] = None,
        rule_dir: Optional[str] = None,
        vector_store_dir: Optional[str] = None,
        auto_update: bool = True,
    ):
        """Initialize base class.

        Args:
            embedding_model: Model for creating embeddings
            agent_llm: LLM for agent operations
            rule_creation_llm: LLM for rule creation
            rule_dir: Directory for rules
            vector_store_dir: Directory for vector store
            auto_update: Whether to automatically update rules
        """
        self.embedding_model = embedding_model
        self.agent_llm = agent_llm
        self.rule_creation_llm = rule_creation_llm

        # Use proper attribute access for DEFAULT_DIRS
        default_rule_dir = getattr(DEFAULT_DIRS, "RULE_DIR", Path("rules"))
        default_vector_dir = getattr(DEFAULT_DIRS, "VECTOR_STORE_DIR", Path("vector_store"))

        self.rule_dir = Path(rule_dir) if rule_dir else default_rule_dir
        self.vector_store_dir = Path(vector_store_dir) if vector_store_dir else default_vector_dir
        self.auto_update = auto_update
        self.vectordb: Optional[FAISS] = None

        # Ensure directories exist
        self.rule_dir.mkdir(parents=True, exist_ok=True)
        self.vector_store_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Initialized {self.__class__.__name__} with rule directory: {self.rule_dir}")

    def load_vectordb(self) -> None:
        """Load vector store from disk, checking for necessary index files."""
        try:
            vector_store_path = Path(self.vector_store_dir)
            logger.info(f"Loading vector store from {vector_store_path}")

            if not self.embedding_model:
                raise ValueError("Embedding model not initialized")

            # Check 1: Directory existence
            if not vector_store_path.exists() or not vector_store_path.is_dir():
                raise FileNotFoundError(f"Vector store directory not found or is not a directory: {vector_store_path}")

            # Check 2: Required FAISS file existence
            faiss_file = vector_store_path / "index.faiss"
            pkl_file = vector_store_path / "index.pkl"

            if not faiss_file.exists() or not pkl_file.exists():
                raise FileNotFoundError(
                    f"Vector store directory '{vector_store_path}' exists, but required index files (index.faiss, index.pkl) are missing. "
                    f"Store needs to be created first."
                )

            # Proceed with loading if checks pass
            self.vectordb = FAISS.load_local(
                folder_path=str(vector_store_path),
                embeddings=self.embedding_model,
                allow_dangerous_deserialization=True,
            )
            logger.info("Vector store loaded successfully")

        except FileNotFoundError as fnf_error:
            # Re-raise FileNotFoundError specifically for clearer handling upstream
            logger.warning(f"Could not load vector store: {fnf_error}")
            raise fnf_error
        except Exception as e:
            # Catch other potential errors during loading (e.g., deserialization issues)
            logger.error(f"Failed to load vector store due to unexpected error: {str(e)}")
            # Consider wrapping in a custom exception or re-raising depending on desired handling
            raise RuntimeError(f"Failed to load vector store from {vector_store_path}: {str(e)}") from e

    async def create_vectordb(
        self,
        texts: Optional[List[str]] = None,
        metadatas: Optional[List[Dict[str, Any]]] = None,
        batch_size: int = 50,
    ) -> None:
        """Create vector store from documents."""
        try:
            logger.info("Creating vector store from documents")
            if not self.embedding_model:
                raise ValueError("Embedding model not initialized")

            # Get documents if not provided
            if not texts or not metadatas:
                documents = await self.create_rule_docs()
                texts = [doc.page_content for doc in documents]
                metadatas = [doc.metadata for doc in documents]

            total_docs = len(texts)
            logger.info(f"Processing {total_docs} documents in batches of {batch_size}")

            # Initialize vector store as None
            vectordb = None

            # Process documents in batches
            for i in range(0, total_docs, batch_size):
                batch_end = min(i + batch_size, total_docs)
                batch_texts = texts[i:batch_end]
                batch_metadatas = metadatas[i:batch_end]

                logger.info(
                    f"Processing batch {i // batch_size + 1}/{(total_docs + batch_size - 1) // batch_size} with {len(batch_texts)} documents"
                )

                # Create embeddings for this batch
                batch_vectordb = FAISS.from_texts(
                    texts=batch_texts,
                    metadatas=batch_metadatas,
                    embedding=self.embedding_model,
                )

                # For the first batch, just save it
                if vectordb is None:
                    vectordb = batch_vectordb
                else:
                    # For subsequent batches, merge with existing one
                    vectordb.merge_from(batch_vectordb)

                logger.info(f"Successfully processed batch {i // batch_size + 1}")

            # Save the final vector store
            self.vectordb = vectordb
            if self.vectordb:
                os.makedirs(str(self.vector_store_dir), exist_ok=True)
                self.vectordb.save_local(str(self.vector_store_dir))
                logger.info(f"Vector store created and saved successfully at {self.vector_store_dir}")
            else:
                raise ValueError("Failed to create vector store - no documents processed")

        except Exception as e:
            logger.error(f"Failed to create vector store: {str(e)}")
            raise

    @abstractmethod
    async def update_rules(self, force: bool = False) -> None:
        """Update rules from source."""
        pass

    @abstractmethod
    async def create_rule_docs(self) -> List[Document]:
        """Create Document objects from rules."""
        pass

    def split_rule_docs(self, documents: List[Document]) -> List[Document]:
        """Do not split documents to preserve rule context."""
        return documents

import os
import json
import logging
import structlog
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path

from core.config import settings

log = structlog.get_logger()


class VectorStore:
    """Vector database for storing and retrieving embeddings"""

    def __init__(self):
        self.db_type = settings.VECTOR_DB_TYPE
        self.db_path = settings.VECTOR_DB_PATH
        self.client = None
        self.collections = {}
        self._initialize()

    def _initialize(self):
        """Initialize the vector database"""
        try:
            if self.db_type == "chromadb":
                self._init_chromadb()
            else:
                log.error(f"Unsupported vector database type: {self.db_type}")

        except Exception as e:
            log.error(f"Failed to initialize vector store: {e}", exc_info=True)

    def _init_chromadb(self):
        """Initialize ChromaDB"""
        try:
            import chromadb

            db_path = Path(self.db_path)
            db_path.mkdir(parents=True, exist_ok=True)

            self.client = chromadb.PersistentClient(path=str(db_path))
            log.info(f"Initialized ChromaDB at {self.db_path}")

        except ImportError:
            log.error("ChromaDB not installed, install with: pip install chromadb")
        except Exception as e:
            log.error(f"Failed to initialize ChromaDB: {e}", exc_info=True)

    def create_collection(self, name: str, metadata: Dict[str, Any] = None) -> bool:
        """Create a new collection"""
        if not self.client:
            log.error("Vector database not initialized")
            return False

        try:
            if name in self.collections:
                log.warning(f"Collection {name} already exists")
                return True

            collection = self.client.create_collection(
                name=name,
                metadata=metadata or {}
            )

            self.collections[name] = collection
            log.info(f"Created collection: {name}")
            return True

        except Exception as e:
            log.error(f"Failed to create collection {name}: {e}", exc_info=True)
            return False

    def get_collection(self, name: str):
        """Get an existing collection"""
        if not self.client:
            log.error("Vector database not initialized")
            return None

        try:
            if name not in self.collections:
                collection = self.client.get_collection(name)
                self.collections[name] = collection

            return self.collections[name]

        except Exception as e:
            log.error(f"Failed to get collection {name}: {e}", exc_info=True)
            return None

    def add_documents(
        self,
        collection_name: str,
        documents: List[str],
        metadatas: List[Dict[str, Any]] = None,
        ids: List[str] = None
    ) -> bool:
        """Add documents to a collection"""
        collection = self.get_collection(collection_name)
        if not collection:
            return False

        try:
            collection.add(
                documents=documents,
                metadatas=metadatas or [{} for _ in documents],
                ids=ids or [f"doc_{datetime.utcnow().timestamp()}_{i}" for i in range(len(documents))]
            )
            log.info(f"Added {len(documents)} documents to {collection_name}")
            return True

        except Exception as e:
            log.error(f"Failed to add documents to {collection_name}: {e}", exc_info=True)
            return False

    def query(
        self,
        collection_name: str,
        query_text: str,
        n_results: int = 5,
        where: Dict[str, Any] = None
    ) -> Optional[Dict[str, Any]]:
        """Query a collection"""
        collection = self.get_collection(collection_name)
        if not collection:
            return None

        try:
            results = collection.query(
                query_texts=[query_text],
                n_results=n_results,
                where=where
            )

            return {
                "documents": results.get("documents", [[]])[0],
                "metadatas": results.get("metadatas", [[]])[0],
                "distances": results.get("distances", [[]])[0],
                "ids": results.get("ids", [[]])[0]
            }

        except Exception as e:
            log.error(f"Failed to query collection {collection_name}: {e}", exc_info=True)
            return None

    def delete_collection(self, name: str) -> bool:
        """Delete a collection"""
        if not self.client:
            log.error("Vector database not initialized")
            return False

        try:
            self.client.delete_collection(name)
            if name in self.collections:
                del self.collections[name]
            log.info(f"Deleted collection: {name}")
            return True

        except Exception as e:
            log.error(f"Failed to delete collection {name}: {e}", exc_info=True)
            return False

    def list_collections(self) -> List[str]:
        """List all collections"""
        if not self.client:
            return []

        try:
            return self.client.list_collections()
        except Exception as e:
            log.error(f"Failed to list collections: {e}", exc_info=True)
            return []

    def get_collection_count(self, name: str) -> int:
        """Get the number of documents in a collection"""
        collection = self.get_collection(name)
        if not collection:
            return 0

        try:
            return collection.count()
        except Exception as e:
            log.error(f"Failed to get count for {name}: {e}", exc_info=True)
            return 0

    def is_available(self) -> bool:
        """Check if vector store is available"""
        return self.client is not None


_vector_store_instance: Optional[VectorStore] = None


def get_vector_store() -> VectorStore:
    """Get or create vector store instance"""
    global _vector_store_instance
    if _vector_store_instance is None:
        _vector_store_instance = VectorStore()
    return _vector_store_instance

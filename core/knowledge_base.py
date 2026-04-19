import os
import json
import logging
import structlog
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path

from core.config import settings
from core.vector_store import get_vector_store

log = structlog.get_logger()


class KnowledgeBase:
    """Manage analysis artifacts and knowledge for RAG"""

    def __init__(self):
        self.vector_store = get_vector_store()
        self.data_dir = settings.DATA_DIR
        self.collections = {
            "functions": None,
            "vulnerabilities": None,
            "malware_behaviors": None,
            "api_signatures": None
        }
        self._initialize_collections()

    def _initialize_collections(self):
        """Initialize default collections"""
        if not self.vector_store.is_available():
            log.warning("Vector store not available, knowledge base will be limited")
            return

        for collection_name in self.collections.keys():
            self.vector_store.create_collection(
                name=collection_name,
                metadata={"type": collection_name, "created_at": datetime.utcnow().isoformat()}
            )
            self.collections[collection_name] = self.vector_store.get_collection(collection_name)

        log.info("Initialized knowledge base collections")

    def index_function(self, function_data: Dict[str, Any]) -> bool:
        """Index a function for retrieval"""
        if not self.vector_store.is_available():
            return False

        try:
            document = self._create_function_document(function_data)
            metadata = {
                "function_name": function_data.get("name", "unknown"),
                "address": function_data.get("address", ""),
                "job_id": function_data.get("job_id", ""),
                "indexed_at": datetime.utcnow().isoformat()
            }

            doc_id = f"func_{function_data.get('address', 'unknown')}_{datetime.utcnow().timestamp()}"

            return self.vector_store.add_documents(
                collection_name="functions",
                documents=[document],
                metadatas=[metadata],
                ids=[doc_id]
            )

        except Exception as e:
            log.error(f"Failed to index function: {e}", exc_info=True)
            return False

    def _create_function_document(self, function_data: Dict[str, Any]) -> str:
        """Create a searchable document from function data"""
        parts = []

        if function_data.get("name"):
            parts.append(f"Function: {function_data['name']}")

        if function_data.get("address"):
            parts.append(f"Address: {function_data['address']}")

        if function_data.get("decompiled_code"):
            parts.append(f"Code:\n{function_data['decompiled_code']}")

        if function_data.get("parameters"):
            parts.append(f"Parameters: {', '.join(function_data['parameters'])}")

        if function_data.get("return_type"):
            parts.append(f"Return Type: {function_data['return_type']}")

        return "\n\n".join(parts)

    def index_vulnerability(self, vulnerability_data: Dict[str, Any]) -> bool:
        """Index a vulnerability pattern"""
        if not self.vector_store.is_available():
            return False

        try:
            document = self._create_vulnerability_document(vulnerability_data)
            metadata = {
                "vulnerability_type": vulnerability_data.get("type", "unknown"),
                "severity": vulnerability_data.get("severity", "unknown"),
                "cve_id": vulnerability_data.get("cve_id", ""),
                "indexed_at": datetime.utcnow().isoformat()
            }

            doc_id = f"vuln_{vulnerability_data.get('type', 'unknown')}_{datetime.utcnow().timestamp()}"

            return self.vector_store.add_documents(
                collection_name="vulnerabilities",
                documents=[document],
                metadatas=[metadata],
                ids=[doc_id]
            )

        except Exception as e:
            log.error(f"Failed to index vulnerability: {e}", exc_info=True)
            return False

    def _create_vulnerability_document(self, vulnerability_data: Dict[str, Any]) -> str:
        """Create a searchable document from vulnerability data"""
        parts = []

        if vulnerability_data.get("type"):
            parts.append(f"Vulnerability Type: {vulnerability_data['type']}")

        if vulnerability_data.get("description"):
            parts.append(f"Description: {vulnerability_data['description']}")

        if vulnerability_data.get("severity"):
            parts.append(f"Severity: {vulnerability_data['severity']}")

        if vulnerability_data.get("cve_id"):
            parts.append(f"CVE ID: {vulnerability_data['cve_id']}")

        if vulnerability_data.get("pattern"):
            parts.append(f"Pattern: {vulnerability_data['pattern']}")

        if vulnerability_data.get("mitigation"):
            parts.append(f"Mitigation: {vulnerability_data['mitigation']}")

        return "\n\n".join(parts)

    def index_malware_behavior(self, behavior_data: Dict[str, Any]) -> bool:
        """Index a malware behavior"""
        if not self.vector_store.is_available():
            return False

        try:
            document = self._create_behavior_document(behavior_data)
            metadata = {
                "behavior_type": behavior_data.get("type", "unknown"),
                "family": behavior_data.get("family", "unknown"),
                "job_id": behavior_data.get("job_id", ""),
                "indexed_at": datetime.utcnow().isoformat()
            }

            doc_id = f"behavior_{behavior_data.get('type', 'unknown')}_{datetime.utcnow().timestamp()}"

            return self.vector_store.add_documents(
                collection_name="malware_behaviors",
                documents=[document],
                metadatas=[metadata],
                ids=[doc_id]
            )

        except Exception as e:
            log.error(f"Failed to index malware behavior: {e}", exc_info=True)
            return False

    def _create_behavior_document(self, behavior_data: Dict[str, Any]) -> str:
        """Create a searchable document from behavior data"""
        parts = []

        if behavior_data.get("type"):
            parts.append(f"Behavior Type: {behavior_data['type']}")

        if behavior_data.get("family"):
            parts.append(f"Malware Family: {behavior_data['family']}")

        if behavior_data.get("description"):
            parts.append(f"Description: {behavior_data['description']}")

        if behavior_data.get("indicators"):
            parts.append(f"Indicators: {', '.join(behavior_data['indicators'])}")

        if behavior_data.get("api_calls"):
            parts.append(f"API Calls: {', '.join(behavior_data['api_calls'])}")

        return "\n\n".join(parts)

    def index_existing_artifacts(self) -> bool:
        """Index existing analysis artifacts from data directory"""
        if not self.vector_store.is_available():
            return False

        try:
            artifacts_dir = self.data_dir
            if not artifacts_dir.exists():
                log.warning(f"Data directory not found: {artifacts_dir}")
                return False

            indexed_count = 0

            for job_dir in artifacts_dir.iterdir():
                if job_dir.is_dir():
                    json_files = list(job_dir.glob("*.json"))
                    for json_file in json_files:
                        try:
                            data = json.loads(json_file.read_text(encoding='utf-8'))
                            if "functions" in data:
                                for func in data["functions"]:
                                    func["job_id"] = job_dir.name
                                    self.index_function(func)
                                    indexed_count += 1
                        except Exception as e:
                            log.error(f"Failed to index {json_file}: {e}")

            log.info(f"Indexed {indexed_count} existing artifacts")
            return True

        except Exception as e:
            log.error(f"Failed to index existing artifacts: {e}", exc_info=True)
            return False

    def search_similar_functions(self, query: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """Search for similar functions"""
        if not self.vector_store.is_available():
            return []

        try:
            results = self.vector_store.query(
                collection_name="functions",
                query_text=query,
                n_results=n_results
            )

            if not results:
                return []

            similar_functions = []
            for i in range(len(results.get("documents", []))):
                similar_functions.append({
                    "document": results["documents"][i],
                    "metadata": results["metadatas"][i],
                    "distance": results["distances"][i] if "distances" in results else None
                })

            return similar_functions

        except Exception as e:
            log.error(f"Failed to search similar functions: {e}", exc_info=True)
            return []

    def search_vulnerabilities(self, query: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """Search for vulnerability patterns"""
        if not self.vector_store.is_available():
            return []

        try:
            results = self.vector_store.query(
                collection_name="vulnerabilities",
                query_text=query,
                n_results=n_results
            )

            if not results:
                return []

            vulnerabilities = []
            for i in range(len(results.get("documents", []))):
                vulnerabilities.append({
                    "document": results["documents"][i],
                    "metadata": results["metadatas"][i],
                    "distance": results["distances"][i] if "distances" in results else None
                })

            return vulnerabilities

        except Exception as e:
            log.error(f"Failed to search vulnerabilities: {e}", exc_info=True)
            return []

    def search_malware_behaviors(self, query: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """Search for malware behaviors"""
        if not self.vector_store.is_available():
            return []

        try:
            results = self.vector_store.query(
                collection_name="malware_behaviors",
                query_text=query,
                n_results=n_results
            )

            if not results:
                return []

            behaviors = []
            for i in range(len(results.get("documents", []))):
                behaviors.append({
                    "document": results["documents"][i],
                    "metadata": results["metadatas"][i],
                    "distance": results["distances"][i] if "distances" in results else None
                })

            return behaviors

        except Exception as e:
            log.error(f"Failed to search malware behaviors: {e}", exc_info=True)
            return []

    def get_collection_stats(self) -> Dict[str, int]:
        """Get statistics for all collections"""
        stats = {}
        for collection_name in self.collections.keys():
            stats[collection_name] = self.vector_store.get_collection_count(collection_name)
        return stats


_knowledge_base_instance: Optional[KnowledgeBase] = None


def get_knowledge_base() -> KnowledgeBase:
    """Get or create knowledge base instance"""
    global _knowledge_base_instance
    if _knowledge_base_instance is None:
        _knowledge_base_instance = KnowledgeBase()
    return _knowledge_base_instance

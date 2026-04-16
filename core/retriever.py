import os
import json
import logging
import structlog
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path

from core.config import settings
from core.knowledge_base import get_knowledge_base
from core.vector_store import get_vector_store

log = structlog.get_logger()


class Retriever:
    """Semantic search and context retrieval for RAG"""

    def __init__(self):
        self.knowledge_base = get_knowledge_base()
        self.vector_store = get_vector_store()
        self.top_k = settings.RAG_TOP_K
        self.similarity_threshold = settings.RAG_SIMILARITY_THRESHOLD

    def retrieve_context(
        self,
        query: str,
        collections: List[str] = None,
        n_results: int = None
    ) -> Dict[str, Any]:
        """Retrieve relevant context from knowledge base"""
        if not self.vector_store.is_available():
            return {"error": "Vector store not available"}

        try:
            n_results = n_results or self.top_k
            collections = collections or ["functions", "vulnerabilities", "malware_behaviors"]

            all_results = {}

            for collection_name in collections:
                results = self.vector_store.query(
                    collection_name=collection_name,
                    query_text=query,
                    n_results=n_results
                )

                if results and results.get("documents"):
                    filtered_results = self._filter_by_similarity(results)
                    if filtered_results["documents"]:
                        all_results[collection_name] = filtered_results

            return {
                "query": query,
                "results": all_results,
                "total_results": sum(len(r.get("documents", [])) for r in all_results.values())
            }

        except Exception as e:
            log.error(f"Failed to retrieve context: {e}", exc_info=True)
            return {"error": str(e)}

    def _filter_by_similarity(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Filter results by similarity threshold"""
        filtered = {
            "documents": [],
            "metadatas": [],
            "distances": [],
            "ids": []
        }

        for i, distance in enumerate(results.get("distances", [])):
            if distance <= (1.0 - self.similarity_threshold):
                filtered["documents"].append(results["documents"][i])
                filtered["metadatas"].append(results["metadatas"][i])
                filtered["distances"].append(distance)
                filtered["ids"].append(results["ids"][i])

        return filtered

    def retrieve_similar_functions(
        self,
        function_code: str,
        n_results: int = None
    ) -> List[Dict[str, Any]]:
        """Retrieve similar functions based on code"""
        return self.knowledge_base.search_similar_functions(
            query=function_code,
            n_results=n_results or self.top_k
        )

    def retrieve_vulnerability_patterns(
        self,
        code_snippet: str,
        n_results: int = None
    ) -> List[Dict[str, Any]]:
        """Retrieve vulnerability patterns matching code"""
        return self.knowledge_base.search_vulnerabilities(
            query=code_snippet,
            n_results=n_results or self.top_k
        )

    def retrieve_malware_behaviors(
        self,
        behavior_description: str,
        n_results: int = None
    ) -> List[Dict[str, Any]]:
        """Retrieve malware behaviors matching description"""
        return self.knowledge_base.search_malware_behaviors(
            query=behavior_description,
            n_results=n_results or self.top_k
        )

    def format_context_for_llm(
        self,
        query: str,
        context: Dict[str, Any],
        max_tokens: int = 2000
    ) -> str:
        """Format retrieved context for LLM consumption"""
        context_parts = []
        current_tokens = 0

        context_parts.append(f"Query: {query}\n")

        for collection_name, results in context.get("results", {}).items():
            context_parts.append(f"\n=== {collection_name.upper()} ===\n")

            for i, doc in enumerate(results.get("documents", [])[:3]):
                doc_str = f"{i + 1}. {doc}\n"
                estimated_tokens = len(doc_str.split())

                if current_tokens + estimated_tokens > max_tokens:
                    break

                context_parts.append(doc_str)
                current_tokens += estimated_tokens

        return "\n".join(context_parts)

    def hybrid_search(
        self,
        query: str,
        keywords: List[str],
        n_results: int = None
    ) -> Dict[str, Any]:
        """Perform hybrid search combining semantic and keyword search"""
        semantic_results = self.retrieve_context(
            query=query,
            n_results=n_results or self.top_k
        )

        keyword_results = self._keyword_search(
            keywords=keywords,
            n_results=n_results or self.top_k
        )

        combined = self._combine_results(
            semantic_results=semantic_results,
            keyword_results=keyword_results
        )

        return combined

    def _keyword_search(
        self,
        keywords: List[str],
        n_results: int
    ) -> Dict[str, Any]:
        """Perform keyword-based search"""
        if not self.vector_store.is_available():
            return {"error": "Vector store not available"}

        try:
            all_results = {}
            collections = ["functions", "vulnerabilities", "malware_behaviors"]

            for collection_name in collections:
                collection = self.vector_store.get_collection(collection_name)
                if not collection:
                    continue

                results = collection.get(include=["documents", "metadatas"])

                keyword_matches = []
                for i, doc in enumerate(results.get("documents", [])):
                    doc_lower = doc.lower()
                    match_count = sum(1 for kw in keywords if kw.lower() in doc_lower)

                    if match_count > 0:
                        keyword_matches.append({
                            "document": doc,
                            "metadata": results["metadatas"][i],
                            "match_count": match_count
                        })

                keyword_matches.sort(key=lambda x: x["match_count"], reverse=True)
                keyword_matches = keyword_matches[:n_results]

                if keyword_matches:
                    all_results[collection_name] = {
                        "documents": [m["document"] for m in keyword_matches],
                        "metadatas": [m["metadata"] for m in keyword_matches],
                        "match_counts": [m["match_count"] for m in keyword_matches]
                    }

            return {"results": all_results}

        except Exception as e:
            log.error(f"Failed to perform keyword search: {e}", exc_info=True)
            return {"error": str(e)}

    def _combine_results(
        self,
        semantic_results: Dict[str, Any],
        keyword_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Combine semantic and keyword search results"""
        combined = {"semantic": semantic_results, "keyword": keyword_results}

        if "error" in semantic_results or "error" in keyword_results:
            return combined

        merged = {}
        all_collections = set(semantic_results.get("results", {}).keys()) | set(keyword_results.get("results", {}).keys())

        for collection in all_collections:
            semantic_docs = set()
            keyword_docs = set()

            if collection in semantic_results.get("results", {}):
                semantic_docs = set(semantic_results["results"][collection].get("ids", []))

            if collection in keyword_results.get("results", {}):
                keyword_docs = set(keyword_results["results"][collection].get("ids", []))

            merged[collection] = {
                "semantic_only": len(semantic_docs - keyword_docs),
                "keyword_only": len(keyword_docs - semantic_docs),
                "both": len(semantic_docs & keyword_docs)
            }

        combined["merged"] = merged
        return combined

    def is_available(self) -> bool:
        """Check if retriever is available"""
        return self.vector_store.is_available()


_retriever_instance: Optional[Retriever] = None


def get_retriever() -> Retriever:
    """Get or create retriever instance"""
    global _retriever_instance
    if _retriever_instance is None:
        _retriever_instance = Retriever()
    return _retriever_instance

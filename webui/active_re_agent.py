import os
import json
import logging
import structlog
from typing import Optional, Dict, Any, List
from datetime import datetime

from core.config import settings
from core.active_re_service import get_active_re_service
from core.frida_instrumentation import get_frida
from core.angr_bridge import get_angr
from core.pwndbg_bridge import get_pwndbg
from core.monitoring import ProcessMonitor, MemoryMonitor, NetworkMonitor, FilesystemMonitor
from core.retriever import get_retriever
from core.llm_client import LLMClient

log = structlog.get_logger()


class ActiveREAgent:
    """AI Agent for Active Reverse Engineering and dynamic analysis"""

    def __init__(self):
        self.active_re_service = get_active_re_service()
        self.frida = get_frida()
        self.angr = get_angr()
        self.pwndbg = get_pwndbg()
        self.retriever = get_retriever()
        self.process_monitor = ProcessMonitor()
        self.memory_monitor = MemoryMonitor()
        self.network_monitor = NetworkMonitor()
        self.filesystem_monitor = FilesystemMonitor()
        self.llm_client = self._init_llm_client()
        self.chat_history: List[Dict[str, Any]] = []
        self.current_job_id = None

    def _init_llm_client(self) -> Optional[LLMClient]:
        """Initialize LLM client for analysis"""
        try:
            return LLMClient(
                model=settings.ANGR_LLM_MODEL,
                api_base=settings.ANGR_LLM_API_BASE,
                api_key=settings.ANGR_LLM_API_KEY
            )
        except Exception as e:
            log.error(f"Failed to initialize LLM client: {e}", exc_info=True)
            return None

    def plan_execution_strategy(self, binary_path: str, analysis_goal: str) -> Dict[str, Any]:
        """Plan an execution strategy for dynamic analysis"""
        plan = {
            "binary_path": binary_path,
            "goal": analysis_goal,
            "steps": [],
            "tools_to_use": [],
            "estimated_risk": "low"
        }

        try:
            if "vulnerability" in analysis_goal.lower():
                plan["steps"].append("Execute binary with Frida instrumentation")
                plan["steps"].append("Monitor API calls and memory access")
                plan["steps"].append("Use angr for symbolic execution")
                plan["tools_to_use"] = ["frida", "angr", "monitoring"]
                plan["estimated_risk"] = "medium"

            elif "behavior" in analysis_goal.lower():
                plan["steps"].append("Execute in sandboxed environment")
                plan["steps"].append("Monitor file, network, and process activity")
                plan["tools_to_use"] = ["sandbox", "monitoring"]
                plan["estimated_risk"] = "medium"

            else:
                plan["steps"].append("Static analysis with Ghidra")
                plan["steps"].append("Dynamic execution with monitoring")
                plan["tools_to_use"] = ["ghidra", "sandbox", "monitoring"]
                plan["estimated_risk"] = "low"

            if settings.HUMAN_APPROVAL_REQUIRED and plan["estimated_risk"] != "low":
                plan["requires_approval"] = True

            return plan

        except Exception as e:
            log.error(f"Failed to plan execution strategy: {e}", exc_info=True)
            return {"error": str(e)}

    def execute_with_frida(self, binary_path: str, script_content: str = None) -> Dict[str, Any]:
        """Execute binary with Frida instrumentation"""
        if not self.frida.is_available():
            return {"error": "Frida not available"}

        try:
            job_id = datetime.utcnow().timestamp()
            self.active_re_service.start_analysis(str(job_id), binary_path)

            if script_content:
                self.frida.load_script(script_content)
            else:
                from core.frida_instrumentation import FridaScriptTemplates
                self.frida.load_script(FridaScriptTemplates.api_call_tracing())

            result = self.active_re_service.execute_binary(str(job_id))
            messages = self.frida.get_messages()

            self.active_re_service.stop_analysis(str(job_id))

            return {
                "job_id": job_id,
                "execution_result": result,
                "frida_messages": messages
            }

        except Exception as e:
            log.error(f"Failed to execute with Frida: {e}", exc_info=True)
            return {"error": str(e)}

    def analyze_with_angr(self, binary_path: str, analysis_type: str = "symbolic") -> Dict[str, Any]:
        """Analyze binary with angr"""
        if not self.angr.is_available():
            return {"error": "angr not available"}

        try:
            if not self.angr.load_binary(binary_path):
                return {"error": "Failed to load binary"}

            if analysis_type == "symbolic":
                self.angr.create_initial_state()
                self.angr.create_simulation_manager()
                results = self.angr.run_symbolic_execution()
            elif analysis_type == "cfg":
                results = self.angr.get_control_flow_graph()
            elif analysis_type == "functions":
                cfg = self.angr.project.analyses.CFGFast()
                results = {"functions": list(cfg.functions.keys())}
            else:
                results = {"error": "Unknown analysis type"}

            return results

        except Exception as e:
            log.error(f"Failed to analyze with angr: {e}", exc_info=True)
            return {"error": str(e)}

    def monitor_execution(self, job_id: str, duration: int = 30) -> Dict[str, Any]:
        """Monitor binary execution with all monitors"""
        monitoring_results = {
            "job_id": job_id,
            "duration": duration,
            "process": None,
            "memory": None,
            "network": None,
            "filesystem": None
        }

        try:
            job_info = self.active_re_service.get_job_status(job_id)
            if "error" in job_info:
                return {"error": job_info["error"]}

            sandbox_name = job_info.get("sandbox_name")
            if sandbox_name:
                monitoring_results["process"] = self.process_monitor.start_monitoring()
                monitoring_results["network"] = self.network_monitor.get_all_connections()

            return monitoring_results

        except Exception as e:
            log.error(f"Failed to monitor execution: {e}", exc_info=True)
            return {"error": str(e)}

    def correlate_findings(
        self,
        static_analysis: Dict[str, Any],
        dynamic_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Correlate static and dynamic analysis findings"""
        correlation = {
            "matched_functions": [],
            "suspicious_patterns": [],
            "confirmed_vulnerabilities": [],
            "risk_score": 0.0
        }

        try:
            static_functions = static_analysis.get("functions", [])
            dynamic_calls = dynamic_analysis.get("frida_messages", [])

            for func in static_functions:
                func_name = func.get("name", "")
                for call in dynamic_calls:
                    if func_name in str(call.get("message", {})):
                        correlation["matched_functions"].append({
                            "function": func_name,
                            "call": call
                        })

            suspicious_count = len(correlation["matched_functions"])
            correlation["risk_score"] = min(suspicious_count * 0.1, 1.0)

            return correlation

        except Exception as e:
            log.error(f"Failed to correlate findings: {e}", exc_info=True)
            return {"error": str(e)}

    def chat_completion_stream(self, message: str) -> str:
        """Process chat message with context from RAG"""
        self.chat_history.append({"role": "user", "content": message})

        try:
            if self.retriever.is_available():
                context = self.retriever.retrieve_context(
                    query=message,
                    n_results=settings.RAG_TOP_K
                )

                formatted_context = self.retriever.format_context_for_llm(
                    query=message,
                    context=context
                )

                enhanced_message = f"""Context:
{formatted_context}

User Question:
{message}

Please provide analysis based on the context above."""

            else:
                enhanced_message = message

            if self.llm_client:
                response = self.llm_client.completion(
                    messages=[{"role": "user", "content": enhanced_message}]
                )
            else:
                response = "LLM client not available"

            self.chat_history.append({"role": "assistant", "content": response})

            return response

        except Exception as e:
            log.error(f"Failed to process chat completion: {e}", exc_info=True)
            return f"Error: {str(e)}"

    def get_chat_history(self) -> List[Dict[str, Any]]:
        """Get chat history"""
        return self.chat_history.copy()

    def clear_chat_history(self):
        """Clear chat history"""
        self.chat_history.clear()

    def set_current_job(self, job_id: str):
        """Set the current job being analyzed"""
        self.current_job_id = job_id

    def get_current_job(self) -> Optional[str]:
        """Get the current job ID"""
        return self.current_job_id


_active_re_agent_instance: Optional[ActiveREAgent] = None


def get_active_re_agent() -> ActiveREAgent:
    """Get or create Active RE agent instance"""
    global _active_re_agent_instance
    if _active_re_agent_instance is None:
        _active_re_agent_instance = ActiveREAgent()
    return _active_re_agent_instance

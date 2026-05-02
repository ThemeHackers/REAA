import os
import json
import logging
import structlog
import uuid
import concurrent.futures
from typing import Optional, Dict, Any, List, Callable
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
        self.job_state: Dict[str, Dict[str, Any]] = {}
        self.enable_parallel = True
        self.max_parallel_tasks = 4

    def _init_llm_client(self) -> Optional[LLMClient]:
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
        if not self.frida.is_available():
            return {"error": "Frida not available"}

        try:
            from pathlib import Path
            job_id = Path(binary_path).parent.name

            # Start sandbox
            service_result = self.active_re_service.start_analysis(job_id, binary_path)
            if "error" in service_result:
                return {"error": f"Failed to start analysis: {service_result['error']}"}

            # Convert binary path to container path for sandbox execution
            if binary_path.startswith("data/"):
                container_binary_path = binary_path.replace("data/", "/app/data/")
            elif "\\" in binary_path or "/" in binary_path:
                path_obj = Path(binary_path)
                parts = path_obj.parts
                if "data" in parts:
                    data_index = parts.index("data")
                    if data_index + 2 < len(parts):
                        job_id_from_path = parts[data_index + 1]
                        filename = parts[-1]
                        container_binary_path = f"/app/data/{job_id_from_path}/{filename}"
                    else:
                        container_binary_path = binary_path
                else:
                    container_binary_path = binary_path
            else:
                container_binary_path = binary_path

            # NOTE: Frida runs on Windows host, not in Docker container
            # On Windows, .exe files run natively without Wine
            # Wine is only needed inside Docker container for sandbox execution
            windows_binary_path = binary_path

            # On Windows, never use Wine for Frida (Windows runs .exe natively)
            import platform
            use_wine = platform.system() != "Windows" and windows_binary_path.lower().endswith('.exe')

            # Spawn process with Frida using Windows path
            if not self.frida.spawn_process(windows_binary_path, use_wine=use_wine):
                log.warning("Failed to spawn with Frida, continuing with sandbox-only execution")
                # Continue without Frida instrumentation
                frida_available = False
            else:
                frida_available = True
                # Hook entry point to prevent premature process exit
                self.frida.hook_entry_point()

                # Load Frida script after spawning and hooking
                if script_content:
                    script_result = self.frida.load_script(script_content)
                else:
                    from core.frida_instrumentation import FridaScriptTemplates
                    script_result = self.frida.load_script(FridaScriptTemplates.api_call_tracing())

                if not script_result:
                    log.warning("Failed to load Frida script, continuing without instrumentation")

                # Resume process to start execution
                self.frida.resume_process()

            # Execute binary through sandbox (uses container path)
            result = self.active_re_service.execute_binary(str(job_id))

            # Get Frida messages if available
            messages = self.frida.get_messages() if frida_available else []

            self.active_re_service.stop_analysis(str(job_id))

            return {
                "job_id": job_id,
                "execution_result": result,
                "frida_messages": messages,
                "binary_executed": container_binary_path,
                "frida_spawn_path": windows_binary_path,
                "frida_available": frida_available
            }

        except Exception as e:
            log.error(f"Failed to execute with Frida: {e}", exc_info=True)
            return {"error": str(e)}

    def analyze_with_angr(self, binary_path: str, analysis_type: str = "symbolic") -> Dict[str, Any]:
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
        return self.chat_history.copy()

    def clear_chat_history(self):
        self.chat_history.clear()

    def set_current_job(self, job_id: str):
        self.current_job_id = job_id

    def get_current_job(self) -> Optional[str]:
        return self.current_job_id

    def execute_parallel_tasks(self, tasks: List[Callable]) -> Dict[str, Any]:
        if not self.enable_parallel:
            results = {}
            for i, task in enumerate(tasks):
                try:
                    results[f"task_{i}"] = task()
                except Exception as e:
                    results[f"task_{i}"] = {"error": str(e)}
            return results

        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_parallel_tasks) as executor:
            future_to_task = {executor.submit(task): (i, task) for i, task in enumerate(tasks)}
            
            for future in concurrent.futures.as_completed(future_to_task):
                i, task = future_to_task[future]
                try:
                    results[f"task_{i}"] = future.result()
                except Exception as e:
                    log.error(f"Parallel task {i} failed: {e}", exc_info=True)
                    results[f"task_{i}"] = {"error": str(e)}

        return results

    def aggregate_monitoring_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        aggregated = {
            "process": {"alerts": [], "events": []},
            "memory": {"anomalies": [], "patterns": {}},
            "network": {"threats": [], "connections": []},
            "filesystem": {"events": [], "quarantined": []},
            "summary": {
                "total_alerts": 0,
                "total_anomalies": 0,
                "total_threats": 0,
                "high_risk_count": 0
            }
        }

        for result in results:
        
            if "process" in result:
                if "alerts" in result["process"]:
                    aggregated["process"]["alerts"].extend(result["process"]["alerts"])
                if "events" in result["process"]:
                    aggregated["process"]["events"].extend(result["process"]["events"])

         
            if "memory" in result:
                if "anomalies" in result["memory"]:
                    aggregated["memory"]["anomalies"].extend(result["memory"]["anomalies"])
                if "patterns" in result["memory"]:
                    aggregated["memory"]["patterns"].update(result["memory"]["patterns"])

           
            if "network" in result:
                if "threats" in result["network"]:
                    aggregated["network"]["threats"].extend(result["network"]["threats"])
                if "connections" in result["network"]:
                    aggregated["network"]["connections"].extend(result["network"]["connections"])

           
            if "filesystem" in result:
                if "events" in result["filesystem"]:
                    aggregated["filesystem"]["events"].extend(result["filesystem"]["events"])
                if "quarantined" in result["filesystem"]:
                    aggregated["filesystem"]["quarantined"].extend(result["filesystem"]["quarantined"])

       
        aggregated["summary"]["total_alerts"] = len(aggregated["process"]["alerts"])
        aggregated["summary"]["total_anomalies"] = len(aggregated["memory"]["anomalies"])
        aggregated["summary"]["total_threats"] = len(aggregated["network"]["threats"])
        
       
        for alert in aggregated["process"]["alerts"]:
            if alert.get("type") in ["cpu_high", "memory_high"]:
                aggregated["summary"]["high_risk_count"] += 1
        for threat in aggregated["network"]["threats"]:
            if threat.get("type") in ["c2_domain", "suspicious_port"]:
                aggregated["summary"]["high_risk_count"] += 1

        return aggregated

    def run_comprehensive_analysis(self, binary_path: str, analysis_goal: str) -> Dict[str, Any]:
        plan = self.plan_execution_strategy(binary_path, analysis_goal)
        
        if "error" in plan:
            return plan

        tasks = []

        if "frida" in plan.get("tools_to_use", []):
            def execute_frida_task(bp=binary_path):
                return self.execute_with_frida(bp)
            tasks.append(execute_frida_task)
        
        if "angr" in plan.get("tools_to_use", []):
            def analyze_angr_task(bp=binary_path):
                return self.analyze_with_angr(bp)
            tasks.append(analyze_angr_task)
        
        if "monitoring" in plan.get("tools_to_use", []):
            def run_monitoring_task():
                job_id = uuid.uuid4().hex
                return self.monitor_execution(job_id)
            tasks.append(run_monitoring_task)

        parallel_results = self.execute_parallel_tasks(tasks)

        monitoring_results = []
        for task_name, result in parallel_results.items():
            if "monitor" in task_name and "error" not in result:
                monitoring_results.append(result)

        aggregated = self.aggregate_monitoring_results(monitoring_results)

        return {
            "plan": plan,
            "parallel_results": parallel_results,
            "aggregated_monitoring": aggregated,
            "overall_risk": aggregated["summary"]["high_risk_count"] > 0
        }


_active_re_agent_instance: Optional[ActiveREAgent] = None


def get_active_re_agent() -> ActiveREAgent:
    global _active_re_agent_instance
    if _active_re_agent_instance is None:
        _active_re_agent_instance = ActiveREAgent()
    return _active_re_agent_instance

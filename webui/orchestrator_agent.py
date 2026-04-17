import os
import json
import logging
import structlog
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum

from core.config import settings
from webui.ghidra_assistant import GhidraAssistant
from webui.security_agent import SecurityAgent
from webui.active_re_agent import get_active_re_agent

log = structlog.get_logger()


class AnalysisMode(Enum):
    """Analysis mode for orchestrator"""
    STATIC = "static"
    DYNAMIC = "dynamic"
    HYBRID = "hybrid"


class OrchestratorAgent:
    """Orchestrator agent to coordinate analysis workflow and decide strategy"""

    def __init__(self):
        self.ghidra_assistant = None
        self.security_agent = None
        self.active_re_agent = get_active_re_agent()
        self.pending_approvals: List[Dict[str, Any]] = []
        self.active_tasks: Dict[str, Dict[str, Any]] = {}
        self.task_history: List[Dict[str, Any]] = []
        self.strategy_performance: Dict[str, Dict[str, Any]] = {
            "static": {"success_count": 0, "total_count": 0, "avg_time": 0},
            "dynamic": {"success_count": 0, "total_count": 0, "avg_time": 0},
            "hybrid": {"success_count": 0, "total_count": 0, "avg_time": 0}
        }
        self.user_preferences: Dict[str, Any] = {
            "preferred_mode": None,
            "risk_tolerance": "medium",
            "analysis_depth": "standard"
        }

    def initialize_agents(self, ghidra_api_base: str):
        """Initialize the static analysis agents"""
        try:
            self.ghidra_assistant = GhidraAssistant(ghidra_api_base)
            self.security_agent = SecurityAgent(ghidra_api_base)
            log.info("Initialized orchestrator agents")
        except Exception as e:
            log.error(f"Failed to initialize agents: {e}", exc_info=True)

    def decide_analysis_strategy(
        self,
        binary_path: str,
        user_request: str,
        binary_type: str = None
    ) -> Dict[str, Any]:
        """Decide which analysis strategy to use"""
        strategy = {
            "mode": AnalysisMode.STATIC,
            "reasoning": "",
            "agents_to_use": [],
            "requires_approval": False,
            "estimated_time": 0
        }

        try:
            request_lower = user_request.lower()

            if any(keyword in request_lower for keyword in ["run", "execute", "dynamic", "runtime"]):
                strategy["mode"] = AnalysisMode.DYNAMIC
                strategy["agents_to_use"] = ["active_re"]
                strategy["reasoning"] = "User requested dynamic/execution analysis"
                strategy["requires_approval"] = True
                strategy["estimated_time"] = 300

            elif any(keyword in request_lower for keyword in ["both", "hybrid", "complete", "thorough"]):
                strategy["mode"] = AnalysisMode.HYBRID
                strategy["agents_to_use"] = ["ghidra", "security", "active_re"]
                strategy["reasoning"] = "User requested comprehensive analysis"
                strategy["requires_approval"] = True
                strategy["estimated_time"] = 600

            else:
                strategy["mode"] = AnalysisMode.STATIC
                strategy["agents_to_use"] = ["ghidra", "security"]
                strategy["reasoning"] = "Default to static analysis for safety"
                strategy["requires_approval"] = False
                strategy["estimated_time"] = 180

            if binary_type and binary_type.lower() in ["exe", "dll", "malware"]:
                strategy["requires_approval"] = True
                strategy["reasoning"] += " (binary type requires approval)"

            return strategy

        except Exception as e:
            log.error(f"Failed to decide analysis strategy: {e}", exc_info=True)
            return {"error": str(e)}

    def execute_analysis(
        self,
        job_id: str,
        binary_path: str,
        strategy: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute analysis according to strategy"""
        task = {
            "job_id": job_id,
            "binary_path": binary_path,
            "strategy": strategy,
            "status": "in_progress",
            "started_at": datetime.utcnow().isoformat(),
            "results": {},
            "errors": []
        }

        self.active_tasks[job_id] = task

        try:
            mode = strategy.get("mode")
            agents = strategy.get("agents_to_use", [])

            if "ghidra" in agents and self.ghidra_assistant:
                task["results"]["static"] = self._run_static_analysis(job_id, binary_path)

            if "security" in agents and self.security_agent:
                task["results"]["security"] = self._run_security_analysis(job_id)

            if "active_re" in agents:
                if strategy.get("requires_approval") and settings.HUMAN_APPROVAL_REQUIRED:
                    approval = self._request_approval(job_id, "dynamic_execution")
                    if not approval:
                        task["status"] = "awaiting_approval"
                        return task

                task["results"]["dynamic"] = self._run_dynamic_analysis(job_id, binary_path)

            task["status"] = "completed"
            task["completed_at"] = datetime.utcnow().isoformat()

            self.task_history.append(task)
            del self.active_tasks[job_id]

           
            self.learn_from_task(task)

            return task

        except Exception as e:
            log.error(f"Failed to execute analysis for job {job_id}: {e}", exc_info=True)
            task["status"] = "failed"
            task["errors"].append(str(e))
            return task

    def _run_static_analysis(self, job_id: str, binary_path: str) -> Dict[str, Any]:
        """Run static analysis with Ghidra"""
        try:
            if not self.ghidra_assistant:
                return {"error": "Ghidra assistant not initialized"}

            response = self.ghidra_assistant.chat_completion_stream(
                f"Analyze the binary at {binary_path}. List all functions and identify any suspicious patterns."
            )

            return {"analysis": response}

        except Exception as e:
            log.error(f"Failed to run static analysis: {e}", exc_info=True)
            return {"error": str(e)}

    def _run_security_analysis(self, job_id: str) -> Dict[str, Any]:
        """Run security analysis"""
        try:
            if not self.security_agent:
                return {"error": "Security agent not initialized"}

            report = self.security_agent.generate_security_report(job_id)

            return {"report": report}

        except Exception as e:
            log.error(f"Failed to run security analysis: {e}", exc_info=True)
            return {"error": str(e)}

    def _run_dynamic_analysis(self, job_id: str, binary_path: str) -> Dict[str, Any]:
        """Run dynamic analysis with Active RE agent"""
        try:
            self.active_re_agent.set_current_job(job_id)

            plan = self.active_re_agent.plan_execution_strategy(
                binary_path=binary_path,
                analysis_goal="dynamic analysis"
            )

            execution_result = self.active_re_agent.execute_with_frida(binary_path)

            monitoring_result = self.active_re_agent.monitor_execution(job_id)

            return {
                "plan": plan,
                "execution": execution_result,
                "monitoring": monitoring_result
            }

        except Exception as e:
            log.error(f"Failed to run dynamic analysis: {e}", exc_info=True)
            return {"error": str(e)}

    def _request_approval(self, job_id: str, operation: str) -> bool:
        """Request human approval for operation"""
        approval_request = {
            "job_id": job_id,
            "operation": operation,
            "requested_at": datetime.utcnow().isoformat(),
            "status": "pending"
        }

        self.pending_approvals.append(approval_request)

        log.warning(f"Approval required for job {job_id}: {operation}")
        return False

    def approve_operation(self, job_id: str, approved: bool) -> bool:
        """Approve or reject pending operation"""
        for i, approval in enumerate(self.pending_approvals):
            if approval["job_id"] == job_id and approval["status"] == "pending":
                self.pending_approvals[i]["status"] = "approved" if approved else "rejected"
                self.pending_approvals[i]["decided_at"] = datetime.utcnow().isoformat()

                if approved:
                    self._resume_analysis(job_id)
                    return True

        return False

    def _resume_analysis(self, job_id: str):
        """Resume analysis after approval"""
        task = self.active_tasks.get(job_id)
        if task and task["status"] == "awaiting_approval":
            task["status"] = "in_progress"

            if "active_re" in task["strategy"].get("agents_to_use", []):
                binary_path = task["binary_path"]
                task["results"]["dynamic"] = self._run_dynamic_analysis(job_id, binary_path)

            task["status"] = "completed"
            task["completed_at"] = datetime.utcnow().isoformat()

            self.task_history.append(task)
            del self.active_tasks[job_id]

    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Get all pending approval requests"""
        return [a for a in self.pending_approvals if a["status"] == "pending"]

    def get_task_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific task"""
        if job_id in self.active_tasks:
            return self.active_tasks[job_id]

        for task in self.task_history:
            if task["job_id"] == job_id:
                return task

        return None

    def get_all_tasks(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get all active and historical tasks"""
        return {
            "active": list(self.active_tasks.values()),
            "history": self.task_history
        }

    def prioritize_tasks(self) -> List[Dict[str, Any]]:
        """Prioritize tasks based on urgency and importance"""
        all_tasks = list(self.active_tasks.values())

        prioritized = sorted(
            all_tasks,
            key=lambda t: (
                0 if t.get("status") == "awaiting_approval" else 1,
                t.get("strategy", {}).get("estimated_time", 0)
            )
        )

        return prioritized

    def get_task_queue(self) -> List[Dict[str, Any]]:
        """Get ordered task queue"""
        return self.prioritize_tasks()

    def cancel_task(self, job_id: str) -> bool:
        """Cancel a task"""
        if job_id in self.active_tasks:
            task = self.active_tasks[job_id]
            task["status"] = "cancelled"
            task["cancelled_at"] = datetime.utcnow().isoformat()

            self.task_history.append(task)
            del self.active_tasks[job_id]

            return True

        return False

    def learn_from_task(self, task: Dict[str, Any]) -> None:
        """Learn from completed task to improve future strategy decisions"""
        strategy_mode = task.get("strategy", {}).get("mode", "static")
        status = task.get("status", "failed")
        
        perf = self.strategy_performance[strategy_mode]
        perf["total_count"] += 1
        
        if status == "completed":
            perf["success_count"] += 1
        
   
        if "completed_at" in task and "started_at" in task:
            start = datetime.fromisoformat(task["started_at"])
            end = datetime.fromisoformat(task["completed_at"])
            duration = (end - start).total_seconds()
            
          
            perf["avg_time"] = (perf["avg_time"] * (perf["total_count"] - 1) + duration) / perf["total_count"]
        
        log.info(f"Updated performance metrics for {strategy_mode} strategy")

    def get_adaptive_strategy(self, binary_path: str, user_request: str, binary_type: str = None) -> Dict[str, Any]:
        """Get adaptive strategy based on learned performance and user preferences"""
        base_strategy = self.decide_analysis_strategy(binary_path, user_request, binary_type)
        
        if "error" in base_strategy:
            return base_strategy

      
        if self.user_preferences["preferred_mode"]:
            base_strategy["mode"] = AnalysisMode(self.user_preferences["preferred_mode"])
            base_strategy["reasoning"] += f" (user prefers {self.user_preferences['preferred_mode']} mode)"

       
        if self.user_preferences["risk_tolerance"] == "low":
           
            if base_strategy["mode"] in [AnalysisMode.DYNAMIC, AnalysisMode.HYBRID]:
                base_strategy["mode"] = AnalysisMode.STATIC
                base_strategy["reasoning"] += " (low risk tolerance preference)"
        elif self.user_preferences["risk_tolerance"] == "high":
          
            if base_strategy["mode"] == AnalysisMode.STATIC:
                base_strategy["mode"] = AnalysisMode.HYBRID
                base_strategy["reasoning"] += " (high risk tolerance preference)"

       
        for mode in ["static", "dynamic", "hybrid"]:
            perf = self.strategy_performance[mode]
            if perf["total_count"] > 5 and perf["success_count"] / perf["total_count"] < 0.5:
               
                if base_strategy["mode"].value == mode:
                    if mode == "dynamic":
                        base_strategy["mode"] = AnalysisMode.STATIC
                        base_strategy["reasoning"] += " (dynamic has low success rate)"
                    elif mode == "static":
                        base_strategy["mode"] = AnalysisMode.HYBRID
                        base_strategy["reasoning"] += " (static has low success rate)"

        return base_strategy

    def set_user_preference(self, preference: str, value: Any) -> bool:
        """Set user preference for strategy selection"""
        if preference in self.user_preferences:
            self.user_preferences[preference] = value
            log.info(f"Set user preference {preference} to {value}")
            return True
        else:
            log.warning(f"Unknown preference: {preference}")
            return False

    def get_performance_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get performance metrics for all strategies"""
        return self.strategy_performance.copy()

    def get_learning_summary(self) -> Dict[str, Any]:
        """Get summary of learned patterns and performance"""
        summary = {
            "total_tasks": len(self.task_history),
            "strategy_performance": self.strategy_performance,
            "user_preferences": self.user_preferences,
            "recommendations": []
        }

       
        for mode, perf in self.strategy_performance.items():
            if perf["total_count"] > 5:
                success_rate = perf["success_count"] / perf["total_count"]
                if success_rate < 0.5:
                    summary["recommendations"].append({
                        "type": "low_success_rate",
                        "strategy": mode,
                        "success_rate": success_rate,
                        "suggestion": f"Consider using alternative strategies instead of {mode}"
                    })
                elif success_rate > 0.8:
                    summary["recommendations"].append({
                        "type": "high_success_rate",
                        "strategy": mode,
                        "success_rate": success_rate,
                        "suggestion": f"{mode} strategy is performing well, consider using it more often"
                    })

        return summary


_orchestrator_agent_instance: Optional[OrchestratorAgent] = None


def get_orchestrator_agent() -> OrchestratorAgent:
    """Get or create orchestrator agent instance"""
    global _orchestrator_agent_instance
    if _orchestrator_agent_instance is None:
        _orchestrator_agent_instance = OrchestratorAgent()
    return _orchestrator_agent_instance

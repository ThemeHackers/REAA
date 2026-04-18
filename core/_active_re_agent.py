import os
import json
import asyncio
import hashlib
from typing import Optional, Dict, Any, List, AsyncGenerator
from datetime import datetime
from pathlib import Path
import structlog

from core.config import settings
from core.active_re_orchestrator import (
    get_modern_orchestrator,
    ModernActiveREOrchestrator,
    AnalysisContext,
    ExecutionStrategy,
    RiskLevel
)
from core.behavioral_analysis_engine import (
    get_behavioral_engine,
    BehavioralAnalysisEngine,
    BehaviorProfile
)
from core.intelligent_sandbox import (
    get_intelligent_sandbox,
    IntelligentSandbox,
    SandboxPolicy
)
from core.active_re_service import get_active_re_service
from core.frida_instrumentation import get_frida, FridaScriptTemplates
from core.angr_bridge import get_angr
from core.pwndbg_bridge import get_pwndbg
from core.llm_client import LLMClient
from core.retriever import get_retriever

log = structlog.get_logger()


class ActiveREAgent:
    """Active RE Agent with intelligent orchestration"""

    def __init__(self):
        self.orchestrator = get_modern_orchestrator()
        self.behavioral_engine = get_behavioral_engine()
        self.intelligent_sandbox = get_intelligent_sandbox()
        self.legacy_service = get_active_re_service()
        self.frida = get_frida()
        self.angr = get_angr()
        self.pwndbg = get_pwndbg()
        self.retriever = get_retriever()

        self.llm_client = self._init_llm()
        self.active_sessions: Dict[str, Dict[str, Any]] = {}

    def _init_llm(self) -> Optional[LLMClient]:
        try:
            return LLMClient(
                model=settings.ANGR_LLM_MODEL,
                api_base=settings.ANGR_LLM_API_BASE,
                api_key=settings.ANGR_LLM_API_KEY
            )
        except Exception as e:
            log.error(f"Failed to initialize LLM: {e}")
            return None

    async def intelligent_analysis(
        self,
        binary_path: str,
        analysis_goal: str = "comprehensive security analysis",
        options: Optional[Dict[str, Any]] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Stream intelligent analysis results"""

        options = options or {}
        job_id = hashlib.sha256(
            f"{binary_path}:{datetime.utcnow().isoformat()}".encode()
        ).hexdigest()[:16]

        log.info(f"Starting intelligent analysis: {job_id}", binary_path=binary_path)

        yield {
            "type": "status",
            "job_id": job_id,
            "message": "Initializing intelligent analysis...",
            "progress": 0
        }

        try:
            context = await self.orchestrator._initialize_context(binary_path, analysis_goal)

            yield {
                "type": "status",
                "job_id": job_id,
                "message": f"Binary analyzed: {context.file_type}, {context.file_size} bytes",
                "progress": 5,
                "metadata": {
                    "file_type": context.file_type,
                    "file_size": context.file_size,
                    "sha256": context.binary_hash[:16] + "..."
                }
            }

            strategy = await self.orchestrator.ai_planner.generate_strategy(
                context,
                self.orchestrator._get_available_tools()
            )

            yield {
                "type": "strategy",
                "job_id": job_id,
                "message": f"AI selected strategy: {strategy.name}",
                "progress": 10,
                "strategy": {
                    "name": strategy.name,
                    "description": strategy.description,
                    "tools": strategy.tools,
                    "risk_level": strategy.risk_level.value,
                    "requires_approval": strategy.requires_approval,
                    "estimated_duration": strategy.estimated_duration
                }
            }

            risk_assessment = await self.orchestrator._perform_pre_execution_risk_assessment(
                context, strategy
            )

            yield {
                "type": "risk_assessment",
                "job_id": job_id,
                "message": f"Risk assessment: {risk_assessment['risk_level']}",
                "progress": 15,
                "risk_assessment": risk_assessment
            }

            if strategy.requires_approval and not options.get("auto_approve", False):
                yield {
                    "type": "approval_required",
                    "job_id": job_id,
                    "message": "Analysis requires approval due to risk level",
                    "progress": 15,
                    "approval_token": self.orchestrator._generate_approval_token(context)
                }
                return

            async for event in self._execute_intelligent_analysis(
                job_id, context, strategy, options
            ):
                yield event

        except Exception as e:
            log.error(f"Intelligent analysis failed: {e}", exc_info=True)
            yield {
                "type": "error",
                "job_id": job_id,
                "message": f"Analysis failed: {str(e)}",
                "progress": 100,
                "error": str(e)
            }

    async def _execute_intelligent_analysis(
        self,
        job_id: str,
        context: AnalysisContext,
        strategy: ExecutionStrategy,
        options: Dict[str, Any]
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Execute the full analysis pipeline"""

        user_policy = options.get("sandbox_policy")

        provision_result = await self.intelligent_sandbox.provision_sandbox(
            job_id=job_id,
            binary_path=context.binary_path,
            binary_hash=context.binary_hash,
            risk_assessment=context.risk_assessment,
            user_policy=user_policy
        )

        if "error" in provision_result:
            yield {
                "type": "error",
                "job_id": job_id,
                "message": f"Sandbox provisioning failed: {provision_result['error']}",
                "progress": 100
            }
            return

        yield {
            "type": "sandbox_ready",
            "job_id": job_id,
            "message": f"Intelligent sandbox ready with policy: {provision_result['policy']}",
            "progress": 20,
            "sandbox": provision_result
        }

        current_progress = 20
        progress_increment = 60 / len(strategy.phases)

        static_results = {}
        dynamic_results = {}
        behavioral_results = {}

        for phase in strategy.phases:
            phase_name = phase.value

            yield {
                "type": "phase_start",
                "job_id": job_id,
                "message": f"Starting phase: {phase_name}",
                "progress": current_progress,
                "phase": phase_name
            }

            try:
                if phase.value == "reconnaissance":
                    static_results["reconnaissance"] = await self.orchestrator._phase_reconnaissance(context)

                elif phase.value == "static_analysis":
                    static_results["deep"] = await self.orchestrator._phase_static_analysis(context)
                    yield {
                        "type": "static_results",
                        "job_id": job_id,
                        "message": f"Static analysis complete: {len(static_results.get('deep', {}).get('functions', []))} functions found",
                        "progress": current_progress + (progress_increment * 0.5),
                        "functions_count": len(static_results.get("deep", {}).get("functions", []))
                    }

                elif phase.value == "dynamic_analysis":
                    async for event in self._execute_dynamic_analysis(
                        job_id, context, provision_result
                    ):
                        if event["type"] == "dynamic_complete":
                            dynamic_results = event["results"]
                        yield event

                elif phase.value == "behavioral_analysis":
                    behavioral_results = await self._execute_behavioral_analysis(
                        job_id, context, dynamic_results
                    )

                elif phase.value == "correlation":
                    correlation = await self.orchestrator.correlation_engine.correlate(
                        static_results,
                        dynamic_results,
                        behavioral_results
                    )

                    yield {
                        "type": "correlation",
                        "job_id": job_id,
                        "message": f"Correlation complete: {len(correlation.get('confirmed_findings', []))} confirmed findings",
                        "progress": current_progress + (progress_increment * 0.8),
                        "correlation": {
                            "confirmed_count": len(correlation.get("confirmed_findings", [])),
                            "suspicious_count": len(correlation.get("suspicious_patterns", [])),
                            "confidence": correlation.get("overall_confidence", 0)
                        }
                    }

                current_progress += progress_increment

                yield {
                    "type": "phase_complete",
                    "job_id": job_id,
                    "message": f"Phase complete: {phase_name}",
                    "progress": min(current_progress, 90),
                    "phase": phase_name
                }

            except Exception as e:
                log.error(f"Phase {phase_name} failed: {e}", job_id=job_id)
                yield {
                    "type": "phase_error",
                    "job_id": job_id,
                    "message": f"Phase {phase_name} failed: {str(e)}",
                    "progress": current_progress,
                    "phase": phase_name,
                    "error": str(e)
                }

        final_report = await self._generate_enhanced_report(
            job_id, context, strategy,
            static_results, dynamic_results, behavioral_results
        )

        await self.intelligent_sandbox.destroy_sandbox(job_id)

        yield {
            "type": "complete",
            "job_id": job_id,
            "message": "Intelligent analysis complete",
            "progress": 100,
            "report": final_report
        }

    async def _execute_dynamic_analysis(
        self,
        job_id: str,
        context: AnalysisContext,
        sandbox_info: Dict[str, Any]
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Execute dynamic analysis with behavioral monitoring"""

        if not self.frida.is_available():
            yield {
                "type": "dynamic_error",
                "job_id": job_id,
                "message": "Frida not available for dynamic analysis"
            }
            return

        yield {
            "type": "dynamic_start",
            "job_id": job_id,
            "message": "Starting dynamic analysis with Frida..."
        }

        try:
            await self.behavioral_engine.start_profiling(
                process_id=job_id,
                binary_hash=context.binary_hash
            )

            script = FridaScriptTemplates.api_call_tracing()
            self.frida.load_script(script)

            result = await self.intelligent_sandbox.execute_in_sandbox(
                job_id=job_id,
                command=[context.binary_path],
                timeout=sandbox_info.get("config", {}).get("max_runtime", 300)
            )

            messages = self.frida.get_messages()

            for msg in messages[:10]:
                await self.behavioral_engine.record_event(
                    process_id=job_id,
                    event_type="api_call",
                    event_data=msg
                )

            yield {
                "type": "dynamic_data",
                "job_id": job_id,
                "message": f"Collected {len(messages)} API calls",
                "api_calls_count": len(messages)
            }

            yield {
                "type": "dynamic_complete",
                "job_id": job_id,
                "message": "Dynamic analysis complete",
                "results": {
                    "execution_result": result,
                    "api_calls": messages,
                    "coverage": len(messages)
                }
            }

        except Exception as e:
            log.error(f"Dynamic analysis failed: {e}", job_id=job_id)
            yield {
                "type": "dynamic_error",
                "job_id": job_id,
                "message": f"Dynamic analysis failed: {str(e)}"
            }

    async def _execute_behavioral_analysis(
        self,
        job_id: str,
        context: AnalysisContext,
        dynamic_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute behavioral analysis and profiling"""

        try:
            behavioral_result = await self.behavioral_engine.finalize_profiling(job_id)

            log.info(
                f"Behavioral analysis complete",
                job_id=job_id,
                classification=behavioral_result.get("classification"),
                risk_score=behavioral_result.get("risk_score")
            )

            return behavioral_result

        except Exception as e:
            log.error(f"Behavioral analysis failed: {e}", job_id=job_id)
            return {"error": str(e)}

    async def _generate_enhanced_report(
        self,
        job_id: str,
        context: AnalysisContext,
        strategy: ExecutionStrategy,
        static_results: Dict[str, Any],
        dynamic_results: Dict[str, Any],
        behavioral_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate comprehensive analysis report"""

        correlation = await self.orchestrator.correlation_engine.correlate(
            static_results,
            dynamic_results,
            behavioral_results
        )

        risk_adjustments = correlation.get("risk_adjustments", {})
        base_risk = context.risk_assessment.get("overall_risk", 0.5)
        adjusted_risk = min(base_risk + risk_adjustments.get("risk_score_adjustment", 0), 1.0)

        behavioral_summary = behavioral_results.get("summary", {})
        behavioral_classification = behavioral_results.get("classification", "unknown")

        report = {
            "executive_summary": {
                "job_id": job_id,
                "binary": context.binary_path,
                "analysis_goal": context.analysis_goal,
                "strategy_used": strategy.name,
                "completion_time": datetime.utcnow().isoformat(),
                "overall_risk_score": adjusted_risk,
                "risk_level": self._risk_to_level(adjusted_risk),
                "behavioral_classification": behavioral_classification,
                "requires_attention": behavioral_summary.get("requires_attention", False)
            },
            "findings": {
                "confirmed": correlation.get("confirmed_findings", []),
                "suspicious": correlation.get("suspicious_patterns", []),
                "anomalies": behavioral_results.get("anomalies", []),
                "confidence": correlation.get("overall_confidence", 0)
            },
            "technical_analysis": {
                "static": {
                    "functions_analyzed": len(static_results.get("deep", {}).get("functions", [])),
                    "strings_extracted": len(static_results.get("deep", {}).get("strings", [])),
                    "coverage": static_results.get("deep", {}).get("coverage", 0)
                },
                "dynamic": {
                    "api_calls_monitored": len(dynamic_results.get("api_calls", [])),
                    "execution_time": dynamic_results.get("execution_result", {}).get("duration", 0),
                    "exit_code": dynamic_results.get("execution_result", {}).get("exit_code", -1)
                },
                "behavioral": behavioral_summary
            },
            "risk_assessment": {
                "initial_risk": context.risk_assessment,
                "final_risk_score": adjusted_risk,
                "risk_factors": correlation.get("risk_adjustments", {}),
                "mitigation_applied": context.risk_assessment.get("mitigation_strategies", [])
            },
            "recommendations": self._generate_enhanced_recommendations(
                adjusted_risk,
                correlation,
                behavioral_results
            ),
            "ai_insights": await self._generate_ai_insights(
                context, correlation, behavioral_results
            )
        }

        return report

    def _risk_to_level(self, risk: float) -> str:
        if risk >= 0.9:
            return "critical"
        elif risk >= 0.7:
            return "high"
        elif risk >= 0.4:
            return "medium"
        elif risk >= 0.2:
            return "low"
        else:
            return "minimal"

    def _generate_enhanced_recommendations(
        self,
        risk_score: float,
        correlation: Dict[str, Any],
        behavioral_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate actionable recommendations"""

        recommendations = []

        if risk_score > 0.8:
            recommendations.append({
                "priority": "critical",
                "category": "immediate_action",
                "recommendation": "Immediate manual review required - high risk binary detected",
                "actions": ["Isolate the binary", "Perform manual reverse engineering", "Check for known malware signatures"]
            })

        confirmed = correlation.get("confirmed_findings", [])
        if confirmed:
            recommendations.append({
                "priority": "high",
                "category": "investigation",
                "recommendation": f"Review {len(confirmed)} confirmed findings for exploitation potential",
                "details": [f["type"] for f in confirmed[:5]]
            })

        anomalies = behavioral_results.get("anomalies", [])
        critical_anomalies = [a for a in anomalies if a.get("severity") == "critical"]
        if critical_anomalies:
            recommendations.append({
                "priority": "critical",
                "category": "anomaly",
                "recommendation": f"{len(critical_anomalies)} critical behavioral anomalies detected",
                "details": [a.get("description") for a in critical_anomalies[:3]]
            })

        return recommendations

    async def _generate_ai_insights(
        self,
        context: AnalysisContext,
        correlation: Dict[str, Any],
        behavioral_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate AI-powered insights"""

        if not self.llm_client:
            return {"available": False, "reason": "LLM not available"}

        try:
            prompt = f"""Analyze the following binary analysis results and provide expert insights:

Binary: {context.binary_path}
Goal: {context.analysis_goal}

Findings Summary:
- Confirmed Findings: {len(correlation.get('confirmed_findings', []))}
- Suspicious Patterns: {len(correlation.get('suspicious_patterns', []))}
- Behavioral Classification: {behavioral_results.get('classification', 'unknown')}
- Risk Score: {behavioral_results.get('risk_score', 0)}

Provide:
1. Key observations about the binary's behavior
2. Potential security implications
3. Recommended next steps for deeper analysis

Keep the response concise and actionable."""

            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.llm_client.completion(
                    messages=[{"role": "user", "content": prompt}]
                )
            )

            return {
                "available": True,
                "insights": response,
                "generated_at": datetime.utcnow().isoformat()
            }

        except Exception as e:
            return {"available": False, "reason": str(e)}

    async def get_session_status(self, job_id: str) -> Dict[str, Any]:
        """Get status of active analysis session"""

        sandbox_status = await self.intelligent_sandbox.get_sandbox_status(job_id)

        return {
            "job_id": job_id,
            "sandbox_status": sandbox_status,
            "session_active": job_id in self.active_sessions
        }

    async def approve_analysis(
        self,
        approval_token: str,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Approve a pending high-risk analysis"""

        return {
            "status": "approved",
            "token": approval_token,
            "options": options or {}
        }


_active_re_agent_instance: Optional[ActiveREAgent] = None

def get_active_re_agent() -> ActiveREAgent:
    global _active_re_agent_instance
    if _active_re_agent_instance is None:
        _active_re_agent_instance = ActiveREAgent()
    return _active_re_agent_instance

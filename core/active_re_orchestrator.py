import os
import json
import uuid
import asyncio
import hashlib
from enum import Enum
from typing import Optional, Dict, Any, List, Callable, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
import structlog

from core.config import settings
from core.llm_client import LLMClient
from core.active_re_service import get_active_re_service
from core.frida_instrumentation import get_frida, FridaScriptTemplates
from core.angr_bridge import get_angr
from core.pwndbg_bridge import get_pwndbg
from core.retriever import get_retriever

log = structlog.get_logger()


class AnalysisPhase(Enum):
    RECONNAISSANCE = "reconnaissance"
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    CORRELATION = "correlation"
    REPORTING = "reporting"


class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


@dataclass
class AnalysisContext:
    binary_path: str
    binary_hash: str
    file_size: int
    file_type: str
    analysis_goal: str
    job_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: datetime = field(default_factory=datetime.utcnow)
    phase: AnalysisPhase = AnalysisPhase.RECONNAISSANCE
    findings: List[Dict[str, Any]] = field(default_factory=list)
    risk_assessment: Dict[str, Any] = field(default_factory=dict)
    execution_history: List[Dict[str, Any]] = field(default_factory=list)
    ai_recommendations: List[str] = field(default_factory=list)
    sandbox_config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionStrategy:
    name: str
    description: str
    tools: List[str]
    phases: List[AnalysisPhase]
    estimated_duration: int
    risk_level: RiskLevel
    requires_approval: bool
    parallelizable: bool
    fallback_strategies: List[str] = field(default_factory=list)


class AIAnalysisPlanner:
    """AI-powered analysis strategy planner using LLM"""

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client or self._init_llm()
        self.strategy_templates = self._load_strategy_templates()

    def _init_llm(self) -> Optional[LLMClient]:
        try:
            return LLMClient(
                model=settings.ANGR_LLM_MODEL,
                api_base=settings.ANGR_LLM_API_BASE,
                api_key=settings.ANGR_LLM_API_KEY
            )
        except Exception as e:
            log.error(f"Failed to initialize LLM for planning: {e}")
            return None

    def _load_strategy_templates(self) -> Dict[str, ExecutionStrategy]:
        return {
            "vulnerability_assessment": ExecutionStrategy(
                name="vulnerability_assessment",
                description="Comprehensive vulnerability detection using multi-tool approach",
                tools=["frida", "angr", "pwndbg", "static_analysis"],
                phases=[
                    AnalysisPhase.RECONNAISSANCE,
                    AnalysisPhase.STATIC_ANALYSIS,
                    AnalysisPhase.DYNAMIC_ANALYSIS,
                    AnalysisPhase.CORRELATION
                ],
                estimated_duration=300,
                risk_level=RiskLevel.MEDIUM,
                requires_approval=True,
                parallelizable=True
            ),
            "behavioral_profiling": ExecutionStrategy(
                name="behavioral_profiling",
                description="Analyze runtime behavior and system interactions",
                tools=["frida", "monitoring", "network_analysis"],
                phases=[
                    AnalysisPhase.RECONNAISSANCE,
                    AnalysisPhase.DYNAMIC_ANALYSIS,
                    AnalysisPhase.BEHAVIORAL_ANALYSIS
                ],
                estimated_duration=180,
                risk_level=RiskLevel.MEDIUM,
                requires_approval=True,
                parallelizable=False
            ),
            "malware_deep_dive": ExecutionStrategy(
                name="malware_deep_dive",
                description="Deep analysis for suspicious/malicious binaries",
                tools=["frida", "angr", "pwndbg", "static_analysis", "yara"],
                phases=[
                    AnalysisPhase.RECONNAISSANCE,
                    AnalysisPhase.STATIC_ANALYSIS,
                    AnalysisPhase.DYNAMIC_ANALYSIS,
                    AnalysisPhase.BEHAVIORAL_ANALYSIS,
                    AnalysisPhase.CORRELATION,
                    AnalysisPhase.REPORTING
                ],
                estimated_duration=600,
                risk_level=RiskLevel.HIGH,
                requires_approval=True,
                parallelizable=True,
                fallback_strategies=["vulnerability_assessment", "behavioral_profiling"]
            ),
            "quick_safety_check": ExecutionStrategy(
                name="quick_safety_check",
                description="Fast analysis for low-risk binaries",
                tools=["static_analysis", "basic_monitoring"],
                phases=[
                    AnalysisPhase.RECONNAISSANCE,
                    AnalysisPhase.STATIC_ANALYSIS
                ],
                estimated_duration=60,
                risk_level=RiskLevel.MINIMAL,
                requires_approval=False,
                parallelizable=True
            )
        }

    async def generate_strategy(
        self,
        context: AnalysisContext,
        available_tools: List[str]
    ) -> ExecutionStrategy:
        """Generate optimal analysis strategy based on binary characteristics"""

        if not self.llm_client:
            return self._fallback_strategy(context)

        prompt = self._build_planning_prompt(context, available_tools)

        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.llm_client.completion(
                    messages=[{"role": "user", "content": prompt}]
                )
            )

            strategy_config = self._parse_strategy_response(response)
            return self._create_strategy_from_config(strategy_config)

        except Exception as e:
            log.error(f"AI strategy generation failed: {e}, using fallback")
            return self._select_template_strategy(context)

    def _build_planning_prompt(
        self,
        context: AnalysisContext,
        available_tools: List[str]
    ) -> str:
        return f"""As an expert reverse engineering AI, analyze the following binary and recommend an optimal analysis strategy.

Binary Information:
- Path: {context.binary_path}
- Hash (SHA256): {context.binary_hash[:16]}...
- Size: {context.file_size} bytes
- File Type: {context.file_type}
- Analysis Goal: {context.analysis_goal}
- Available Tools: {', '.join(available_tools)}

Available Strategy Templates:
1. vulnerability_assessment - For finding security vulnerabilities
2. behavioral_profiling - For understanding runtime behavior
3. malware_deep_dive - For suspicious/malicious samples
4. quick_safety_check - For fast preliminary analysis

Based on the binary characteristics and goal, recommend:
1. Which strategy template to use (or create a custom one)
2. Specific tools to prioritize
3. Estimated risk level (minimal/low/medium/high/critical)
4. Whether human approval is needed
5. Key areas to focus on

Respond in JSON format:
{{
    "strategy_name": "name",
    "risk_level": "level",
    "requires_approval": true/false,
    "priority_tools": ["tool1", "tool2"],
    "focus_areas": ["area1", "area2"],
    "reasoning": "explanation"
}}"""

    def _parse_strategy_response(self, response: str) -> Dict[str, Any]:
        try:
            json_str = response.strip()
            if "```json" in json_str:
                json_str = json_str.split("```json")[1].split("```")[0]
            elif "```" in json_str:
                json_str = json_str.split("```")[1].split("```")[0]
            return json.loads(json_str.strip())
        except Exception:
            return {}

    def _create_strategy_from_config(
        self,
        config: Dict[str, Any]
    ) -> ExecutionStrategy:
        template = self.strategy_templates.get(
            config.get("strategy_name", "vulnerability_assessment"),
            self.strategy_templates["vulnerability_assessment"]
        )

        risk_map = {
            "critical": RiskLevel.CRITICAL,
            "high": RiskLevel.HIGH,
            "medium": RiskLevel.MEDIUM,
            "low": RiskLevel.LOW,
            "minimal": RiskLevel.MINIMAL
        }

        return ExecutionStrategy(
            name=config.get("strategy_name", template.name),
            description=template.description,
            tools=config.get("priority_tools", template.tools),
            phases=template.phases,
            estimated_duration=template.estimated_duration,
            risk_level=risk_map.get(config.get("risk_level", "medium"), RiskLevel.MEDIUM),
            requires_approval=config.get("requires_approval", template.requires_approval),
            parallelizable=template.parallelizable,
            fallback_strategies=template.fallback_strategies
        )

    def _select_template_strategy(self, context: AnalysisContext) -> ExecutionStrategy:
        goal_lower = context.analysis_goal.lower()

        if any(term in goal_lower for term in ["malware", "virus", "trojan", "suspicious"]):
            return self.strategy_templates["malware_deep_dive"]
        elif any(term in goal_lower for term in ["vulnerability", "exploit", "bug"]):
            return self.strategy_templates["vulnerability_assessment"]
        elif any(term in goal_lower for term in ["behavior", "runtime", "dynamic"]):
            return self.strategy_templates["behavioral_profiling"]
        else:
            return self.strategy_templates["quick_safety_check"]

    def _fallback_strategy(self, context: AnalysisContext) -> ExecutionStrategy:
        return self._select_template_strategy(context)


class SmartCorrelationEngine:
    """Intelligent correlation between static and dynamic analysis results"""

    def __init__(self):
        self.correlation_rules = self._load_correlation_rules()
        self.confidence_threshold = 0.7

    def _load_correlation_rules(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "function_call_match",
                "weight": 0.3,
                "description": "Match static function names with dynamic call traces"
            },
            {
                "name": "string_reference_match",
                "weight": 0.2,
                "description": "Correlate static strings with runtime usage"
            },
            {
                "name": "api_behavior_anomaly",
                "weight": 0.25,
                "description": "Detect anomalous API usage patterns"
            },
            {
                "name": "control_flow_deviation",
                "weight": 0.25,
                "description": "Identify deviations from expected control flow"
            }
        ]

    async def correlate(
        self,
        static_results: Dict[str, Any],
        dynamic_results: Dict[str, Any],
        behavioral_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Correlate findings from multiple analysis sources"""

        correlations = {
            "confirmed_findings": [],
            "suspicious_patterns": [],
            "anomalies": [],
            "confidence_scores": {},
            "risk_adjustments": {},
            "correlation_matrix": {}
        }

        tasks = [
            self._correlate_functions(static_results, dynamic_results),
            self._correlate_strings(static_results, behavioral_results),
            self._detect_api_anomalies(dynamic_results),
            self._analyze_control_flow(static_results, dynamic_results)
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                log.error(f"Correlation task {i} failed: {result}")
                continue

            rule = self.correlation_rules[i]
            correlations["confidence_scores"][rule["name"]] = result.get("confidence", 0)

            if result.get("findings"):
                for finding in result["findings"]:
                    finding["correlation_rule"] = rule["name"]
                    finding["weight"] = rule["weight"]

                    if finding.get("confidence", 0) >= self.confidence_threshold:
                        correlations["confirmed_findings"].append(finding)
                    else:
                        correlations["suspicious_patterns"].append(finding)

        correlations["overall_confidence"] = self._calculate_overall_confidence(
            correlations["confidence_scores"]
        )

        correlations["risk_adjustments"] = self._calculate_risk_adjustments(
            correlations["confirmed_findings"],
            correlations["suspicious_patterns"]
        )

        return correlations

    async def _correlate_functions(
        self,
        static_results: Dict[str, Any],
        dynamic_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Correlate static functions with dynamic call traces"""

        static_funcs = static_results.get("functions", [])
        dynamic_calls = dynamic_results.get("api_calls", [])

        matched = []
        unmatched_static = []

        static_names = {f.get("name", "").lower() for f in static_funcs}
        dynamic_names = {call.get("function", "").lower() for call in dynamic_calls}

        for func in static_funcs:
            func_name = func.get("name", "").lower()
            if func_name in dynamic_names:
                matched.append({
                    "function": func,
                    "calls": [c for c in dynamic_calls if c.get("function", "").lower() == func_name],
                    "confidence": 0.9
                })
            else:
                unmatched_static.append(func)

        return {
            "confidence": len(matched) / max(len(static_funcs), 1) if static_funcs else 0,
            "findings": [
                {
                    "type": "function_correlation",
                    "matched_count": len(matched),
                    "unmatched_count": len(unmatched_static),
                    "coverage": len(matched) / max(len(static_funcs), 1),
                    "details": matched[:10]
                }
            ]
        }

    async def _correlate_strings(
        self,
        static_results: Dict[str, Any],
        behavioral_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Correlate static strings with runtime usage"""

        static_strings = static_results.get("strings", [])
        file_events = behavioral_results.get("filesystem", {}).get("events", [])
        network_events = behavioral_results.get("network", {}).get("events", [])

        interesting_strings = [s for s in static_strings if len(s) > 4]
        matched_strings = []

        for s in interesting_strings[:100]:
            for event in file_events + network_events:
                if s.lower() in str(event).lower():
                    matched_strings.append({
                        "string": s,
                        "event": event,
                        "confidence": 0.85
                    })
                    break

        return {
            "confidence": len(matched_strings) / max(len(interesting_strings), 1),
            "findings": [
                {
                    "type": "string_usage_correlation",
                    "matched_count": len(matched_strings),
                    "key_strings": matched_strings[:5]
                }
            ] if matched_strings else []
        }

    async def _detect_api_anomalies(
        self,
        dynamic_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Detect anomalous API usage patterns"""

        api_calls = dynamic_results.get("api_calls", [])

        if not api_calls:
            return {"confidence": 0, "findings": []}

        call_patterns = defaultdict(int)
        for call in api_calls:
            call_patterns[call.get("api", "unknown")] += 1

        anomalies = []
        for api, count in call_patterns.items():
            if any(term in api.lower() for term in ["crypto", "encrypt", "hash"]):
                if count > 100:
                    anomalies.append({
                        "api": api,
                        "count": count,
                        "type": "excessive_crypto_usage",
                        "confidence": 0.8
                    })

            if any(term in api.lower() for term in ["socket", "connect", "send"]):
                if count > 50:
                    anomalies.append({
                        "api": api,
                        "count": count,
                        "type": "excessive_network_activity",
                        "confidence": 0.75
                    })

        return {
            "confidence": 0.7 if anomalies else 0.5,
            "findings": anomalies
        }

    async def _analyze_control_flow(
        self,
        static_results: Dict[str, Any],
        dynamic_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze control flow deviations"""

        static_cfg = static_results.get("control_flow", {})
        dynamic_trace = dynamic_results.get("execution_trace", [])

        if not static_cfg or not dynamic_trace:
            return {"confidence": 0.3, "findings": []}

        executed_blocks = set()
        for trace in dynamic_trace:
            if "address" in trace:
                executed_blocks.add(trace["address"])

        static_blocks = set(static_cfg.get("basic_blocks", []))

        covered = executed_blocks & static_blocks
        uncovered = static_blocks - executed_blocks
        unexpected = executed_blocks - static_blocks

        return {
            "confidence": len(covered) / max(len(static_blocks), 1),
            "findings": [
                {
                    "type": "control_flow_analysis",
                    "coverage": len(covered) / max(len(static_blocks), 1),
                    "uncovered_blocks": len(uncovered),
                    "unexpected_executions": len(unexpected),
                    "confidence": len(covered) / max(len(static_blocks), 1)
                }
            ]
        }

    def _calculate_overall_confidence(self, scores: Dict[str, float]) -> float:
        if not scores:
            return 0.0
        weights = [r["weight"] for r in self.correlation_rules]
        weighted_sum = sum(
            scores.get(rule["name"], 0) * weight
            for rule, weight in zip(self.correlation_rules, weights)
        )
        return min(weighted_sum / sum(weights), 1.0) if sum(weights) > 0 else 0.0

    def _calculate_risk_adjustments(
        self,
        confirmed: List[Dict],
        suspicious: List[Dict]
    ) -> Dict[str, float]:
        base_score = 0.0

        for finding in confirmed:
            base_score += finding.get("weight", 0.1) * finding.get("confidence", 0.5)

        for finding in suspicious:
            base_score += finding.get("weight", 0.1) * finding.get("confidence", 0.5) * 0.5

        return {
            "risk_score_adjustment": min(base_score, 1.0),
            "confirmed_findings_impact": len(confirmed) * 0.1,
            "suspicious_patterns_impact": len(suspicious) * 0.05
        }


class ModernActiveREOrchestrator:
    """Modern AI-powered orchestrator for Active Reverse Engineering"""

    def __init__(self):
        self.ai_planner = AIAnalysisPlanner()
        self.correlation_engine = SmartCorrelationEngine()
        self.active_re_service = get_active_re_service()
        self.frida = get_frida()
        self.angr = get_angr()
        self.pwndbg = get_pwndbg()
        self.retriever = get_retriever()
        self.llm_client = self.ai_planner.llm_client

        self.active_contexts: Dict[str, AnalysisContext] = {}
        self.execution_history: List[Dict[str, Any]] = []

    async def analyze_binary(
        self,
        binary_path: str,
        analysis_goal: str,
        custom_config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Main entry point for intelligent binary analysis"""

        context = await self._initialize_context(binary_path, analysis_goal)

        log.info(f"Starting intelligent analysis for {binary_path}", job_id=context.job_id)

        try:
            strategy = await self.ai_planner.generate_strategy(
                context,
                self._get_available_tools()
            )

            context.risk_assessment = await self._perform_pre_execution_risk_assessment(
                context, strategy
            )

            if strategy.requires_approval and not custom_config.get("skip_approval", False):
                return {
                    "job_id": context.job_id,
                    "status": "awaiting_approval",
                    "strategy": self._strategy_to_dict(strategy),
                    "risk_assessment": context.risk_assessment,
                    "approval_token": self._generate_approval_token(context)
                }

            results = await self._execute_strategy(context, strategy)

            final_report = await self._generate_comprehensive_report(context, results)

            return {
                "job_id": context.job_id,
                "status": "completed",
                "strategy": self._strategy_to_dict(strategy),
                "results": results,
                "report": final_report,
                "risk_assessment": context.risk_assessment
            }

        except Exception as e:
            log.error(f"Analysis failed: {e}", exc_info=True, job_id=context.job_id)
            return {
                "job_id": context.job_id,
                "status": "failed",
                "error": str(e)
            }

    async def _initialize_context(
        self,
        binary_path: str,
        analysis_goal: str
    ) -> AnalysisContext:
        """Initialize analysis context with binary metadata"""

        path = Path(binary_path)
        file_size = path.stat().st_size if path.exists() else 0

        binary_hash = ""
        if path.exists():
            sha256 = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            binary_hash = sha256.hexdigest()

        file_type = self._detect_file_type(path)

        context = AnalysisContext(
            binary_path=binary_path,
            binary_hash=binary_hash,
            file_size=file_size,
            file_type=file_type,
            analysis_goal=analysis_goal
        )

        self.active_contexts[context.job_id] = context
        return context

    def _detect_file_type(self, path: Path) -> str:
        """Detect file type based on extension and magic bytes"""

        extension = path.suffix.lower()

        if extension in [".exe", ".dll"]:
            return "pe"
        elif extension in [".elf", ".so", ".o"]:
            return "elf"
        elif extension == ".macho":
            return "macho"
        else:
            try:
                with open(path, "rb") as f:
                    magic = f.read(4)
                    if magic[:2] == b"MZ":
                        return "pe"
                    elif magic == b"\x7fELF":
                        return "elf"
                    elif magic in [b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"]:
                        return "macho"
            except Exception:
                pass
            return "unknown"

    def _get_available_tools(self) -> List[str]:
        """Get list of available analysis tools"""

        tools = ["static_analysis"]

        if self.frida.is_available():
            tools.append("frida")
        if self.angr.is_available():
            tools.append("angr")
        if self.pwndbg.is_available():
            tools.append("pwndbg")
        if self.retriever.is_available():
            tools.append("rag")

        return tools

    async def _perform_pre_execution_risk_assessment(
        self,
        context: AnalysisContext,
        strategy: ExecutionStrategy
    ) -> Dict[str, Any]:
        """Perform risk assessment before execution"""

        risk_factors = {
            "file_size_risk": min(context.file_size / (100 * 1024 * 1024), 1.0),
            "file_type_risk": 0.3 if context.file_type == "pe" else 0.1,
            "strategy_risk": {
                RiskLevel.CRITICAL: 1.0,
                RiskLevel.HIGH: 0.8,
                RiskLevel.MEDIUM: 0.5,
                RiskLevel.LOW: 0.2,
                RiskLevel.MINIMAL: 0.0
            }.get(strategy.risk_level, 0.5),
            "unknown_binary_risk": 0.2 if not self._is_known_binary(context.binary_hash) else 0.0
        }

        overall_risk = sum(risk_factors.values()) / len(risk_factors)

        mitigation_strategies = []
        if overall_risk > 0.7:
            mitigation_strategies.extend([
                "Use isolated sandbox with no network access",
                "Limit execution time to 60 seconds",
                "Monitor all system calls",
                "Enable memory dump analysis"
            ])
        elif overall_risk > 0.4:
            mitigation_strategies.extend([
                "Use standard sandbox environment",
                "Monitor file and network activity"
            ])

        return {
            "overall_risk": overall_risk,
            "risk_level": self._risk_to_level(overall_risk).value,
            "risk_factors": risk_factors,
            "mitigation_strategies": mitigation_strategies,
            "recommended_sandbox_config": {
                "network_isolated": overall_risk > 0.6,
                "max_runtime": 60 if overall_risk > 0.7 else 300,
                "memory_limit": "512MB" if overall_risk > 0.8 else "2GB"
            }
        }

    def _is_known_binary(self, binary_hash: str) -> bool:
        """Check if binary hash is in known database"""

        return False

    def _risk_to_level(self, risk: float) -> RiskLevel:
        if risk >= 0.9:
            return RiskLevel.CRITICAL
        elif risk >= 0.7:
            return RiskLevel.HIGH
        elif risk >= 0.4:
            return RiskLevel.MEDIUM
        elif risk >= 0.2:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL

    async def _execute_strategy(
        self,
        context: AnalysisContext,
        strategy: ExecutionStrategy
    ) -> Dict[str, Any]:
        """Execute the analysis strategy"""

        results = {
            "phases_completed": [],
            "static_analysis": {},
            "dynamic_analysis": {},
            "behavioral_analysis": {},
            "correlation": {},
            "errors": []
        }

        for phase in strategy.phases:
            context.phase = phase
            log.info(f"Executing phase: {phase.value}", job_id=context.job_id)

            try:
                if phase == AnalysisPhase.RECONNAISSANCE:
                    results["static_analysis"]["reconnaissance"] = await self._phase_reconnaissance(context)

                elif phase == AnalysisPhase.STATIC_ANALYSIS:
                    results["static_analysis"]["deep"] = await self._phase_static_analysis(context)

                elif phase == AnalysisPhase.DYNAMIC_ANALYSIS:
                    results["dynamic_analysis"] = await self._phase_dynamic_analysis(context, strategy)

                elif phase == AnalysisPhase.BEHAVIORAL_ANALYSIS:
                    results["behavioral_analysis"] = await self._phase_behavioral_analysis(context)

                elif phase == AnalysisPhase.CORRELATION:
                    results["correlation"] = await self._phase_correlation(
                        context,
                        results["static_analysis"],
                        results["dynamic_analysis"],
                        results["behavioral_analysis"]
                    )

                results["phases_completed"].append(phase.value)

            except Exception as e:
                log.error(f"Phase {phase.value} failed: {e}", job_id=context.job_id)
                results["errors"].append({"phase": phase.value, "error": str(e)})

        return results

    async def _phase_reconnaissance(self, context: AnalysisContext) -> Dict[str, Any]:
        """Initial reconnaissance phase"""

        return {
            "binary_path": context.binary_path,
            "file_size": context.file_size,
            "file_type": context.file_type,
            "sha256": context.binary_hash,
            "timestamp": datetime.utcnow().isoformat()
        }

    async def _phase_static_analysis(self, context: AnalysisContext) -> Dict[str, Any]:
        """Deep static analysis phase"""

        if not self.angr.is_available():
            return {"error": "angr not available"}

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self.angr.analyze_binary(context.binary_path)
            )
            return result or {"functions": [], "strings": []}
        except Exception as e:
            return {"error": str(e)}

    async def _phase_dynamic_analysis(
        self,
        context: AnalysisContext,
        strategy: ExecutionStrategy
    ) -> Dict[str, Any]:
        """Dynamic analysis with Frida"""

        if not self.frida.is_available():
            return {"error": "Frida not available"}

        try:
            self.active_re_service.start_analysis(context.job_id, context.binary_path)

            script = FridaScriptTemplates.api_call_tracing()
            self.frida.load_script(script)

            result = self.active_re_service.execute_binary(context.job_id)

            messages = self.frida.get_messages()

            self.active_re_service.stop_analysis(context.job_id)

            return {
                "execution_result": result,
                "api_calls": messages,
                "coverage": len(messages)
            }

        except Exception as e:
            return {"error": str(e)}

    async def _phase_behavioral_analysis(self, context: AnalysisContext) -> Dict[str, Any]:
        """Behavioral analysis phase"""

        return {
            "filesystem": {"events": [], "quarantined": []},
            "network": {"events": [], "threats": []},
            "memory": {"anomalies": [], "patterns": {}},
            "process": {"alerts": [], "events": []}
        }

    async def _phase_correlation(
        self,
        context: AnalysisContext,
        static_results: Dict[str, Any],
        dynamic_results: Dict[str, Any],
        behavioral_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Correlation phase"""

        return await self.correlation_engine.correlate(
            static_results,
            dynamic_results,
            behavioral_results
        )

    async def _generate_comprehensive_report(
        self,
        context: AnalysisContext,
        results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate comprehensive analysis report"""

        correlation = results.get("correlation", {})
        risk_adjustments = correlation.get("risk_adjustments", {})

        base_risk = context.risk_assessment.get("overall_risk", 0.5)
        adjusted_risk = min(base_risk + risk_adjustments.get("risk_score_adjustment", 0), 1.0)

        report = {
            "summary": {
                "job_id": context.job_id,
                "binary": context.binary_path,
                "analysis_goal": context.analysis_goal,
                "completion_time": datetime.utcnow().isoformat(),
                "phases_completed": results.get("phases_completed", []),
                "overall_risk_score": adjusted_risk,
                "risk_level": self._risk_to_level(adjusted_risk).value
            },
            "findings": {
                "confirmed": correlation.get("confirmed_findings", []),
                "suspicious": correlation.get("suspicious_patterns", []),
                "anomalies": correlation.get("anomalies", [])
            },
            "technical_details": results,
            "recommendations": self._generate_recommendations(results, adjusted_risk)
        }

        return report

    def _generate_recommendations(
        self,
        results: Dict[str, Any],
        risk_score: float
    ) -> List[str]:
        """Generate actionable recommendations"""

        recommendations = []

        if risk_score > 0.8:
            recommendations.append("CRITICAL: Immediate manual review required")
            recommendations.append("Consider isolating the binary in a dedicated analysis environment")

        if risk_score > 0.6:
            recommendations.append("Perform additional static analysis on suspicious code paths")

        correlation = results.get("correlation", {})
        if correlation.get("confirmed_findings"):
            recommendations.append("Review confirmed findings for exploitation potential")

        return recommendations

    def _strategy_to_dict(self, strategy: ExecutionStrategy) -> Dict[str, Any]:
        """Convert strategy to dictionary"""

        return {
            "name": strategy.name,
            "description": strategy.description,
            "tools": strategy.tools,
            "phases": [p.value for p in strategy.phases],
            "estimated_duration": strategy.estimated_duration,
            "risk_level": strategy.risk_level.value,
            "requires_approval": strategy.requires_approval,
            "parallelizable": strategy.parallelizable
        }

    def _generate_approval_token(self, context: AnalysisContext) -> str:
        """Generate approval token for high-risk analysis"""

        return hashlib.sha256(
            f"{context.job_id}:{context.binary_hash}:{datetime.utcnow().isoformat()}".encode()
        ).hexdigest()[:32]


_orchestrator_instance: Optional[ModernActiveREOrchestrator] = None


def get_modern_orchestrator() -> ModernActiveREOrchestrator:
    global _orchestrator_instance
    if _orchestrator_instance is None:
        _orchestrator_instance = ModernActiveREOrchestrator()
    return _orchestrator_instance

import os
import docker
import json
import asyncio
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
import structlog

from core.config import settings

log = structlog.get_logger()


class SandboxPolicy(Enum):
    PERMISSIVE = "permissive"
    STANDARD = "standard"
    RESTRICTED = "restricted"
    MAXIMUM_SECURITY = "maximum_security"
    CUSTOM = "custom"


class IsolationLevel(Enum):
    NONE = "none"
    PROCESS = "process"
    CONTAINER = "container"
    VM = "vm"


@dataclass
class SandboxConfig:
    """Dynamic sandbox configuration"""

    policy: SandboxPolicy = SandboxPolicy.STANDARD
    isolation_level: IsolationLevel = IsolationLevel.CONTAINER

    network_access: bool = True
    internet_access: bool = False
    dns_resolution: bool = False

    max_runtime: int = 300
    max_memory: str = "2GB"
    max_cpu: float = 2.0
    max_disk: str = "10GB"

    allow_file_read: bool = True
    allow_file_write: bool = False
    allowed_directories: List[str] = field(default_factory=list)

    allow_registry_read: bool = True
    allow_registry_write: bool = False

    syscall_filter: List[str] = field(default_factory=list)
    blocked_syscalls: List[str] = field(default_factory=list)

    monitoring_interval: int = 5
    enable_strace: bool = False
    enable_perf: bool = False

    auto_terminate_on_anomaly: bool = True
    anomaly_threshold: float = 0.8


@dataclass
class SecurityProfile:
    """Security profile for a binary"""

    binary_hash: str
    binary_path: str
    assessed_risk: float
    risk_level: str

    known_indicators: Dict[str, Any] = field(default_factory=dict)
    reputation_score: float = 0.5

    previous_executions: int = 0
    previous_incidents: int = 0

    recommended_policy: SandboxPolicy = SandboxPolicy.STANDARD


class AdaptivePolicyEngine:
    """Adaptive policy engine that adjusts sandbox settings based on risk"""

    def __init__(self):
        self.risk_thresholds = {
            SandboxPolicy.PERMISSIVE: (0.0, 0.2),
            SandboxPolicy.STANDARD: (0.2, 0.5),
            SandboxPolicy.RESTRICTED: (0.5, 0.8),
            SandboxPolicy.MAXIMUM_SECURITY: (0.8, 1.0)
        }

        self.policy_templates = {
            SandboxPolicy.PERMISSIVE: self._permissive_config(),
            SandboxPolicy.STANDARD: self._standard_config(),
            SandboxPolicy.RESTRICTED: self._restricted_config(),
            SandboxPolicy.MAXIMUM_SECURITY: self._maximum_security_config()
        }

        self.execution_history: Dict[str, List[Dict[str, Any]]] = {}

    def _permissive_config(self) -> SandboxConfig:
        return SandboxConfig(
            policy=SandboxPolicy.PERMISSIVE,
            network_access=True,
            internet_access=True,
            allow_file_write=True,
            allow_registry_write=True,
            max_runtime=600,
            enable_strace=False
        )

    def _standard_config(self) -> SandboxConfig:
        return SandboxConfig(
            policy=SandboxPolicy.STANDARD,
            network_access=True,
            internet_access=False,
            allow_file_write=False,
            allow_registry_write=False,
            max_runtime=300,
            enable_strace=False
        )

    def _restricted_config(self) -> SandboxConfig:
        return SandboxConfig(
            policy=SandboxPolicy.RESTRICTED,
            network_access=False,
            internet_access=False,
            allow_file_write=False,
            allow_registry_write=False,
            max_runtime=120,
            max_memory="1GB",
            enable_strace=True,
            blocked_syscalls=["execve", "fork", "clone", "ptrace"],
            auto_terminate_on_anomaly=True
        )

    def _maximum_security_config(self) -> SandboxConfig:
        return SandboxConfig(
            policy=SandboxPolicy.MAXIMUM_SECURITY,
            isolation_level=IsolationLevel.VM,
            network_access=False,
            internet_access=False,
            allow_file_read=False,
            allow_file_write=False,
            allow_registry_read=False,
            allow_registry_write=False,
            max_runtime=60,
            max_memory="512MB",
            max_cpu=1.0,
            enable_strace=True,
            enable_perf=True,
            syscall_filter=["read", "write", "exit", "exit_group"],
            auto_terminate_on_anomaly=True,
            anomaly_threshold=0.5
        )

    def determine_policy(
        self,
        security_profile: SecurityProfile,
        user_preference: Optional[SandboxPolicy] = None
    ) -> SandboxConfig:
        """Determine appropriate sandbox policy based on risk assessment"""

        if user_preference and user_preference != SandboxPolicy.CUSTOM:
            return self.policy_templates[user_preference]

        risk_score = self._calculate_comprehensive_risk(security_profile)

        for policy, (min_risk, max_risk) in self.risk_thresholds.items():
            if min_risk <= risk_score < max_risk:
                config = self.policy_templates[policy]
                config = self._apply_profile_customizations(config, security_profile)
                return config

        return self.policy_templates[SandboxPolicy.STANDARD]

    def _calculate_comprehensive_risk(self, profile: SecurityProfile) -> float:
        """Calculate comprehensive risk score"""

        base_risk = profile.assessed_risk

        history_factor = min(profile.previous_incidents / max(profile.previous_executions, 1), 1.0)

        reputation_factor = 1.0 - profile.reputation_score

        indicators_factor = len(profile.known_indicators) * 0.1

        comprehensive_risk = (
            base_risk * 0.4 +
            history_factor * 0.3 +
            reputation_factor * 0.2 +
            indicators_factor * 0.1
        )

        return min(comprehensive_risk, 1.0)

    def _apply_profile_customizations(
        self,
        config: SandboxConfig,
        profile: SecurityProfile
    ) -> SandboxConfig:
        """Apply customizations based on security profile"""

        if profile.previous_incidents > 0:
            config.auto_terminate_on_anomaly = True
            config.anomaly_threshold = max(0.5, config.anomaly_threshold - 0.1 * profile.previous_incidents)

        if profile.known_indicators.get("packer_detected"):
            config.enable_strace = True
            config.max_runtime = min(config.max_runtime, 180)

        return config

    def record_execution_result(
        self,
        binary_hash: str,
        result: Dict[str, Any]
    ):
        """Record execution result for future policy adjustments"""

        if binary_hash not in self.execution_history:
            self.execution_history[binary_hash] = []

        self.execution_history[binary_hash].append({
            "timestamp": datetime.utcnow().isoformat(),
            "anomalies_detected": result.get("anomalies", []),
            "risk_score": result.get("risk_score", 0),
            "policy_used": result.get("policy", "standard")
        })

        self.execution_history[binary_hash] = self.execution_history[binary_hash][-10:]


class IntelligentSandbox:
    """Intelligent sandbox with adaptive security policies"""

    def __init__(self):
        self.policy_engine = AdaptivePolicyEngine()
        self.docker_client = None
        self._init_docker()

        self.active_sandboxes: Dict[str, Dict[str, Any]] = {}
        self.security_profiles: Dict[str, SecurityProfile] = {}

        self.default_image = settings.ACTIVE_RE_SANDBOX_IMAGE
        self.base_container_name = "reaa-intelligent-sandbox"

    def _init_docker(self):
        """Initialize Docker client"""

        try:
            self.docker_client = docker.from_env()
        except Exception as e:
            log.error(f"Failed to initialize Docker: {e}")
            try:
                self.docker_client = docker.DockerClient()
            except Exception as e2:
                log.error(f"Failed to initialize Docker client: {e2}")

    async def create_security_profile(
        self,
        binary_path: str,
        binary_hash: str,
        risk_assessment: Dict[str, Any]
    ) -> SecurityProfile:
        """Create security profile for a binary"""

        known_indicators = await self._analyze_binary_indicators(binary_path)

        previous_data = self._get_historical_data(binary_hash)

        profile = SecurityProfile(
            binary_hash=binary_hash,
            binary_path=binary_path,
            assessed_risk=risk_assessment.get("overall_risk", 0.5),
            risk_level=risk_assessment.get("risk_level", "medium"),
            known_indicators=known_indicators,
            reputation_score=previous_data.get("reputation_score", 0.5),
            previous_executions=previous_data.get("executions", 0),
            previous_incidents=previous_data.get("incidents", 0)
        )

        self.security_profiles[binary_hash] = profile

        return profile

    async def _analyze_binary_indicators(
        self,
        binary_path: str
    ) -> Dict[str, Any]:
        """Analyze binary for security indicators"""

        indicators = {}
        path = Path(binary_path)

        if not path.exists():
            return indicators

        try:
            with open(path, "rb") as f:
                content = f.read(8192)

                packer_signatures = [
                    b"UPX", b"ASPack", b"PECompact",
                    b"FSG", b"MPRESS", b" Themida"
                ]
                for sig in packer_signatures:
                    if sig in content:
                        indicators["packer_detected"] = True
                        indicators["packer_name"] = sig.decode("latin-1", errors="ignore")
                        break

                suspicious_imports = [
                    b"VirtualAlloc", b"WriteProcessMemory",
                    b"CreateRemoteThread", b"LoadLibrary",
                    b"GetProcAddress", b"InternetConnect"
                ]
                indicators["suspicious_imports"] = [
                    imp.decode("latin-1", errors="ignore")
                    for imp in suspicious_imports
                    if imp in content
                ][:5]

        except Exception as e:
            log.error(f"Failed to analyze binary indicators: {e}")

        return indicators

    def _get_historical_data(self, binary_hash: str) -> Dict[str, Any]:
        """Get historical execution data for a binary"""

        history = self.policy_engine.execution_history.get(binary_hash, [])

        if not history:
            return {"reputation_score": 0.5, "executions": 0, "incidents": 0}

        incidents = sum(
            1 for h in history
            if h.get("anomalies_detected") or h.get("risk_score", 0) > 0.7
        )

        avg_risk = sum(h.get("risk_score", 0) for h in history) / len(history)

        reputation = max(0.0, 1.0 - (incidents / len(history)) - (avg_risk * 0.5))

        return {
            "reputation_score": reputation,
            "executions": len(history),
            "incidents": incidents
        }

    async def provision_sandbox(
        self,
        job_id: str,
        binary_path: str,
        binary_hash: str,
        risk_assessment: Dict[str, Any],
        user_policy: Optional[str] = None
    ) -> Dict[str, Any]:
        """Provision an intelligent sandbox for binary execution"""

        profile = await self.create_security_profile(
            binary_path, binary_hash, risk_assessment
        )

        policy = None
        if user_policy:
            try:
                policy = SandboxPolicy(user_policy)
            except ValueError:
                pass

        config = self.policy_engine.determine_policy(profile, policy)

        container_name = f"{self.base_container_name}-{job_id}"

        try:
            container_config = self._build_container_config(
                container_name, config, binary_path, job_id
            )

            container = self.docker_client.containers.run(**container_config)

            self.active_sandboxes[job_id] = {
                "container_id": container.id,
                "container_name": container_name,
                "config": config,
                "profile": profile,
                "started_at": datetime.utcnow().isoformat(),
                "status": "running"
            }

            log.info(
                f"Provisioned intelligent sandbox for {job_id}",
                policy=config.policy.value,
                risk_level=profile.risk_level
            )

            return {
                "job_id": job_id,
                "container_id": container.id,
                "container_name": container_name,
                "policy": config.policy.value,
                "config": self._config_to_dict(config),
                "security_profile": {
                    "risk_level": profile.risk_level,
                    "assessed_risk": profile.assessed_risk,
                    "indicators": profile.known_indicators
                },
                "status": "provisioned"
            }

        except Exception as e:
            log.error(f"Failed to provision sandbox: {e}")
            return {"error": str(e), "job_id": job_id}

    def _build_container_config(
        self,
        name: str,
        config: SandboxConfig,
        binary_path: str,
        job_id: str
    ) -> Dict[str, Any]:
        """Build Docker container configuration"""

        security_opt = ["no-new-privileges"]

        cap_drop = ["ALL"]
        cap_add = []

        if config.policy == SandboxPolicy.PERMISSIVE:
            cap_add = ["NET_BIND_SERVICE", "NET_RAW", "SYS_PTRACE"]
        elif config.policy == SandboxPolicy.STANDARD:
            cap_add = ["NET_BIND_SERVICE"]
        elif config.policy in [SandboxPolicy.RESTRICTED, SandboxPolicy.MAXIMUM_SECURITY]:
            security_opt.append("seccomp=unconfined")

        network_mode = "bridge" if config.network_access else "none"

        volumes = {}

        data_dir = settings.DATA_DIR
        job_dir = data_dir / job_id
        artifacts_dir = job_dir / "artifacts"
        job_dir.mkdir(parents=True, exist_ok=True)
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        volumes[str(data_dir)] = {"bind": "/app/data", "mode": "rw"}

        if config.allow_file_write and config.allowed_directories:
            for directory in config.allowed_directories:
                volumes[directory] = {"bind": f"/sandbox/{Path(directory).name}", "mode": "rw"}

        environment = {
            "SANDBOX_POLICY": config.policy.value,
            "JOB_ID": job_id,
            "MAX_RUNTIME": str(config.max_runtime),
            "MONITORING_INTERVAL": str(config.monitoring_interval),
            "ENABLE_STRACE": "1" if config.enable_strace else "0",
            "ENABLE_PERF": "1" if config.enable_perf else "0",
            "AUTO_TERMINATE": "1" if config.auto_terminate_on_anomaly else "0",
            "ANOMALY_THRESHOLD": str(config.anomaly_threshold)
        }

        return {
            "image": self.default_image,
            "name": name,
            "detach": True,
            "network_mode": network_mode,
            "mem_limit": config.max_memory,
            "cpu_quota": int(config.max_cpu * 100000),
            "storage_opt": {"size": config.max_disk} if config.max_disk else None,
            "security_opt": security_opt,
            "cap_drop": cap_drop,
            "cap_add": cap_add,
            "volumes": volumes,
            "environment": environment,
            "read_only": not config.allow_file_write,
            "tmpfs": {"/tmp": "rw,noexec,nosuid,size=100m"} if not config.allow_file_write else None
        }

    def _config_to_dict(self, config: SandboxConfig) -> Dict[str, Any]:
        """Convert sandbox config to dictionary"""

        return {
            "policy": config.policy.value,
            "isolation_level": config.isolation_level.value,
            "network_access": config.network_access,
            "internet_access": config.internet_access,
            "max_runtime": config.max_runtime,
            "max_memory": config.max_memory,
            "max_cpu": config.max_cpu,
            "allow_file_write": config.allow_file_write,
            "allow_registry_write": config.allow_registry_write,
            "enable_strace": config.enable_strace,
            "enable_perf": config.enable_perf,
            "auto_terminate_on_anomaly": config.auto_terminate_on_anomaly,
            "anomaly_threshold": config.anomaly_threshold
        }

    async def execute_in_sandbox(
        self,
        job_id: str,
        command: List[str],
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """Execute command in intelligent sandbox"""

        if job_id not in self.active_sandboxes:
            return {"error": "Sandbox not found"}

        sandbox = self.active_sandboxes[job_id]
        config = sandbox["config"]

        try:
            container = self.docker_client.containers.get(sandbox["container_id"])

            effective_timeout = timeout or config.max_runtime

            result = container.exec_run(
                cmd=command,
                workdir="/app",
                demux=True,
                timeout=effective_timeout
            )

            stdout = result.output[0].decode("utf-8", errors="ignore") if result.output[0] else ""
            stderr = result.output[1].decode("utf-8", errors="ignore") if result.output[1] else ""

            return {
                "exit_code": result.exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "timed_out": result.exit_code == -1
            }

        except Exception as e:
            log.error(f"Execution failed in sandbox {job_id}: {e}")
            return {"error": str(e)}

    async def monitor_sandbox(
        self,
        job_id: str,
        callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """Monitor sandbox for anomalies"""

        if job_id not in self.active_sandboxes:
            return {"error": "Sandbox not found"}

        sandbox = self.active_sandboxes[job_id]
        config = sandbox["config"]

        try:
            container = self.docker_client.containers.get(sandbox["container_id"])
            stats = container.stats(stream=False)

            monitoring_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "container_stats": {
                    "cpu_usage": stats.get("cpu_stats", {}).get("cpu_usage", {}),
                    "memory_usage": stats.get("memory_stats", {}),
                    "network_io": stats.get("networks", {})
                },
                "status": container.status
            }

            if callback:
                await callback(monitoring_data)

            return monitoring_data

        except Exception as e:
            log.error(f"Monitoring failed for sandbox {job_id}: {e}")
            return {"error": str(e)}

    async def destroy_sandbox(
        self,
        job_id: str,
        force: bool = False
    ) -> Dict[str, Any]:
        """Destroy sandbox and cleanup resources"""

        if job_id not in self.active_sandboxes:
            return {"status": "not_found"}

        sandbox = self.active_sandboxes[job_id]

        try:
            container = self.docker_client.containers.get(sandbox["container_id"])

            if force:
                container.kill()
            else:
                container.stop(timeout=10)

            container.remove()

            execution_result = sandbox.get("execution_result", {})

            self.policy_engine.record_execution_result(
                sandbox["profile"].binary_hash,
                {
                    "anomalies": execution_result.get("anomalies", []),
                    "risk_score": execution_result.get("risk_score", 0),
                    "policy": sandbox["config"].policy.value
                }
            )

            del self.active_sandboxes[job_id]

            log.info(f"Destroyed sandbox for {job_id}")

            return {"status": "destroyed", "job_id": job_id}

        except Exception as e:
            log.error(f"Failed to destroy sandbox {job_id}: {e}")
            return {"error": str(e)}

    async def get_sandbox_status(self, job_id: str) -> Dict[str, Any]:
        """Get current sandbox status"""

        if job_id not in self.active_sandboxes:
            return {"status": "not_found"}

        sandbox = self.active_sandboxes[job_id]

        try:
            container = self.docker_client.containers.get(sandbox["container_id"])

            return {
                "job_id": job_id,
                "status": container.status,
                "health": container.attrs.get("State", {}).get("Health", {}).get("Status", "unknown"),
                "started_at": sandbox["started_at"],
                "policy": sandbox["config"].policy.value,
                "container_id": container.id[:12]
            }

        except Exception as e:
            return {"status": "error", "error": str(e)}


_intelligent_sandbox_instance: Optional[IntelligentSandbox] = None


def get_intelligent_sandbox() -> IntelligentSandbox:
    global _intelligent_sandbox_instance
    if _intelligent_sandbox_instance is None:
        _intelligent_sandbox_instance = IntelligentSandbox()
    return _intelligent_sandbox_instance

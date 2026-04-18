import os
import json
import math
import asyncio
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
from enum import Enum
import structlog

log = structlog.get_logger()


class BehaviorPattern(Enum):
    NORMAL = "normal"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class AnomalyType(Enum):
    FREQUENCY_ANOMALY = "frequency_anomaly"
    SEQUENCE_ANOMALY = "sequence_anomaly"
    TIMING_ANOMALY = "timing_anomaly"
    CORRELATION_ANOMALY = "correlation_anomaly"
    ENTROPY_ANOMALY = "entropy_anomaly"


@dataclass
class BehaviorProfile:
    """Behavior profile for a binary execution"""

    process_id: str
    binary_hash: str
    start_time: datetime
    end_time: Optional[datetime] = None

    api_calls: List[Dict[str, Any]] = field(default_factory=list)
    file_operations: List[Dict[str, Any]] = field(default_factory=list)
    network_operations: List[Dict[str, Any]] = field(default_factory=list)
    registry_operations: List[Dict[str, Any]] = field(default_factory=list)
    memory_operations: List[Dict[str, Any]] = field(default_factory=list)
    process_operations: List[Dict[str, Any]] = field(default_factory=list)

    api_frequency: Dict[str, int] = field(default_factory=dict)
    sequence_patterns: List[List[str]] = field(default_factory=list)
    timing_data: Dict[str, List[float]] = field(default_factory=dict)

    risk_score: float = 0.0
    behavior_classification: BehaviorPattern = BehaviorPattern.UNKNOWN

    def duration(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return (datetime.utcnow() - self.start_time).total_seconds()


@dataclass
class AnomalyDetection:
    """Detected anomaly with metadata"""

    anomaly_type: AnomalyType
    description: str
    confidence: float
    severity: str
    affected_apis: List[str]
    timestamp: datetime
    raw_data: Dict[str, Any]
    recommended_action: str


class StatisticalBehaviorAnalyzer:
    """Statistical analysis of behavior patterns"""

    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.baseline_stats: Dict[str, Dict[str, float]] = defaultdict(dict)
        self.historical_profiles: deque = deque(maxlen=1000)

    def compute_baseline(self, profiles: List[BehaviorProfile]) -> Dict[str, Any]:
        """Compute statistical baseline from historical profiles"""

        if not profiles:
            return {}

        all_api_frequencies = defaultdict(list)
        all_durations = []
        all_api_counts = []

        for profile in profiles:
            for api, count in profile.api_frequency.items():
                all_api_frequencies[api].append(count)

            all_durations.append(profile.duration())
            all_api_counts.append(sum(profile.api_frequency.values()))

        baseline = {
            "api_frequencies": {
                api: {
                    "mean": sum(counts) / len(counts),
                    "std": self._std_dev(counts),
                    "max": max(counts),
                    "min": min(counts)
                }
                for api, counts in all_api_frequencies.items()
            },
            "duration": {
                "mean": sum(all_durations) / len(all_durations),
                "std": self._std_dev(all_durations),
                "max": max(all_durations),
                "min": min(all_durations)
            },
            "api_count": {
                "mean": sum(all_api_counts) / len(all_api_counts),
                "std": self._std_dev(all_api_counts),
                "max": max(all_api_counts),
                "min": min(all_api_counts)
            }
        }

        return baseline

    def _std_dev(self, values: List[float]) -> float:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return math.sqrt(variance)

    def detect_frequency_anomalies(
        self,
        profile: BehaviorProfile,
        baseline: Dict[str, Any]
    ) -> List[AnomalyDetection]:
        """Detect API call frequency anomalies"""

        anomalies = []
        baseline_freqs = baseline.get("api_frequencies", {})

        for api, count in profile.api_frequency.items():
            if api in baseline_freqs:
                stats = baseline_freqs[api]
                mean = stats.get("mean", 0)
                std = stats.get("std", 1)

                if std > 0:
                    z_score = (count - mean) / std

                    if z_score > 3.0:
                        anomalies.append(AnomalyDetection(
                            anomaly_type=AnomalyType.FREQUENCY_ANOMALY,
                            description=f"API '{api}' called {count} times (expected ~{mean:.0f})",
                            confidence=min(z_score / 5.0, 1.0),
                            severity="high" if z_score > 4.0 else "medium",
                            affected_apis=[api],
                            timestamp=datetime.utcnow(),
                            raw_data={"count": count, "expected": mean, "z_score": z_score},
                            recommended_action="Investigate excessive API usage"
                        ))

        return anomalies

    def detect_sequence_anomalies(
        self,
        profile: BehaviorProfile,
        known_sequences: List[List[str]]
    ) -> List[AnomalyDetection]:
        """Detect suspicious API call sequences"""

        anomalies = []
        suspicious_patterns = [
            (["CreateFile", "WriteFile", "RegSetValue"], "file_to_registry"),
            (["socket", "connect", "send", "recv"], "network_communication"),
            (["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"], "process_injection"),
            (["CryptEncrypt", "CryptDecrypt", "CryptCreateHash"], "encryption_activity"),
            (["OpenProcess", "ReadProcessMemory", "WriteProcessMemory"], "memory_manipulation")
        ]

        call_sequence = [call.get("api", "") for call in profile.api_calls]

        for pattern, pattern_name in suspicious_patterns:
            if self._find_subsequence(call_sequence, pattern):
                confidence = self._calculate_pattern_confidence(
                    call_sequence, pattern
                )

                anomalies.append(AnomalyDetection(
                    anomaly_type=AnomalyType.SEQUENCE_ANOMALY,
                    description=f"Detected suspicious pattern: {pattern_name}",
                    confidence=confidence,
                    severity="critical" if pattern_name == "process_injection" else "high",
                    affected_apis=pattern,
                    timestamp=datetime.utcnow(),
                    raw_data={"pattern_name": pattern_name, "sequence": pattern},
                    recommended_action="Immediate investigation required" if pattern_name == "process_injection" else "Review suspicious sequence"
                ))

        return anomalies

    def _find_subsequence(self, sequence: List[str], pattern: List[str]) -> bool:
        """Check if pattern exists as subsequence"""

        if not pattern:
            return True
        if not sequence:
            return False

        pattern_idx = 0
        for item in sequence:
            if pattern_idx < len(pattern) and pattern[pattern_idx].lower() in item.lower():
                pattern_idx += 1
                if pattern_idx == len(pattern):
                    return True

        return False

    def _calculate_pattern_confidence(
        self,
        sequence: List[str],
        pattern: List[str]
    ) -> float:
        """Calculate confidence score for pattern match"""

        matches = 0
        pattern_idx = 0

        for item in sequence:
            if pattern_idx < len(pattern) and pattern[pattern_idx].lower() in item.lower():
                matches += 1
                pattern_idx += 1

        return matches / len(pattern) if pattern else 0.0

    def detect_entropy_anomalies(self, profile: BehaviorProfile) -> List[AnomalyDetection]:
        """Detect entropy-based anomalies in behavior"""

        anomalies = []

        if len(profile.api_calls) < 10:
            return anomalies

        unique_apis = set(call.get("api", "") for call in profile.api_calls)
        total_calls = len(profile.api_calls)

        if total_calls > 0:
            entropy = -sum(
                (profile.api_frequency.get(api, 0) / total_calls) *
                math.log2(profile.api_frequency.get(api, 0) / total_calls)
                for api in unique_apis
                if profile.api_frequency.get(api, 0) > 0
            )

            max_entropy = math.log2(len(unique_apis)) if unique_apis else 1
            normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0

            if normalized_entropy < 0.3 and total_calls > 50:
                anomalies.append(AnomalyDetection(
                    anomaly_type=AnomalyType.ENTROPY_ANOMALY,
                    description="Low behavior entropy - repetitive API usage detected",
                    confidence=0.8,
                    severity="medium",
                    affected_apis=list(unique_apis)[:5],
                    timestamp=datetime.utcnow(),
                    raw_data={
                        "entropy": entropy,
                        "normalized_entropy": normalized_entropy,
                        "unique_apis": len(unique_apis),
                        "total_calls": total_calls
                    },
                    recommended_action="Check for possible packing or obfuscation"
                ))

        return anomalies


class MLBehaviorClassifier:
    """ML-based behavior classification (placeholder for actual ML model)"""

    def __init__(self):
        self.feature_weights = {
            "api_diversity": 0.15,
            "suspicious_api_ratio": 0.25,
            "network_activity": 0.20,
            "file_manipulation": 0.15,
            "registry_modification": 0.15,
            "process_manipulation": 0.10
        }

        self.suspicious_apis = {
            "createprocess", "createremotethread", "writeprocessmemory",
            "virtualallocex", "loadlibrary", "getprocaddress",
            "internetconnect", "socket", "connect",
            "regsetvalue", "regcreatekey", "regdeletekey",
            "createfile", "writefile", "deletefile",
            "cryptencrypt", "cryptdecrypt", "cryptcreatehash"
        }

    def classify(self, profile: BehaviorProfile) -> Tuple[BehaviorPattern, float]:
        """Classify behavior profile and return pattern + confidence"""

        features = self._extract_features(profile)
        risk_score = self._calculate_risk_score(features)

        if risk_score > 0.8:
            return BehaviorPattern.MALICIOUS, risk_score
        elif risk_score > 0.5:
            return BehaviorPattern.SUSPICIOUS, risk_score
        elif risk_score < 0.2:
            return BehaviorPattern.NORMAL, 1 - risk_score
        else:
            return BehaviorPattern.UNKNOWN, 0.5

    def _extract_features(self, profile: BehaviorProfile) -> Dict[str, float]:
        """Extract behavioral features"""

        all_apis = [call.get("api", "").lower() for call in profile.api_calls]

        unique_apis = set(all_apis)
        total_calls = len(all_apis)

        suspicious_count = sum(
            1 for api in all_apis
            if any(susp in api for susp in self.suspicious_apis)
        )

        features = {
            "api_diversity": len(unique_apis) / max(total_calls, 1),
            "suspicious_api_ratio": suspicious_count / max(total_calls, 1),
            "network_activity": len(profile.network_operations) / max(total_calls, 1),
            "file_manipulation": len(profile.file_operations) / max(total_calls, 1),
            "registry_modification": len(profile.registry_operations) / max(total_calls, 1),
            "process_manipulation": len(profile.process_operations) / max(total_calls, 1)
        }

        return features

    def _calculate_risk_score(self, features: Dict[str, float]) -> float:
        """Calculate overall risk score from features"""

        score = sum(
            features.get(feature, 0) * weight
            for feature, weight in self.feature_weights.items()
        )

        return min(score, 1.0)


class BehavioralAnalysisEngine:
    """Main behavioral analysis engine"""

    def __init__(self):
        self.statistical_analyzer = StatisticalBehaviorAnalyzer()
        self.ml_classifier = MLBehaviorClassifier()
        self.active_profiles: Dict[str, BehaviorProfile] = {}
        self.anomaly_history: List[AnomalyDetection] = []
        self.behavioral_baseline: Optional[Dict[str, Any]] = None

    async def start_profiling(
        self,
        process_id: str,
        binary_hash: str
    ) -> BehaviorProfile:
        """Start behavioral profiling for a process"""

        profile = BehaviorProfile(
            process_id=process_id,
            binary_hash=binary_hash,
            start_time=datetime.utcnow()
        )

        self.active_profiles[process_id] = profile
        log.info(f"Started behavioral profiling for {process_id}")

        return profile

    async def record_event(
        self,
        process_id: str,
        event_type: str,
        event_data: Dict[str, Any]
    ):
        """Record an event for a profile"""

        if process_id not in self.active_profiles:
            return

        profile = self.active_profiles[process_id]

        if event_type == "api_call":
            profile.api_calls.append(event_data)
            api_name = event_data.get("api", "unknown")
            profile.api_frequency[api_name] = profile.api_frequency.get(api_name, 0) + 1

        elif event_type == "file_operation":
            profile.file_operations.append(event_data)

        elif event_type == "network_operation":
            profile.network_operations.append(event_data)

        elif event_type == "registry_operation":
            profile.registry_operations.append(event_data)

        elif event_type == "memory_operation":
            profile.memory_operations.append(event_data)

        elif event_type == "process_operation":
            profile.process_operations.append(event_data)

    async def finalize_profiling(
        self,
        process_id: str
    ) -> Dict[str, Any]:
        """Finalize profiling and generate analysis"""

        if process_id not in self.active_profiles:
            return {"error": "Profile not found"}

        profile = self.active_profiles[process_id]
        profile.end_time = datetime.utcnow()

        if not self.behavioral_baseline:
            self.behavioral_baseline = self.statistical_analyzer.compute_baseline([])

        classification, confidence = self.ml_classifier.classify(profile)
        profile.behavior_classification = classification
        profile.risk_score = confidence

        anomalies = await self._detect_all_anomalies(profile)

        self.anomaly_history.extend(anomalies)

        del self.active_profiles[process_id]

        return {
            "profile": self._profile_to_dict(profile),
            "classification": classification.value,
            "risk_score": confidence,
            "anomalies": [self._anomaly_to_dict(a) for a in anomalies],
            "summary": self._generate_summary(profile, anomalies)
        }

    async def _detect_all_anomalies(
        self,
        profile: BehaviorProfile
    ) -> List[AnomalyDetection]:
        """Run all anomaly detection algorithms"""

        tasks = [
            self.statistical_analyzer.detect_frequency_anomalies(
                profile, self.behavioral_baseline
            ),
            self.statistical_analyzer.detect_sequence_anomalies(profile, []),
            self.statistical_analyzer.detect_entropy_anomalies(profile)
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_anomalies = []
        for result in results:
            if isinstance(result, list):
                all_anomalies.extend(result)

        return all_anomalies

    def _profile_to_dict(self, profile: BehaviorProfile) -> Dict[str, Any]:
        """Convert profile to dictionary"""

        return {
            "process_id": profile.process_id,
            "binary_hash": profile.binary_hash,
            "duration": profile.duration(),
            "api_calls_count": len(profile.api_calls),
            "file_operations_count": len(profile.file_operations),
            "network_operations_count": len(profile.network_operations),
            "registry_operations_count": len(profile.registry_operations),
            "memory_operations_count": len(profile.memory_operations),
            "process_operations_count": len(profile.process_operations),
            "unique_apis": len(profile.api_frequency),
            "top_apis": sorted(
                profile.api_frequency.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
        }

    def _anomaly_to_dict(self, anomaly: AnomalyDetection) -> Dict[str, Any]:
        """Convert anomaly to dictionary"""

        return {
            "type": anomaly.anomaly_type.value,
            "description": anomaly.description,
            "confidence": anomaly.confidence,
            "severity": anomaly.severity,
            "affected_apis": anomaly.affected_apis,
            "timestamp": anomaly.timestamp.isoformat(),
            "recommended_action": anomaly.recommended_action
        }

    def _generate_summary(
        self,
        profile: BehaviorProfile,
        anomalies: List[AnomalyDetection]
    ) -> Dict[str, Any]:
        """Generate analysis summary"""

        critical_count = sum(1 for a in anomalies if a.severity == "critical")
        high_count = sum(1 for a in anomalies if a.severity == "high")
        medium_count = sum(1 for a in anomalies if a.severity == "medium")

        return {
            "classification": profile.behavior_classification.value,
            "risk_score": profile.risk_score,
            "duration": profile.duration(),
            "total_events": (
                len(profile.api_calls) +
                len(profile.file_operations) +
                len(profile.network_operations) +
                len(profile.registry_operations)
            ),
            "anomaly_counts": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "total": len(anomalies)
            },
            "requires_attention": critical_count > 0 or high_count > 2
        }

    async def get_baseline_statistics(self) -> Dict[str, Any]:
        """Get current baseline statistics"""

        return self.behavioral_baseline or {}

    async def update_baseline(self, profiles: List[BehaviorProfile]):
        """Update behavioral baseline with new profiles"""

        self.behavioral_baseline = self.statistical_analyzer.compute_baseline(profiles)
        log.info("Updated behavioral baseline")


_behavioral_engine_instance: Optional[BehavioralAnalysisEngine] = None


def get_behavioral_engine() -> BehavioralAnalysisEngine:
    global _behavioral_engine_instance
    if _behavioral_engine_instance is None:
        _behavioral_engine_instance = BehavioralAnalysisEngine()
    return _behavioral_engine_instance

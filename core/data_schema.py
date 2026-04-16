import os
import json
import logging
import structlog
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path
from pydantic import BaseModel, Field

from core.config import settings

log = structlog.get_logger()


class ExecutionTrace(BaseModel):
    """Schema for execution trace events"""
    timestamp: str
    event_type: str
    process_id: Optional[int] = None
    thread_id: Optional[int] = None
    function_name: Optional[str] = None
    address: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    return_value: Optional[Any] = None
    duration_ms: Optional[float] = None


class MemorySnapshot(BaseModel):
    """Schema for memory snapshot"""
    timestamp: str
    process_id: int
    base_address: str
    size: int
    permissions: str
    data: Optional[str] = None
    region_name: Optional[str] = None


class NetworkEvent(BaseModel):
    """Schema for network events"""
    timestamp: str
    process_id: int
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: str
    direction: str
    size: int
    flags: Optional[str] = None


class FileOperation(BaseModel):
    """Schema for file operations"""
    timestamp: str
    process_id: int
    operation: str
    path: str
    handle: Optional[str] = None
    size: Optional[int] = None
    result: Optional[str] = None


class BehaviorReport(BaseModel):
    """Schema for behavioral analysis report"""
    job_id: str
    binary_path: str
    started_at: str
    completed_at: str
    duration_seconds: float
    execution_traces: List[ExecutionTrace] = Field(default_factory=list)
    memory_snapshots: List[MemorySnapshot] = Field(default_factory=list)
    network_events: List[NetworkEvent] = Field(default_factory=list)
    file_operations: List[FileOperation] = Field(default_factory=list)
    suspicious_activities: List[Dict[str, Any]] = Field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list)
    risk_score: float = 0.0
    summary: str = ""


class DataStorage:
    """Handle storage of dynamic analysis artifacts"""

    def __init__(self):
        self.data_dir = settings.DATA_DIR
        self.ensure_directories()

    def ensure_directories(self):
        """Ensure all required directories exist"""
        directories = [
            self.data_dir,
            self.data_dir / "artifacts",
            self.data_dir / "execution_traces",
            self.data_dir / "memory_dumps",
            self.data_dir / "network_captures",
            self.data_dir / "behavior_reports"
        ]

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

    def save_execution_trace(self, job_id: str, trace: ExecutionTrace) -> str:
        """Save an execution trace to disk"""
        try:
            trace_dir = self.data_dir / "execution_traces" / job_id
            trace_dir.mkdir(parents=True, exist_ok=True)

            trace_file = trace_dir / f"trace_{datetime.utcnow().timestamp()}.json"
            trace_file.write_text(trace.json(), encoding='utf-8')

            log.info(f"Saved execution trace to {trace_file}")
            return str(trace_file)

        except Exception as e:
            log.error(f"Failed to save execution trace: {e}", exc_info=True)
            return ""

    def save_memory_snapshot(self, job_id: str, snapshot: MemorySnapshot) -> str:
        """Save a memory snapshot to disk"""
        try:
            snapshot_dir = self.data_dir / "memory_dumps" / job_id
            snapshot_dir.mkdir(parents=True, exist_ok=True)

            snapshot_file = snapshot_dir / f"snapshot_{datetime.utcnow().timestamp()}.json"
            snapshot_file.write_text(snapshot.json(), encoding='utf-8')

            log.info(f"Saved memory snapshot to {snapshot_file}")
            return str(snapshot_file)

        except Exception as e:
            log.error(f"Failed to save memory snapshot: {e}", exc_info=True)
            return ""

    def save_network_event(self, job_id: str, event: NetworkEvent) -> str:
        """Save a network event to disk"""
        try:
            event_dir = self.data_dir / "network_captures" / job_id
            event_dir.mkdir(parents=True, exist_ok=True)

            event_file = event_dir / f"event_{datetime.utcnow().timestamp()}.json"
            event_file.write_text(event.json(), encoding='utf-8')

            log.info(f"Saved network event to {event_file}")
            return str(event_file)

        except Exception as e:
            log.error(f"Failed to save network event: {e}", exc_info=True)
            return ""

    def save_file_operation(self, job_id: str, operation: FileOperation) -> str:
        """Save a file operation to disk"""
        try:
            operation_dir = self.data_dir / "artifacts" / job_id
            operation_dir.mkdir(parents=True, exist_ok=True)

            operation_file = operation_dir / f"operation_{datetime.utcnow().timestamp()}.json"
            operation_file.write_text(operation.json(), encoding='utf-8')

            log.info(f"Saved file operation to {operation_file}")
            return str(operation_file)

        except Exception as e:
            log.error(f"Failed to save file operation: {e}", exc_info=True)
            return ""

    def save_behavior_report(self, job_id: str, report: BehaviorReport) -> str:
        """Save a complete behavior report to disk"""
        try:
            report_dir = self.data_dir / "behavior_reports"
            report_dir.mkdir(parents=True, exist_ok=True)

            report_file = report_dir / f"{job_id}_report.json"
            report_file.write_text(report.json(indent=2), encoding='utf-8')

            log.info(f"Saved behavior report to {report_file}")
            return str(report_file)

        except Exception as e:
            log.error(f"Failed to save behavior report: {e}", exc_info=True)
            return ""

    def load_behavior_report(self, job_id: str) -> Optional[BehaviorReport]:
        """Load a behavior report from disk"""
        try:
            report_file = self.data_dir / "behavior_reports" / f"{job_id}_report.json"
            if not report_file.exists():
                return None

            report_data = json.loads(report_file.read_text(encoding='utf-8'))
            return BehaviorReport(**report_data)

        except Exception as e:
            log.error(f"Failed to load behavior report for job {job_id}: {e}", exc_info=True)
            return None

    def get_job_artifacts(self, job_id: str) -> Dict[str, List[str]]:
        """Get all artifacts for a job"""
        try:
            artifacts = {
                "execution_traces": [],
                "memory_snapshots": [],
                "network_events": [],
                "file_operations": []
            }

            trace_dir = self.data_dir / "execution_traces" / job_id
            if trace_dir.exists():
                artifacts["execution_traces"] = [str(f) for f in trace_dir.glob("*.json")]

            snapshot_dir = self.data_dir / "memory_dumps" / job_id
            if snapshot_dir.exists():
                artifacts["memory_snapshots"] = [str(f) for f in snapshot_dir.glob("*.json")]

            event_dir = self.data_dir / "network_captures" / job_id
            if event_dir.exists():
                artifacts["network_events"] = [str(f) for f in event_dir.glob("*.json")]

            operation_dir = self.data_dir / "artifacts" / job_id
            if operation_dir.exists():
                artifacts["file_operations"] = [str(f) for f in operation_dir.glob("*.json")]

            return artifacts

        except Exception as e:
            log.error(f"Failed to get artifacts for job {job_id}: {e}", exc_info=True)
            return {}

    def cleanup_job_artifacts(self, job_id: str) -> bool:
        """Clean up all artifacts for a job"""
        try:
            directories = [
                self.data_dir / "execution_traces" / job_id,
                self.data_dir / "memory_dumps" / job_id,
                self.data_dir / "network_captures" / job_id,
                self.data_dir / "artifacts" / job_id
            ]

            for directory in directories:
                if directory.exists():
                    for item in directory.iterdir():
                        if item.is_file():
                            item.unlink()
                    directory.rmdir()

            log.info(f"Cleaned up artifacts for job {job_id}")
            return True

        except Exception as e:
            log.error(f"Failed to cleanup artifacts for job {job_id}: {e}", exc_info=True)
            return False


_data_storage_instance: Optional[DataStorage] = None


def get_data_storage() -> DataStorage:
    """Get or create data storage instance"""
    global _data_storage_instance
    if _data_storage_instance is None:
        _data_storage_instance = DataStorage()
    return _data_storage_instance

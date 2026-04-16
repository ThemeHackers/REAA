import os
import json
import uuid
import docker
import logging
import structlog
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime

from core.config import settings

log = structlog.get_logger()


class ActiveRESandbox:
    """manager for Docker sandbox lifecycle for Active Reverse Engineering"""

    def __init__(self):
        self.docker_client = docker.from_env()
        self.container_name = None
        self.sandbox_image = settings.ACTIVE_RE_SANDBOX_IMAGE

    def start_sandbox(self, job_id: str) -> str:
        container_id = uuid.uuid4().hex
        self.container_name = f"reaa-active-re-{job_id}-{container_id[:8]}"

        try:
            container = self.docker_client.containers.run(
                self.sandbox_image,
                name=self.container_name,
                detach=True,
                network_mode=settings.ACTIVE_RE_NETWORK_MODE,
                mem_limit=settings.ACTIVE_RE_MAX_MEMORY,
                cpu_quota=int(settings.ACTIVE_RE_MAX_CPU * 100000),
                volumes={
                    str(settings.DATA_DIR / job_id): {
                        'bind': '/app/data',
                        'mode': 'rw'
                    },
                    str(settings.DATA_DIR / job_id / 'artifacts'): {
                        'bind': '/app/artifacts',
                        'mode': 'rw'
                    }
                },
                environment={
                    'FRIDA_SCRIPTS_DIR': '/app/frida_scripts',
                    'PYTHONUNBUFFERED': '1'
                },
                security_opt=['no-new-privileges'],
                cap_drop=['ALL'],
                cap_add=['NET_BIND_SERVICE'],
                read_only=True,
                tmpfs={'/tmp': 'noexec,nosuid,size=100m'}
            )

            log.info(f"Started sandbox container: {self.container_name}")
            return self.container_name

        except Exception as e:
            log.error(f"Failed to start sandbox: {e}", exc_info=True)
            raise

    def stop_sandbox(self) -> bool:
        if not self.container_name:
            return True

        try:
            container = self.docker_client.containers.get(self.container_name)
            container.stop(timeout=10)
            container.remove()
            log.info(f"Stopped sandbox container: {self.container_name}")
            self.container_name = None
            return True
        except Exception as e:
            log.error(f"Failed to stop sandbox: {e}", exc_info=True)
            return False

    def execute_in_sandbox(self, command: List[str]) -> Dict[str, Any]:
        if not self.container_name:
            return {"error": "No sandbox running"}

        try:
            container = self.docker_client.containers.get(self.container_name)
            result = container.exec_run(
                cmd=command,
                workdir='/app/data',
                demux=True
            )

            return {
                "exit_code": result.exit_code,
                "stdout": result.output[0].decode('utf-8', errors='ignore') if result.output[0] else "",
                "stderr": result.output[1].decode('utf-8', errors='ignore') if result.output[1] else ""
            }
        except Exception as e:
            log.error(f"Failed to execute in sandbox: {e}", exc_info=True)
            return {"error": str(e)}

    def get_sandbox_status(self) -> Dict[str, Any]:
        if not self.container_name:
            return {"status": "not_running"}

        try:
            container = self.docker_client.containers.get(self.container_name)
            return {
                "status": container.status,
                "container_id": container.id,
                "image": container.image.tags[0] if container.image.tags else "unknown"
            }
        except Exception as e:
            log.error(f"Failed to get sandbox status: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}


class ActiveREService:
    """Main service for Active Reverse Engineering operations"""

    def __init__(self):
        self.sandbox = ActiveRESandbox()
        self.active_jobs: Dict[str, Dict[str, Any]] = {}

    def start_analysis(self, job_id: str, binary_path: str) -> Dict[str, Any]:
        job_info = {
            "job_id": job_id,
            "binary_path": binary_path,
            "status": "initializing",
            "started_at": datetime.utcnow().isoformat(),
            "sandbox_name": None,
            "execution_trace": []
        }

        try:
            sandbox_name = self.sandbox.start_sandbox(job_id)
            job_info["sandbox_name"] = sandbox_name
            job_info["status"] = "sandbox_ready"

            self.active_jobs[job_id] = job_info

            return {
                "job_id": job_id,
                "status": "started",
                "sandbox_name": sandbox_name
            }
        except Exception as e:
            log.error(f"Failed to start analysis for job {job_id}: {e}", exc_info=True)
            job_info["status"] = "failed"
            job_info["error"] = str(e)
            return {"error": str(e)}

    def execute_binary(self, job_id: str, args: List[str] = None) -> Dict[str, Any]:
        if job_id not in self.active_jobs:
            return {"error": "Job not found"}

        job_info = self.active_jobs[job_id]

        if job_info["status"] != "sandbox_ready":
            return {"error": f"Job not in ready state: {job_info['status']}"}

        try:
            binary_name = Path(job_info["binary_path"]).name
            command = [f"./{binary_name}"]
            if args:
                command.extend(args)

            result = self.sandbox.execute_in_sandbox(command)

            job_info["execution_trace"].append({
                "timestamp": datetime.utcnow().isoformat(),
                "command": command,
                "result": result
            })

            job_info["status"] = "executed"

            return result

        except Exception as e:
            log.error(f"Failed to execute binary for job {job_id}: {e}", exc_info=True)
            job_info["status"] = "execution_failed"
            job_info["error"] = str(e)
            return {"error": str(e)}

    def stop_analysis(self, job_id: str) -> Dict[str, Any]:
        if job_id not in self.active_jobs:
            return {"error": "Job not found"}

        try:
            success = self.sandbox.stop_sandbox()
            self.active_jobs[job_id]["status"] = "stopped"
            self.active_jobs[job_id]["stopped_at"] = datetime.utcnow().isoformat()

            return {"job_id": job_id, "status": "stopped", "success": success}
        except Exception as e:
            log.error(f"Failed to stop analysis for job {job_id}: {e}", exc_info=True)
            return {"error": str(e)}

    def get_job_status(self, job_id: str) -> Dict[str, Any]:
        if job_id not in self.active_jobs:
            return {"error": "Job not found"}

        job_info = self.active_jobs[job_id].copy()
        job_info["sandbox_status"] = self.sandbox.get_sandbox_status()

        return job_info

    def cleanup_job(self, job_id: str) -> bool:
        if job_id in self.active_jobs:
            self.stop_analysis(job_id)
            del self.active_jobs[job_id]
        return True


_active_re_service_instance: Optional[ActiveREService] = None


def get_active_re_service() -> ActiveREService:
    global _active_re_service_instance
    if _active_re_service_instance is None:
        _active_re_service_instance = ActiveREService()
    return _active_re_service_instance

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
from core.file_type_detector import FileTypeDetector, BinaryType

log = structlog.get_logger()


class ActiveRESandbox:

    def __init__(self, image: str = None):
        try:
            self.docker_client = docker.from_env()
        except AttributeError:
            self.docker_client = docker.DockerClient()
        self.container_name = "reaa-active-re-linux-sandbox"
        self.sandbox_image = image or settings.ACTIVE_RE_SANDBOX_IMAGE
        self.start_time = None
        self.max_runtime = getattr(settings, 'ACTIVE_RE_MAX_RUNTIME', 3600)  

    def start_sandbox(self, job_id: str) -> str:
        self.start_time = datetime.utcnow()

        try:
            try:
                existing_container = self.docker_client.containers.get(self.container_name)
                if existing_container:
                    if existing_container.status == 'running':
                        return self.container_name
                    else:
                        existing_container.start()
                        return self.container_name
            except:
                pass
            
            data_dir = settings.DATA_DIR
            job_dir = data_dir / job_id
            artifacts_dir = job_dir / 'artifacts'
            
            if not data_dir.is_absolute():
                data_dir = Path(os.path.abspath(str(data_dir)))
                job_dir = data_dir / job_id
                artifacts_dir = job_dir / 'artifacts'
            
            job_dir.mkdir(parents=True, exist_ok=True)
            artifacts_dir.mkdir(parents=True, exist_ok=True)
            
            container = self.docker_client.containers.run(
                self.sandbox_image,
                name=self.container_name,
                detach=True,
                working_dir='/app',
                network_mode=settings.ACTIVE_RE_NETWORK_MODE,
                mem_limit=settings.ACTIVE_RE_MAX_MEMORY,
                cpu_quota=int(settings.ACTIVE_RE_MAX_CPU * 100000),
                volumes={
                    str(data_dir): {
                        'bind': '/app/data',
                        'mode': 'rw'
                    }
                },
                environment={
                    'FRIDA_SCRIPTS_DIR': '/app/frida_scripts',
                    'PYTHONUNBUFFERED': '1',
                    'MAX_RUNTIME': str(self.max_runtime)
                },
                security_opt=['no-new-privileges'],
                cap_drop=['ALL'],
                cap_add=['NET_BIND_SERVICE', 'NET_RAW', 'SYS_PTRACE'],
                healthcheck={
                    'test': ['CMD', 'curl', '-f', 'http://localhost:8080'],
                    'interval': 30000000,
                    'timeout': 10000000,
                    'retries': 3
                }
            )

            return self.container_name

        except Exception as e:
            log.error(f"Failed to start sandbox: {e}", exc_info=True)
            self.start_time = None
            raise

    def stop_sandbox(self, force: bool = False, remove_container: bool = False) -> bool:
        if not self.container_name:
            return True

        try:
            container = self.docker_client.containers.get(self.container_name)
            
            if force:
                container.kill()
            else:
                container.stop(timeout=10)
            
            if remove_container:
                container.remove()
                self.container_name = None
                self.start_time = None
            
            return True
        except Exception as e:
            log.error(f"Failed to stop sandbox: {e}", exc_info=True)
            try:
                container = self.docker_client.containers.get(self.container_name)
                container.kill()
                if remove_container:
                    container.remove()
                    self.container_name = None
                    self.start_time = None
                return True
            except Exception as cleanup_error:
                self.container_name = None
                self.start_time = None
                log.error(f"Failed to cleanup sandbox: {cleanup_error}")
                return False

    def execute_in_sandbox(self, command: List[str]) -> Dict[str, Any]:
        if not self.container_name:
            return {"error": "No sandbox running"}

        try:
            container = self.docker_client.containers.get(self.container_name)
            result = container.exec_run(
                cmd=command,
                workdir='/app',
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
            status = {
                "status": container.status,
                "container_id": container.id,
                "image": container.image.tags[0] if container.image.tags else "unknown",
                "runtime": None,
                "near_timeout": False
            }
            
            if self.start_time:
                runtime = (datetime.utcnow() - self.start_time).total_seconds()
                status["runtime"] = runtime
                status["near_timeout"] = runtime > (self.max_runtime * 0.9) 
            
            return status
        except Exception as e:
            log.error(f"Failed to get sandbox status: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}

    def check_runtime_exceeded(self) -> bool:
        if not self.start_time:
            return False
        
        runtime = (datetime.utcnow() - self.start_time).total_seconds()
        return runtime > self.max_runtime


class ActiveREService:


    LINUX_IMAGE = settings.ACTIVE_RE_SANDBOX_IMAGE
    WINDOWS_IMAGE = getattr(settings, 'ACTIVE_RE_WINDOWS_IMAGE', 'reaa-active-re-windows:latest')

    def __init__(self):
        self.sandboxes: Dict[str, ActiveRESandbox] = {}
        self.active_jobs: Dict[str, Dict[str, Any]] = {}
        self.max_retries = getattr(settings, 'ACTIVE_RE_MAX_RETRIES', 3)
        self.retry_delay = getattr(settings, 'ACTIVE_RE_RETRY_DELAY', 2)

    def _get_sandbox_for_binary(self, binary_path: str) -> ActiveRESandbox:
        """Get or create appropriate sandbox based on binary type"""
        binary_type = FileTypeDetector.detect(binary_path)

        if binary_type == BinaryType.PE:
        
            image = self.WINDOWS_IMAGE
            container_name = "reaa-active-re-windows"
            log.info(f"Detected Windows binary (PE), using Wine sandbox: {image}")
        elif binary_type == BinaryType.ELF:
        
            image = self.LINUX_IMAGE
            container_name = "reaa-active-re-linux-sandbox"
            log.info(f"Detected Linux binary (ELF), using Linux sandbox: {image}")
        elif binary_type == BinaryType.MACHO:
         
            image = self.LINUX_IMAGE
            container_name = "reaa-active-re-macho"
            log.info(f"Detected macOS binary (Mach-O), using Linux sandbox (limited support)")
        else:
          
            image = self.LINUX_IMAGE
            container_name = "reaa-active-re-linux-sandbox"
            log.warning(f"Unknown binary type for {binary_path}, defaulting to Linux sandbox")

       
        sandbox = ActiveRESandbox(image=image)
        sandbox.container_name = container_name
        return sandbox, binary_type

    def start_analysis(self, job_id: str, binary_path: str) -> Dict[str, Any]:
      
        sandbox, binary_type = self._get_sandbox_for_binary(binary_path)

        job_info = {
            "job_id": job_id,
            "binary_path": binary_path,
            "binary_type": binary_type.value,
            "status": "initializing",
            "started_at": datetime.utcnow().isoformat(),
            "sandbox_name": None,
            "execution_trace": [],
            "retry_count": 0,
            "requires_wine": binary_type == BinaryType.PE
        }

        for attempt in range(self.max_retries + 1):
            try:
                sandbox_name = sandbox.start_sandbox(job_id)
                job_info["sandbox_name"] = sandbox_name
                job_info["status"] = "sandbox_ready"
                job_info["retry_count"] = attempt

                self.active_jobs[job_id] = job_info
                self.sandboxes[job_id] = sandbox

                return {
                    "job_id": job_id,
                    "status": "started",
                    "sandbox_name": sandbox_name,
                    "binary_type": binary_type.value,
                    "attempts": attempt + 1
                }
            except Exception as e:
                log.error(f"Failed to start analysis for job {job_id} (attempt {attempt + 1}/{self.max_retries + 1}): {e}")
                if attempt < self.max_retries:
                    import time
                    time.sleep(self.retry_delay * (2 ** attempt))
                else:
                    job_info["status"] = "failed"
                    job_info["error"] = str(e)
                    return {"error": str(e), "attempts": attempt + 1}

    def execute_binary(self, job_id: str, args: List[str] = None, timeout: int = None) -> Dict[str, Any]:
        if job_id not in self.active_jobs:
            return {"error": "Job not found"}

        job_info = self.active_jobs[job_id]

        if job_info["status"] != "sandbox_ready":
            return {"error": f"Job not in ready state: {job_info['status']}"}

      
        sandbox = self.sandboxes.get(job_id)
        if not sandbox:
            return {"error": "Sandbox not found for job"}

        if sandbox.check_runtime_exceeded():
            log.warning(f"Job {job_id} exceeded max runtime, forcing stop")
            sandbox.stop_sandbox(force=True)
            job_info["status"] = "timeout"
            return {"error": "Runtime exceeded", "timeout": True}

        try:
            binary_path = job_info["binary_path"]
            binary_type = job_info.get("binary_type", "unknown")
            requires_wine = job_info.get("requires_wine", False)

         
            if binary_path.startswith("data/"):
                container_binary_path = binary_path.replace("data/", "/app/data/")
            elif "\\" in binary_path or "/" in binary_path:
                from pathlib import Path as LibPath
                path_obj = LibPath(binary_path)
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

        
            if requires_wine:
             
                command = ["wine", container_binary_path]
                log.info(f"Using Wine to execute Windows binary: {container_binary_path}")
            else:
             
                command = [container_binary_path]

            if args:
                command.extend(args)

            result = sandbox.execute_in_sandbox(command)

            job_info["execution_trace"].append({
                "timestamp": datetime.utcnow().isoformat(),
                "command": command,
                "result": result
            })

            job_info["status"] = "executed"

            return {
                "exit_code": result.get("exit_code", -1),
                "stdout": result.get("stdout", ""),
                "stderr": result.get("stderr", ""),
                "binary_type": binary_type,
                "used_wine": requires_wine
            }

        except Exception as e:
            log.error(f"Failed to execute binary for job {job_id}: {e}", exc_info=True)
            job_info["status"] = "execution_failed"
            job_info["error"] = str(e)
            return {"error": str(e)}

    def stop_analysis(self, job_id: str) -> Dict[str, Any]:
        if job_id not in self.active_jobs:
            return {"error": "Job not found"}

        try:
       
            sandbox = self.sandboxes.get(job_id)
            if sandbox:
                success = sandbox.stop_sandbox(remove_container=False)
            else:
                success = True

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

     
        sandbox = self.sandboxes.get(job_id)
        if sandbox:
            job_info["sandbox_status"] = sandbox.get_sandbox_status()
        else:
            job_info["sandbox_status"] = {"status": "unknown"}

        return job_info

    def cleanup_job(self, job_id: str) -> bool:
        if job_id in self.active_jobs:
            self.stop_analysis(job_id)
            del self.active_jobs[job_id]
            if job_id in self.sandboxes:
                del self.sandboxes[job_id]
        return True

    def cleanup_shared_container(self) -> bool:
        """Remove all sandboxes (for cleanup)"""
        try:
            for job_id, sandbox in self.sandboxes.items():
                try:
                    sandbox.stop_sandbox(force=True, remove_container=True)
                    log.info(f"Cleaned up sandbox for job {job_id}")
                except Exception as e:
                    log.error(f"Failed to cleanup sandbox for job {job_id}: {e}")

            self.sandboxes.clear()
            return True
        except Exception as e:
            log.error(f"Failed to cleanup containers: {e}", exc_info=True)
            return False


_active_re_service_instance: Optional[ActiveREService] = None


def get_active_re_service() -> ActiveREService:
    global _active_re_service_instance
    if _active_re_service_instance is None:
        _active_re_service_instance = ActiveREService()
    return _active_re_service_instance

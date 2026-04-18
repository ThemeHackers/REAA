import os
import json
import logging
import structlog
import psutil
import subprocess
import threading
from typing import Optional, Dict, Any, List, Callable
from datetime import datetime

log = structlog.get_logger()


class ProcessMonitor:
    """Monitor process creation, termination, and behavior"""

    def __init__(self):
        self.processes: Dict[int, Dict[str, Any]] = {}
        self.events: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self.alerts: List[Dict[str, Any]] = []
        self.monitoring_active = False
        self.alert_thresholds = {
            "cpu_percent": 80.0,
            "memory_mb": 1000,
            "connection_count": 50
        }

    def start_monitoring(self, pid: int = None) -> Dict[str, Any]:
        """Start monitoring a specific process or all processes"""
        if pid:
            return self._monitor_single_process(pid)
        else:
            return self._monitor_all_processes()

    def _monitor_single_process(self, pid: int) -> Dict[str, Any]:
        """Monitor a single process"""
        try:
            process = psutil.Process(pid)
            process_info = {
                "pid": pid,
                "name": process.name(),
                "status": process.status(),
                "create_time": process.create_time(),
                "cpu_percent": process.cpu_percent(),
                "memory_info": {
                    "rss": process.memory_info().rss,
                    "vms": process.memory_info().vms
                },
                "num_threads": process.num_threads(),
                "connections": [],
                "open_files": []
            }

            try:
                process_info["connections"] = [
                    {
                        "local_address": conn.laddr,
                        "remote_address": conn.raddr,
                        "status": conn.status
                    }
                    for conn in process.connections()
                ]
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            try:
                process_info["open_files"] = [
                    {"path": f.path, "fd": f.fd}
                    for f in process.open_files()
                ]
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            with self._lock:
                self.processes[pid] = process_info
            self._log_event("process_monitored", {"pid": pid, "name": process.name()})

            return process_info

        except psutil.NoSuchProcess:
            log.error(f"Process {pid} not found")
            return {"error": "Process not found"}
        except Exception as e:
            log.error(f"Failed to monitor process {pid}: {e}", exc_info=True)
            return {"error": str(e)}

    def _monitor_all_processes(self) -> Dict[str, Any]:
        """Monitor all processes"""
        all_processes = {}
        for proc in psutil.process_iter(['pid', 'name', 'status']):
            try:
                pid = proc.info['pid']
                process_info = self._monitor_single_process(pid)
                if "error" not in process_info:
                    all_processes[pid] = process_info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return {"processes": all_processes, "count": len(all_processes)}

    def get_process_tree(self, pid: int) -> Optional[Dict[str, Any]]:
        """Get process tree starting from a PID"""
        try:
            process = psutil.Process(pid)
            tree = self._build_process_tree(process)
            return tree
        except psutil.NoSuchProcess:
            log.error(f"Process {pid} not found")
            return None

    def _build_process_tree(self, process: psutil.Process) -> Dict[str, Any]:
        """Recursively build process tree"""
        try:
            children = process.children(recursive=False)
            return {
                "pid": process.pid,
                "name": process.name(),
                "status": process.status(),
                "children": [self._build_process_tree(child) for child in children]
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {"pid": process.pid, "name": "unknown", "children": []}

    def trace_syscalls(self, pid: int, duration: int = 10) -> Dict[str, Any]:
        """Trace system calls for a process using strace"""
        try:
            cmd = ["strace", "-p", str(pid), "-f", "-e", "trace=all", "-o", "/dev/stdout"]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=duration
            )

            output, error = process.communicate()

            syscalls = []
            for line in output.split("\n"):
                if line.strip():
                    syscalls.append({"syscall": line, "timestamp": datetime.utcnow().isoformat()})

            return {
                "pid": pid,
                "duration": duration,
                "syscalls": syscalls,
                "count": len(syscalls)
            }

        except subprocess.TimeoutExpired:
            log.error(f"Syscall tracing timed out for process {pid}")
            return {"error": "Timeout"}
        except Exception as e:
            log.error(f"Failed to trace syscalls for process {pid}: {e}", exc_info=True)
            return {"error": str(e)}

    def get_process_environment(self, pid: int) -> Optional[Dict[str, str]]:
        """Get environment variables for a process (Linux only)"""
        try:
            with open(f"/proc/{pid}/environ", "r") as f:
                env_data = f.read()

            env_vars = {}
            for line in env_data.split("\x00"):
                if "=" in line:
                    key, value = line.split("=", 1)
                    env_vars[key] = value

            return env_vars

        except (FileNotFoundError, PermissionError) as e:
            log.error(f"Failed to get environment for process {pid}: {e}")
            return None

    def kill_process(self, pid: int, signal: int = 15) -> bool:
        """Send signal to process"""
        try:
            process = psutil.Process(pid)
            process.send_signal(signal)
            self._log_event("process_killed", {"pid": pid, "signal": signal})
            return True
        except psutil.NoSuchProcess:
            log.error(f"Process {pid} not found")
            return False
        except Exception as e:
            log.error(f"Failed to kill process {pid}: {e}", exc_info=True)
            return False

    def get_events(self) -> List[Dict[str, Any]]:
        """Get all logged events"""
        return self.events.copy()

    def clear_events(self):
        """Clear event log"""
        self.events.clear()

    def _log_event(self, event_type: str, data: Dict[str, Any]):
        """Log an event"""
        event = {
            "type": event_type,
            "data": data,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.events.append(event)
        log.info(f"Event logged: {event_type}", event_data=data)

    def start_realtime_monitoring(self, pid: int, interval: int = 5, callback: Callable = None) -> None:
        """Start real-time monitoring of a process"""
        self.monitoring_active = True
        import threading
        
        def monitor_loop():
            while self.monitoring_active:
                try:
                    process_info = self._monitor_single_process(pid)
                    self._check_alerts(process_info)
                    if callback:
                        callback(process_info)
                except psutil.NoSuchProcess:
                    self._log_event("process_terminated", {"pid": pid})
                    break
                except Exception as e:
                    log.error(f"Error in realtime monitoring: {e}")
                
                import time
                time.sleep(interval)
        
        thread = threading.Thread(target=monitor_loop, daemon=True)
        thread.start()
        log.info(f"Started realtime monitoring for PID {pid} with {interval}s interval")

    def stop_realtime_monitoring(self) -> None:
        """Stop real-time monitoring"""
        self.monitoring_active = False
        log.info("Stopped realtime monitoring")

    def _check_alerts(self, process_info: Dict[str, Any]) -> None:
        """Check if process exceeds alert thresholds"""
        if "error" in process_info:
            return

        pid = process_info["pid"]
        
      
        cpu_percent = process_info.get("cpu_percent", 0)
        if cpu_percent > self.alert_thresholds["cpu_percent"]:
            alert = {
                "type": "cpu_high",
                "pid": pid,
                "value": cpu_percent,
                "threshold": self.alert_thresholds["cpu_percent"],
                "timestamp": datetime.utcnow().isoformat()
            }
            self.alerts.append(alert)
            log.warning(f"CPU alert for PID {pid}: {cpu_percent}%")

       
        memory_mb = process_info.get("memory_info", {}).get("rss", 0) / (1024 * 1024)
        if memory_mb > self.alert_thresholds["memory_mb"]:
            alert = {
                "type": "memory_high",
                "pid": pid,
                "value": memory_mb,
                "threshold": self.alert_thresholds["memory_mb"],
                "timestamp": datetime.utcnow().isoformat()
            }
            self.alerts.append(alert)
            log.warning(f"Memory alert for PID {pid}: {memory_mb:.2f} MB")

     
        conn_count = len(process_info.get("connections", []))
        if conn_count > self.alert_thresholds["connection_count"]:
            alert = {
                "type": "connection_high",
                "pid": pid,
                "value": conn_count,
                "threshold": self.alert_thresholds["connection_count"],
                "timestamp": datetime.utcnow().isoformat()
            }
            self.alerts.append(alert)
            log.warning(f"Connection alert for PID {pid}: {conn_count} connections")

    def get_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        return self.alerts[-limit:]

    def clear_alerts(self) -> None:
        """Clear all alerts"""
        with self._lock:
            self.alerts.clear()
        log.info("Cleared all alerts")

    def set_alert_threshold(self, metric: str, value: float) -> None:
        """Set alert threshold for a metric"""
        if metric in self.alert_thresholds:
            self.alert_thresholds[metric] = value
            log.info(f"Set alert threshold for {metric} to {value}")
        else:
            log.warning(f"Unknown metric: {metric}")

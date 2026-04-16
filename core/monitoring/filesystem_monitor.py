import os
import json
import logging
import structlog
import psutil
import subprocess
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path

log = structlog.get_logger()


class FilesystemMonitor:
    """Monitor filesystem changes and file operations"""

    def __init__(self):
        self.watches: Dict[str, Dict[str, Any]] = {}
        self.events: List[Dict[str, Any]] = []

    def watch_directory(self, path: str, recursive: bool = True) -> bool:
        """Start watching a directory for changes"""
        try:
            if not Path(path).exists():
                log.error(f"Directory {path} does not exist")
                return False

            self.watches[path] = {
                "path": path,
                "recursive": recursive,
                "started_at": datetime.utcnow().isoformat()
            }

            log.info(f"Started watching directory: {path}")
            return True

        except Exception as e:
            log.error(f"Failed to watch directory {path}: {e}", exc_info=True)
            return False

    def get_file_changes(self, pid: int) -> List[Dict[str, Any]]:
        """Get file changes made by a process"""
        try:
            process = psutil.Process(pid)
            open_files = process.open_files()

            changes = []
            for file_info in open_files:
                change_info = {
                    "pid": pid,
                    "path": file_info.path,
                    "fd": file_info.fd,
                    "mode": file_info.mode,
                    "timestamp": datetime.utcnow().isoformat()
                }
                changes.append(change_info)

            return changes

        except psutil.NoSuchProcess:
            log.error(f"Process {pid} not found")
            return []
        except Exception as e:
            log.error(f"Failed to get file changes for PID {pid}: {e}", exc_info=True)
            return []

    def get_disk_usage(self, path: str = "/") -> Optional[Dict[str, Any]]:
        """Get disk usage statistics"""
        try:
            usage = psutil.disk_usage(path)

            return {
                "path": path,
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
                "percent": usage.percent,
                "timestamp": datetime.utcnow().isoformat()
            }

        except Exception as e:
            log.error(f"Failed to get disk usage for {path}: {e}", exc_info=True)
            return None

    def get_disk_partitions(self) -> List[Dict[str, Any]]:
        """Get disk partition information"""
        try:
            partitions = []
            for part in psutil.disk_partitions(all=True):
                part_info = {
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "opts": part.opts
                }
                partitions.append(part_info)

            return partitions

        except Exception as e:
            log.error(f"Failed to get disk partitions: {e}", exc_info=True)
            return []

    def get_file_info(self, path: str) -> Optional[Dict[str, Any]]:
        """Get detailed file information"""
        try:
            file_path = Path(path)
            if not file_path.exists():
                return None

            stat = file_path.stat()

            info = {
                "path": path,
                "size": stat.st_size,
                "created": stat.st_ctime,
                "modified": stat.st_mtime,
                "accessed": stat.st_atime,
                "is_file": file_path.is_file(),
                "is_dir": file_path.is_dir(),
                "is_symlink": file_path.is_symlink(),
                "permissions": oct(stat.st_mode)[-3:]
            }

            if file_path.is_file():
                try:
                    info["mime_type"] = subprocess.check_output(
                        ["file", "--mime-type", path],
                        stderr=subprocess.DEVNULL
                    ).decode().strip().split(":")[1].strip()
                except:
                    info["mime_type"] = "unknown"

            return info

        except Exception as e:
            log.error(f"Failed to get file info for {path}: {e}", exc_info=True)
            return None

    def scan_directory(self, path: str, pattern: str = "*") -> List[Dict[str, Any]]:
        """Scan a directory for files matching a pattern"""
        try:
            files = []
            for item in Path(path).glob(pattern):
                info = self.get_file_info(str(item))
                if info:
                    files.append(info)

            return files

        except Exception as e:
            log.error(f"Failed to scan directory {path}: {e}", exc_info=True)
            return []

    def detect_suspicious_files(self, path: str) -> List[Dict[str, Any]]:
        """Detect potentially suspicious files"""
        try:
            suspicious = []
            suspicious_extensions = [".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".vbs", ".js"]

            for file_info in self.scan_directory(path, "*"):
                if file_info.get("is_file"):
                    ext = Path(file_info["path"]).suffix.lower()

                    if ext in suspicious_extensions:
                        suspicious.append({
                            "file": file_info,
                            "reason": "suspicious_extension",
                            "extension": ext
                        })

                    if file_info.get("size", 0) > 10 * 1024 * 1024:
                        suspicious.append({
                            "file": file_info,
                            "reason": "large_file",
                            "size": file_info["size"]
                        })

                    if file_info.get("permissions") == "777":
                        suspicious.append({
                            "file": file_info,
                            "reason": "world_writable",
                            "permissions": file_info["permissions"]
                        })

            return suspicious

        except Exception as e:
            log.error(f"Failed to detect suspicious files in {path}: {e}", exc_info=True)
            return []

    def get_events(self) -> List[Dict[str, Any]]:
        """Get all filesystem events"""
        return self.events.copy()

    def clear_events(self):
        """Clear event log"""
        self.events.clear()

    def _log_event(self, event_type: str, data: Dict[str, Any]):
        """Log a filesystem event"""
        event = {
            "type": event_type,
            "data": data,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.events.append(event)
        log.info(f"Filesystem event logged: {event_type}", event_data=data)

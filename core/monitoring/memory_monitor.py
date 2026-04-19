import os
import json
import logging
import structlog
import psutil
import threading
from typing import Optional, Dict, Any, List
from datetime import datetime

log = structlog.get_logger()


class MemoryMonitor:
    """Monitor memory access patterns and allocations"""

    def __init__(self):
        self.snapshots: List[Dict[str, Any]] = []
        self.memory_regions: Dict[int, List[Dict[str, Any]]] = {}
        self._lock = threading.Lock()
        self.anomalies: List[Dict[str, Any]] = []
        self.patterns: Dict[str, Dict[str, List[bytes]]] = {
            "shellcode": {
                "nop_sleds": [b"\x90\x90\x90\x90", b"\x90" * 8, b"\x90" * 16],
                "common_opcodes": [
                    b"\x31\xc0", 
                    b"\x50",     
                    b"\x90",    
                    b"\xcc",     
                    b"\xc3",     
                    b"\xeb",    
                    b"\xe9",      
                ],
                "shell_exec": [
                    b"/bin/sh",
                    b"cmd.exe",
                    b"powershell",
                ]
            },
            "encryption": {
                "common_keys": [
                    b"\x00\x11\x22\x33\x44\x55\x66\x77",  
                    b"\x00\x01\x02\x03\x04\x05\x06\x07",  
                    b"\x00" * 16,                        
                    b"\xff" * 16,                       
                ],
                "iv_patterns": [
                    b"\x00" * 16,  
                    b"\x01" * 16, 
                ]
            },
            "addresses": {
                "stack_addresses": [
                    b"\x7f",      
                    b"\xff",    
                ],
                "heap_addresses": [
                    b"\x55",      
                    b"\x56",     
                ],
                "code_addresses": [
                    b"\x40",     
                    b"\x00",      
                ]
            },
            "strings": {
                "suspicious_strings": [
                    b"http://",
                    b"https://",
                    b"ftp://",
                    b"password",
                    b"secret",
                    b"key",
                    b"token",
                ],
                "file_extensions": [
                    b".exe",
                    b".dll",
                    b".sys",
                    b".bat",
                    b".cmd",
                ]
            }
        }
        self.anomaly_thresholds = {
            "rapid_allocation_rate": 10,  
            "memory_growth_rate": 100 * 1024 * 1024,  
            "unusual_region_size": 50 * 1024 * 1024  
        }

    def take_snapshot(self, pid: int) -> Optional[Dict[str, Any]]:
        """Take a memory snapshot of a process"""
        try:
            process = psutil.Process(pid)
            memory_info = process.memory_info()
            memory_maps = process.memory_maps()

            snapshot = {
                "pid": pid,
                "timestamp": datetime.utcnow().isoformat(),
                "rss": memory_info.rss,
                "vms": memory_info.vms,
                "shared": getattr(memory_info, 'shared', 0),
                "text": getattr(memory_info, 'text', 0),
                "lib": getattr(memory_info, 'lib', 0),
                "data": getattr(memory_info, 'data', 0),
                "dirty": getattr(memory_info, 'dirty', 0),
                "percent": process.memory_percent(),
                "regions": []
            }

            for region in memory_maps:
                region_info = {
                    "addr": region.addr,
                    "perms": region.perms,
                    "path": region.path,
                    "rss": region.rss,
                    "size": region.size
                }
                snapshot["regions"].append(region_info)

            with self._lock:
                self.snapshots.append(snapshot)
                self.memory_regions[pid] = snapshot["regions"]

            log.info(f"Memory snapshot taken for PID {pid}")
            return snapshot

        except psutil.NoSuchProcess:
            log.error(f"Process {pid} not found")
            return None
        except Exception as e:
            log.error(f"Failed to take memory snapshot for PID {pid}: {e}", exc_info=True)
            return None

    def compare_snapshots(self, pid: int, snapshot1: Dict[str, Any], snapshot2: Dict[str, Any]) -> Dict[str, Any]:
        """Compare two memory snapshots"""
        try:
            diff = {
                "pid": pid,
                "timestamp": datetime.utcnow().isoformat(),
                "rss_delta": snapshot2["rss"] - snapshot1["rss"],
                "vms_delta": snapshot2["vms"] - snapshot1["vms"],
                "percent_delta": snapshot2["percent"] - snapshot1["percent"],
                "new_regions": [],
                "removed_regions": [],
                "modified_regions": []
            }

            regions1 = {r["addr"]: r for r in snapshot1["regions"]}
            regions2 = {r["addr"]: r for r in snapshot2["regions"]}

            for addr, region in regions2.items():
                if addr not in regions1:
                    diff["new_regions"].append(region)
                elif regions1[addr]["rss"] != region["rss"]:
                    diff["modified_regions"].append({
                        "addr": addr,
                        "old_rss": regions1[addr]["rss"],
                        "new_rss": region["rss"],
                        "delta": region["rss"] - regions1[addr]["rss"]
                    })

            for addr, region in regions1.items():
                if addr not in regions2:
                    diff["removed_regions"].append(region)

            return diff

        except Exception as e:
            log.error(f"Failed to compare snapshots for PID {pid}: {e}", exc_info=True)
            return {"error": str(e)}

    def detect_heap_corruption(self, pid: int) -> Optional[Dict[str, Any]]:
        """Detect potential heap corruption patterns"""
        try:
            snapshot = self.take_snapshot(pid)
            if not snapshot:
                return None

            corruption_indicators = {
                "double_free": [],
                "use_after_free": [],
                "buffer_overflow": [],
                "uninitialized_read": []
            }

            for region in snapshot["regions"]:
                if "heap" in region["path"].lower() or "[heap]" in region["path"]:
                    if region["rss"] > 100 * 1024 * 1024:
                        corruption_indicators["buffer_overflow"].append({
                            "region": region["addr"],
                            "size": region["rss"]
                        })

            return {
                "pid": pid,
                "timestamp": datetime.utcnow().isoformat(),
                "corruption_indicators": corruption_indicators,
                "has_indicators": any(len(v) > 0 for v in corruption_indicators.values())
            }

        except Exception as e:
            log.error(f"Failed to detect heap corruption for PID {pid}: {e}", exc_info=True)
            return None

    def get_memory_dump(self, pid: int, start_addr: int, size: int) -> Optional[bytes]:
        """Get memory dump from a process (requires root privileges)"""
        try:
            with open(f"/proc/{pid}/mem", "rb") as mem_file:
                mem_file.seek(start_addr)
                data = mem_file.read(size)
                return data

        except (FileNotFoundError, PermissionError) as e:
            log.error(f"Failed to read memory for PID {pid}: {e}")
            return None
        except Exception as e:
            log.error(f"Failed to get memory dump for PID {pid}: {e}", exc_info=True)
            return None

    def search_memory_pattern(self, pid: int, pattern: bytes, start_addr: int = None, end_addr: int = None) -> List[int]:
        """Search for a byte pattern in process memory"""
        try:
            process = psutil.Process(pid)
            memory_maps = process.memory_maps()
        except psutil.NoSuchProcess:
            log.error(f"Process {pid} not found")
            return []
        except Exception as e:
            log.error(f"Failed to get memory maps for PID {pid}: {e}", exc_info=True)
            return []

        matches = []

        for region in memory_maps:
            if "r" not in region.perms:
                continue

            region_start = int(region.addr.split("-")[0], 16)
            region_end = int(region.addr.split("-")[1], 16)

            if start_addr and region_end < start_addr:
                continue
            if end_addr and region_start > end_addr:
                continue

            try:
                data = self.get_memory_dump(pid, region_start, region_end - region_start)
                if data:
                    offset = 0
                    while True:
                        pos = data.find(pattern, offset)
                        if pos == -1:
                            break
                        matches.append(region_start + pos)
                        offset = pos + len(pattern)
            except Exception:
                continue

        return matches

    def get_process_memory_stats(self, pid: int) -> Optional[Dict[str, Any]]:
        """Get detailed memory statistics for a process"""
        try:
            process = psutil.Process(pid)
            memory_info = process.memory_info()
            memory_full_info = process.memory_info(extensive=True)

            stats = {
                "pid": pid,
                "timestamp": datetime.utcnow().isoformat(),
                "basic": {
                    "rss": memory_info.rss,
                    "vms": memory_info.vms,
                    "percent": process.memory_percent()
                },
                "extended": {
                    "num_page_faults": memory_full_info.num_page_faults,
                    "major_page_faults": memory_full_info.major_page_faults,
                    "minor_page_faults": memory_full_info.minor_page_faults,
                    "uss": memory_full_info.uss,
                    "pss": memory_full_info.pss,
                    "swap": memory_full_info.swap
                }
            }

            return stats

        except psutil.NoSuchProcess:
            log.error(f"Process {pid} not found")
            return None
        except Exception as e:
            log.error(f"Failed to get memory stats for PID {pid}: {e}", exc_info=True)
            return None

    def get_snapshots(self) -> List[Dict[str, Any]]:
        """Get all memory snapshots"""
        return self.snapshots.copy()

    def clear_snapshots(self):
        """Clear all snapshots"""
        self.snapshots.clear()
        self.memory_regions.clear()

    def detect_patterns(self, pid: int) -> Dict[str, Dict[str, List[int]]]:
        """Detect known patterns in process memory"""
        matches = {
            "shellcode": {"nop_sleds": [], "common_opcodes": [], "shell_exec": []},
            "encryption": {"common_keys": [], "iv_patterns": []},
            "addresses": {"stack_addresses": [], "heap_addresses": [], "code_addresses": []},
            "strings": {"suspicious_strings": [], "file_extensions": []}
        }

        try:
            process = psutil.Process(pid)
            memory_maps = process.memory_maps()

            for region in memory_maps:
                if "r" not in region.perms:
                    continue

                region_start = int(region.addr.split("-")[0], 16)
                region_end = int(region.addr.split("-")[1], 16)

                try:
                    data = self.get_memory_dump(pid, region_start, region_end - region_start)
                    if data:
                        for category, subcategories in self.patterns.items():
                            for subcategory, patterns in subcategories.items():
                                for pattern in patterns:
                                    offset = 0
                                    while True:
                                        pos = data.find(pattern, offset)
                                        if pos == -1:
                                            break
                                        matches[category][subcategory].append(region_start + pos)
                                        offset = pos + len(pattern)
                except Exception:
                    continue

            return matches
        except Exception as e:
            log.error(f"Failed to detect patterns: {e}", exc_info=True)
            return matches

    def detect_anomalies(self, pid: int) -> List[Dict[str, Any]]:
        """Detect memory anomalies"""
        anomalies = []
        
        try:
            snapshot = self.take_snapshot(pid)
            if not snapshot:
                return anomalies
            
       
            for region in snapshot["regions"]:
                size = region.get("size", 0)
                if size > self.anomaly_thresholds["unusual_region_size"]:
                    anomalies.append({
                        "type": "large_region",
                        "address": region["addr"],
                        "size": size,
                        "threshold": self.anomaly_thresholds["unusual_region_size"]
                    })
            
          
            if len(self.snapshots) >= 2:
                prev_snapshot = self.snapshots[-2]
                growth = snapshot["rss"] - prev_snapshot["rss"]
                time_diff = (datetime.fromisoformat(snapshot["timestamp"]) -
                           datetime.fromisoformat(prev_snapshot["timestamp"])).total_seconds()

                if time_diff > 0:
                    growth_rate = growth / time_diff
                    if growth_rate > self.anomaly_thresholds["memory_growth_rate"]:
                        anomalies.append({
                            "type": "rapid_growth",
                            "growth_rate": growth_rate,
                            "threshold": self.anomaly_thresholds["memory_growth_rate"]
                        })
            
            with self._lock:
                self.anomalies.extend(anomalies)
            
            return anomalies
        except Exception as e:
            log.error(f"Failed to detect anomalies: {e}", exc_info=True)
            return anomalies

    def get_anomalies(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent anomalies"""
        return self.anomalies[-limit:]

    def clear_anomalies(self):
        """Clear all anomalies"""
        with self._lock:
            self.anomalies.clear()
        log.info("Cleared all memory anomalies")

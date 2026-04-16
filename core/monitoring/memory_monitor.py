import os
import json
import logging
import structlog
import psutil
from typing import Optional, Dict, Any, List
from datetime import datetime

log = structlog.get_logger()


class MemoryMonitor:
    """Monitor memory access patterns and allocations"""

    def __init__(self):
        self.snapshots: List[Dict[str, Any]] = []
        self.memory_regions: Dict[int, List[Dict[str, Any]]] = {}

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

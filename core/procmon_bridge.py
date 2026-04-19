import os
import json
import logging
import structlog
import subprocess
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path

log = structlog.get_logger()


class ProcmonBridge:
    """Bridge for Procmon integration (Windows only)"""

    def __init__(self, procmon_path: str = None):
        self.procmon_path = procmon_path or "Procmon.exe"
        self.is_available = self._check_availability()
        self.active_monitor = None

    def _check_availability(self) -> bool:
        """Check if Procmon is available"""
        try:
            result = subprocess.run(
                [self.procmon_path, "/?"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def start_monitoring(self, output_file: str, filters: List[str] = None) -> bool:
        """Start Procmon monitoring"""
        if not self.is_available:
            log.warning("Procmon not available")
            return False

        try:
            cmd = [
                self.procmon_path,
                "/accepteula",
                "/quiet",
                "/minimized",
                "/backingfile", output_file
            ]

            if filters:
                for filter_rule in filters:
                    cmd.extend(["/filter", filter_rule])

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            self.active_monitor = process
            log.info(f"Started Procmon monitoring to {output_file}")
            return True

        except Exception as e:
            log.error(f"Failed to start Procmon: {e}", exc_info=True)
            return False

    def stop_monitoring(self) -> bool:
        """Stop Procmon monitoring"""
        if not self.active_monitor:
            return True

        try:
            self.active_monitor.terminate()
            self.active_monitor.wait(timeout=10)
            self.active_monitor = None
            log.info("Stopped Procmon monitoring")
            return True
        except Exception as e:
            log.error(f"Failed to stop Procmon: {e}", exc_info=True)
            try:
                self.active_monitor.kill()
                self.active_monitor = None
            except:
                pass
            return False

    def parse_pml(self, pml_file: str) -> Optional[Dict[str, Any]]:
        """Parse Procmon PML file (XML format)"""
        try:
            if not Path(pml_file).exists():
                log.error(f"PML file not found: {pml_file}")
                return None

            import xml.etree.ElementTree as ET

            tree = ET.parse(pml_file)
            root = tree.getroot()

            events = []
            for event in root.findall(".//event"):
                event_data = {
                    "timestamp": event.get("time_of_day"),
                    "process": event.get("process_name"),
                    "pid": event.get("pid"),
                    "operation": event.get("operation"),
                    "path": event.get("path"),
                    "result": event.get("result"),
                    "details": event.get("detail")
                }
                events.append(event_data)

            return {
                "file": pml_file,
                "event_count": len(events),
                "events": events
            }

        except ImportError:
            log.error("XML parsing library not available")
            return None
        except Exception as e:
            log.error(f"Failed to parse PML file {pml_file}: {e}", exc_info=True)
            return None

    def export_to_csv(self, pml_file: str, csv_file: str) -> bool:
        """Export PML file to CSV format"""
        try:
            parsed_data = self.parse_pml(pml_file)
            if not parsed_data:
                return False

            import csv

            with open(csv_file, 'w', newline='', encoding='utf-8') as csvfile:
                if parsed_data["events"]:
                    fieldnames = parsed_data["events"][0].keys()
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(parsed_data["events"])

            log.info(f"Exported PML to CSV: {csv_file}")
            return True

        except Exception as e:
            log.error(f"Failed to export PML to CSV: {e}", exc_info=True)
            return False

    def analyze_patterns(self, pml_file: str) -> Dict[str, Any]:
        """Analyze patterns in Procmon data"""
        try:
            parsed_data = self.parse_pml(pml_file)
            if not parsed_data:
                return {}

            events = parsed_data["events"]

            analysis = {
                "processes": {},
                "operations": {},
                "paths": {},
                "suspicious_activities": []
            }

            for event in events:
                process = event.get("process", "unknown")
                operation = event.get("operation", "unknown")
                path = event.get("path", "unknown")

                analysis["processes"][process] = analysis["processes"].get(process, 0) + 1
                analysis["operations"][operation] = analysis["operations"].get(operation, 0) + 1
                analysis["paths"][path] = analysis["paths"].get(path, 0) + 1

                suspicious_ops = ["RegSetValue", "RegCreateKey", "CreateFile", "WriteFile"]
                if operation in suspicious_ops and "System32" not in path:
                    analysis["suspicious_activities"].append(event)

            return analysis

        except Exception as e:
            log.error(f"Failed to analyze patterns in PML: {e}", exc_info=True)
            return {}


_procmon_instance: Optional[ProcmonBridge] = None


def get_procmon() -> ProcmonBridge:
    """Get or create Procmon bridge instance"""
    global _procmon_instance
    if _procmon_instance is None:
        _procmon_instance = ProcmonBridge()
    return _procmon_instance

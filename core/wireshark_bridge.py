import os
import json
import logging
import structlog
import subprocess
import pyshark
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path

log = structlog.get_logger()


class WiresharkBridge:
    """Bridge for Wireshark/tshark integration"""

    def __init__(self, tshark_path: str = None):
        self.tshark_path = tshark_path or "tshark"
        self.is_available = self._check_availability()
        self.active_capture = None

    def _check_availability(self) -> bool:
        """Check if tshark is available"""
        try:
            result = subprocess.run(
                [self.tshark_path, "-v"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def start_capture(self, interface: str, output_file: str, filter: str = None, duration: int = 30) -> bool:
        """Start network packet capture using tshark"""
        if not self.is_available:
            log.warning("tshark not available")
            return False

        try:
            cmd = [self.tshark_path, "-i", interface, "-w", output_file, "-a", f"duration:{duration}"]

            if filter:
                cmd.extend(["-f", filter])

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            self.active_capture = process
            log.info(f"Started capture on interface {interface} to {output_file}")
            return True

        except Exception as e:
            log.error(f"Failed to start capture: {e}", exc_info=True)
            return False

    def stop_capture(self) -> bool:
        """Stop active capture"""
        if not self.active_capture:
            return True

        try:
            self.active_capture.terminate()
            self.active_capture.wait(timeout=10)
            self.active_capture = None
            log.info("Stopped capture")
            return True
        except Exception as e:
            log.error(f"Failed to stop capture: {e}", exc_info=True)
            try:
                self.active_capture.kill()
                self.active_capture = None
            except:
                pass
            return False

    def analyze_capture(self, capture_file: str) -> Optional[Dict[str, Any]]:
        """Analyze a network capture file"""
        try:
            cap = pyshark.FileCapture(capture_file)

            analysis = {
                "file": capture_file,
                "packet_count": len(cap),
                "protocols": {},
                "conversations": [],
                "dns_queries": [],
                "http_requests": [],
                "tls_handshakes": [],
                "suspicious_activities": []
            }

            for packet in cap:
                if hasattr(packet, 'highest_layer'):
                    protocol = packet.highest_layer
                    analysis["protocols"][protocol] = analysis["protocols"].get(protocol, 0) + 1

                if hasattr(packet, 'dns'):
                    if hasattr(packet.dns, 'qry_name'):
                        analysis["dns_queries"].append({
                            "query": packet.dns.qry_name,
                            "type": packet.dns.qry_type if hasattr(packet.dns, 'qry_type') else "unknown",
                            "response": packet.dns.resp_name if hasattr(packet.dns, 'resp_name') else None
                        })

                if hasattr(packet, 'http'):
                    if hasattr(packet.http, 'host'):
                        analysis["http_requests"].append({
                            "host": packet.http.host,
                            "method": packet.http.request_method if hasattr(packet.http, 'request_method') else "unknown",
                            "uri": packet.http.request_uri if hasattr(packet.http, 'request_uri') else "/",
                            "user_agent": packet.http.user_agent if hasattr(packet.http, 'user_agent') else None
                        })

                if hasattr(packet, 'tls'):
                    if hasattr(packet.tls, 'handshake_type'):
                        analysis["tls_handshakes"].append({
                            "type": packet.tls.handshake_type,
                            "version": packet.tls.handshake_version if hasattr(packet.tls, 'handshake_version') else "unknown"
                        })

                if hasattr(packet, 'tcp'):
                    if hasattr(packet.tcp, 'flags'):
                        flags = packet.tcp.flags
                        if "0x002" in str(flags) and "0x010" not in str(flags):
                            analysis["suspicious_activities"].append({
                                "type": "syn_scan",
                                "packet": str(packet)
                            })

            cap.close()

            return analysis

        except Exception as e:
            log.error(f"Failed to analyze capture {capture_file}: {e}", exc_info=True)
            return None

    def export_to_json(self, capture_file: str, json_file: str) -> bool:
        """Export capture to JSON format"""
        try:
            analysis = self.analyze_capture(capture_file)
            if not analysis:
                return False

            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(analysis, f, indent=2)

            log.info(f"Exported capture to JSON: {json_file}")
            return True

        except Exception as e:
            log.error(f"Failed to export capture to JSON: {e}", exc_info=True)
            return False

    def filter_packets(self, capture_file: str, display_filter: str, output_file: str) -> bool:
        """Filter packets using Wireshark display filter"""
        if not self.is_available:
            log.warning("tshark not available")
            return False

        try:
            cmd = [
                self.tshark_path,
                "-r", capture_file,
                "-Y", display_filter,
                "-w", output_file
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                log.info(f"Filtered packets saved to {output_file}")
                return True
            else:
                log.error(f"Failed to filter packets: {result.stderr}")
                return False

        except Exception as e:
            log.error(f"Failed to filter packets: {e}", exc_info=True)
            return False

    def get_statistics(self, capture_file: str) -> Optional[Dict[str, Any]]:
        """Get capture statistics"""
        if not self.is_available:
            log.warning("tshark not available")
            return None

        try:
            cmd = [self.tshark_path, "-r", capture_file, "-q", "-z", "io,phs"]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                return {"statistics": result.stdout}
            else:
                return None

        except Exception as e:
            log.error(f"Failed to get statistics: {e}", exc_info=True)
            return None


_wireshark_instance: Optional[WiresharkBridge] = None


def get_wireshark() -> WiresharkBridge:
    """Get or create Wireshark bridge instance"""
    global _wireshark_instance
    if _wireshark_instance is None:
        _wireshark_instance = WiresharkBridge()
    return _wireshark_instance

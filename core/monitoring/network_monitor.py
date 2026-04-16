import os
import json
import logging
import structlog
import psutil
import pyshark
from typing import Optional, Dict, Any, List
from datetime import datetime

log = structlog.get_logger()


class NetworkMonitor:
    """Monitor network traffic and connections"""

    def __init__(self):
        self.connections: List[Dict[str, Any]] = []
        self.captures: Dict[str, str] = {}

    def get_all_connections(self) -> List[Dict[str, Any]]:
        """Get all network connections"""
        try:
            all_connections = []
            for conn in psutil.net_connections(kind='inet'):
                conn_info = {
                    "fd": conn.fd,
                    "family": conn.family,
                    "type": conn.type,
                    "laddr": {
                        "ip": conn.laddr.ip if conn.laddr else None,
                        "port": conn.laddr.port if conn.laddr else None
                    },
                    "raddr": {
                        "ip": conn.raddr.ip if conn.raddr else None,
                        "port": conn.raddr.port if conn.raddr else None
                    },
                    "status": conn.status,
                    "pid": conn.pid
                }
                all_connections.append(conn_info)

            self.connections = all_connections
            return all_connections

        except Exception as e:
            log.error(f"Failed to get network connections: {e}", exc_info=True)
            return []

    def get_connections_by_pid(self, pid: int) -> List[Dict[str, Any]]:
        """Get network connections for a specific process"""
        try:
            process = psutil.Process(pid)
            connections = []

            for conn in process.connections(kind='inet'):
                conn_info = {
                    "fd": conn.fd,
                    "family": conn.family,
                    "type": conn.type,
                    "laddr": {
                        "ip": conn.laddr.ip if conn.laddr else None,
                        "port": conn.laddr.port if conn.laddr else None
                    },
                    "raddr": {
                        "ip": conn.raddr.ip if conn.raddr else None,
                        "port": conn.raddr.port if conn.raddr else None
                    },
                    "status": conn.status
                }
                connections.append(conn_info)

            return connections

        except psutil.NoSuchProcess:
            log.error(f"Process {pid} not found")
            return []
        except Exception as e:
            log.error(f"Failed to get connections for PID {pid}: {e}", exc_info=True)
            return []

    def start_capture(self, interface: str, output_file: str, filter: str = None, duration: int = 30) -> bool:
        """Start network packet capture"""
        try:
            capture_cmd = ["tshark", "-i", interface, "-w", output_file, "-a", f"duration:{duration}"]

            if filter:
                capture_cmd.extend(["-f", filter])

            import subprocess
            process = subprocess.Popen(
                capture_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            self.captures[output_file] = output_file
            log.info(f"Started network capture on interface {interface} to {output_file}")

            return True

        except Exception as e:
            log.error(f"Failed to start network capture: {e}", exc_info=True)
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
                "http_requests": []
            }

            for packet in cap:
                if hasattr(packet, 'highest_layer'):
                    protocol = packet.highest_layer
                    analysis["protocols"][protocol] = analysis["protocols"].get(protocol, 0) + 1

                if hasattr(packet, 'dns'):
                    if hasattr(packet.dns, 'qry_name'):
                        analysis["dns_queries"].append({
                            "query": packet.dns.qry_name,
                            "type": packet.dns.qry_type if hasattr(packet.dns, 'qry_type') else "unknown"
                        })

                if hasattr(packet, 'http'):
                    if hasattr(packet.http, 'host'):
                        analysis["http_requests"].append({
                            "host": packet.http.host,
                            "method": packet.http.request_method if hasattr(packet.http, 'request_method') else "unknown",
                            "uri": packet.http.request_uri if hasattr(packet.http, 'request_uri') else "/"
                        })

            cap.close()

            return analysis

        except Exception as e:
            log.error(f"Failed to analyze capture {capture_file}: {e}", exc_info=True)
            return None

    def get_network_io_counters(self) -> Dict[str, Any]:
        """Get network I/O statistics"""
        try:
            io_counters = psutil.net_io_counters(pernic=True)

            stats = {}
            for interface, counters in io_counters.items():
                stats[interface] = {
                    "bytes_sent": counters.bytes_sent,
                    "bytes_recv": counters.bytes_recv,
                    "packets_sent": counters.packets_sent,
                    "packets_recv": counters.packets_recv,
                    "errin": counters.errin,
                    "errout": counters.errout,
                    "dropin": counters.dropin,
                    "dropout": counters.dropout
                }

            return stats

        except Exception as e:
            log.error(f"Failed to get network I/O counters: {e}", exc_info=True)
            return {}

    def get_network_interfaces(self) -> List[Dict[str, Any]]:
        """Get network interface information"""
        try:
            interfaces = []
            for name, addrs in psutil.net_if_addrs().items():
                interface_info = {
                    "name": name,
                    "addresses": []
                }

                for addr in addrs:
                    addr_info = {
                        "family": addr.family,
                        "address": addr.address,
                        "netmask": addr.netmask,
                        "broadcast": addr.broadcast
                    }
                    interface_info["addresses"].append(addr_info)

                interfaces.append(interface_info)

            return interfaces

        except Exception as e:
            log.error(f"Failed to get network interfaces: {e}", exc_info=True)
            return []

    def detect_suspicious_connections(self) -> List[Dict[str, Any]]:
        """Detect potentially suspicious network connections"""
        try:
            all_connections = self.get_all_connections()
            suspicious = []

            known_suspicious_ports = [
                6666, 6667, 6668, 6669,
                4444, 5555, 31337, 12345,
                5900, 6900, 8080, 8443
            ]

            for conn in all_connections:
                if conn["raddr"] and conn["raddr"]["port"] in known_suspicious_ports:
                    suspicious.append({
                        "connection": conn,
                        "reason": "suspicious_port",
                        "port": conn["raddr"]["port"]
                    })

                if conn["status"] == "ESTABLISHED" and conn["raddr"]:
                    suspicious.append({
                        "connection": conn,
                        "reason": "outbound_connection",
                        "destination": f"{conn['raddr']['ip']}:{conn['raddr']['port']}"
                    })

            return suspicious

        except Exception as e:
            log.error(f"Failed to detect suspicious connections: {e}", exc_info=True)
            return []

    def get_connections_history(self) -> List[Dict[str, Any]]:
        """Get historical connection data"""
        return self.connections.copy()

    def clear_history(self):
        """Clear connection history"""
        self.connections.clear()

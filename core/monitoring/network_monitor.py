import os
import json
import logging
import structlog
import psutil
import pyshark
import threading
from typing import Optional, Dict, Any, List
from datetime import datetime

log = structlog.get_logger()


class NetworkMonitor:
    """Monitor network traffic and connections"""

    def __init__(self):
        self.connections: List[Dict[str, Any]] = []
        self.captures: Dict[str, str] = {}
        self._lock = threading.Lock()
        self.threats: List[Dict[str, Any]] = []
        self.protocol_analyzers = {
            "dns": self._analyze_dns,
            "http": self._analyze_http,
            "tls": self._analyze_tls
        }
        self.threat_indicators = {
            "c2_domains": ["evil.com", "malware.net", "c2server.org"],
            "suspicious_ports": [6666, 6667, 4444, 31337, 12345, 5900],
            "high_volume_threshold": 1000000  
        }

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

            with self._lock:
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

    def _analyze_dns(self, packet) -> Optional[Dict[str, Any]]:
        """Analyze DNS protocol"""
        if not hasattr(packet, 'dns'):
            return None
        
        try:
            return {
                "query": packet.dns.qry_name if hasattr(packet.dns, 'qry_name') else "unknown",
                "type": packet.dns.qry_type if hasattr(packet.dns, 'qry_type') else "unknown",
                "response": packet.dns.flags if hasattr(packet.dns, 'flags') else "unknown"
            }
        except:
            return None

    def _analyze_http(self, packet) -> Optional[Dict[str, Any]]:
        """Analyze HTTP protocol"""
        if not hasattr(packet, 'http'):
            return None
        
        try:
            return {
                "host": packet.http.host if hasattr(packet.http, 'host') else "unknown",
                "method": packet.http.request_method if hasattr(packet.http, 'request_method') else "unknown",
                "uri": packet.http.request_uri if hasattr(packet.http, 'request_uri') else "/",
                "user_agent": packet.http.user_agent if hasattr(packet.http, 'user_agent') else "unknown"
            }
        except:
            return None

    def _analyze_tls(self, packet) -> Optional[Dict[str, Any]]:
        """Analyze TLS protocol"""
        if not hasattr(packet, 'tls'):
            return None
        
        try:
            return {
                "version": packet.tls.version if hasattr(packet.tls, 'version') else "unknown",
                "cipher": packet.tls.cipher_suite if hasattr(packet.tls, 'cipher_suite') else "unknown"
            }
        except:
            return None

    def analyze_protocol_traffic(self, capture_file: str) -> Dict[str, List[Dict[str, Any]]]:
        """Analyze protocol-specific traffic in capture"""
        protocol_data = {"dns": [], "http": [], "tls": []}
        
        try:
            cap = pyshark.FileCapture(capture_file)
            
            for packet in cap:
                for protocol, analyzer in self.protocol_analyzers.items():
                    result = analyzer(packet)
                    if result:
                        protocol_data[protocol].append(result)
            
            cap.close()
            return protocol_data
        except Exception as e:
            log.error(f"Failed to analyze protocol traffic: {e}", exc_info=True)
            return protocol_data

    def detect_threats(self, capture_file: str = None) -> List[Dict[str, Any]]:
        """Detect network threats"""
        threats = []
        
        try:
         
            if not capture_file:
                all_connections = self.get_all_connections()
                
                for conn in all_connections:
                  
                    if conn.get("raddr") and conn["raddr"]["port"] in self.threat_indicators["suspicious_ports"]:
                        threats.append({
                            "type": "suspicious_port",
                            "connection": conn,
                            "port": conn["raddr"]["port"]
                        })
                    
                    
                    if conn.get("raddr"):
                        domain = conn["raddr"]["ip"]
                        if any(c2 in domain for c2 in self.threat_indicators["c2_domains"]):
                            threats.append({
                                "type": "c2_domain",
                                "connection": conn,
                                "domain": domain
                            })
            else:
         
                protocol_data = self.analyze_protocol_traffic(capture_file)
                
             
                for dns_query in protocol_data["dns"]:
                    if any(c2 in dns_query["query"] for c2 in self.threat_indicators["c2_domains"]):
                        threats.append({
                            "type": "c2_domain",
                            "query": dns_query["query"]
                        })
                
              
                for http_req in protocol_data["http"]:
                    if any(c2 in http_req["host"] for c2 in self.threat_indicators["c2_domains"]):
                        threats.append({
                            "type": "c2_domain",
                            "http_request": http_req
                        })
            
            with self._lock:
                self.threats.extend(threats)
            
            return threats
        except Exception as e:
            log.error(f"Failed to detect threats: {e}", exc_info=True)
            return threats

    def get_threats(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent threats"""
        return self.threats[-limit:]

    def clear_threats(self):
        """Clear all threats"""
        with self._lock:
            self.threats.clear()
        log.info("Cleared all network threats")

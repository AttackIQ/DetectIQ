from typing import Any, Dict, List, Optional, Sequence

from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from .base import BaseAnalyzer
from .content import ContentAnalyzer
from .http import HTTPAnalyzer


class AnomalyAnalyzer(BaseAnalyzer):
    """Analyzes traffic for anomalous patterns."""

    def __init__(self):
        self.http_analyzer = HTTPAnalyzer()
        self.content_analyzer = ContentAnalyzer()

    def analyze(self, packets: Any) -> Dict[str, Any]:
        return {
            "network_anomalies": self._detect_network_anomalies(packets),
            "protocol_anomalies": self._detect_protocol_anomalies(packets),
            "behavioral_anomalies": self._detect_behavioral_anomalies(packets),
            "statistical_anomalies": self._detect_statistical_anomalies(packets),
        }

    def _detect_network_anomalies(self, packets: Any) -> List[Dict[str, Any]]:
        """Detect network-level anomalies."""
        anomalies = []
        ip_counts = {}
        port_counts = {}

        for packet in packets:
            if packet.haslayer(IP):
                # Track source IP addresses
                src_ip = packet[IP].src
                ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1

                # Check for port scanning
                if packet.haslayer(TCP) or packet.haslayer(UDP):
                    dst_port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
                    port_key = f"{src_ip}:{dst_port}"
                    port_counts[port_key] = port_counts.get(port_key, 0) + 1

        # Detect potential port scans
        for src_ip in ip_counts:
            unique_ports = len([k for k in port_counts if k.startswith(f"{src_ip}:")])
            if unique_ports > 20:  # Threshold for port scan detection
                anomalies.append(
                    {"type": "port_scan", "source_ip": src_ip, "unique_ports": unique_ports, "severity": "high"}
                )

        return anomalies

    def _detect_protocol_anomalies(self, packets: Any) -> List[Dict[str, Any]]:
        """Detect protocol-specific anomalies."""
        anomalies = []

        for packet in packets:
            # Use ContentAnalyzer for pattern detection
            if packet.haslayer(Raw):
                patterns = self.content_analyzer._find_ascii_patterns(packet[Raw].load)
                for pattern in patterns:
                    if pattern["type"] in ["command", "script"]:
                        anomalies.append(
                            {"type": "suspicious_payload", "pattern": pattern["pattern"], "severity": "high"}
                        )

            # Check TCP flags
            if packet.haslayer(TCP):
                flags = packet[TCP].flags
                if self._is_anomalous_tcp_flags(flags):
                    anomalies.append(
                        {
                            "type": "tcp_flags",
                            "flags": flags,
                            "source_ip": packet[IP].src if packet.haslayer(IP) else None,
                            "severity": "medium",
                        }
                    )

            # Check HTTP anomalies
            if packet.haslayer(HTTPRequest):
                http_anomaly = self._check_http_anomalies(packet[HTTPRequest])
                if http_anomaly:
                    anomalies.append(http_anomaly)

        return anomalies

    def _detect_behavioral_anomalies(self, packets: Any) -> List[Dict[str, Any]]:
        """Detect behavioral anomalies."""
        return self._analyze_traffic_patterns(packets)

    def _detect_statistical_anomalies(self, packets: Any) -> List[Dict[str, Any]]:
        """Detect statistical anomalies in traffic patterns."""
        # Convert packet sizes to float during list creation
        packet_sizes = [float(len(packet)) for packet in packets]
        return self._find_statistical_outliers(packet_sizes)

    def _check_http_anomalies(self, request: Any) -> Optional[Dict[str, Any]]:
        """Check for HTTP-specific anomalies using HTTPAnalyzer."""
        http_data = self.http_analyzer._analyze_requests([request])
        if not http_data:
            return None

        request_data = http_data[0]
        method = request_data.get("method")
        path = request_data.get("path")
        headers = request_data.get("headers", {})

        # Check for unusual methods
        unusual_methods = ["TRACE", "CONNECT", "DELETE"]
        if method in unusual_methods:
            return {"type": "unusual_http_method", "method": method, "severity": "medium"}

        # Reuse existing pattern checks
        if path:
            anomaly = self._check_path_patterns(path)
            if anomaly:
                return anomaly

        # Check headers for suspicious patterns
        if headers:
            anomaly = self._check_header_patterns(headers)
            if anomaly:
                return anomaly

        return None

    def _analyze_traffic_patterns(self, packets: Any) -> List[Dict[str, Any]]:
        """Analyze traffic patterns for behavioral anomalies."""
        anomalies = []
        flow_stats = self._calculate_flow_statistics(packets)

        # Detect rapid connection attempts
        if flow_stats["rate"] > 100:  # More than 100 connections per second
            anomalies.append({"type": "high_connection_rate", "rate": flow_stats["rate"], "severity": "medium"})

        return anomalies

    @staticmethod
    def _find_statistical_outliers(values: Sequence[float]) -> List[Dict[str, Any]]:
        """Find statistical outliers using IQR method."""
        if not values:
            return []

        sorted_values = sorted(values)
        q1_idx = len(sorted_values) // 4
        q3_idx = (3 * len(sorted_values)) // 4

        q1 = float(sorted_values[q1_idx])
        q3 = float(sorted_values[q3_idx])
        iqr = q3 - q1

        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr

        outliers = []
        for value in values:
            if value < lower_bound or value > upper_bound:
                outliers.append(
                    {
                        "type": "statistical_outlier",
                        "value": value,
                        "bounds": {"lower": lower_bound, "upper": upper_bound},
                        "severity": "low",
                    }
                )

        return outliers

    def _calculate_flow_statistics(self, packets: Any) -> Dict[str, float]:
        """Calculate basic flow statistics."""
        if not packets:
            return {"rate": 0.0, "avg_size": 0.0}

        duration = packets[-1].time - packets[0].time
        if duration == 0:
            return {"rate": 0.0, "avg_size": 0.0}

        return {"rate": len(packets) / duration, "avg_size": sum(len(p) for p in packets) / len(packets)}

    def _check_path_patterns(self, path: str) -> Optional[Dict[str, Any]]:
        """Check URI path for suspicious patterns using ContentAnalyzer."""
        # Convert path to bytes for ContentAnalyzer
        path_bytes = path.encode("utf-8")

        # Use ContentAnalyzer's pattern detection
        patterns = self.content_analyzer._find_ascii_patterns(path_bytes)

        # Map pattern types to attack types
        attack_patterns = {
            "ascii_unix_path": "system_path",
            "ascii_windows_path": "system_path",
            "ascii_command": "command_injection",
            "ascii_url": "path_traversal",
        }

        for pattern in patterns:
            pattern_type = pattern.get("type", "")  # Default to empty string if type is None
            if pattern_type and pattern_type in attack_patterns:
                return {
                    "type": "suspicious_uri_pattern",
                    "pattern_type": attack_patterns[pattern_type],
                    "path": path,
                    "severity": "high",
                }

        return None

    def _check_header_patterns(self, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Check headers for suspicious patterns using ContentAnalyzer."""
        # Convert headers to string for pattern matching
        header_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
        header_bytes = header_str.encode("utf-8")

        # Use ContentAnalyzer's pattern detection
        patterns = self.content_analyzer._find_ascii_patterns(header_bytes)

        # Map ContentAnalyzer pattern types to attack types
        attack_patterns = {
            "ascii_command": "command_injection",
            "ascii_base64": "encoded_content",
            "ascii_script": "code_execution",
            "ascii_url": "suspicious_redirect",
        }

        for pattern in patterns:
            pattern_type = pattern.get("type", "")  # Default to empty string if type is None
            if pattern_type and pattern_type in attack_patterns:
                return {
                    "type": "suspicious_header_value",
                    "header": pattern.get("pattern", ""),  # Default to empty string if pattern is None
                    "pattern_type": attack_patterns[pattern_type],
                    "severity": "high",
                }

        return None

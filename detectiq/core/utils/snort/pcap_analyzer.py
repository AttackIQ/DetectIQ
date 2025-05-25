import re
from collections import defaultdict
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Union

from scapy.all import rdpcap
from scapy.packet import Packet

from ..logging import get_logger
from .analyzers import (
    AnomalyAnalyzer,
    ContentAnalyzer,
    HTTPAnalyzer,
    ProtocolAnalyzer,
    ThresholdAnalyzer,
    WhitelistAnalyzer,
)

logger = get_logger(__name__)


class PcapAnalyzer:
    """Utility class for analyzing PCAP files for Snort rule creation."""

    def __init__(self):
        """Initialize analyzers."""
        self.protocol_analyzer = ProtocolAnalyzer()
        self.content_analyzer = ContentAnalyzer()
        self.http_analyzer = HTTPAnalyzer()
        self.anomaly_analyzer = AnomalyAnalyzer()
        self.threshold_analyzer = ThresholdAnalyzer()
        self.whitelist_analyzer = WhitelistAnalyzer()

    async def analyze_file(self, data: Union[Path, bytes]) -> Dict[str, Any]:
        """Analyze a PCAP file and extract key data for Snort rule generation."""
        try:
            packets = self._read_pcap(data)
            if not packets:
                logger.warning("No packets found in PCAP data")
                return {}

            packet_list = list(packets)

            # Run all analyzers but extract only key data
            protocol_data = self._extract_protocol_insights(self.protocol_analyzer.analyze(packet_list))
            content_data = self._extract_content_insights(self.content_analyzer.analyze(packet_list))
            http_data = self._extract_http_insights(self.http_analyzer.analyze(packet_list))
            anomaly_data = self._extract_anomaly_insights(self.anomaly_analyzer.analyze(packet_list))

            # Extract additional network information
            network_info = self._extract_network_info(packet_list)
            flow_info = self._extract_flow_info(packet_list)

            return {
                "key_patterns": {
                    "content": content_data["significant_patterns"],
                    "http": http_data["significant_patterns"],
                    "protocol": protocol_data["significant_patterns"],
                },
                "anomalies": anomaly_data["critical_anomalies"],
                "statistics": {
                    "protocol": protocol_data["key_stats"],
                    "http": http_data["key_stats"],
                    "content": content_data["key_stats"],
                },
                "network_info": network_info,
                "flow_info": flow_info,
                "metadata": self._generate_minimal_metadata(packet_list),
            }

        except Exception as e:
            logger.error(f"Failed to analyze PCAP: {e}")
            raise

    def _read_pcap(self, data: Union[Path, bytes]) -> List[Packet]:
        """Read PCAP data from file or bytes."""
        try:
            if isinstance(data, Path):
                return list(rdpcap(str(data)))
            return list(rdpcap(BytesIO(data)))
        except Exception as e:
            logger.error(f"Error reading PCAP data: {e}")
            return []

    def _extract_network_info(self, packets: List[Packet]) -> Dict[str, Any]:
        """Extract detailed network information from packets."""
        from scapy.layers.inet import ICMP, IP, TCP, UDP

        network_info = {
            "ip_addresses": {
                "sources": defaultdict(int),
                "destinations": defaultdict(int),
                "conversations": defaultdict(int),
            },
            "ports": {"sources": defaultdict(int), "destinations": defaultdict(int), "services": defaultdict(int)},
            "protocols": defaultdict(int),
            "packet_directions": {"inbound": 0, "outbound": 0},
        }

        for packet in packets:
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst

                # Track IPs
                network_info["ip_addresses"]["sources"][src_ip] += 1
                network_info["ip_addresses"]["destinations"][dst_ip] += 1
                network_info["ip_addresses"]["conversations"][f"{src_ip}->{dst_ip}"] += 1

                # Track protocols
                if packet.haslayer(TCP):
                    network_info["protocols"]["TCP"] += 1
                    tcp_layer = packet[TCP]
                    network_info["ports"]["sources"][tcp_layer.sport] += 1
                    network_info["ports"]["destinations"][tcp_layer.dport] += 1
                    network_info["ports"]["services"][f"tcp/{tcp_layer.dport}"] += 1
                elif packet.haslayer(UDP):
                    network_info["protocols"]["UDP"] += 1
                    udp_layer = packet[UDP]
                    network_info["ports"]["sources"][udp_layer.sport] += 1
                    network_info["ports"]["destinations"][udp_layer.dport] += 1
                    network_info["ports"]["services"][f"udp/{udp_layer.dport}"] += 1
                elif packet.haslayer(ICMP):
                    network_info["protocols"]["ICMP"] += 1
                else:
                    network_info["protocols"][f"IP_PROTO_{ip_layer.proto}"] += 1

        # Convert defaultdicts to regular dicts and get top entries
        return {
            "ip_addresses": {
                "top_sources": dict(
                    sorted(network_info["ip_addresses"]["sources"].items(), key=lambda x: x[1], reverse=True)[:10]
                ),
                "top_destinations": dict(
                    sorted(network_info["ip_addresses"]["destinations"].items(), key=lambda x: x[1], reverse=True)[:10]
                ),
                "top_conversations": dict(
                    sorted(network_info["ip_addresses"]["conversations"].items(), key=lambda x: x[1], reverse=True)[:10]
                ),
            },
            "ports": {
                "top_src_ports": dict(
                    sorted(network_info["ports"]["sources"].items(), key=lambda x: x[1], reverse=True)[:10]
                ),
                "top_dst_ports": dict(
                    sorted(network_info["ports"]["destinations"].items(), key=lambda x: x[1], reverse=True)[:10]
                ),
                "services": dict(
                    sorted(network_info["ports"]["services"].items(), key=lambda x: x[1], reverse=True)[:10]
                ),
            },
            "protocols": dict(network_info["protocols"]),
        }

    def _extract_flow_info(self, packets: List[Packet]) -> Dict[str, Any]:
        """Extract flow-level information from packets."""
        from scapy.layers.inet import IP, TCP, UDP

        flows = defaultdict(
            lambda: {
                "packets": 0,
                "bytes": 0,
                "start_time": None,
                "end_time": None,
                "tcp_flags": set(),
                "payload_sizes": [],
            }
        )

        for packet in packets:
            if packet.haslayer(IP):
                ip_layer = packet[IP]

                # Create flow key
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    flow_key = f"{ip_layer.src}:{tcp_layer.sport}->{ip_layer.dst}:{tcp_layer.dport}/tcp"

                    # Track TCP flags
                    if tcp_layer.flags:
                        flows[flow_key]["tcp_flags"].add(str(tcp_layer.flags))
                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    flow_key = f"{ip_layer.src}:{udp_layer.sport}->{ip_layer.dst}:{udp_layer.dport}/udp"
                else:
                    flow_key = f"{ip_layer.src}->{ip_layer.dst}/ip"

                # Update flow stats
                flow = flows[flow_key]
                flow["packets"] += 1
                flow["bytes"] += len(packet)

                if flow["start_time"] is None:
                    flow["start_time"] = float(packet.time)
                flow["end_time"] = float(packet.time)

                # Track payload size if present
                if hasattr(packet, "load"):
                    flow["payload_sizes"].append(len(packet.load))

        # Process flows for output
        processed_flows = []
        for flow_key, flow_data in sorted(flows.items(), key=lambda x: x[1]["packets"], reverse=True)[:20]:
            duration = flow_data["end_time"] - flow_data["start_time"] if flow_data["start_time"] else 0
            processed_flows.append(
                {
                    "flow": flow_key,
                    "packets": flow_data["packets"],
                    "bytes": flow_data["bytes"],
                    "duration": round(duration, 3),
                    "tcp_flags": list(flow_data["tcp_flags"]),
                    "avg_payload_size": (
                        sum(flow_data["payload_sizes"]) / len(flow_data["payload_sizes"])
                        if flow_data["payload_sizes"]
                        else 0
                    ),
                }
            )

        return {"top_flows": processed_flows, "total_flows": len(flows)}

    def _extract_protocol_insights(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key protocol patterns and statistics."""
        # Get the actual protocol data from the analyzer
        protocols = analysis.get("protocols", {})
        connections = analysis.get("connections", [])
        protocol_details = analysis.get("protocol_details", {})

        # Extract TCP flags from protocol details
        tcp_flags = {}
        if "tcp" in protocol_details:
            tcp_data = protocol_details["tcp"]
            tcp_flags = tcp_data.get("common_flag_combinations", {})

        # Extract port patterns from connections
        port_patterns = []
        if connections:
            # Get unique destination ports
            dst_ports = {}
            for conn in connections[:50]:  # Limit to first 50 connections
                if ":" in conn.get("dst", ""):
                    port = conn["dst"].split(":")[-1]
                    proto = conn.get("proto", "unknown")
                    port_key = f"{proto}/{port}"
                    dst_ports[port_key] = dst_ports.get(port_key, 0) + 1

            # Convert to list of top ports
            port_patterns = [
                {"port": k, "count": v} for k, v in sorted(dst_ports.items(), key=lambda x: x[1], reverse=True)[:10]
            ]

        # Get protocol distribution
        protocol_dist = {}
        for proto, stats in protocols.items():
            protocol_dist[proto] = stats.get("count", 0)

        return {
            "significant_patterns": {
                "tcp_flags": tcp_flags,
                "port_patterns": port_patterns,
                "protocols": protocol_dist,
            },
            "key_stats": {
                "total_connections": len(connections),
                "avg_packet_size": sum(p.get("bytes", 0) for p in protocols.values())
                / max(sum(p.get("count", 0) for p in protocols.values()), 1),
                "top_protocols": list(sorted(protocol_dist.items(), key=lambda x: x[1], reverse=True))[:3],
            },
        }

    def _extract_content_insights(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key content patterns and statistics."""
        content_matches = analysis.get("content_matches", [])
        return {
            "significant_patterns": [
                match
                for match in content_matches
                if match.get("score", 0) > 0.7
                and match.get("type") in ["binary_repeat", "ascii_command", "ascii_script"]
            ][:10],
            "key_stats": {
                "avg_entropy": analysis.get("statistics", {}).get("entropy_stats", {}).get("mean", 0),
                "payload_sizes": analysis.get("statistics", {}).get("size_stats", {}),
            },
        }

    def _extract_http_insights(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key HTTP patterns and statistics."""
        return {
            "significant_patterns": {
                "suspicious_uris": [
                    req for req in analysis.get("requests", []) if self._is_suspicious_uri(req.get("path", ""))
                ][:5],
                "suspicious_headers": [
                    header for header in analysis.get("headers", []) if header.get("significance") == "high"
                ][:5],
            },
            "key_stats": {"methods": analysis.get("methods", {}), "status_codes": analysis.get("status_codes", {})},
        }

    def _extract_anomaly_insights(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Extract critical anomalies and patterns."""
        return {
            "critical_anomalies": [
                anomaly
                for anomaly in analysis.get("network_anomalies", []) + analysis.get("protocol_anomalies", [])
                if anomaly.get("severity") in ["high", "critical"]
            ][:10],
            "key_stats": {
                "total_anomalies": len(analysis.get("network_anomalies", []))
                + len(analysis.get("protocol_anomalies", []))
            },
        }

    def _generate_minimal_metadata(self, packets: List[Packet]) -> Dict[str, Any]:
        """Generate minimal metadata for rule context."""

        return {
            "traffic_profile": {
                "total_packets": len(packets),
                "protocols": {},
                "anomaly_stats": {},
                "content_stats": {},
            },
            "analysis_timestamp": datetime.now().isoformat(),
            "legitimate_patterns": self.whitelist_analyzer._identify_legitimate_patterns({}),
        }

    def _is_suspicious_uri(self, uri: str) -> bool:
        """Determine if a URI is suspicious."""

        suspicious_patterns = [
            r"(?i)(?:eval|exec|system|cmd|powershell)",
            r"(?:[;|&]|\{\s*[\w\-]+\s*\})",
            r"(?:<script|javascript:)",
        ]

        return any(re.search(pattern, uri) for pattern in suspicious_patterns)

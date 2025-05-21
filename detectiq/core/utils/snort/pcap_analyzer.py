import re
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

    def _extract_protocol_insights(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key protocol patterns and statistics."""
        return {
            "significant_patterns": {
                "tcp_flags": analysis.get("tcp", {}).get("common_flag_combinations", {}),
                "port_patterns": analysis.get("port_patterns", [])[:5],
                "protocols": analysis.get("protocol_distribution", {}),
            },
            "key_stats": {
                "total_connections": analysis.get("total_connections", 0),
                "avg_packet_size": analysis.get("avg_packet_size", 0),
                "top_protocols": list(analysis.get("protocol_distribution", {}).items())[:3],
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

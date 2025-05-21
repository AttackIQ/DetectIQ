from typing import Any, Dict, List

from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.packet import Packet

from detectiq.core.utils.logging import get_logger

from .base import BaseAnalyzer

logger = get_logger(__name__)


class HTTPAnalyzer(BaseAnalyzer):
    """Analyzes HTTP traffic patterns."""

    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """Analyze HTTP traffic and return structured results."""
        try:
            return {
                "requests": self._analyze_requests(packets),
                "responses": self._analyze_responses(packets),
                "methods": self._analyze_methods(packets),
                "user_agents": self._analyze_user_agents(packets),
                "status_codes": self._analyze_status_codes(packets),
            }
        except Exception as e:
            logger.error(f"Error analyzing HTTP traffic: {e}")
            return {}

    def _analyze_requests(self, packets: List[Packet]) -> List[Dict[str, Any]]:
        """Analyze HTTP requests."""
        requests = []
        for packet in packets:
            try:
                if isinstance(packet, Packet) and packet.haslayer(HTTPRequest):
                    request = packet[HTTPRequest]
                    requests.append(
                        {
                            "method": request.Method.decode() if hasattr(request, "Method") else None,
                            "path": request.Path.decode() if hasattr(request, "Path") else None,
                            "headers": self._extract_headers(request),
                            "host": request.Host.decode() if hasattr(request, "Host") else None,
                        }
                    )
            except Exception as e:
                logger.debug(f"Error processing HTTP request: {e}")
                continue
        return requests

    def _analyze_responses(self, packets: Any) -> List[Dict[str, Any]]:
        """Analyze HTTP responses."""
        responses = []
        for packet in packets:
            if packet.haslayer(HTTPResponse):
                response = packet[HTTPResponse]
                responses.append(
                    {
                        "status_code": response.Status_Code if hasattr(response, "Status_Code") else None,
                        "headers": self._extract_headers(response),
                        "content_type": response.Content_Type.decode() if hasattr(response, "Content_Type") else None,
                    }
                )
        return responses

    def _analyze_methods(self, packets: Any) -> Dict[str, int]:
        """Analyze HTTP methods usage."""
        methods = {}
        for packet in packets:
            if packet.haslayer(HTTPRequest):
                method = packet[HTTPRequest].Method.decode() if hasattr(packet[HTTPRequest], "Method") else "UNKNOWN"
                methods[method] = methods.get(method, 0) + 1
        return methods

    def _analyze_user_agents(self, packets: Any) -> Dict[str, int]:
        """Analyze User-Agent strings."""
        user_agents = {}
        for packet in packets:
            if packet.haslayer(HTTPRequest):
                headers = self._extract_headers(packet[HTTPRequest])
                ua = headers.get("User-Agent")
                if ua:
                    user_agents[ua] = user_agents.get(ua, 0) + 1
        return user_agents

    def _analyze_status_codes(self, packets: Any) -> Dict[str, int]:
        """Analyze HTTP status codes."""
        status_codes = {}
        for packet in packets:
            if packet.haslayer(HTTPResponse):
                status = (
                    str(packet[HTTPResponse].Status_Code) if hasattr(packet[HTTPResponse], "Status_Code") else "UNKNOWN"
                )
                status_codes[status] = status_codes.get(status, 0) + 1
        return status_codes

    @staticmethod
    def _extract_headers(layer: Any) -> Dict[str, str]:
        """Extract headers from HTTP layer."""
        headers = {}
        for field in layer.fields:
            if field.startswith("Unknown_Header_"):
                continue
            value = getattr(layer, field)
            if isinstance(value, bytes):
                value = value.decode()
            headers[field] = value
        return headers

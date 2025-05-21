import ipaddress
import re
from typing import Any, Dict

from .base import BaseAnalyzer


class WhitelistAnalyzer(BaseAnalyzer):
    """Analyzes traffic to identify patterns that should be whitelisted."""

    def analyze(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "ip_addresses": self._identify_legitimate_ips(analysis),
            "domains": self._identify_legitimate_domains(analysis),
            "user_agents": self._identify_legitimate_user_agents(analysis),
            "services": self._identify_legitimate_services(analysis),
            "content_patterns": self._identify_legitimate_patterns(analysis),
        }

    def _identify_legitimate_ips(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Identify IP addresses that exhibit legitimate behavior."""
        ip_stats = {}
        legitimate_ips = {}

        # Analyze connections
        for conn in analysis.get("connections", []):
            src_ip = conn.get("src")
            dst_ip = conn.get("dst")

            for ip in [src_ip, dst_ip]:
                if not ip or self._is_special_ip(ip):
                    continue

                if ip not in ip_stats:
                    ip_stats[ip] = {
                        "connection_count": 0,
                        "successful_connections": 0,
                        "error_count": 0,
                        "protocols": set(),
                        "ports": set(),
                    }

                ip_stats[ip]["connection_count"] += 1

                # Track protocols and ports
                if "proto" in conn:
                    ip_stats[ip]["protocols"].add(conn["proto"])
                if "dport" in conn:
                    ip_stats[ip]["ports"].add(conn["dport"])

        # Analyze HTTP traffic
        for request in analysis.get("http", {}).get("requests", []):
            ip = request.get("src_ip")
            if ip and ip in ip_stats:
                response_code = request.get("response_code", 0)
                if 200 <= response_code < 400:
                    ip_stats[ip]["successful_connections"] += 1
                elif response_code >= 400:
                    ip_stats[ip]["error_count"] += 1

        # Identify legitimate IPs
        for ip, stats in ip_stats.items():
            if self._is_legitimate_ip_behavior(stats):
                legitimate_ips[ip] = {
                    "stats": {
                        "connection_count": stats["connection_count"],
                        "successful_rate": (
                            stats["successful_connections"] / stats["connection_count"]
                            if stats["connection_count"] > 0
                            else 0
                        ),
                        "error_rate": (
                            stats["error_count"] / stats["connection_count"] if stats["connection_count"] > 0 else 0
                        ),
                        "protocols": list(stats["protocols"]),
                        "ports": list(stats["ports"]),
                    },
                    "confidence": self._calculate_ip_confidence(stats),
                }

        return legitimate_ips

    def _identify_legitimate_domains(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Identify domains that exhibit legitimate behavior."""
        domain_stats = {}
        legitimate_domains = {}

        # Analyze HTTP hosts
        for request in analysis.get("http", {}).get("requests", []):
            host = request.get("host")
            if not host:
                continue

            if host not in domain_stats:
                domain_stats[host] = {
                    "request_count": 0,
                    "successful_requests": 0,
                    "error_requests": 0,
                    "methods": set(),
                    "paths": set(),
                }

            domain_stats[host]["request_count"] += 1

            # Track HTTP methods and paths
            if "method" in request:
                domain_stats[host]["methods"].add(request["method"])
            if "path" in request:
                domain_stats[host]["paths"].add(request["path"])

            # Track response codes
            response_code = request.get("response_code", 0)
            if 200 <= response_code < 400:
                domain_stats[host]["successful_requests"] += 1
            elif response_code >= 400:
                domain_stats[host]["error_requests"] += 1

        # Identify legitimate domains
        for domain, stats in domain_stats.items():
            if self._is_legitimate_domain_behavior(stats):
                legitimate_domains[domain] = {
                    "stats": {
                        "request_count": stats["request_count"],
                        "success_rate": (
                            stats["successful_requests"] / stats["request_count"] if stats["request_count"] > 0 else 0
                        ),
                        "methods": list(stats["methods"]),
                        "paths": list(stats["paths"])[:5],  # Limit to top 5 paths
                    },
                    "confidence": self._calculate_domain_confidence(stats),
                }

        return legitimate_domains

    def _identify_legitimate_user_agents(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Identify legitimate user agent strings."""
        user_agent_stats = {}
        legitimate_user_agents = {}

        for request in analysis.get("http", {}).get("requests", []):
            ua = request.get("user_agent")
            if not ua:
                continue

            if ua not in user_agent_stats:
                user_agent_stats[ua] = {"request_count": 0, "successful_requests": 0, "hosts": set(), "methods": set()}

            user_agent_stats[ua]["request_count"] += 1

            if request.get("host"):
                user_agent_stats[ua]["hosts"].add(request["host"])
            if request.get("method"):
                user_agent_stats[ua]["methods"].add(request["method"])

            if 200 <= request.get("response_code", 0) < 400:
                user_agent_stats[ua]["successful_requests"] += 1

        # Identify legitimate user agents
        for ua, stats in user_agent_stats.items():
            if self._is_legitimate_user_agent(ua, stats):
                legitimate_user_agents[ua] = {
                    "stats": {
                        "request_count": stats["request_count"],
                        "success_rate": (
                            stats["successful_requests"] / stats["request_count"] if stats["request_count"] > 0 else 0
                        ),
                        "hosts": list(stats["hosts"])[:5],
                        "methods": list(stats["methods"]),
                    },
                    "confidence": self._calculate_ua_confidence(stats),
                }

        return legitimate_user_agents

    def _identify_legitimate_services(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Identify legitimate services based on port usage patterns."""
        service_stats = {}
        legitimate_services = {}

        for conn in analysis.get("connections", []):
            port = conn.get("dport")
            if not port:
                continue

            service = self._get_service_name(port)
            if service not in service_stats:
                service_stats[service] = {"connection_count": 0, "unique_clients": set(), "protocols": set()}

            service_stats[service]["connection_count"] += 1
            if conn.get("src"):
                service_stats[service]["unique_clients"].add(conn["src"])
            if conn.get("proto"):
                service_stats[service]["protocols"].add(conn["proto"])

        # Identify legitimate services
        for service, stats in service_stats.items():
            if self._is_legitimate_service(service, stats):
                legitimate_services[service] = {
                    "stats": {
                        "connection_count": stats["connection_count"],
                        "unique_clients": len(stats["unique_clients"]),
                        "protocols": list(stats["protocols"]),
                    },
                    "confidence": self._calculate_service_confidence(stats),
                }

        return legitimate_services

    def _identify_legitimate_patterns(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Identify legitimate content patterns."""
        patterns = {}

        for content in analysis.get("content", {}).get("payload_patterns", []):
            pattern = content.get("hex")
            if not pattern or len(pattern) < 8:  # Ignore very short patterns
                continue

            if pattern not in patterns:
                patterns[pattern] = {"occurrence_count": 0, "contexts": set(), "sizes": []}

            patterns[pattern]["occurrence_count"] += 1
            if content.get("size"):
                patterns[pattern]["sizes"].append(content["size"])
            if content.get("context"):
                patterns[pattern]["contexts"].add(content["context"])

        return {pattern: stats for pattern, stats in patterns.items() if self._is_legitimate_pattern(pattern, stats)}

    @staticmethod
    def _is_special_ip(ip: str) -> bool:
        """Check if IP is special (private, loopback, etc.)."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast
        except ValueError:
            return False

    @staticmethod
    def _is_legitimate_ip_behavior(stats: Dict[str, Any]) -> bool:
        """Determine if IP behavior appears legitimate."""
        if stats["connection_count"] < 5:
            return False

        error_rate = stats["error_count"] / stats["connection_count"] if stats["connection_count"] > 0 else 1

        return (
            error_rate < 0.2  # Less than 20% errors
            and len(stats["protocols"]) >= 1
            and len(stats["ports"]) < 100  # Not scanning too many ports
        )

    @staticmethod
    def _is_legitimate_domain_behavior(stats: Dict[str, Any]) -> bool:
        """Determine if domain behavior appears legitimate."""
        if stats["request_count"] < 3:
            return False

        success_rate = stats["successful_requests"] / stats["request_count"] if stats["request_count"] > 0 else 0

        return (
            success_rate > 0.8  # More than 80% successful requests
            and len(stats["methods"]) <= 4  # Not using too many different HTTP methods
        )

    @staticmethod
    def _is_legitimate_user_agent(ua: str, stats: Dict[str, Any]) -> bool:
        """Determine if user agent appears legitimate."""
        if stats["request_count"] < 5:
            return False

        success_rate = stats["successful_requests"] / stats["request_count"] if stats["request_count"] > 0 else 0

        return (
            success_rate > 0.8  # More than 80% successful requests
            and len(stats["hosts"]) > 1  # Used with multiple hosts
            and len(stats["methods"]) <= 3  # Not using too many different HTTP methods
        )

    @staticmethod
    def _is_legitimate_service(service: str, stats: Dict[str, Any]) -> bool:
        """Determine if service usage appears legitimate."""
        return (
            stats["connection_count"] >= 5  # Minimum number of connections
            and len(stats["unique_clients"]) >= 2  # Multiple clients
            and len(stats["protocols"]) >= 1  # Using expected protocols
        )

    @staticmethod
    def _is_legitimate_pattern(pattern: str, stats: Dict[str, Any]) -> bool:
        """Determine if content pattern appears legitimate."""
        return (
            stats["occurrence_count"] >= 3  # Seen multiple times
            and len(stats["contexts"]) >= 1  # Has context
            and len(stats["sizes"]) >= 2  # Seen in multiple sizes
        )

    @staticmethod
    def _calculate_ip_confidence(stats: Dict[str, Any]) -> float:
        """Calculate confidence score for IP legitimacy."""
        score = 0.0
        max_score = 4.0

        # Connection count score (up to 1.0)
        score += min(1.0, stats["connection_count"] / 100)

        # Success rate score (up to 1.0)
        success_rate = (
            stats["successful_connections"] / stats["connection_count"] if stats["connection_count"] > 0 else 0
        )
        score += success_rate

        # Protocol diversity score (up to 1.0)
        score += min(1.0, len(stats["protocols"]) / 3)

        # Port usage score (up to 1.0)
        port_score = 1.0 - (min(1.0, len(stats["ports"]) / 100))
        score += port_score

        return round(score / max_score, 2)

    @staticmethod
    def _get_service_name(port: int) -> str:
        """Get service name from port number."""
        common_ports = {
            80: "HTTP",
            443: "HTTPS",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            110: "POP3",
            143: "IMAP",
            445: "SMB",
            3389: "RDP",
        }
        return common_ports.get(port, f"PORT_{port}")

    @staticmethod
    def _calculate_domain_confidence(stats: Dict[str, Any]) -> float:
        """Calculate confidence score for domain legitimacy."""
        score = 0.0
        max_score = 4.0

        # Request count score (up to 1.0)
        score += min(1.0, stats["request_count"] / 50)

        # Success rate score (up to 1.0)
        success_rate = stats["successful_requests"] / stats["request_count"] if stats["request_count"] > 0 else 0
        score += success_rate

        # Method diversity score (up to 1.0)
        method_score = 1.0 - (min(1.0, len(stats["methods"]) / 8))
        score += method_score

        # Path diversity score (up to 1.0)
        path_score = min(1.0, len(stats["paths"]) / 10)
        score += path_score

        return round(score / max_score, 2)

    @staticmethod
    def _calculate_ua_confidence(stats: Dict[str, Any]) -> float:
        """Calculate confidence score for user agent legitimacy."""
        score = 0.0
        max_score = 4.0

        # Request count score (up to 1.0)
        score += min(1.0, stats["request_count"] / 20)

        # Success rate score (up to 1.0)
        success_rate = stats["successful_requests"] / stats["request_count"] if stats["request_count"] > 0 else 0
        score += success_rate

        # Host diversity score (up to 1.0)
        host_score = min(1.0, len(stats["hosts"]) / 5)
        score += host_score

        # Method consistency score (up to 1.0)
        method_score = 1.0 - (min(1.0, len(stats["methods"]) / 5))
        score += method_score

        return round(score / max_score, 2)

    @staticmethod
    def _calculate_service_confidence(stats: Dict[str, Any]) -> float:
        """Calculate confidence score for service legitimacy."""
        score = 0.0
        max_score = 3.0

        # Connection count score (up to 1.0)
        score += min(1.0, stats["connection_count"] / 50)

        # Client diversity score (up to 1.0)
        client_score = min(1.0, len(stats["unique_clients"]) / 10)
        score += client_score

        # Protocol consistency score (up to 1.0)
        protocol_score = min(1.0, len(stats["protocols"]))
        score += protocol_score

        return round(score / max_score, 2)

    @staticmethod
    def _calculate_pattern_confidence(stats: Dict[str, Any]) -> float:
        """Calculate confidence score for content pattern legitimacy."""
        score = 0.0
        max_score = 3.0

        # Occurrence count score (up to 1.0)
        score += min(1.0, stats["occurrence_count"] / 10)

        # Context diversity score (up to 1.0)
        context_score = min(1.0, len(stats["contexts"]) / 3)
        score += context_score

        # Size diversity score (up to 1.0)
        size_score = min(1.0, len(stats["sizes"]) / 5)
        score += size_score

        return round(score / max_score, 2)

    @staticmethod
    def _validate_user_agent(ua: str) -> bool:
        """Validate user agent string format and characteristics."""
        if not ua or len(ua) < 5:
            return False

        common_browsers = ["Mozilla", "Chrome", "Safari", "Firefox", "Edge", "Opera"]
        common_platforms = ["Windows", "Macintosh", "Linux", "Android", "iPhone"]

        # Check for common browser identifiers
        has_browser = any(browser.lower() in ua.lower() for browser in common_browsers)
        # Check for common platform identifiers
        has_platform = any(platform.lower() in ua.lower() for platform in common_platforms)
        # Check for version numbers
        has_version = bool(re.search(r"\d+\.\d+", ua))

        return has_browser and has_platform and has_version

    @staticmethod
    def _validate_domain_format(domain: str) -> bool:
        """Validate domain name format."""
        if not domain or len(domain) < 4:
            return False

        domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        return bool(re.match(domain_pattern, domain))

    @staticmethod
    def _validate_service_port(port: int) -> bool:
        """Validate if port number is within expected ranges."""
        if not isinstance(port, int):
            return False

        # Well-known ports
        if 0 <= port <= 1023:
            return True
        # Registered ports
        if 1024 <= port <= 49151:
            return True
        # Dynamic/private ports
        if 49152 <= port <= 65535:
            return True

        return False

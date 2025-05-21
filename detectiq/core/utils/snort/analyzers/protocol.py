from collections import defaultdict
from typing import Any, Dict, List

from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.tls.record import TLS

from .base import BaseAnalyzer
from .http import HTTPAnalyzer


class ProtocolAnalyzer(BaseAnalyzer):
    """Handles protocol-specific analysis."""

    def __init__(self):
        self.http_analyzer = HTTPAnalyzer()

    def analyze(self, packets: Any) -> Dict[str, Any]:
        return {
            "protocols": self._analyze_protocols(packets),
            "connections": self._analyze_connections(packets),
            "flows": self._analyze_flows(packets),
            "protocol_details": self._analyze_protocol_details(packets),
        }

    def _analyze_protocols(self, packets: Any) -> Dict[str, Dict[str, Any]]:
        """Analyze protocol distribution and characteristics."""
        protocol_stats: Dict[str, Dict[str, Any]] = {}

        for packet in packets:
            if packet.haslayer(IP):
                ip = packet[IP]
                proto = self._get_protocol_name(packet)

                if proto not in protocol_stats:
                    protocol_stats[proto] = {
                        "count": 0,
                        "bytes": 0,
                        "ports": set(),
                        "source_ips": set(),
                        "dest_ips": set(),
                    }

                stats = protocol_stats[proto]
                stats["count"] += 1
                stats["bytes"] += len(packet)
                stats["source_ips"].add(ip.src)
                stats["dest_ips"].add(ip.dst)

                # Track ports for TCP/UDP
                if packet.haslayer(TCP):
                    stats["ports"].add(packet[TCP].sport)
                    stats["ports"].add(packet[TCP].dport)
                elif packet.haslayer(UDP):
                    stats["ports"].add(packet[UDP].sport)
                    stats["ports"].add(packet[UDP].dport)

        # Convert sets to lists for JSON serialization
        return {
            proto: {
                "count": stats["count"],
                "bytes": stats["bytes"],
                "ports": sorted(list(stats["ports"])),
                "unique_sources": len(stats["source_ips"]),
                "unique_destinations": len(stats["dest_ips"]),
            }
            for proto, stats in protocol_stats.items()
        }

    def _analyze_connections(self, packets: Any) -> List[Dict[str, Any]]:
        """Analyze network connections in detail."""
        connections = {}

        for packet in packets:
            if packet.haslayer(IP):
                ip = packet[IP]
                proto = self._get_protocol_name(packet)

                # Create connection key
                if packet.haslayer(TCP) or packet.haslayer(UDP):
                    layer = packet[TCP] if packet.haslayer(TCP) else packet[UDP]
                    conn_key = f"{ip.src}:{layer.sport}-{ip.dst}:{layer.dport}-{proto}"
                else:
                    conn_key = f"{ip.src}-{ip.dst}-{proto}"

                if conn_key not in connections:
                    connections[conn_key] = {
                        "src": ip.src,
                        "dst": ip.dst,
                        "proto": proto,
                        "start_time": packet.time,
                        "last_time": packet.time,
                        "packets": 0,
                        "bytes": 0,
                        "flags": set() if packet.haslayer(TCP) else None,
                    }

                conn = connections[conn_key]
                conn["packets"] += 1
                conn["bytes"] += len(packet)
                conn["last_time"] = packet.time

                if packet.haslayer(TCP):
                    conn["flags"].update(self._decode_tcp_flags(packet[TCP].flags))

        # Process connections for output
        return [
            {
                **conn,
                "duration": round(conn["last_time"] - conn["start_time"], 3),
                "flags": sorted(list(conn["flags"])) if conn["flags"] is not None else None,
            }
            for conn in connections.values()
        ]

    def _analyze_flows(self, packets: Any) -> List[Dict[str, Any]]:
        """Analyze bidirectional flows."""
        flows = {}

        for packet in packets:
            if packet.haslayer(IP):
                ip = packet[IP]
                proto = self._get_protocol_name(packet)

                # Create bidirectional flow key
                if packet.haslayer(TCP) or packet.haslayer(UDP):
                    layer = packet[TCP] if packet.haslayer(TCP) else packet[UDP]
                    endpoints = sorted([f"{ip.src}:{layer.sport}", f"{ip.dst}:{layer.dport}"])
                    flow_key = f"{endpoints[0]}-{endpoints[1]}-{proto}"
                else:
                    endpoints = sorted([ip.src, ip.dst])
                    flow_key = f"{endpoints[0]}-{endpoints[1]}-{proto}"

                if flow_key not in flows:
                    flows[flow_key] = {
                        "endpoints": endpoints,
                        "proto": proto,
                        "start_time": packet.time,
                        "last_time": packet.time,
                        "packets": 0,
                        "bytes": 0,
                        "states": set(),
                        "application": self._detect_application_protocol(packet),
                    }

                flow = flows[flow_key]
                flow["packets"] += 1
                flow["bytes"] += len(packet)
                flow["last_time"] = packet.time

                if packet.haslayer(TCP):
                    flow["states"].add(self._get_tcp_state(packet[TCP].flags))

        # Process flows for output
        return [
            {
                **flow,
                "duration": round(flow["last_time"] - flow["start_time"], 3),
                "states": sorted(list(flow["states"])),
            }
            for flow in flows.values()
        ]

    def _analyze_protocol_details(self, packets: Any) -> Dict[str, Any]:
        """Analyze detailed protocol-specific characteristics."""
        return {
            "tcp": self._analyze_tcp_details(packets),
            "udp": self._analyze_udp_details(packets),
            "http": self.http_analyzer.analyze(packets),
            "dns": self._analyze_dns_details(packets),
            "tls": self._analyze_tls_details(packets),
        }

    def _analyze_tcp_details(self, packets: Any) -> Dict[str, Any]:
        """Analyze TCP-specific details."""
        tcp_stats = {"handshakes": 0, "resets": 0, "window_sizes": [], "flag_combinations": defaultdict(int)}

        for packet in packets:
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                flags = self._decode_tcp_flags(tcp.flags)
                tcp_stats["flag_combinations"][tuple(sorted(flags))] += 1

                if "S" in flags and "A" not in flags:
                    tcp_stats["handshakes"] += 1
                if "R" in flags:
                    tcp_stats["resets"] += 1
                tcp_stats["window_sizes"].append(tcp.window)

        return {
            "handshakes": tcp_stats["handshakes"],
            "resets": tcp_stats["resets"],
            "avg_window_size": (
                sum(tcp_stats["window_sizes"]) / len(tcp_stats["window_sizes"]) if tcp_stats["window_sizes"] else 0
            ),
            "common_flag_combinations": dict(tcp_stats["flag_combinations"]),
        }

    def _analyze_udp_details(self, packets: Any) -> Dict[str, Any]:
        """Analyze UDP-specific details."""
        udp_stats = {"total_packets": 0, "total_bytes": 0}
        port_usage = defaultdict(int)

        for packet in packets:
            if packet.haslayer(UDP):
                udp = packet[UDP]
                udp_stats["total_packets"] += 1
                udp_stats["total_bytes"] += len(packet)
                port_usage[udp.dport] += 1

        return {
            "total_packets": udp_stats["total_packets"],
            "total_bytes": udp_stats["total_bytes"],
            "common_ports": dict(sorted(port_usage.items(), key=lambda x: x[1], reverse=True)[:10]),
        }

    def _analyze_dns_details(self, packets: Any) -> Dict[str, Any]:
        """Analyze DNS-specific details."""
        dns_stats = {
            "queries": 0,
            "responses": 0,
            "query_types": defaultdict(int),
            "response_codes": defaultdict(int),
            "domains": defaultdict(int),
        }

        for packet in packets:
            if packet.haslayer(DNS):
                dns = packet[DNS]

                # Check if it's a query or response
                if dns.qr == 0:  # Query
                    dns_stats["queries"] += 1
                    if dns.qd:
                        dns_stats["query_types"][dns.qd.qtype] += 1
                        if hasattr(dns.qd, "qname"):
                            domain = dns.qd.qname.decode()
                            dns_stats["domains"][domain] += 1
                else:  # Response
                    dns_stats["responses"] += 1
                    dns_stats["response_codes"][dns.rcode] += 1

        return {
            "query_count": dns_stats["queries"],
            "response_count": dns_stats["responses"],
            "query_types": dict(dns_stats["query_types"]),
            "response_codes": dict(dns_stats["response_codes"]),
            "top_domains": dict(sorted(dns_stats["domains"].items(), key=lambda x: x[1], reverse=True)[:10]),
        }

    def _analyze_tls_details(self, packets: Any) -> Dict[str, Any]:
        """Analyze TLS-specific details."""
        tls_stats = {
            "handshakes": 0,
            "versions": defaultdict(int),
            "cipher_suites": defaultdict(int),
            "certificates": set(),
        }

        for packet in packets:
            if packet.haslayer(TLS):
                tls = packet[TLS]

                # Track TLS versions
                if hasattr(tls, "version"):
                    tls_stats["versions"][tls.version] += 1

                # Track handshakes
                if hasattr(tls, "type") and tls.type == 22:  # Handshake
                    tls_stats["handshakes"] += 1

                    # Track cipher suites if available
                    if hasattr(tls, "cipher_suites"):
                        for suite in tls.cipher_suites:
                            tls_stats["cipher_suites"][suite] += 1

                    # Track certificates if available
                    if hasattr(tls, "certificates"):
                        for cert in tls.certificates:
                            tls_stats["certificates"].add(cert)

        return {
            "handshake_count": tls_stats["handshakes"],
            "versions": dict(tls_stats["versions"]),
            "cipher_suites": dict(tls_stats["cipher_suites"]),
            "unique_certificates": len(tls_stats["certificates"]),
        }

    @staticmethod
    def _get_protocol_name(packet: Any) -> str:
        """Get protocol name from packet."""
        if packet.haslayer(TCP):
            if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
                return "HTTP"
            if packet.haslayer(TLS):
                return "TLS"
            return "TCP"
        elif packet.haslayer(UDP):
            if packet.haslayer(DNS):
                return "DNS"
            return "UDP"
        elif packet.haslayer(IP):
            return f"IP_{packet[IP].proto}"
        return "OTHER"

    @staticmethod
    def _get_tcp_state(flags: int) -> str:
        """Get TCP connection state from flags."""
        flags_set = set()
        if flags & 0x02:  # SYN
            flags_set.add("S")
        if flags & 0x10:  # ACK
            flags_set.add("A")
        if flags & 0x01:  # FIN
            flags_set.add("F")
        if flags & 0x04:  # RST
            flags_set.add("R")

        if "S" in flags_set and "A" not in flags_set:
            return "SYN"
        elif "S" in flags_set and "A" in flags_set:
            return "SYN-ACK"
        elif "F" in flags_set:
            return "FIN"
        elif "R" in flags_set:
            return "RST"
        elif "A" in flags_set:
            return "ESTABLISHED"
        return "OTHER"

    @staticmethod
    def _detect_application_protocol(packet: Any) -> str:
        """Detect application protocol from packet."""
        if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
            return "HTTP"
        elif packet.haslayer(DNS):
            return "DNS"
        elif packet.haslayer(TLS):
            return "TLS"
        elif packet.haslayer(TCP):
            dport = packet[TCP].dport
            if dport == 80:
                return "HTTP"
            elif dport == 443:
                return "HTTPS"
            elif dport == 22:
                return "SSH"
            elif dport == 21:
                return "FTP"
        elif packet.haslayer(UDP):
            dport = packet[UDP].dport
            if dport == 53:
                return "DNS"
            elif dport == 67 or dport == 68:
                return "DHCP"
        return "UNKNOWN"

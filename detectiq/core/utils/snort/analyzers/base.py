from abc import ABC, abstractmethod
from typing import Any, Dict, List


class BaseAnalyzer(ABC):
    """Base class for PCAP analysis components."""

    @abstractmethod
    def analyze(self, data: Any) -> Dict[str, Any]:
        """Perform analysis and return results."""
        pass

    @staticmethod
    def _decode_tcp_flags(flags: int) -> List[str]:
        """Decode TCP flags - shared method for all analyzers."""
        flag_map = {0x01: "FIN", 0x02: "SYN", 0x04: "RST", 0x08: "PSH", 0x10: "ACK", 0x20: "URG"}
        return [flag for mask, flag in flag_map.items() if flags & mask]

    @staticmethod
    def _is_anomalous_tcp_flags(flags: int) -> bool:
        """Check for anomalous TCP flag combinations."""
        suspicious_combinations = [0x03, 0x06, 0x05, 0x00]  # SYN-FIN  # SYN-RST  # FIN-RST  # NULL
        return flags in suspicious_combinations

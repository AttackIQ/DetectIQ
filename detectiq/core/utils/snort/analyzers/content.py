import binascii
import re
from collections import Counter
from typing import Any, Dict, List, Sequence

import numpy as np
from scapy.packet import Raw

from detectiq.core.utils.logging import get_logger
from detectiq.core.utils.snort.analyzers.base import BaseAnalyzer

logger = get_logger(__name__)


class ContentAnalyzer(BaseAnalyzer):
    """Analyzes packet content and payload patterns with performance optimizations."""

    def __init__(self):
        super().__init__()
        # Precompile regex patterns once
        self.binary_signatures = [
            (re.compile(b"^PK\x03\x04"), "ZIP archive"),
            (re.compile(b"^\x89PNG\r\n\x1a\n"), "PNG image"),
            (re.compile(b"^GIF8[79]a"), "GIF image"),
            (re.compile(b"^\xff\xd8\xff"), "JPEG image"),
            (re.compile(b"^%PDF"), "PDF document"),
            (re.compile(b"^\x7fELF"), "ELF executable"),
            (re.compile(b"^MZ"), "Windows executable"),
            (re.compile(b"^\x1f\x8b\x08"), "GZIP archive"),
            (re.compile(b"^BZh"), "BZIP2 archive"),
            (re.compile(b"^\x42\x4d"), "BMP image"),
            (re.compile(b"^ustar"), "TAR archive"),
        ]

        # Precompile ASCII pattern regexes
        self.ascii_patterns = {
            "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
            "url": re.compile(r'(?:http[s]?://[^\s<>"]+|www\.[^\s<>"]+)'),
            "windows_path": re.compile(r'(?:[A-Za-z]:\\[^/\\:*?"<>|\r\n]+)'),
            "unix_path": re.compile(r"(?:/[A-Za-z0-9_.-]+)+"),
            "domain": re.compile(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"),
            "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
            "base64": re.compile(r"[A-Za-z0-9+/]{32,}={0,2}"),
            "command": re.compile(r"(?:[A-Za-z]+\s+(?:--?[a-zA-Z-]+\s*)?){2,}"),
            "guid": re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
            "json": re.compile(r"\{(?:[^{}]|{[^{}]*})*\}"),
        }

    def analyze(self, packets: Any) -> Dict[str, Any]:
        # Limit the number of packets to process (e.g., first 1000 packets)
        max_packets = 1000
        packets = packets[:max_packets]

        # Process packets in parallel if possible
        # For simplicity, we'll process them sequentially here
        # Consider using concurrent.futures.ThreadPoolExecutor for parallel processing

        # Preprocess payloads to avoid redundant computations
        payloads = [bytes(p[Raw].load) for p in packets if p.haslayer(Raw) and p[Raw].load]

        # Precompute entropy values
        entropy_values = [self._calculate_entropy(payload) for payload in payloads]

        # Extract patterns and statistics
        content_matches = self._find_content_matches(payloads)
        statistics = self._calculate_content_statistics(payloads, entropy_values)

        return {
            "content_matches": content_matches,
            "statistics": statistics,
        }

    def _find_content_matches(self, payloads: List[bytes]) -> List[Dict[str, Any]]:
        """Find meaningful content patterns in payloads."""
        content_matches = []
        for payload in payloads:
            matches = self._find_patterns(payload)
            if matches:
                content_matches.extend(matches)
        return content_matches

    def _calculate_content_statistics(self, payloads: List[bytes], entropy_values: List[float]) -> Dict[str, Any]:
        """Calculate statistics about packet content."""
        sizes = [len(payload) for payload in payloads]

        return {
            "size_stats": self._calculate_statistics(sizes),
            "entropy_stats": self._calculate_statistics(entropy_values),
        }

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of payload using numpy."""
        if not data:
            return 0.0

        arr = np.frombuffer(data, dtype=np.uint8)
        if arr.size == 0:
            return 0.0

        counts = np.bincount(arr)
        probabilities = counts[counts > 0] / arr.size
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return round(float(entropy), 4)

    @staticmethod
    def _calculate_statistics(values: Sequence[float]) -> Dict[str, float]:
        """Calculate basic statistics for a list of values."""
        if not values:
            return {"min": 0, "max": 0, "avg": 0, "median": 0}

        values_sorted = sorted(values)
        length = len(values)
        median = (
            values_sorted[length // 2]
            if length % 2 == 1
            else (values_sorted[length // 2 - 1] + values_sorted[length // 2]) / 2
        )

        return {
            "min": min(values),
            "max": max(values),
            "avg": sum(values) / length,
            "median": median,
        }

    def _find_patterns(self, payload: bytes) -> List[Dict[str, Any]]:
        """Find various types of patterns in payload."""
        patterns = []

        # Limit payload size to first N bytes
        max_payload_size = 2048  # Process only first 2KB
        payload = payload[:max_payload_size]

        # Check for binary signatures
        for regex, description in self.binary_signatures:
            if regex.match(payload):
                patterns.append(
                    {
                        "pattern": description,
                        "offset": 0,
                        "depth": len(regex.pattern),
                        "type": "binary_signature",
                        "score": 1.0,
                    }
                )
                break  # Stop after finding a signature

        # Find ASCII patterns
        ascii_patterns = self._find_ascii_patterns(payload)
        if ascii_patterns:
            patterns.extend(ascii_patterns)

        # Find repeating binary patterns (limited to small payloads)
        if len(payload) <= 1024:
            binary_patterns = self._find_repeating_binary_patterns(payload)
            if binary_patterns:
                patterns.extend(binary_patterns)

        return patterns

    def _find_ascii_patterns(self, payload: bytes) -> List[Dict[str, Any]]:
        """Find ASCII patterns in payload."""
        patterns = []
        try:
            ascii_str = payload.decode("ascii", errors="ignore")
            for pattern_type, regex in self.ascii_patterns.items():
                for match in regex.finditer(ascii_str):
                    pattern_text = match.group()
                    score = self._calculate_ascii_pattern_score(pattern_text, ascii_str)
                    if score > 0.5:  # Adjust threshold as needed
                        patterns.append(
                            {
                                "pattern": pattern_text,
                                "offset": match.start(),
                                "depth": match.end(),
                                "type": f"ascii_{pattern_type}",
                                "score": score,
                            }
                        )
        except Exception as e:
            logger.debug(f"Error finding ASCII patterns: {e}")

        return patterns

    def _calculate_ascii_pattern_score(self, pattern_text: str, ascii_str: str) -> float:
        """Calculate score for ASCII pattern."""
        length_score = min(len(pattern_text) / 50, 1.0)  # Adjust max length
        frequency = ascii_str.count(pattern_text) / len(ascii_str)
        frequency_score = min(frequency * 10, 1.0)
        return 0.5 * length_score + 0.5 * frequency_score

    def _find_repeating_binary_patterns(self, payload: bytes) -> List[Dict[str, Any]]:
        """Find repeating binary patterns in payload (optimized)."""
        patterns = []
        try:
            arr = np.frombuffer(payload, dtype=np.uint8)
            if arr.size == 0:
                return patterns

            # Limit pattern lengths and avoid nested loops
            for length in range(4, 9):  # Lengths from 4 to 8 bytes
                if arr.size < length:
                    continue

                windows = np.lib.stride_tricks.sliding_window_view(arr, length)
                if windows.size == 0:
                    continue

                # Hash windows to reduce memory usage
                window_hashes = [hash(bytes(window)) for window in windows]
                counts = Counter(window_hashes)

                for window_hash, count in counts.items():
                    if count > 1:
                        index = window_hashes.index(window_hash)
                        pattern_bytes = bytes(windows[index])
                        score = self._calculate_binary_pattern_score(pattern_bytes, count, arr.size)
                        if score > 0.6:  # Adjust threshold as needed
                            patterns.append(
                                {
                                    "pattern": binascii.hexlify(pattern_bytes).decode("ascii"),
                                    "offset": index,
                                    "depth": length,
                                    "type": "binary_repeat",
                                    "count": count,
                                    "score": score,
                                }
                            )
        except Exception as e:
            logger.debug(f"Error finding binary patterns: {e}")

        return patterns

    def _calculate_binary_pattern_score(self, pattern: bytes, count: int, total_length: int) -> float:
        """Calculate score for binary pattern."""
        length_score = min(len(pattern) / 8, 1.0)
        frequency = (count * len(pattern)) / total_length
        frequency_score = min(frequency * 5, 1.0)
        entropy_score = self._calculate_entropy(pattern) / 8.0
        return 0.3 * length_score + 0.4 * frequency_score + 0.3 * entropy_score

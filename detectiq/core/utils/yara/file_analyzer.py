import hashlib
import importlib.util
import math
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Union

from detectiq.core.utils.logging import get_logger
from detectiq.core.utils.snort.pcap_analyzer import PcapAnalyzer
from detectiq.core.utils.yara.config import AnalysisConfig

from .pe_analyzer import analyze_pe


class FileAnalyzer:
    """Utility class for analyzing files for rule creation."""

    def __init__(self, config: Optional[AnalysisConfig] = None):
        """Initialize analyzer and check for optional dependencies."""
        self.config = config or AnalysisConfig()
        self.has_pefile = importlib.util.find_spec("pefile") is not None
        self.pcap_analyzer = PcapAnalyzer()
        self.logger = get_logger(__name__)

    async def analyze_file(self, file: Union[Path, BinaryIO, bytes], file_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze a file for YARA rule creation.

        Args:
            file: File to analyze (Path, file-like object, or bytes)
            file_type: Optional file type hint

        Returns:
            Dict[str, Any]: Analysis results
        """
        try:
            # Handle different input types
            if isinstance(file, (str, Path)):
                with open(file, "rb") as f:
                    data = f.read()
            elif isinstance(file, bytes):
                data = file
            elif isinstance(file, (bytearray, memoryview)):
                data = bytes(file)
            elif hasattr(file, "read"):
                data = file.read()
            else:
                raise ValueError("Unsupported file input type")

            # Determine file type if not provided
            if not file_type:
                file_type = self._determine_file_type(data)

            analysis = {
                "file_info": self._get_file_info(data, file_type),
                "insights": [],
            }

            # Add high-entropy strings only
            strings = self._extract_strings(data)
            analysis["suspicious_strings"] = {
                category: [s for s in strings[category] if len(s) > 8][:10]  # Limit to top 10 longer strings
                for category in strings
            }

            # Add only high-entropy regions and overall entropy
            entropy_data = self._analyze_entropy_patterns(data)
            analysis["entropy"] = {
                "total": entropy_data["total"],
                "high_entropy_regions": [
                    region for region in entropy_data["high_entropy_regions"] if region["entropy"] > 7.0
                ][
                    :5
                ],  # Limit to top 5 suspicious regions
            }

            # Add only suspicious code patterns
            code_patterns = self._analyze_code_patterns(data)
            if code_patterns["api_sequences"] or code_patterns["crypto_constants"]:
                analysis["suspicious_code"] = {
                    "api_calls": code_patterns["api_sequences"][:5],
                    "crypto_indicators": code_patterns["crypto_constants"][:3],
                }

            # Add only detected anti-analysis techniques
            anti_analysis = self._analyze_anti_analysis_patterns(data)
            if anti_analysis:
                analysis["evasion_techniques"] = anti_analysis[:5]

            # Add only suspicious network indicators
            network = self._analyze_network_indicators(data)
            if any(network.values()):
                analysis["network_indicators"] = {
                    k: v[:5] for k, v in network.items() if v  # Limit each category to top 5
                }

            # Add only suspicious persistence mechanisms
            persistence = self._analyze_persistence_mechanisms(data)
            if any(persistence.values()):
                analysis["persistence_indicators"] = {
                    k: v[:3] for k, v in persistence.items() if v  # Limit each category to top 3
                }

            # PE-specific analysis with reduced output
            if file_type == "PE" and self.has_pefile:
                pe_info = analyze_pe(data)
                if pe_info:
                    analysis["pe_info"] = self._filter_pe_info(pe_info)

            # Generate focused insights
            analysis["insights"] = self._generate_insights(analysis)

            return analysis

        except Exception as e:
            self.logger.error(f"Error during file analysis: {e}")
            raise

    def _filter_pe_info(self, pe_info: Dict[str, Any]) -> Dict[str, Any]:
        """Filter PE information to include only the most relevant data."""
        filtered = {}

        # Include suspicious sections with high entropy or unusual characteristics
        if "sections" in pe_info and pe_info["sections"]:
            filtered["suspicious_sections"] = pe_info["sections"][:3]  # Already filtered in analyze_pe

        # Include suspicious imports
        if "imports" in pe_info and pe_info["imports"]:
            filtered["suspicious_imports"] = pe_info["imports"][:5]  # Already filtered in analyze_pe

        # Include anomalies (already limited to top 5 in detect_pe_anomalies)
        if "anomalies" in pe_info and pe_info["anomalies"]:
            filtered["anomalies"] = pe_info["anomalies"]

        # Add severity assessment based on findings
        severity_score = 0
        if filtered.get("suspicious_sections"):
            severity_score += len(filtered["suspicious_sections"]) * 2
        if filtered.get("suspicious_imports"):
            severity_score += len(filtered["suspicious_imports"]) * 1.5
        if filtered.get("anomalies"):
            severity_score += len(filtered["anomalies"])

        filtered["risk_assessment"] = {
            "score": min(10, severity_score),  # Cap at 10
            "level": "High" if severity_score > 7 else "Medium" if severity_score > 4 else "Low",
            "summary": f"Found {len(filtered.get('suspicious_sections', []))} suspicious sections, "
            f"{len(filtered.get('suspicious_imports', []))} suspicious imports, and "
            f"{len(filtered.get('anomalies', []))} anomalies",
        }

        return filtered

    def _generate_insights(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate insights for YARA rule creation based on analysis results."""
        insights = []

        try:
            # Check entropy patterns
            if "entropy" in analysis and analysis["entropy"]["total"] > self.config.entropy_threshold:
                insights.append("High overall entropy - possible packed/encrypted content")

            # Check for suspicious network indicators
            if "network_indicators" in analysis and (
                analysis["network_indicators"].get("urls") or analysis["network_indicators"].get("domains")
            ):
                insights.append("Contains network indicators - consider adding network-related conditions")

            # Check for anti-analysis techniques
            if "evasion_techniques" in analysis and analysis["evasion_techniques"]:
                insights.append("Anti-analysis techniques detected - consider anti-evasion conditions")

            # PE-specific insights
            if "pe_info" in analysis and analysis["pe_info"].get("anomalies"):
                insights.append("PE anomalies detected - consider adding specific PE conditions")

        except Exception as e:
            self.logger.error(f"Error generating insights: {e}")

        return insights

    def _extract_strings(self, data: bytes) -> Dict[str, List[str]]:
        """Enhanced string extraction with categorization."""
        strings = {
            "ascii": [],
            "unicode": [],
            "base64": [],
            # "hex": [],  # Uncomment if needed
            # "urls": [],
            # "paths": [],
            # "commands": [],
        }

        try:
            min_len = self.config.min_string_length

            # ASCII strings
            ascii_pattern = rb"[\x20-\x7e]{%d,}" % min_len
            strings["ascii"] = [m.group().decode("utf-8", errors="replace") for m in re.finditer(ascii_pattern, data)]

            # Unicode strings
            unicode_pattern = rb"(?:[\x20-\x7e]\x00){%d,}" % min_len
            strings["unicode"] = [
                m.group().decode("utf-16le", errors="replace") for m in re.finditer(unicode_pattern, data)
            ]

            # Base64 strings
            b64_pattern = rb"(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
            strings["base64"] = [m.group().decode("utf-8", errors="replace") for m in re.finditer(b64_pattern, data)]

            # Limit results
            for category in strings:
                strings[category] = strings[category][: self.config.max_strings]

        except Exception as e:
            self.logger.error(f"Error extracting strings: {e}")

        return strings

    def _get_file_info(self, data: bytes, file_type: str) -> Dict[str, Any]:
        """Get basic file information."""
        return {
            "size": len(data),
            "type": file_type,
            "md5": hashlib.md5(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    def _determine_file_type(self, data: bytes) -> str:
        """Determine the type of file based on magic bytes."""
        if data.startswith(b"MZ"):
            return "PE"
        elif data.startswith(b"PK\x03\x04"):
            return "ZIP"
        elif data.startswith(b"\x7fELF"):
            return "ELF"
        elif data.startswith(b"%PDF"):
            return "PDF"
        return "Unknown"

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        entropy = 0.0
        byte_counts = Counter(data)
        for count in byte_counts.values():
            p_x = count / len(data)
            entropy += -p_x * math.log2(p_x)
        return round(entropy, 4)

    async def analyze_pcap(self, data: Union[Path, bytes]) -> Dict[str, Any]:
        """Delegate PCAP analysis to PcapAnalyzer."""
        return await self.pcap_analyzer.analyze_file(data)

    def _analyze_code_patterns(self, data: bytes) -> Dict[str, List[str]]:
        """Analyze code patterns and potential indicators of malicious behavior."""
        patterns = {
            "api_sequences": [],
            "function_prologs": [],
            "crypto_constants": [],
            "suspicious_instructions": [],
        }

        try:
            # Common API patterns
            api_patterns = [
                b"GetProcAddress",
                b"LoadLibrary",
                b"VirtualAlloc",
                b"WriteProcessMemory",
                b"CreateThread",
            ]

            # Function prologs
            prolog_patterns = [
                b"\x55\x8b\xec",  # push ebp; mov ebp, esp
                b"\x48\x89\x5c",  # mov [rsp+var], rbx
            ]

            # Crypto constants
            crypto_constants = [
                bytes.fromhex("67452301"),  # MD5
                bytes.fromhex("0123456789ABCDEF"),  # Common crypto
            ]

            for api in api_patterns:
                if api in data:
                    patterns["api_sequences"].append(api.decode("utf-8", errors="replace"))

            for prolog in prolog_patterns:
                if prolog in data:
                    patterns["function_prologs"].append(prolog.hex())

            for const in crypto_constants:
                if const in data:
                    patterns["crypto_constants"].append(const.hex())

        except Exception as e:
            self.logger.error(f"Error analyzing code patterns: {e}")

        return patterns

    def _analyze_anti_analysis_patterns(self, data: bytes) -> List[str]:
        """Detect anti-analysis and evasion techniques."""
        findings = []

        try:
            # Anti-debugging APIs
            anti_debug_apis = {
                b"IsDebuggerPresent": "Debug detection",
                b"CheckRemoteDebuggerPresent": "Remote debug detection",
                b"NtQueryInformationProcess": "Process information check",
            }

            # VM detection strings
            vm_strings = [
                b"VMware",
                b"VBox",
                b"QEMU",
                b"Virtual",
                b"Sandbox",
            ]

            for api, technique in anti_debug_apis.items():
                if api in data:
                    findings.append(
                        f"Anti-debugging technique found: {api.decode('utf-8', errors='replace')} ({technique})"
                    )

            for vm_string in vm_strings:
                if vm_string in data:
                    findings.append(f"VM detection string found: {vm_string.decode('utf-8', errors='replace')}")

        except Exception as e:
            self.logger.error(f"Error analyzing anti-analysis patterns: {e}")

        return findings

    def _analyze_network_indicators(self, data: bytes) -> Dict[str, List[str]]:
        """Analyze potential network-related indicators."""
        indicators = {"urls": [], "domains": [], "ip_addresses": [], "email_addresses": [], "network_apis": []}

        try:
            # URL pattern
            url_pattern = rb'(?:http[s]?://|hxxp[s]?://|ftp://|sftp://|www\.)[^\s"\'<>]+'

            # Domain pattern
            domain_pattern = rb"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,6})\b"

            # IP address pattern (IPv4)
            ipv4_pattern = rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"

            # Email pattern
            email_pattern = rb"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

            # Network-related API calls
            network_apis = [
                b"WSAStartup",
                b"socket",
                b"connect",
                b"bind",
                b"listen",
                b"accept",
                b"send",
                b"recv",
                b"InternetOpen",
                b"InternetConnect",
                b"HttpOpenRequest",
                b"WinHttpOpen",
                b"URLDownloadToFile",
                b"DnsQuery",
            ]

            # Extract indicators
            indicators["urls"].extend([m.decode("utf-8", errors="replace") for m in re.findall(url_pattern, data)])
            indicators["domains"].extend(
                [m.decode("utf-8", errors="replace") for m in re.findall(domain_pattern, data)]
            )
            indicators["ip_addresses"].extend(
                [m.decode("utf-8", errors="replace") for m in re.findall(ipv4_pattern, data)]
            )
            indicators["email_addresses"].extend(
                [m.decode("utf-8", errors="replace") for m in re.findall(email_pattern, data)]
            )

            # Check for network APIs
            for api in network_apis:
                if api in data:
                    indicators["network_apis"].append(api.decode("utf-8", errors="replace"))

            # Deduplicate results
            for key in indicators:
                indicators[key] = list(set(indicators[key]))

        except Exception as e:
            self.logger.error(f"Error analyzing network indicators: {e}")

        return indicators

    def _analyze_persistence_mechanisms(self, data: bytes) -> Dict[str, List[str]]:
        """Analyze potential persistence mechanisms."""
        persistence = {
            "registry_keys": [],
            "startup_locations": [],
            "scheduled_tasks": [],
            "services": [],
            "wmi_persistence": [],
            "dll_hijacking": [],
        }

        try:
            # Registry persistence patterns
            registry_patterns = [
                b"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                b"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                b"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
                b"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
                b"System\\CurrentControlSet\\Services",
                b"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
                b"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
            ]

            # Startup location patterns
            startup_patterns = [
                b"\\Startup\\",
                b"\\Start Menu\\Programs\\Startup",
                b"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                b"\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            ]

            # Scheduled task patterns
            task_patterns = [
                b"schtasks",
                b"Schedule.Service",
                b"ITaskScheduler",
                b"\\Microsoft\\Windows\\Task Scheduler",
            ]

            # Service patterns
            service_patterns = [
                b"CreateService",
                b"OpenService",
                b"StartService",
                b"\\services.exe",
                b"ServiceMain",
            ]

            # WMI persistence patterns
            wmi_patterns = [
                b"root\\subscription",
                b"ActiveScriptEventConsumer",
                b"CommandLineEventConsumer",
                b"__EventFilter",
                b"Win32_LocalTime",
            ]

            # DLL hijacking patterns
            dll_patterns = [
                b"LoadLibrary",
                b".dll",
                b"DllMain",
                b"DllRegisterServer",
                b"DllInstall",
            ]

            # Check for patterns
            for pattern in registry_patterns:
                if pattern in data:
                    persistence["registry_keys"].append(pattern.decode("utf-8", errors="replace"))

            for pattern in startup_patterns:
                if pattern in data:
                    persistence["startup_locations"].append(pattern.decode("utf-8", errors="replace"))

            for pattern in task_patterns:
                if pattern in data:
                    persistence["scheduled_tasks"].append(pattern.decode("utf-8", errors="replace"))

            for pattern in service_patterns:
                if pattern in data:
                    persistence["services"].append(pattern.decode("utf-8", errors="replace"))

            for pattern in wmi_patterns:
                if pattern in data:
                    persistence["wmi_persistence"].append(pattern.decode("utf-8", errors="replace"))

            for pattern in dll_patterns:
                if pattern in data:
                    persistence["dll_hijacking"].append(pattern.decode("utf-8", errors="replace"))

            # Deduplicate results
            for key in persistence:
                persistence[key] = list(set(persistence[key]))

        except Exception as e:
            self.logger.error(f"Error analyzing persistence mechanisms: {e}")

        return persistence

    def _analyze_entropy_patterns(self, data: bytes) -> Dict[str, Any]:
        """Analyze entropy patterns in different regions of the file."""
        result = {
            "total": self._calculate_entropy(data),
            "chunks": [],
            "high_entropy_regions": [],
            "entropy_distribution": {},
        }

        # Analyze chunks
        chunk_size = min(1024, len(data))
        for i in range(0, len(data), chunk_size):
            chunk = data[i : i + chunk_size]
            entropy = self._calculate_entropy(chunk)
            result["chunks"].append({"offset": i, "size": len(chunk), "entropy": entropy})
            if entropy > 7.0:
                result["high_entropy_regions"].append({"offset": i, "size": len(chunk), "entropy": entropy})

        # Calculate entropy distribution
        byte_counts = Counter(data)
        total_bytes = len(data)
        result["entropy_distribution"] = {byte: count / total_bytes for byte, count in byte_counts.items()}

        return result

    def _process_large_file(self, file_path: Path, chunk_size: int = 1024 * 1024) -> Dict[str, Any]:
        """Process large files in chunks to avoid memory issues."""
        results = {
            "entropy_chunks": [],
            "strings": set(),
            "patterns": set(),
        }

        try:
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    # Process entropy
                    chunk_entropy = self._calculate_entropy(chunk)
                    results["entropy_chunks"].append(chunk_entropy)

                    # Extract strings
                    chunk_strings = self._extract_strings(chunk)
                    for category in chunk_strings:
                        results["strings"].update(chunk_strings[category])

                    # Look for patterns
                    chunk_patterns = self._find_patterns(chunk)
                    results["patterns"].update(chunk_patterns)

            # Aggregate results
            return {
                "entropy": {
                    "average": sum(results["entropy_chunks"]) / len(results["entropy_chunks"]),
                    "max": max(results["entropy_chunks"]),
                    "chunks": results["entropy_chunks"],
                },
                "strings": list(results["strings"]),
                "patterns": list(results["patterns"]),
            }

        except Exception as e:
            self.logger.error(f"Error processing large file: {e}")
            raise

    async def analyze_files(self, files: List[Union[Path, bytes]], max_workers: int = 5) -> Dict[str, Dict[str, Any]]:
        """Analyze multiple files concurrently."""
        results = {}

        async def _analyze_single(file):
            try:
                return await self.analyze_file(file)
            except Exception as e:
                self.logger.error(f"Error analyzing file {file}: {e}")
                return None

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {executor.submit(_analyze_single, file): file for file in files}
            for future in as_completed(future_to_file):
                file = future_to_file[future]
                result = future.result()
                if result is not None:
                    results[str(file)] = result

        return results

    def _find_patterns(self, data: bytes) -> set:
        """Find common patterns in binary data."""
        patterns = set()

        # Add pattern detection logic here
        # Example: Look for common byte sequences
        for i in range(len(data) - 4):
            sequence = data[i : i + 4]
            if sequence.count(sequence[0]) != 4:  # Avoid repetitive bytes
                patterns.add(sequence.hex())

        return patterns

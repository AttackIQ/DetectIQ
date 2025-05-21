import importlib.util
import math
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, cast

from detectiq.core.utils.logging import get_logger

logger = get_logger(__name__)

# Check if pefile is available at module level
PEFILE_AVAILABLE = importlib.util.find_spec("pefile") is not None

if PEFILE_AVAILABLE:
    try:
        import pefile
    except ImportError:
        PEFILE_AVAILABLE = False
        logger.warning("pefile module found but failed to import")


def analyze_pe(file_data: Union[Path, bytes]) -> Optional[Dict[str, Any]]:
    """Analyze PE file structure with focused output."""
    if not PEFILE_AVAILABLE:
        return None

    try:
        pe = pefile.PE(str(file_data)) if isinstance(file_data, Path) else pefile.PE(data=file_data)

        analysis = {"sections": [], "imports": [], "anomalies": []}

        # Only include suspicious sections
        for section in pe.sections:
            entropy = round(section.get_entropy(), 4)
            if entropy > 7.0 or section.Characteristics & 0xE0000000:
                analysis["sections"].append(
                    {
                        "name": section.Name.rstrip(b"\x00").decode("utf-8", errors="replace"),
                        "entropy": entropy,
                        "characteristics": section.Characteristics,
                    }
                )

        # Only include suspicious imports
        suspicious_apis = {
            "VirtualAlloc",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "LoadLibrary",
            "GetProcAddress",
            "CreateProcess",
        }

        try:
            # Parse the import directory first
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])

            # Use cast to tell type checker this is okay
            pe_obj = cast(Any, pe)
            if hasattr(pe_obj, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe_obj.DIRECTORY_ENTRY_IMPORT:
                    suspicious_found = []
                    for imp in entry.imports:
                        if imp.name and imp.name.decode("utf-8", errors="replace") in suspicious_apis:
                            suspicious_found.append(imp.name.decode("utf-8", errors="replace"))
                    if suspicious_found:
                        analysis["imports"].append(
                            {"dll": entry.dll.decode("utf-8", errors="replace"), "suspicious_imports": suspicious_found}
                        )
        except Exception as e:
            logger.debug(f"Failed to parse import directory: {e}")

        # Only include significant anomalies
        analysis["anomalies"] = detect_pe_anomalies(pe)[:5]

        return {k: v for k, v in analysis.items() if v}

    except Exception as e:
        logger.error(f"PE analysis failed: {e}")
        return None


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data.

    Args:
        data: Bytes to calculate entropy for

    Returns:
        float: Shannon entropy value between 0 and 8
    """
    if not data:
        return 0.0

    entropy = 0.0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return round(entropy, 4)


def detect_pe_anomalies(pe: Any) -> List[str]:
    """Detect various anomalies in PE files."""
    anomalies = []

    try:
        # Add error handling for section name decoding
        for section in pe.sections:
            try:
                section_name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            except Exception:
                section_name = "unknown"

            try:
                entropy = round(section.get_entropy(), 4)
            except Exception:
                entropy = 0.0000

            # Check for suspicious section names
            if section_name in [".text", ".data", ".rdata"] and entropy > 7.0:
                anomalies.append(f"High entropy in standard section {section_name}")

            # Check for suspicious section characteristics
            if section.Characteristics & 0xE0000000:  # Unusual section flags
                anomalies.append(f"Section {section_name} has unusual characteristics")

            # Check for executable data sections
            if section_name in [".data", ".rdata"] and section.Characteristics & 0x20000000:
                anomalies.append(f"Data section {section_name} is executable")

        # Header anomalies
        if pe.FILE_HEADER.Characteristics & 0x0002:  # IMAGE_FILE_EXECUTABLE_IMAGE
            if not any(section.Characteristics & 0x20000000 for section in pe.sections):
                anomalies.append("Executable file without executable sections")

        # Timestamp analysis
        if pe.FILE_HEADER.TimeDateStamp == 0:
            anomalies.append("Null timestamp in PE header")
        elif pe.FILE_HEADER.TimeDateStamp > int(time.time()):
            anomalies.append("Future timestamp in PE header")

        # Import analysis
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            suspicious_apis = {
                "VirtualAlloc": "Memory allocation",
                "WriteProcessMemory": "Process manipulation",
                "CreateRemoteThread": "Remote thread creation",
                "LoadLibrary": "Dynamic loading",
                "GetProcAddress": "API resolution",
            }

            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode("utf-8", errors="replace")
                        if api_name in suspicious_apis:
                            anomalies.append(f"Suspicious API: {api_name} ({suspicious_apis[api_name]})")

        # Resource analysis
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_type.struct.Id == 0x18:  # RT_MANIFEST
                    for resource_id in resource_type.directory.entries:
                        if resource_id.struct.Id == 1:
                            anomalies.append("Found manifest resource - possible UAC bypass")

                # Check for high entropy resources
                try:
                    for resource_id in resource_type.directory.entries:
                        for resource_lang in resource_id.directory.entries:
                            data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                            if calculate_entropy(data) > 7.5:
                                anomalies.append(f"High entropy resource found (type: {resource_type.struct.Id})")
                except Exception:
                    continue

        # Check for overlay
        overlay = pe.get_overlay()
        if overlay:
            overlay_entropy = round(calculate_entropy(overlay), 4)
            if overlay_entropy > 7.0:
                anomalies.append(f"High entropy overlay detected ({overlay_entropy:.4f})")

    except Exception as e:
        logger.debug(f"Error detecting anomalies: {e}")

    return anomalies


def extract_rich_strings(data: bytes) -> List[str]:
    """Extract printable strings from Rich header data."""
    strings = []
    current_string = []

    for byte in data:
        if 32 <= byte <= 126:  # printable ASCII range
            current_string.append(chr(byte))
        elif current_string:
            if len(current_string) >= 4:  # minimum string length
                strings.append("".join(current_string))
            current_string = []

    if current_string and len(current_string) >= 4:
        strings.append("".join(current_string))

    return strings


def decode_rich_products(entries: List[Dict[str, Any]]) -> List[str]:
    """Decode Rich header product IDs to human-readable names."""
    # Known Product IDs (expanded list)
    PRODUCTS = {
        0x0001: "Import0",
        0x0002: "Linker510",
        0x0003: "Cvtomf510",
        0x0004: "Export0",
        0x0005: "Implib0",
        0x0006: "Unknown",  # Add more product IDs as needed
    }

    products = []
    for entry in entries:
        comp_id = entry.get("comp_id")
        build_id = entry.get("build_id", 0)
        count = entry.get("count", 0)
        if comp_id and isinstance(comp_id, int) and comp_id in PRODUCTS:
            product_name = PRODUCTS[comp_id]
            products.append(f"{product_name} (Build ID: {build_id}, Count: {count})")
        else:
            products.append(f"Unknown Product ID: {comp_id} (Build ID: {build_id}, Count: {count})")

    return products

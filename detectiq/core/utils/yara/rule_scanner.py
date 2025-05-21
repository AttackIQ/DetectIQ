from pathlib import Path
from typing import Any, Dict, List, Optional

import yara

from detectiq.core.utils.logging import get_logger

logger = get_logger(__name__)


class YaraScanner:
    """Scanner for YARA rules."""

    def __init__(self, rule_dir: str):
        """
        Initialize YARA scanner.

        Args:
            rule_dir: Directory containing YARA rules
        """
        self.rule_dir = Path(rule_dir)
        self._rules: Optional[yara.Rules] = None
        self._compile_rules()

    def _compile_rules(self) -> None:
        """Compile all YARA rules in the directory."""
        try:
            filepaths = {}
            for rule_file in self.rule_dir.glob("*.yar"):
                filepaths[rule_file.stem] = str(rule_file)

            if filepaths:
                self._rules = yara.compile(filepaths=filepaths)
            else:
                logger.warning(f"No YARA rules found in {self.rule_dir}")

        except Exception as e:
            logger.error(f"Failed to compile YARA rules: {e}")
            self._rules = None

    def scan_file(
        self,
        file_path: Optional[str] = None,
        file_bytes: Optional[bytes] = None,
    ) -> List[Dict[str, Any]]:
        """
        Scan a file with YARA rules.

        Args:
            file_path: Path to file to scan
            file_bytes: Bytes to scan

        Returns:
            List[Dict[str, Any]]: List of rule matches
        """
        if not self._rules:
            logger.warning("No YARA rules compiled")
            return []

        try:
            # Perform the scan
            matches = self._rules.match(filepath=file_path) if file_path else self._rules.match(data=file_bytes)

            # Convert matches to a more usable format
            results = []
            for match in matches:
                result = {
                    "rule_name": match.rule,
                    "namespace": match.namespace,
                    "tags": list(match.tags) if match.tags else [],
                    "meta": match.meta,
                    "strings": [],
                }

                # Process string matches
                if match.strings:
                    for string_match in match.strings:
                        # For each matched string
                        for instance in string_match.instances:
                            result["strings"].append(
                                {
                                    "identifier": string_match.identifier,
                                    "data": instance.matched_data,
                                    "offset": instance.offset,
                                    "length": instance.matched_length,
                                    "xor_key": (instance.xor_key if hasattr(instance, "xor_key") else None),
                                }
                            )

                results.append(result)

            return results

        except Exception as e:
            logger.error(f"YARA scan failed: {e}")
            return []

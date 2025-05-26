import asyncio
from pathlib import Path
from typing import Any, Dict, Optional, Union

from langchain.schema.language_model import BaseLanguageModel
from langchain.tools import BaseTool
from pydantic import BaseModel, Field

from detectiq.core.utils.yara.file_analyzer import FileAnalyzer
from detectiq.core.utils.yara.rule_scanner import YaraScanner
from detectiq.globals import DEFAULT_DIRS


class AnalyzeFileInput(BaseModel):
    """Input for file analysis."""

    file_path: str
    file_bytes: Optional[bytes] = None
    min_string_length: int = 4
    max_strings: int = 50


class AnalyzeFileTool(BaseTool):
    """Tool for analyzing files for YARA rule creation."""

    name: str = "analyze_file"
    description: str = """
    Analyze a file to identify unique patterns and characteristics for YARA rule creation.
    Provide either a file path or file bytes.
    """
    args_schema: type[BaseModel] = AnalyzeFileInput
    llm: BaseLanguageModel
    analyzer: FileAnalyzer = Field(default_factory=FileAnalyzer)
    rule_dir: Union[str, Path] = Field(default=DEFAULT_DIRS.YARA_RULE_DIR)
    scanner: Optional[YaraScanner] = None

    def __init__(self, **data):
        super().__init__(**data)
        self.rule_dir = str(self.rule_dir)
        try:
            self.scanner = YaraScanner(self.rule_dir)
        except Exception as e:
            print(f"Failed to initialize YaraScanner: {e}")
            self.scanner = None

    def _run(
        self,
        file_path: str,
        file_bytes: Optional[bytes] = None,
        min_string_length: int = 4,
        max_strings: int = 50,
    ) -> str:
        """Synchronous run method."""
        analysis_result = asyncio.run(
            self._arun(
                file_path=file_path,
                file_bytes=file_bytes,
                min_string_length=min_string_length,
                max_strings=max_strings,
            )
        )
        return self._format_analysis_results(analysis_result)

    async def _arun(
        self,
        file_path: str,
        file_bytes: Optional[bytes] = None,
        min_string_length: int = 4,
        max_strings: int = 50,
    ) -> Dict[str, Any]:
        """
        Run file analysis.

        Args:
            file_path: Path to the file to analyze
            file_bytes: Optional bytes content of the file
            min_string_length: Minimum length for string extraction
            max_strings: Maximum number of strings to extract

        Returns:
            Dict[str, Any]: Analysis results
        """
        if file_bytes:
            # Create temporary file from bytes
            temp_path = Path("temp_file")
            temp_path.write_bytes(file_bytes)
            try:
                return await self.analyzer.analyze_file(temp_path)
            finally:
                temp_path.unlink(missing_ok=True)
        else:
            return await self.analyzer.analyze_file(Path(file_path))

    def _format_analysis_results(self, analysis: Dict[str, Any]) -> str:
        """Format analysis results as string."""
        result = []

        # File Info
        result.append("### Basic File Information")
        info = analysis.get("file_info", {})
        result.append(f"Size: {info.get('size', 0)} bytes")
        result.append(f"Type: {info.get('type', 'Unknown')}")

        # Hashes if available
        for hash_type in ["md5", "sha1", "sha256"]:
            if hash_value := info.get(hash_type):
                result.append(f"{hash_type.upper()}: {hash_value}")

        # String Patterns
        if string_patterns := analysis.get("string_patterns", {}):
            result.append("\n### String Analysis")
            for pattern_type, strings in string_patterns.items():
                if strings:
                    result.append(f"\n{pattern_type.upper()} Strings:")
                    for s in strings[:10]:  # Limit to 10 strings
                        result.append(f"- {s}")

        # Entropy Analysis
        if entropy_data := analysis.get("entropy"):
            result.append("\n### Entropy Analysis")
            if isinstance(entropy_data, dict):
                result.append(f"Total Entropy: {entropy_data.get('total', 0):.2f}")
                if high_entropy := entropy_data.get("high_entropy_regions", []):
                    result.append(f"High Entropy Regions Found: {len(high_entropy)}")
            else:
                result.append(f"Total Entropy: {entropy_data:.2f}")

        # File Structure
        if structure := analysis.get("file_structure", {}):
            if structure.get("type") != "Unknown":
                result.append(f"\n### {structure['type']} Analysis")
                if sections := analysis.get("sections", []):
                    result.append("\nSections:")
                    for section in sections:
                        result.append(
                            f"- {section.get('name', 'Unknown')} " f"(entropy: {section.get('entropy', 0):.2f})"
                        )

        # Insights
        if insights := analysis.get("insights", []):
            result.append("\n### Analysis Insights")
            for insight in insights:
                result.append(f"- {insight}")

        return "\n".join(result)

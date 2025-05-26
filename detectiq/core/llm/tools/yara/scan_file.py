import asyncio
from pathlib import Path
from typing import Optional, Type, Union

from langchain.prompts import ChatPromptTemplate
from langchain.schema.language_model import BaseLanguageModel
from langchain.schema.output_parser import StrOutputParser
from langchain.tools import BaseTool
from pydantic import BaseModel, Field

from detectiq.core.utils.yara.rule_scanner import YaraScanner
from detectiq.globals import DEFAULT_DIRS


class ScanFileInput(BaseModel):
    """Input for ScanFileTool."""

    file_path: Optional[str] = None
    file_bytes: Optional[bytes] = None


class ScanFileTool(BaseTool):
    """Class for scanning files with existing YARA rules"""

    name: str = "scan_file"
    args_schema: Type[BaseModel] = ScanFileInput
    description: str = """
Use this tool to scan a file with existing YARA rules from the rules directory.
The tool will return any matching rules and their details, including:
- Rule name and namespace
- Matching strings and their locations
- Rule metadata and tags
The input can be either a file path or file bytes.
"""
    llm: BaseLanguageModel
    verbose: bool = False
    rule_dir: Union[str, Path] = Field(default=DEFAULT_DIRS.YARA_RULE_DIR)
    scanner: Optional[YaraScanner] = None

    def __init__(self, **data):
        super().__init__(**data)
        self.rule_dir = str(self.rule_dir)
        self.scanner = YaraScanner(self.rule_dir)

    def _run(
        self,
        file_path: Optional[str] = None,
        file_bytes: Optional[bytes] = None,
    ) -> str:
        return asyncio.run(self._arun(file_path, file_bytes))

    async def _arun(
        self,
        file_path: Optional[str] = None,
        file_bytes: Optional[bytes] = None,
    ) -> str:
        """Scan a file with YARA rules."""
        if not self.scanner:
            self.rule_dir = str(self.rule_dir)
            self.scanner = YaraScanner(self.rule_dir)

        matches = self.scanner.scan_file(file_path, file_bytes)

        if not matches:
            return "No YARA rules matched this file."

        # Get rule texts for matches
        rule_texts = {}
        reference_dir = Path(self.rule_dir) / "reference_rules"
        for match in matches:
            rule_file = reference_dir / f"{match['rule_name']}.yar"
            if rule_file.exists():
                rule_texts[match["rule_name"]] = rule_file.read_text()

        # Calculate match statistics
        match_stats = {
            "total_matches": len(matches),
            "rules_with_strings": len([m for m in matches if m["strings"]]),
            "total_strings_matched": sum(len(m["strings"]) for m in matches),
            "namespaces": len(set(m["namespace"] for m in matches)),
        }

        template = """You are a malware analyst reviewing YARA rule matches.
Analyze the following YARA rule matches and provide a clear summary of the findings.

### MATCHING RULES
{matching_rules}

Match Statistics:
- Total matching rules: {total_matches}
- Rules with string matches: {rules_with_strings}
- Total strings matched: {total_strings_matched}
- Distinct rule namespaces: {namespaces}

Detailed Matches:
{matches_text}

Note: When creating new rules, you can use entropy calculations with the math module:
- Import both 'pe' and 'math' modules
- Use math.entropy(offset, length) to calculate entropy of specific regions
- Use math.in_range(value, min, max) to check entropy ranges
- For PE files, you can check resource entropy using pe.resources

Example entropy usage in YARA rules:
import "pe"
import "math"

rule high_entropy_check {{
    condition:
        // Check file section entropy
        for any section in pe.sections: (
            math.in_range(math.entropy(section.raw_data_offset, section.raw_data_size), 7.8, 8.0)
        ) or
        // Check resource entropy
        for any resource in pe.resources: (
            math.in_range(math.entropy(resource.offset, resource.length), 7.8, 8.0)
        )
}}

Provide an analysis in the following format:

### Summary
[Brief overview of the matching rules and their significance]

### Detailed Analysis
[For each matching rule:
1. Rule name and purpose
2. Significance of the match
3. Notable matching patterns
4. Any relevant metadata or tags
5. Potential implications]

### Recommendations
[Based on the matches:
1. Suggested next steps
2. Additional analysis needed
3. Potential false positive considerations]

IMPORTANT: Always include ALL matching rule names in your summary."""

        # Format matching rules section prominently
        matching_rules = "\n".join(f"- {match['rule_name']} ({match['namespace']})" for match in matches)

        # Format detailed matches
        matches_text = ""
        for match in matches:
            matches_text += f"\nRule: {match['rule_name']} (from {match['namespace']})"
            if match["rule_name"] in rule_texts:
                matches_text += f"\nRule Text:\n{rule_texts[match['rule_name']]}"
            if match["meta"]:
                matches_text += f"\nMetadata: {match['meta']}"
            if match["tags"]:
                matches_text += f"\nTags: {', '.join(match['tags'])}"
            if match["strings"]:
                matches_text += "\nMatched Strings:"
                for s in match["strings"]:
                    matches_text += f"\n- {s['identifier']} at offset {s['offset']}: {s['data']}"
            matches_text += "\n"

        prompt = ChatPromptTemplate.from_template(template)
        chain = prompt | self.llm | StrOutputParser()

        return await chain.ainvoke(
            {
                "matching_rules": matching_rules,
                "matches_text": matches_text,
                "total_matches": match_stats["total_matches"],
                "rules_with_strings": match_stats["rules_with_strings"],
                "total_strings_matched": match_stats["total_strings_matched"],
                "namespaces": match_stats["namespaces"],
            }
        )

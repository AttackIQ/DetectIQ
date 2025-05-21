import asyncio
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Type

import yara
from langchain.prompts import ChatPromptTemplate

# Import message types for chat history formatting
from langchain.schema import AIMessage, BaseMessage, HumanMessage
from langchain.schema.language_model import BaseLanguageModel
from langchain.schema.output_parser import StrOutputParser
from langchain.schema.vectorstore import VectorStore
from langchain.tools import BaseTool
from pydantic import BaseModel, ConfigDict

from detectiq.core.utils.logging import get_logger

logger = get_logger(__name__)


# Helper function to format chat history
def format_chat_history(chat_history: Optional[List[BaseMessage]]) -> str:
    if not chat_history:
        return "No prior conversation history."
    formatted_history = []
    for msg in chat_history:
        if isinstance(msg, HumanMessage):
            formatted_history.append(f"Human: {msg.content}")
        elif isinstance(msg, AIMessage):
            formatted_history.append(f"AI: {msg.content}")
        # You can add more specific types like SystemMessage if needed
        else:
            # Generic fallback, though ideally, you'd handle all expected types
            formatted_history.append(f"{type(msg).__name__}: {msg.content}")
    return "\n".join(formatted_history)


class CreateYaraRuleInput(BaseModel):
    """Input for CreateYaraRuleTool."""

    description: str
    rule_context: Optional[str] = None
    file_analysis: Optional[str] = None
    matching_rules: Optional[List[Dict]] = None
    model_config = ConfigDict(arbitrary_types_allowed=True)


class CreateYaraRuleTool(BaseTool):
    """Class for creating YARA rules based on file analysis or description"""

    name: str = "create_yara_rule"
    args_schema: Type[BaseModel] = CreateYaraRuleInput
    description: str = """
Use this tool to create YARA rules based on either:
1. File analysis results from the analyze_file tool
2. A description of what you want to detect in files

as well as similar rules from the YARA database and/or a YARA Scaner.

The tool will generate appropriate YARA rules to detect similar files
or patterns while avoiding false positives.
"""
    llm: BaseLanguageModel
    yaradb: VectorStore
    k: int = 3
    verbose: bool = False
    model_config = ConfigDict(arbitrary_types_allowed=True)

    def _run(
        self,
        description: str,
        rule_context: Optional[str] = None,
        file_analysis: Optional[Dict[str, Any]] = None,
        matching_rules: Optional[List[Dict]] = None,
    ) -> Dict[str, Any]:
        return asyncio.run(self._arun(description, rule_context, file_analysis, matching_rules))

    async def _arun(
        self,
        description: str,
        rule_context: Optional[str] = None,
        file_analysis: Optional[Dict[str, Any]] = None,
        matching_rules: Optional[List[Dict]] = None,
        k: int = 3,
        chat_history: Optional[List[BaseMessage]] = None,
    ) -> Dict[str, Any]:
        """Create a YARA rule based on description or analysis."""
        try:
            # Get current date
            current_date = datetime.now().strftime("%Y-%m-%d")

            # Calculate how many additional rules to fetch from vector store
            num_matching = len(matching_rules) if matching_rules else 0
            k_remaining = max(0, k - num_matching)

            # Get similar rules from vector store if needed
            similar_rules = []
            if k_remaining > 0:
                retriever = self.yaradb.as_retriever(search_kwargs={"k": k_remaining})
                similar_rule_text = ""
                if file_analysis:
                    similar_rule_text = str(file_analysis)
                else:
                    similar_rules = await retriever.ainvoke(description + " " + similar_rule_text)
            # TODO: Load rule strings from rule names to pass instead
            # Format matching rules context
            matching_context = ""
            if matching_rules:
                matching_context = "\n#### Matching YARA Rules\n"
                for match in matching_rules:
                    matching_context += f"\nRule: {match['rule_name']} (from {match['namespace']})"
                    if match["meta"]:
                        matching_context += f"\nMetadata: {match['meta']}"
                    if match["tags"]:
                        matching_context += f"\nTags: {', '.join(match['tags'])}"

            # Format similar rules context
            similar_context = (
                "\n#### Similar YARA Rules\n" + "\n".join(doc.page_content for doc in similar_rules)
                if similar_rules
                else ""
            )

            # Combine contexts
            context_text = matching_context + similar_context

            template = """You are a malware analyst specializing in YARA rule creation.

Based on the provided description, file analysis, and any similar or matching rules, create an effective YARA rule to detect similar files or patterns while avoiding false positives.

Description from user: {description}

File Analysis: {file_analysis}

Additional Context: {rule_context}

Conversation History:
{chat_history_formatted}

Similar and matching YARA Rules from Database: {context}

YARA Rule Creation Guidelines:

    Rule Structure:
        Start with required imports (e.g., pe, math).
        Use descriptive rule names (alphanumeric and underscores only).
        Include comprehensive metadata (description, author, date, etc.).
        Define strings before conditions; ensure all strings used in conditions are defined.
        Validate syntax and logic of conditions.

    String Definitions:
        Prefix all string identifiers with $.
        Use appropriate string modifiers (wide, ascii, nocase).
        Utilize hex strings for binary patterns; format them properly.
        Escape special characters in strings.
        Group related strings with common prefixes.
        IMPORTANT: Any strings in the strings section must be used in the condition section. Remove any unused strings.

    Condition Logic:
        Include basic file checks (e.g., uint16(0) == 0x5A4D for PE files).
        **IMPORTANT**: When using functions from imported modules (like `pe`), ALWAYS prefix the function call with the module name (e.g., use `pe.is_dll()`, NOT `is_dll`; use `pe.exports('func')`, NOT `exports('func')`).
        Combine string matches appropriately (any of, all of).
        Use correct boolean operators (and, or, not).
        Include file size checks when relevant.
        Reference strings with the $ prefix.

    Syntax and Validation:
        Use correct syntax for hex strings, text strings, and regex.
        Ensure proper spacing and parentheses placement.
        All imports must be utilized in conditions.
        String identifiers must be unique.
    IMPORTANT: Review the final YARA rule carefully to ensure all identifiers from imported modules (like 'pe') are used correctly (e.g., `pe.is_dll()`) and that all defined strings are referenced in the condition.

    Rule References:
        If matching or similar rules are provided, reference them in the metadata.
        Include original authors and "DetectIQ" in the author field.
        List rule names in the related field.
        If no matching rules are provided, use "DetectIQ" as the author.
Example Valid Rule Structure:

```yara
import pe
rule Example_Malware {{
    meta:
        description = "Detection for Example malware family"
        author = "DetectIQ <and similar rule authors>"
        date = "{current_date}"
        reference = "URL or description"
        score = <0-100>
        quality = <0-100>
        severity = <0-100>
        tags = "<FILE, MEMORY, etc.>"
        arch_context = "<x86, x64, etc.>"
        os = "<windows, linux, macos, etc.>"
        related = "<Related Rule Names>"
    strings:
        $str1 = "suspicious string" wide
        $hex1 = {{ 90 ?? 90 }}  // Example hex pattern
        $api1 = "suspicious_api" nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        (
            all of ($str*) or
            2 of ($hex*) or
            any of ($api*)
        )
}}

```

Output Format:

You MUST provide your response in the following format, (including the '#### <section title>' and ensuring that each section is detailed):

+ IMPORTANT: Ensure all analysis text uses standard Markdown formatting. Use double newlines ('\n\n') between paragraphs and list items for proper rendering.

#### Analysis Summary

[Provide a detailed analysis covering:
    1. File Type and Format Analysis
    2. Behavioral Indicators
    3. Static Features
    4. Contextual Information]

#### Detection Strategy

[Explain the detection approach, including:
    1. Pattern Selection
    2. Condition Logic Design
    3. False Positive Mitigation
    4. Rule Optimization
    5. Limitations and Considerations]

#### YARA Rule

[Provide the YARA rule in a code block with valid syntax, e.g., 

```yara
<YARA rule>
```

All strings that are defined in the strings section MUST be used in the condition section. Remove any unused strings.]
"""

            prompt = ChatPromptTemplate.from_template(template)

            # Prepare the input for the chain
            chain_input = {
                "description": description,
                "file_analysis": file_analysis or "No file analysis provided.",
                "rule_context": rule_context or "No additional context provided.",
                "context": context_text,
                "current_date": current_date,
                "chat_history_formatted": format_chat_history(chat_history),
            }

            chain = prompt | self.llm | StrOutputParser()

            response = await chain.ainvoke(chain_input)

            # Extract and validate the rule
            try:
                # First try to extract from code block
                yara_block_match = re.search(r"```yara\n(.*?)\n```", response, re.DOTALL)
                if yara_block_match:
                    rule_text = yara_block_match.group(1).strip()
                else:
                    # Fallback to section extraction
                    yara_match = re.search(r"#### YARA Rule\n(.*?)(?=\n####|$)", response, re.DOTALL)
                    if not yara_match:
                        raise ValueError("Could not extract YARA rule from response")
                    rule_text = yara_match.group(1).strip()

                # Extract the analysis sections
                analysis_summary = re.search(r"#### Analysis Summary\n(.*?)(?=\n####)", response, re.DOTALL)
                detection_strategy = re.search(r"#### Detection Strategy\n(.*?)(?=\n####)", response, re.DOTALL)

                if not analysis_summary or not detection_strategy:
                    logger.warning("Missing required analysis sections in response")
                    raise ValueError("Response missing required analysis sections")

                # Combine analysis sections for agent output
                agent_output = ""
                agent_output += "#### Analysis Summary\n" + analysis_summary.group(1).strip() + "\n\n"
                agent_output += "#### Detection Strategy\n" + detection_strategy.group(1).strip()

                if not agent_output.strip():
                    logger.warning("Empty agent output generated")
                    raise ValueError("Empty analysis sections in response")

                # Try to compile the rule
                try:
                    yara.compile(source=rule_text)
                except yara.SyntaxError as e:
                    error_message = f"Syntax Error compiling YARA rule: {str(e)}. Check for common issues like incorrect module usage (e.g., using 'is_pe' instead of 'pe.is_pe' after 'import \"pe\"') or undefined strings."
                    logger.error(error_message)
                    raise ValueError(error_message)
                except yara.Error as e:
                    logger.error(f"Error compiling YARA rule: {str(e)}")
                    raise ValueError(f"Error compiling YARA rule: {str(e)}")

                # Extract rule name for title and format it
                rule_name_match = re.search(r"rule\s+(\w+(?:_\w+)*)\s*{", rule_text)
                if rule_name_match:
                    # Convert underscores to spaces and preserve capitalization
                    title = rule_name_match.group(1).replace("_", " ")
                else:
                    title = "YARA Rule"

                # Extract severity from metadata if present
                severity_match = re.search(r"severity\s*=\s*(\d+)", rule_text)
                if severity_match:
                    severity_num = int(severity_match.group(1))
                    if severity_num <= 20:
                        severity = "information"
                    elif severity_num <= 40:
                        severity = "low"
                    elif severity_num <= 60:
                        severity = "medium"
                    elif severity_num <= 80:
                        severity = "high"
                    elif severity_num <= 100:
                        severity = "critical"
                    else:
                        severity = "medium"  # Default for invalid numbers
                else:
                    severity = "high"  # Default if no severity specified

                return {
                    "rule": rule_text,
                    "agent_output": agent_output,
                    "title": title,  # Now contains properly formatted rule name
                    "severity": severity,
                }

            except Exception as e:
                logger.error(f"Error in YARA rule: {str(e)}")
                raise e

        except Exception as e:
            logger.error(f"Error creating YARA rule: {e}")
            raise e

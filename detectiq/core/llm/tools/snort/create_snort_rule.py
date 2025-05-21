import asyncio
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Type

from langchain.prompts import ChatPromptTemplate
from langchain.schema.language_model import BaseLanguageModel
from langchain.schema.output_parser import StrOutputParser
from langchain.schema.runnable import RunnablePassthrough
from langchain.schema.vectorstore import VectorStore
from langchain.tools import BaseTool
from pydantic import BaseModel, ConfigDict

from detectiq.core.utils.logging import get_logger

# Initialize logger
logger = get_logger(__name__)


class CreateSnortRuleInput(BaseModel):
    """Input for CreateSnortRuleTool."""

    description: str
    rule_context: Optional[str] = None
    model_config = ConfigDict(arbitrary_types_allowed=True)


class CreateSnortRuleTool(BaseTool):
    """Class for creating Snort rules based on PCAP analysis or description"""

    name: str = "create_snort_rule"
    args_schema: Type[BaseModel] = CreateSnortRuleInput
    description: str = """
Use this tool to create Snort rules based on either:
1. PCAP analysis results from the analyze_pcap tool
2. A description of what you want to detect

The tool will generate appropriate Snort rules to detect similar traffic patterns
while avoiding false positives.
"""
    llm: BaseLanguageModel
    snortdb: VectorStore
    k: int = 3
    verbose: bool = False
    model_config = ConfigDict(arbitrary_types_allowed=True)

    def _run(
        self,
        description: str,
        rule_context: Optional[str] = None,
        file_analysis: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Synchronous run method required by BaseTool."""
        return asyncio.run(self._arun(description, rule_context, file_analysis))

    async def _arun(
        self,
        description: str,
        rule_context: Optional[str] = None,
        file_analysis: Optional[Dict[str, Any]] = None,
        chat_history: Optional[List[Any]] = None,
    ) -> Dict[str, Any]:
        try:
            execution_id = id(description)  # Get unique execution identifier
            logger.info(f"Starting Snort rule creation with execution ID: {execution_id}")
            # Get current date
            current_date = datetime.now().strftime("%Y-%m-%d")

            # Get similar rules silently
            retriever = self.snortdb.as_retriever(search_kwargs={"k": self.k})
            similar_rules = await retriever.ainvoke(
                description + " " + str(file_analysis) if file_analysis else description
            )

            # Format similar rules context
            context_text = "\n".join(doc.page_content for doc in similar_rules)

            # Format chat history for prompt
            formatted_chat_history = "N/A"
            if chat_history:
                history_lines = []
                for msg in chat_history:
                    # Assuming msg objects have 'type' (e.g., 'human', 'ai') and 'content' attributes
                    role = "User" if msg.type == "human" else "Assistant"
                    history_lines.append(f"{role}: {msg.content}")
                formatted_chat_history = "\n".join(history_lines)

            template = """You are an expert network security analyst specializing in Snort rule creation.

Given the following description, conversation history, and context, create an effective Snort rule that detects malicious network traffic while minimizing false positives.

Conversation History:
{formatted_chat_history}

Context (Similar Rules):
{context_text}

Description:
{description}

PCAP Analysis:
{file_analysis}

Additional Context:
{rule_context}

Ensure your Snort rule follows Snort 3 format and includes:

1. Rule Header Components:
   - Appropriate action (alert, drop, reject, etc.)
   - Protocol (tcp, udp, icmp, ip, http, ftp, etc.)
   - Source/Destination IP addresses and ports, preferring to use variables instead of specific addresses when possible
   - Direction operator (->, <->)

2. Rule Options:
   - msg: Clear description of the alert
   - flow: Traffic direction and state
   - content: Specific patterns to match
   - pcre: Regular expressions when needed
   - metadata: Additional information
   - reference: CVE or other references
   - classtype: Attack classification
   - sid: Unique identifier
   - rev: Rule revision number
   - service: Application protocol
   - threshold: Rate limiting if needed

Example Format:

```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"MALWARE-CNC Example Trojan outbound connection"; flow:established,to_server; content:"|00 01 02 03|"; metadata:impact_flag red,policy balanced-ips drop,policy security-ips drop; reference:url,example.com/threat; classtype:trojan-activity; sid:1234567; rev:1;)  
```
Remember:
1. Use the most unique and specific patterns from PCAP analysis when available
2. Implement precise flow and stream options
3. Consider protocol-specific options
4. Use threshold options for noisy rules
6. Follow Snort best practices for performance

Output Format: 

You MUST provide your response in the following format, using standard markdown headings:

#### Analysis Summary
[Provide a detailed analysis of:
1. Network traffic patterns and protocols identified
2. Key indicators of malicious behavior
3. Important packet characteristics
4. Content patterns and their significance
5. Protocol-specific behaviors]

#### Detection Strategy
[Explain in detail:
1. Why specific detection methods were chosen
2. How the rule options work together
3. Why certain content patterns were selected
4. How false positives are minimized
5. Performance considerations
6. Any limitations or edge cases]

### Rule Description
[Provide a clear and concise description of the rule's purpose, what it is detecting, and any other relevant details]

#### Snort Rule
[Provide the Snort rule(s) following Snort 3 syntax]
"""

            prompt = ChatPromptTemplate.from_template(template)
            chain = (
                {
                    "context_text": lambda x: context_text,
                    "description": RunnablePassthrough(),
                    "file_analysis": lambda x: file_analysis,
                    "rule_context": lambda x: rule_context or "No additional context provided.",
                    "current_date": lambda x: current_date,
                    "formatted_chat_history": lambda x: formatted_chat_history,
                }
                | prompt
                | self.llm
                | StrOutputParser()
            )

            result = await chain.ainvoke(description)

            # Extract and validate the rule
            try:
                # First try to extract from code block
                snort_block_match = re.search(r"```snort\n(.*?)\n```", result, re.DOTALL)
                if snort_block_match:
                    rule_text = snort_block_match.group(1).strip()
                else:
                    # Fallback to section extraction
                    snort_match = re.search(r"#### Snort Rule\n(.*?)(?=\n####|$)", result, re.DOTALL)
                    if not snort_match:
                        raise ValueError("Could not extract Snort Rule from response")
                    rule_text = snort_match.group(1).strip()

                # Extract the analysis sections
                analysis_summary = re.search(r"#### Analysis Summary\n(.*?)(?=\n####)", result, re.DOTALL)
                detection_strategy = re.search(r"#### Detection Strategy\n(.*?)(?=\n####)", result, re.DOTALL)
                rule_description = re.search(r"#### Rule Description\n(.*?)(?=\n####)", result, re.DOTALL)

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

                # Basic validation of rule structure
                if not re.match(r"^(alert|drop|reject|pass)\s+(tcp|udp|icmp|ip|http|ftp)", rule_text):
                    raise ValueError("Invalid Snort rule header format")

                if "(" not in rule_text or ")" not in rule_text:
                    raise ValueError("Missing rule options section")

                # Extract metadata
                msg_match = re.search(r'msg:"([^"]+)"', rule_text)
                title = msg_match.group(1) if msg_match else "Untitled Rule"
                rule_description = rule_description.group(1).strip() if rule_description else "No description provided."

                # Determine severity based on classtype or metadata
                severity = "medium"  # Default
                if "classtype:high" in rule_text or "impact_flag red" in rule_text:
                    severity = "high"
                elif "classtype:low" in rule_text or "impact_flag green" in rule_text:
                    severity = "low"

                return {
                    "rule": rule_text,
                    "agent_output": agent_output,
                    "title": title,
                    "severity": severity,
                    "description": rule_description,
                }

            except Exception as e:
                logger.error(f"Error in Snort rule: {str(e)}")
                raise ValueError(f"Failed to create valid Snort rule: {str(e)}")
        except Exception as e:
            logger.error(f"Error creating Snort rule: {e}")
            raise ValueError(f"Failed to create Snort rule: {str(e)}")

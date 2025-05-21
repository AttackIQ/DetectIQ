import asyncio
import json
from typing import Type, Union

from langchain.tools import BaseTool
from pydantic import BaseModel, Extra, Field

from detectiq.sigmaiq.sigmaiq_backend_factory import AVAILABLE_BACKENDS, SigmAIQBackend
from detectiq.sigmaiq.sigmaiq_pipeline_factory import AVAILABLE_PIPELINES


class TranslateSigmaRuleInput(BaseModel):
    """Input for TranslateSigmaRule tool, which uses SigmAIQ backend factory to convert a Sigma Rule into
    a query for a specific backend."""

    sigma_rule: Union[str, dict] = Field(
        default=None,
        description="""The Sigma Rule to translate. This can be one of two formats:

1. A YAML string of the Sigma rule, with at least the title, logsource, and detection fields.
2. A dict object of the Sigma rule, which is the same as the YAML string and must contain the 
"title, logsource, and detection fields""",
    )
    backend: str = Field(
        default=None,
        description="""The backend or product to translate the Sigma rule to. Backend options their descriptions are as 
follows:\n"""
        + f"{json.dumps(AVAILABLE_BACKENDS, indent=2)}",
    )
    processing_pipeline: str = Field(
        default=None,
        description="""The processing pipeline to use for the Sigma rule. This should only be set if explicitly provided
by the user, as certain pipelines are only compatible with certain backends. Otherwise, set this to None.
Pipeline options and their 
descriptions are as follows:\n"""
        + f"{json.dumps({k: v['description'] for k, v in AVAILABLE_PIPELINES.items()}, indent=2)}",
    )
    output_format: str = Field(
        default="default",
        description="""The output format for the translated rule. Unless specified, 'default' should be used, as this is
    the option available in all backends. Each backend option and valid backends with their
    descriptions are as follows:\n"""
        + f"{json.dumps({k: v['output_formats'] for k, v in SigmAIQBackend.display_backends_and_outputs().items()}, indent=2)}",
    )


class TranslateSigmaRuleTool(BaseTool):
    """Class for translating Sigma rules via SigmAIQ Backend Factory"""

    name: str = "translate_sigma_rule"
    args_schema: Type[BaseModel] = TranslateSigmaRuleInput
    description: str = """
Use this tool to translate or convert a Sigma rule into a query for a specific backend.
The input must be a Sigma Rule, which can be provided as a YAML string or dict object.
Additionally, the backend (product) must be specified, and the processing pipeline and output format can be 
optionally specified.
The output is json of the translated rule to a query for the backend, or an error message if the 
translation fails.
"""
    # return_direct = True  # We don't need an agent LLM to think about the output, it is what it is.
    verbose: bool = False

    class Config:
        """Configuration for this pydantic object."""

        extra = Extra.forbid

    def _run(
        self,
        sigma_rule: Union[str, dict] = None,
        backend: str = None,
        processing_pipeline: str = None,
        output_format: str = "default",
    ) -> str:
        """Run the tool"""
        return asyncio.run(self._arun(sigma_rule, backend, processing_pipeline, output_format))

    async def _arun(
        self,
        sigma_rule: Union[str, dict] = None,
        backend: str = None,
        processing_pipeline: str = None,
        output_format: str = "default",
    ) -> str:
        """Async run the tool"""
        # Get backend object
        backend_obj = SigmAIQBackend(
            backend=backend, processing_pipeline=processing_pipeline, output_format=output_format
        ).create_backend()

        try:
            output = backend_obj.translate(sigma_rule)[0]
        except Exception as e:
            output = f"ERROR: {e}"
        # Return translated rule
        return output

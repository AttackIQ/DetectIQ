from sigma.backends.cortexxdr import CortexXDRBackend
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule

from detectiq.sigmaiq.backends.sigmaiq_abstract_backend import (
    AbstractGenericSigmAIQBackendClass,
)


class SigmAIQCortexXDRBackend(AbstractGenericSigmAIQBackendClass, CortexXDRBackend):
    custom_formats = {}
    associated_pipelines = [
        "cortexxdr",
    ]
    default_pipeline = "cortexxdr"

    # Fix CortexXDR json output format. "id" key in JSON is of type UUID, should be str
    def finalize_query_json(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> dict:
        return {"query": query, "title": rule.title, "id": str(rule.id), "description": rule.description}

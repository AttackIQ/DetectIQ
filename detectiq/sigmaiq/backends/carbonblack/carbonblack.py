from typing import Any

from sigma.backends.carbonblack import CarbonBlackBackend
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule

from detectiq.sigmaiq.backends.sigmaiq_abstract_backend import (
    AbstractGenericSigmAIQBackendClass,
)


class SigmAIQCarbonBlackBackend(AbstractGenericSigmAIQBackendClass, CarbonBlackBackend):
    custom_formats = {}
    associated_pipelines = ["carbonblack", "carbonblack_enterprise"]
    default_pipeline = "carbonblack"

    # Fix CarbonBlack json output format. "id" key in JSON is of type UUID, should be str
    def finalize_query_json(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> Any:
        return {"query": query, "title": rule.title, "id": str(rule.id), "description": rule.description}

from sigma.backends.sentinelone import SentinelOneBackend
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule

from detectiq.sigmaiq.backends.sigmaiq_abstract_backend import (
    AbstractGenericSigmAIQBackendClass,
)


class SigmAIQSentinelOneBackend(AbstractGenericSigmAIQBackendClass, SentinelOneBackend):
    custom_formats = {}
    associated_pipelines = ["sentinelone"]
    default_pipeline = "sentinelone"

    # Fix SentinelOne json output format. "id" key in JSON is of type UUID, should be str
    def finalize_query_json(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> dict:
        return {"query": query, "title": rule.title, "id": str(rule.id), "description": rule.description}

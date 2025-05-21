from sigma.backends.insight_idr import InsightIDRBackend

from detectiq.sigmaiq.backends.sigmaiq_abstract_backend import (
    AbstractGenericSigmAIQBackendClass,
)


class SigmAIQInsightIDRBackend(AbstractGenericSigmAIQBackendClass, InsightIDRBackend):
    custom_formats = {}
    associated_pipelines = ["insightidr"]
    default_pipeline = "insightidr"

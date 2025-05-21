from sigma.backends.elasticsearch import LuceneBackend

from detectiq.sigmaiq.backends.sigmaiq_abstract_backend import (
    AbstractGenericSigmAIQBackendClass,
)


class SigmAIQElasticsearchBackend(AbstractGenericSigmAIQBackendClass, LuceneBackend):
    """SigmAIQ backend interface for the pySigma Elasticsearch Backend library to translate a SigmaRule object
    to an Elasticsearch search query"""

    custom_formats = {}
    associated_pipelines = [
        "ecs_windows",
        "ecs_kubernetes",
        "ecs_windows_old",
        "ecs_zeek_beats",
        "ecs_zeek_corelight",
        "zeek_raw",
    ]
    default_pipeline = "ecs_windows"

from sigma.backends.opensearch import OpensearchLuceneBackend
from sigmaiq.backends.sigmaiq_abstract_backend import AbstractGenericSigmAIQBackendClass


class SigmAIQOpensearchBackend(AbstractGenericSigmAIQBackendClass, OpensearchLuceneBackend):
    custom_formats = {}
    # Opensearch uses elasticsearch pysigma stuff, per their README
    associated_pipelines = ["ecs_windows", "ecs_windows_old", "ecs_zeek_beats", "ecs_zeek_corelight", "zeek_raw"]
    default_pipeline = "ecs_windows"

from sigma.backends.loki import LogQLBackend

from detectiq.sigmaiq.backends.sigmaiq_abstract_backend import (
    AbstractGenericSigmAIQBackendClass,
)


class SigmAIQLokiBackend(AbstractGenericSigmAIQBackendClass, LogQLBackend):
    custom_formats = {}
    associated_pipelines = ["loki_grafana_logfmt", "loki_promtail_sysmon", "loki_okta_system_log"]
    default_pipeline = "loki_grafana_logfmt"

from sigma.backends.QRadarAQL import QRadarAQLBackend

from detectiq.sigmaiq.backends.sigmaiq_abstract_backend import (
    AbstractGenericSigmAIQBackendClass,
)


class SigmAIQQRadarBackend(AbstractGenericSigmAIQBackendClass, QRadarAQLBackend):
    """SigmAIQ backend interface for the pySigma QRadar-AQL Backend library to translate a SigmaRule object
    to a Splunk search query"""

    associated_pipelines = ["qradar_fields", "qradar_payload"]
    default_pipeline = "qradar_fields"

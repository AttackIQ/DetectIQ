from sigma.backends.secops import SecOpsBackend

from detectiq.sigmaiq.backends.sigmaiq_abstract_backend import (
    AbstractGenericSigmAIQBackendClass,
)


class SigmAIQSecOpsBackend(AbstractGenericSigmAIQBackendClass, SecOpsBackend):
    """SigmAIQ backend interface for the pySigma SecOps Backend library to translate a SigmaRule object
    to a SecOps query"""

    associated_pipelines = ["secops_udm"]
    default_pipeline = "secops_udm"

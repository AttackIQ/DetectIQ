from sigma.backends.netwitness import NetWitnessBackend

from detectiq.sigmaiq.backends.sigmaiq_abstract_backend import (
    AbstractGenericSigmAIQBackendClass,
)


class SigmAIQNetwitnessBackend(AbstractGenericSigmAIQBackendClass, NetWitnessBackend):
    """SigmAIQ backend interface for the pySigma Netwitness Backend library to translate a SigmaRule object
    to a Netwitness search query"""

    associated_pipelines = ["netwitness_windows"]
    default_pipeline = "netwitness_windows"

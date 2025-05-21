from sigma.backends.crowdstrike import LogScaleBackend
from sigma.backends.splunk import SplunkBackend

from detectiq.sigmaiq.backends.sigmaiq_abstract_backend import (
    AbstractGenericSigmAIQBackendClass,
)


class SigmAIQCrowdstrikeSplunkBackend(AbstractGenericSigmAIQBackendClass, SplunkBackend):
    """SigmAIQ backend interface for the pySigma Splunk Backend library to translate a SigmaRule object
    to a Splunk search query with the Crowdstrike FDR format"""

    custom_formats = {}
    associated_pipelines = ["crowdstrike_fdr"]
    default_pipeline = "crowdstrike_fdr"
    formats = {"default": SplunkBackend.formats["default"]}


class SigmAIQCrowdstrikeLogscaleBackend(AbstractGenericSigmAIQBackendClass, LogScaleBackend):
    """SigmAIQ backend interface for the pySigma Logscale Backend library to translate a SigmaRule object
    to a Logscale search query with the Crowdstrike Falcon format"""

    custom_formats = {}
    associated_pipelines = ["crowdstrike_falcon"]
    default_pipeline = "crowdstrike_falcon"
    formats = {"default": LogScaleBackend.formats["default"]}

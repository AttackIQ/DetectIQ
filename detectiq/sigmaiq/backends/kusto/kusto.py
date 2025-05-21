from sigma.backends.kusto import KustoBackend

from detectiq.sigmaiq.backends.sigmaiq_abstract_backend import (
    AbstractGenericSigmAIQBackendClass,
)


class SigmAIQDefenderXDRBackend(AbstractGenericSigmAIQBackendClass, KustoBackend):
    """SigmAIQ backend interface for the pySigma Kusto Backend library to translate a SigmaRule object
    to a Kusto search query with the Microsoft Defender XDR format"""

    custom_formats = {}
    associated_pipelines = ["microsoft_xdr"]
    default_pipeline = "microsoft_xdr"


class SigmAIQSentinelASIMBackend(AbstractGenericSigmAIQBackendClass, KustoBackend):
    """SigmAIQ backend interface for the pySigma Kusto Backend library to translate a SigmaRule object
    to a Kusto search query with the Microsoft Sentinel ASIM format"""

    custom_formats = {}
    associated_pipelines = ["sentinel_asim"]
    default_pipeline = "sentinel_asim"


class SigmAIQAzureMonitorBackend(AbstractGenericSigmAIQBackendClass, KustoBackend):
    """SigmAIQ backend interface for the pySigma Kusto Backend library to translate a SigmaRule object
    to a Kusto search query with the Microsoft Azure Monitor format"""

    custom_formats = {}
    associated_pipelines = ["azure_monitor"]
    default_pipeline = "azure_monitor"

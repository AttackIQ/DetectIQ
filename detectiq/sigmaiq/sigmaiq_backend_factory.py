import logging
from copy import deepcopy
from typing import Any, Dict, List, Optional, Union

from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule

# Backends
from detectiq.sigmaiq.backends.carbonblack import SigmAIQCarbonBlackBackend
from detectiq.sigmaiq.backends.cortexxdr import SigmAIQCortexXDRBackend
from detectiq.sigmaiq.backends.crowdstrike import (
    SigmAIQCrowdstrikeLogscaleBackend,
    SigmAIQCrowdstrikeSplunkBackend,
)
from detectiq.sigmaiq.backends.elasticsearch import SigmAIQElasticsearchBackend
from detectiq.sigmaiq.backends.insightidr import SigmAIQInsightIDRBackend
from detectiq.sigmaiq.backends.kusto import (
    SigmAIQAzureMonitorBackend,
    SigmAIQDefenderXDRBackend,
    SigmAIQSentinelASIMBackend,
)
from detectiq.sigmaiq.backends.loki import SigmAIQLokiBackend
from detectiq.sigmaiq.backends.netwitness import SigmAIQNetwitnessBackend
from detectiq.sigmaiq.backends.opensearch import SigmAIQOpensearchBackend
from detectiq.sigmaiq.backends.qradar import SigmAIQQRadarBackend
from detectiq.sigmaiq.backends.secops import SigmAIQSecOpsBackend
from detectiq.sigmaiq.backends.sentinelone import SigmAIQSentinelOneBackend
from detectiq.sigmaiq.backends.sigma import SigmAIQSigmaBackend

## Abstract
from detectiq.sigmaiq.backends.sigmaiq_abstract_backend import (
    AbstractGenericSigmAIQBackendClass,
)
from detectiq.sigmaiq.backends.splunk import SigmAIQSplunkBackend
from detectiq.sigmaiq.backends.stix import SigmAIQStixBackend
from detectiq.sigmaiq.exceptions import InvalidSigmAIQBackend
from detectiq.sigmaiq.sigmaiq_pipeline_factory import (
    SigmAIQPipeline,
    SigmAIQPipelineResolver,
)

# Utils
from detectiq.sigmaiq.utils.sigmaiq.sigmaiq_utils import create_sigma_rule_obj

AVAILABLE_BACKENDS = {
    "carbonblack": "Carbon Black EDR",
    "cortexxdr": "Palo Alto Cortex XDR",
    "crowdstrike_splunk": "Crowdstrike FDR Splunk Query",
    "crowdstrike_logscale": "Crowdstrike Logscale Query",
    "elasticsearch": "Elastic Elasticsearch SIEM",
    # RS uncommented this line after Stephen uncomment corresponding line in pyproject.toml
    # "insightidr": "Rapid7 InsightIDR SIEM",
    "loki": "Grafana Loki LogQL SIEM",
    "microsoft_xdr": "Microsoft XDR Advanced Hunting Query (KQL) (Defender, Office365, etc)",
    "microsoft_sentinel_asim": "Microsoft Sentinel ASIM Query (KQL)",
    "microsoft_azure_monitor": "Microsoft Azure Monitor Query (KQL)",
    "netwitness": "Netwitness Query",
    "opensearch": "OpenSearch Lucene",
    "qradar": "IBM QRadar",
    "secops": "Google SecOps (Chronicle)",
    "sentinelone": "SentinelOne EDR",
    "splunk": "Splunk SIEM",
    "sigma": "Original YAML/JSON Sigma Rule Output",
    "stix": "STIX 2.0 & STIX Shifter Queries",
}


class SigmAIQBackend:
    """
    Implement the Factory pattern for the pySigma Backends, which provide the translation from SigmaRule objects
    to SIEM/Security Tool queries.
    """

    def __init__(
        self,
        backend: str,
        processing_pipeline: Optional[Union[str, list, ProcessingPipeline]] = None,
        output_format: Optional[str] = None,
    ):
        """Initialize instance attributes.

        :param backend: Specifies the desired backend.
        :type backend: str
        :param processing_pipeline: Submit processing pipeline to pySigma backend to automatically apply processing pipeline
        when converting a SigmaRule object to the backend query. This can also be done manually outside the backend,
        defaults to None
        :type processing_pipeline: ProcessingPipeline, optional
        :param output_format: Format specific to each SigmAIQBackendClass to output specific formats, such as
        'yaml' or 'json' for the raw Sigma Backend, defaults to None
        :type output_format: str, optional
        """
        logging.debug(f"Executing SigmAIQBackend constructor. backend: {backend}")
        self.backend = backend
        self.processing_pipeline = self._setup_processing_pipeline(processing_pipeline)
        self.output_format = output_format

    def create_backend(self) -> AbstractGenericSigmAIQBackendClass:
        """
        Create the factory agents.

        :return: The custom AbstractGenericSigmAIQBackendClass instance of the pySigma Backend depending on the
        value of the `backend` parameter. The abstract backend class inherits the TextBackend and specific pySigma
        backend classes attributes and methods.
        :rtype: AbstractGenericSigmAIQBackendClass
        """
        kwargs = {"processing_pipeline": self.processing_pipeline, "output_format": self.output_format}

        # Carbon Black EDR (standard & enterprise)
        if self.backend == "carbonblack":
            return SigmAIQCarbonBlackBackend(**kwargs)
        # Cortex XDR, Palo Alto
        if self.backend == "cortexxdr":
            return SigmAIQCortexXDRBackend(**kwargs)
        # Crowdstrike Splunk Query
        if self.backend == "crowdstrike_splunk":
            pipelines = ["crowdstrike_fdr", kwargs["processing_pipeline"]]
            kwargs["processing_pipeline"] = SigmAIQPipelineResolver(pipelines).process_pipelines()
            return SigmAIQCrowdstrikeSplunkBackend(**kwargs)
        # Crowdstrike Logscale Query
        if self.backend == "crowdstrike_logscale":
            pipelines = ["crowdstrike_falcon", kwargs["processing_pipeline"]]
            kwargs["processing_pipeline"] = SigmAIQPipelineResolver(pipelines).process_pipelines()
            return SigmAIQCrowdstrikeLogscaleBackend(**kwargs)
        # Elasticsearch
        if self.backend == "elasticsearch":
            return SigmAIQElasticsearchBackend(**kwargs)
        # InsightIDR
        if self.backend == "insightidr":
            return SigmAIQInsightIDRBackend(**kwargs)
        # Loki (Grafana)
        if self.backend == "loki":
            return SigmAIQLokiBackend(**kwargs)
        # Microsoft Kusto
        if self.backend == "microsoft_xdr":
            return SigmAIQDefenderXDRBackend(**kwargs)
        if self.backend == "microsoft_sentinel_asim":
            return SigmAIQSentinelASIMBackend(**kwargs)
        if self.backend == "microsoft_azure_monitor":
            return SigmAIQAzureMonitorBackend(**kwargs)
        # Netwitness
        if self.backend == "netwitness":
            return SigmAIQNetwitnessBackend(**kwargs)
        # Opensearch
        if self.backend == "opensearch":
            return SigmAIQOpensearchBackend(**kwargs)
        #
        # QRadar Backend
        if self.backend == "qradar":
            return SigmAIQQRadarBackend(**kwargs)
        # SecOps Backend
        if self.backend == "secops":
            return SigmAIQSecOpsBackend(**kwargs)
        # SentinelOne
        if self.backend == "sentinelone":
            return SigmAIQSentinelOneBackend(**kwargs)
        # Splunk Backend
        if self.backend == "splunk":
            if kwargs["output_format"] == "data_model":
                pipelines = [p for p in ["splunk_cim_dm", kwargs.get("processing_pipeline")] if p is not None]
                kwargs["processing_pipeline"] = SigmAIQPipelineResolver(pipelines).process_pipelines()
            return SigmAIQSplunkBackend(**kwargs)
        # Raw sigma output
        if self.backend == "sigma":
            if not kwargs.get("output_format"):
                kwargs["output_format"] = "yaml"
            return SigmAIQSigmaBackend(**kwargs)
        # STIX
        if self.backend == "stix":
            return SigmAIQStixBackend(**kwargs)

        raise InvalidSigmAIQBackend(
            'Backend not supported: "{}". Available backends:\n{}'.format(
                self.backend, "\n".join([f"{k}: {v}" for k, v in AVAILABLE_BACKENDS.items()])
            )
        )

    @staticmethod
    def _setup_processing_pipeline(processing_pipeline):
        """Return the processing pipeline if None or already a ProcessingPipeline
        Otherwise, try to create them with our processing_pipeline_factory"""

        if processing_pipeline:
            if not isinstance(processing_pipeline, list):
                processing_pipeline = [processing_pipeline]
        else:
            processing_pipeline = []

        # Use pipeline resolver to combine pipelines
        if processing_pipeline:
            return SigmAIQPipelineResolver(processing_pipelines=processing_pipeline).process_pipelines()
        return None

    @classmethod
    def create_all_and_translate(
        cls,
        sigma_rule: Union[SigmaRule, SigmaCollection, str, dict],
        show_errors: Optional[bool] = False,
        excluded_backends: Optional[List[str]] = None,
    ) -> Dict[Any, Any]:
        """Iterates through all combinations of backends, associated pipelines with each backend, and output formats
        for each backend, and creates a dict of outputs.

        :param sigma_rule: A valid SigmaRule or SigmaCollection object to translate
        :type sigma_rule: Union[SigmaRule, SigmaCollection]
        :param show_errors: If True, errors will be included in the list of outputs. Errors can include errors from a
        backend when specific fields cannot be converted to a query. Defaults to False
        :type show_errors: bool
        :param excluded_backends: List of backends to exclude from translations. Defaults to None
        :return: Dict of output results in the following format:
            {backend: {pipeline: {output_format: [queries]}
        :rtype: Dict[Any, Any]
        """
        backends_pipelines = cls.display_all_associated_pipelines()
        backends_output_formats = cls.display_backends_and_outputs()
        excluded_backends = [x.lower() for x in excluded_backends] if excluded_backends else []
        results = {}
        sigma_rule = create_sigma_rule_obj(sigma_rule)
        for backend, pipelines in backends_pipelines.items():
            if backend.lower() in excluded_backends:
                continue
            backend_obj = cls(backend=backend).create_backend()
            for pipeline in pipelines:
                backend_obj.set_pipeline(pipeline)
                for output_format in backends_output_formats[backend].get("output_formats"):
                    backend_obj.set_output_format(output_format)
                    output = []
                    try:
                        output = backend_obj.translate(deepcopy(sigma_rule))
                    except Exception as exc:
                        if show_errors:
                            output = [exc]
                    if output:
                        if backend not in results.keys():
                            results[backend] = {}
                        if pipeline not in results[backend].keys():
                            results[backend][pipeline] = {}
                        results[backend][pipeline][output_format] = output
        return results

    @classmethod
    def display_available_backends(cls) -> Dict[str, str]:
        """Simple class method for returning dict of available backends and descriptions
        :return: Dict containing backend name and description
        :rtype: Dict[str, str]
        """
        return AVAILABLE_BACKENDS

    @classmethod
    def display_backends_and_outputs(cls) -> Dict:
        """Display all available backends as well as their associated output formats, both standard and SigmAIQ
        custom

        :return: Dict containing available backends for keys, and a dict of output formats with descriptions as values
        :rtype: Dict
        """
        backend_formats = {}
        for backend, description in AVAILABLE_BACKENDS.items():
            backend_instance = cls(backend=backend).create_backend()
            output_formats = backend_instance.formats or {"default": "Default output format"}
            custom_output_formats = backend_instance.custom_formats or {}
            output_formats = {**output_formats, **custom_output_formats} if custom_output_formats else output_formats
            backend_formats[backend] = {}
            backend_formats[backend]["description"] = description
            backend_formats[backend]["output_formats"] = output_formats
        return backend_formats

    @classmethod
    def display_all_associated_pipelines(cls) -> Dict:
        """Displays all available backends with their associated pipelines. Output format is a dict with the available
        pipeline as a key and a dict of the pipeline name and descriptions as the value.

        :return: Dict of backend pipline information
        :rtype: Dict

        """
        associated_pipelines = {}
        available_pipelines = SigmAIQPipeline.display_available_pipelines()
        for backend in AVAILABLE_BACKENDS.keys():
            pipeline_desc = {}
            backend_instance = cls(backend=backend).create_backend()
            pipelines = backend_instance.associated_pipelines
            for pipeline in pipelines:
                pipeline_desc[pipeline] = available_pipelines[pipeline]
            associated_pipelines[backend] = pipeline_desc

        return associated_pipelines

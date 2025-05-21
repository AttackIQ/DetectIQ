from typing import Callable, Dict, List, Optional, Union
from uuid import uuid4

from sigma.pipelines.azuremonitor import azure_monitor_pipeline

## Carbon Black
from sigma.pipelines.carbonblack import (
    CarbonBlack_pipeline,
    CarbonBlackResponse_pipeline,
)

## Cortex XDR
from sigma.pipelines.cortexxdr import CortexXDR_pipeline

## Crowdstrike
from sigma.pipelines.crowdstrike import (
    crowdstrike_falcon_pipeline,
    crowdstrike_fdr_pipeline,
)

## Elasticsearch
from sigma.pipelines.elasticsearch import (
    ecs_kubernetes,
    ecs_windows,
    ecs_windows_old,
    ecs_zeek_beats,
    ecs_zeek_corelight,
    zeek_raw,
)

## Loki
from sigma.pipelines.loki import (
    loki_grafana_logfmt,
    loki_okta_system_log,
    loki_promtail_sysmon,
)

## Microsoft
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline

# Netwitness
from sigma.pipelines.netwitness import netwitness_windows_pipeline

## QRadar
from sigma.pipelines.QRadarAQL import (
    QRadarAQL_fields_pipeline,
    QRadarAQL_payload_pipeline,
)

## SecOps
from sigma.pipelines.secops import secops_udm_pipeline
from sigma.pipelines.sentinelasim import sentinel_asim_pipeline

## SentinelOne
from sigma.pipelines.sentinelone import sentinelone_pipeline

## Splunk
from sigma.pipelines.splunk import (
    splunk_cim_data_model,
    splunk_windows_pipeline,
    splunk_windows_sysmon_acceleration_keywords,
)

## STIX
from sigma.pipelines.stix import stix_2_0, stix_shifter

## Sysmon
from sigma.pipelines.sysmon import sysmon_pipeline

## Windows
from sigma.pipelines.windows import windows_audit_pipeline, windows_logsource_pipeline
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.resolver import ProcessingPipelineResolver
from sigma.processing.transformations import FieldMappingTransformation

from detectiq.sigmaiq.exceptions import (
    InvalidCustomFieldMapping,
    InvalidSigmAIQPipeline,
)

## AIQ
from detectiq.sigmaiq.pipelines.splunk_windows_audit import splunk_wineventlog_pipeline

#############
# PIPELINES #
#############
## InsightIDR
# RS uncommented this line after Stephen uncomment corresponding line in pyproject.toml
# from sigma.pipelines.insight_idr import insight_idr_pipeline

AVAILABLE_PIPELINES = {  # AIQ Custom
    "splunk_wineventlog": {
        "description": "SigmAIQ Custom combined windows_audit and splunk_windows pipelines to convert Sysmon fields to "
        "Windows Event Log fields for Splunk searches",
        "pipeline": splunk_wineventlog_pipeline(),
        "display_name": "Splunk WinEventLog",
    },  # CarbonBlack
    "carbonblack": {
        "description": "Uses Carbon Black EDR field mappings",
        "pipeline": CarbonBlackResponse_pipeline(),
        "display_name": "CB",
    },  # Cortex XDR, Palo Alto
    "cortexxdr": {
        "description": "Uses Palo Alto Cortex XDR field mappings",
        "pipeline": CortexXDR_pipeline(),
        "display_name": "Palo Alto Cortex XDR",
    },
    "carbonblack_enterprise": {
        "description": "Uses Carbon Black Enterprise EDR field mappings",
        "pipeline": CarbonBlack_pipeline(),
        "display_name": "CB",
    },  # Crowdstrike
    "crowdstrike_fdr": {
        "description": "Crowdstrike FDR Splunk Mappings",
        "pipeline": crowdstrike_fdr_pipeline(),
        "display_name": "CrowdStrike FDR SPL",
    },
    "crowdstrike_falcon": {
        "description": "Crowdstrike Falcon Logscale Mappings",
        "pipeline": crowdstrike_falcon_pipeline(),
        "display_name": "CrowdStrike Falcon Logscale",
    },  # Elasticsearch
    "ecs_kubernetes": {
        "description": "Elastic Common Schema (ECS) Kubernetes audit log mappings",
        "pipeline": ecs_kubernetes(),
        "display_name": "ECS Kubernetes",
    },
    "ecs_windows": {
        "description": "Elastic Common Schema (ECS) Windows log mappings from Winlogbeat from version 7",
        "pipeline": ecs_windows(),
        "display_name": "ECS Winlogbeat",
    },
    "ecs_windows_old": {
        "description": "Elastic Common Schema (ECS) Windows log mappings from Winlogbeat up to version 6",
        "pipeline": ecs_windows_old(),
        "display_name": "ESC Winlogbeat (<= v6.x)",
    },
    "ecs_zeek_beats": {
        "description": "Elastic Common Schema (ECS) for Zeek using filebeat >= 7.6.1",
        "pipeline": ecs_zeek_beats(),
        "display_name": "ECS Zeek (Elastic)",
    },
    "ecs_zeek_corelight": {
        "description": "Elastic Common Schema (ECS) mapping from Corelight",
        "pipeline": ecs_zeek_corelight(),
        "display_name": "ESC Zeek (Corelight)",
    },
    "zeek_raw": {
        "description": "Zeek raw JSON field naming",
        "pipeline": zeek_raw(),
        "display_name": "Zeek Raw JSON",
    },  # InsightIDR
    # RS uncommented this line after Stephen uncomment corresponding line in pyproject.toml
    # "insightidr": {
    #     "description": "InsightIDR Log Entry Query Language (LEQL) Transformations",
    #     "pipeline": insight_idr_pipeline(),
    #     "display_name": "InsightIDR LEQL",
    # },
    # Loki
    "loki_grafana_logfmt": {
        "description": "Converts field names to logfmt labels used by Grafana",
        "pipeline": loki_grafana_logfmt(),
        "display_name": "Logfmt Labels",
    },
    "loki_promtail_sysmon": {
        "description": "Parse and adjust field names for Windows sysmon data produced by promtail",
        "pipeline": loki_promtail_sysmon(),
        "display_name": "WinSysmon Promtail",
    },
    "loki_okta_system_log": {
        "description": "Parse the Okta System Log event json, adjusting field-names appropriately",
        "pipeline": loki_okta_system_log(),
        "display_name": "Okta System Event",
    },  # Microsoft Kusto
    "microsoft_xdr": {
        "description": "Mappings for Sysmon -> XDR Advanced Hunting Query Table Schema",
        "pipeline": microsoft_xdr_pipeline(),
        "display_name": "Microsoft XDR KustoQL",
    },  # Microsoft Sentinel ASIM
    "sentinel_asim": {
        "description": "Mappings for Sysmon -> Sentinel ASIM Query Table Schema",
        "pipeline": sentinel_asim_pipeline(),
        "display_name": "Sentinel ASIM KustoQL",
    },  # Microsoft Azure Monitor
    "azure_monitor": {
        "description": "Mappings for Sysmon -> Azure Monitor Query Table Schema",
        "pipeline": azure_monitor_pipeline(),
        "display_name": "Azure Monitor KustoQL",
    },  # Netwitness
    "netwitness_windows": {
        "description": "Netwitness Windows log mappings",
        "pipeline": netwitness_windows_pipeline(),
        "display_name": "Netwitness Windows",
    },  # QRadar
    "qradar_fields": {
        "description": "Supports only the Sigma fields in the Field Mapping",
        "pipeline": QRadarAQL_fields_pipeline(),
        "display_name": "Sigma Fields",
    },
    "qradar_payload": {
        "description": "Uses UTF8(payload) instead of fields unsupported by the Field Mapping.",
        "pipeline": QRadarAQL_payload_pipeline(),
        "display_name": "UTF8(payload) (Non-Sigma Fields)",
    },
    # Sigma Pipeline Placeholder
    "sigma_default": {
        "description": "Empty ProcessingPipeline placeholder",
        "pipeline": ProcessingPipeline(name="Sigma Placeholder"),
        "display_name": "Sigma",
    },  # SecOps
    "secops_udm": {
        "description": "Mappings for Google SecOps (Chronicle) UDM",
        "pipeline": secops_udm_pipeline(),
        "display_name": "Google SecOps UDM",
    },  # SentinelOne
    "sentinelone": {
        "description": "Mappings for SentinelOne Deep Visibility Queries",
        "pipeline": sentinelone_pipeline(),
        "display_name": "SentinelOne Deep Visibility",
    },  # Splunk
    "splunk_windows": {
        "description": "Splunk Query, Windows Mappings",
        "pipeline": splunk_windows_pipeline(),
        "display_name": "Splunk Query (Windows)",
    },
    "splunk_windows_sysmon_acc": {
        "description": "Splunk Windows Sysmon search acceleration keywords",
        "pipeline": splunk_windows_sysmon_acceleration_keywords(),
        "display_name": "Splunk Query (Sysmon)",
    },
    "splunk_cim_dm": {
        "description": "Splunk Datamodel Field Mappings",
        "pipeline": splunk_cim_data_model(),
        "display_name": "Splunk Datamodel Query",
    },  # STIX
    "stix_2_0": {"description": "STIX 2.0 Mappings", "pipeline": stix_2_0(), "display_name": "STIX 2.0"},
    "stix_shifter": {
        "description": "STIX Shifter Mappings",
        "pipeline": stix_shifter(),
        "display_name": "STIX Shifter",
    },  # Windows
    "windows_sysmon": {"description": "Sysmon for Windows", "pipeline": sysmon_pipeline(), "display_name": "Sysmon"},
    "windows_audit": {
        "description": "Windows Event Logs",
        "pipeline": windows_audit_pipeline(),
        "display_name": "Windows Event Logs",
    },
    "windows_logsource": {
        "description": "Windows Logs, General",
        "pipeline": windows_logsource_pipeline(),
        "display_name": "Windows Logs, General",
    },
}


class SigmAIQPipeline:
    """
    Implement the Factory pattern for the pySigma transformation Pipelines, which provide the functionality to
    transform SigmaRule objects. Examples are field renames, changing logsource fields, etc.

    If you would like to apply multiple processing pipelines, use the class SigmAIQPipelineResolver instead, which will
    use this factory class for each ProcessingPipeline in a list of pipelines, and return a single consolidated
    ProcessingPipeline from multiple pipelines using pySigma's ProcessingPipelineResolver class.


    """

    def __init__(self, processing_pipeline: Optional[Union[str, ProcessingPipeline, Callable]] = None):
        """Initialize the class to create a ProcessingPipeline

            :param processing_pipeline: Specifies the desired pipeline to create. This can be one of three types:
            1. A str based on the keys in PIPELINES that will load predefined pipelines according to this factory
            2. A function (or callable) that return a pySigma ProcessingPipeline object
            3. A ProcessingPipeline object
            If providing a callable or ProcessingPipeline, the ProcessingPipeline must have the 'name' attribute set
        :type processing_pipeline: str or function or ProcessingPipeline
        """

        if not processing_pipeline:  # _validate_pipeline should catch this but just to be sure
            raise ValueError("Please provide a valid processing pipeline value to processing_pipeline")
        self.pipeline = processing_pipeline

    def create_pipeline(self):
        """Simple method to just return the validated pipeline, call this after creating the class"""
        return self._validate_pipeline(self.pipeline)

    @classmethod
    def from_fieldmap(cls, fieldmapping: Dict[str, Union[str, List[str]]], name=None, priority: int = 10):
        """Creates a ProcessingPipeline object from custom field renaming dict
        :param fieldmapping: Dictionary containing field mappings in format {'original_field': 'new_field'}
        Values can be a string of the new field name, or list of strings for new field names.
        :type fieldmapping: Dict[str, Union[str, List[str]]]
        :param name: Name of the new ProcessingPipeline. If not given, defaults to
        'Custom Field Renames Pipeline <uid>'
        :type name: str, optional
        :param priority: Priority to assign to new ProcessingPipeline between 0 and 100. Pipelines with a lower
        priority will be applied first if combined with other pipelines in a resolver. Defaults to 10
        :type priority: int, optional
        """

        # Helper methods
        def _validate_field_mappings(field_mappings):
            if not field_mappings:
                raise InvalidCustomFieldMapping(
                    "The provided field_mappings is empty or None. "
                    "Please provide a valid dictionary for field mappings."
                )
            if isinstance(field_mappings, dict):
                if all(isinstance(k, str) and isinstance(v, str) for k, v in field_mappings.items()):
                    return field_mappings
            raise TypeError(
                f"fieldmappings must be of type 'dict' with str keys and values or None, "
                f"but is {type(field_mappings)}"
            )

        def _validate_name(pname):
            if pname is not None:
                if not isinstance(pname, str):
                    raise TypeError(
                        f"'name' given for new fieldmapping pipeline must be of type str, "
                        f"got {type(pname)} instead."
                    )
            return pname

        def _validate_priority(priority_num):
            """Ensure priority is valid and 0 <= priority <= 100"""
            if not priority_num:
                return 0
            if not isinstance(priority_num, int):
                raise TypeError(
                    f"custom_field_mappings_priority must be of type `int`, but {type(priority_num)} was provided"
                )
            if priority_num < 0:
                return 0
            if priority_num > 100:
                return 100
            return priority_num

        uid = str(uuid4())
        pipeline_name = _validate_name(name) or f"Custom Field Renames Pipeline {uid}"
        pipeline_priority = _validate_priority(priority)
        fieldmapping = _validate_field_mappings(fieldmapping)
        pipeline_item = ProcessingItem(identifier=uid, transformation=FieldMappingTransformation(fieldmapping))
        pipeline = ProcessingPipeline(name=pipeline_name, priority=pipeline_priority, items=[pipeline_item])
        return cls(processing_pipeline=pipeline)

    @classmethod
    def display_available_pipelines(cls) -> Dict:
        """Simple class method for returning dict of available pipelines and descriptions"""
        return {k: v.get("description") for k, v in AVAILABLE_PIPELINES.items()}

    @classmethod
    def display_available_pipelines_display_names(cls) -> Dict:
        """Simple class method for returning dict of available pipelines and display names"""
        return {k: v.get("display_name") for k, v in AVAILABLE_PIPELINES.items()}

    @staticmethod
    def _get_pipeline(pipeline_name: str) -> ProcessingPipeline:
        """Get pipeline obj from dict of PIPELINES
        :param pipeline_name: The name of the pipeline, should be a key in PIPELINES dict
        :type pipeline_name: str
        :return: pySigma ProcessingPipeline object
        :rtype: ProcessingPipeline
        """
        return AVAILABLE_PIPELINES.get(pipeline_name, {}).get("pipeline", None)

    def _validate_pipeline(self, processing_pipeline):
        """Validates if the pipeline is in the dict of available_pipelines, or is a valid ProcessingPipeline obj"""
        # If string, check to see if it's in our list of valid pipelines and call the callable
        if isinstance(processing_pipeline, str):
            if new_processing_pipeline := self._get_pipeline(processing_pipeline):
                return self._validate_pipeline(new_processing_pipeline)
            else:
                raise InvalidSigmAIQPipeline(
                    f"Provided processing_pipeline str {processing_pipeline} not in list of "
                    f"available pipelines: {', '.join(AVAILABLE_PIPELINES.keys())}"
                )

        # If it's a callable, call it and re-check it to ensure it is of type ProcessingPipeline
        if callable(processing_pipeline):
            processing_pipeline = self._validate_pipeline(processing_pipeline())
            return processing_pipeline

        # If it's a list, return SigmAIQPipelineResolver so each element/pipeline can be resolved
        if isinstance(processing_pipeline, list):
            return SigmAIQPipelineResolver(processing_pipelines=processing_pipeline).process_pipelines()

        # Last, check if is of type ProcessingPipeline
        if isinstance(processing_pipeline, ProcessingPipeline):
            return processing_pipeline

        raise TypeError(
            "Invalid processing_pipeline, or invalid object returned from callable passed as processing_pipeline"
        )


class SigmAIQPipelineResolver:
    """Takes list of processing pipelines that can be either a string, callable that returns a ProcessingPipeline,
    or ProcessingPipeline object, then consolidates them into a single pipeline based on the individual
    ProcessingPipeline's priority attribute.
    https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html#resolvers
    If you want to include a custom ad-hoc ProcessingPipeline in the list of supplied pipelines, create one first
    with SigmAIQPipeline().create_pipeline(), and include the returned ProcessingPipeline object in the list
    """

    def __init__(self, processing_pipelines: List[Union[str, ProcessingPipeline, Callable]]):
        """Init the class
        :param processing_pipelines: List of strings found in available_pipelines, ProcessingPipeline, or callable that
        returns a ProcessingPipeline object
        :type processing_pipelines: List[Union[str, ProcessingPipeline, Callable]]
        """
        self.processing_pipelines = self._setup(processing_pipelines)
        self.resolver = ProcessingPipelineResolver()

    @staticmethod
    def _setup(processing_pipelines):
        if processing_pipelines:
            if isinstance(processing_pipelines, list) or isinstance(processing_pipelines, set):
                return list(filter(None, processing_pipelines))
            raise TypeError(f"processing_pipelines is not of type list or set: type is {type(processing_pipelines)}")
        raise ValueError("processing_pipelines is empty or None, please provide valid values to processing_pipelines")

    def process_pipelines(self, name: Optional[str] = None) -> ProcessingPipeline:
        """Consolidates processing_pipelines with a resolver by creating a ProcessingPipeline via
        SigmAIQPipeline for each item in the processing_pipelines list.  An optional name can be passed
        to the method; if present, the final resolved singular ProcessingPipeline will be given this name. Otherwise,
        it will be named "SigmAIQ Resolved Pipelines" if multiple pipelines are in the resolver. If only one pipeline
        is in the resolver, the name will be the name of that pipeline.

        :param name: Optional, the name to give the final resolved single ProcessingPipeline. Defaults to None.
        :type name: str
        :return: Single ProcessingPipeline ordered by the priority of each pipeline returned from
        SigmAIQPipeline.
        :rtype: ProcessingPipeline
        """

        for pipeline in self.processing_pipelines:
            self.resolver.add_pipeline_class(SigmAIQPipeline(processing_pipeline=pipeline).create_pipeline())
        processing_pipeline = self.resolver.resolve(list(self.resolver.pipelines.keys()))
        list_resolver_pipelines = list(self.resolver.list_pipelines())
        num_pipelines = len(list_resolver_pipelines)  # [(name (str), ProcessingPipeline),]
        # Name final pipeline
        if name:
            processing_pipeline.name = name
        elif num_pipelines == 1:
            processing_pipeline.name = list_resolver_pipelines[0][0]
        else:
            processing_pipeline.name = "SigmAIQ Resolved Pipelines"
        return processing_pipeline

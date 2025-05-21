from sigma.pipelines.splunk import splunk_windows_pipeline
from sigma.pipelines.windows import windows_audit_pipeline
from sigma.processing.pipeline import ProcessingPipeline
from sigma.processing.resolver import ProcessingPipelineResolver


def splunk_wineventlog_pipeline() -> ProcessingPipeline:
    """Returns ProcessingPipeline that combines the windows_audit pipeline with the Splunk Windows pipeline
    for using Windows Event Log field names in Splunk searches rather than Sysmon.
    """
    pipelines = [windows_audit_pipeline(), splunk_windows_pipeline()]
    resolver = ProcessingPipelineResolver.from_pipeline_list(pipelines)
    pipeline = resolver.resolve(resolver.pipelines)
    pipeline.name = "Splunk WinEventLog Pipeline"
    return pipeline


splunk_wineventlog_pipeline()

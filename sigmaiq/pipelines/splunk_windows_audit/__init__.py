from .splunk_wineventlog import splunk_wineventlog_pipeline

pipelines = {
    "splunk_wineventlog": splunk_wineventlog_pipeline(),
}

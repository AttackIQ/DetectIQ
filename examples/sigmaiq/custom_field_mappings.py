# %% This example shows how to use the SigmAIQ pySigma wrapper to provide custom field mappings for a backend
# %% This will allow you to translate specific field names to custom field names during rule translation

from copy import copy

# %% Import pprint for pretty printing, and copy for copying rules
from pprint import pprint
from typing import Dict, Union, List

# %% Import SigmAIQ
from sigmaiq import SigmAIQBackend, SigmAIQPipeline

# %% A basic Sigma Rule in YAML str to convert to a query.
# %% SigmAIQ also accepts a rule in JSON/Dict format, SigmaRule objects, and SigmaCollection objects

sigma_rule = """
title: whoami Command
description: Detects a basic whoami commandline execution
logsource:
    product: windows
    category: process_creation
detection:
    selection1:
        - CommandLine|contains: 'whoami.exe'
    condition: selection1
"""

# %% Create SigmAIQ backend translate the rule to a Microsoft 365 Defender query
sigmaiq_backend = SigmAIQBackend(backend="splunk").create_backend()
query = sigmaiq_backend.translate(copy(sigma_rule))  # Returns List of queries

print("\nM365Defender Query: ", end="\n\n")
pprint(query[0])
print("\n-------------------")

# %% Create custom field mappings
# %% This will map the CommandLine field to a custom field named "CustomCommandLine"
custom_field_mappings: Dict[str, Union[str, List[str]]] = {"CommandLine": "CustomCommandLine"}
my_custom_pipeline = SigmAIQPipeline.from_fieldmap(custom_field_mappings, priority=0).create_pipeline()

# %% Create SigmAIQ backend translate the rule to a Microsoft 365 Defender query with our custom field mappings
sigmaiq_backend = SigmAIQBackend(backend="splunk", processing_pipeline=my_custom_pipeline).create_backend()

query = sigmaiq_backend.translate(copy(sigma_rule))  # Returns List of queries

print("\nM365Defender Query with Custom Fieldmappings: ", end="\n\n")
pprint(query[0])
print("\n-------------------")

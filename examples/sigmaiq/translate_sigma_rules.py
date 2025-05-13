# %% This example shows how to use the SigmAIQ pySigma wrapper to easily translate Sigma rules to queries
# %% easily, without having to worry about installing and configuring the correct backends, pipelines and other details.


from copy import copy

# %% Import pprint for pretty printing, and copy for copying rules
from pprint import pprint

# %% Import SigmAIQ
from sigmaiq import SigmAIQBackend

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

# %% BACKENDS
# %% Show the available supported backends
print("Supported Backends:", end="\n\n")
pprint(SigmAIQBackend.display_available_backends())
print("\n-------------------")

# %% Create SigmAIQ backend translate the rule to a Microsoft XDR query
# %% SigmAIQ will automatically select the best pipeline for the backend
sigmaiq_backend = SigmAIQBackend(backend="microsoft_xdr").create_backend()
query = sigmaiq_backend.translate(copy(sigma_rule))  # Returns List of queries

print("\nMicrosoft XDR KQL Query: ", end="\n\n")
pprint(query[0])
print("\n-------------------")

# %% PIPELINES
# %% Show the available pipelines with each backend
print("Available Pipelines:", end="\n\n")
pprint(SigmAIQBackend.display_all_associated_pipelines())
print("\n-------------------")

# %% Create SigmAIQ backend translate the rule to a Splunk search with the CIM pipeline
sigmaiq_backend = SigmAIQBackend(backend="splunk", processing_pipeline="splunk_cim_dm").create_backend()
query = sigmaiq_backend.translate(copy(sigma_rule))

print("\nSplunk CIM Query: ", end="\n\n")
pprint(query[0])
print("\n-------------------")

# %% OUTPUT FORMATS
# %% Show the available output formats with each backend
print("\nAvailable Output Formats:", end="\n\n")
pprint(SigmAIQBackend.display_backends_and_outputs())
print("\n-------------------")

# %% Change the output_format to an Enterprise Security Correlation Search stanza
sigmaiq_backend.set_output_format("stanza")
query = sigmaiq_backend.translate(copy(sigma_rule))

print("\nSplunk CIM Query, Stanza Output: ", end="\n\n")
pprint(query[0])
print("\n-------------------")

# %% You can also translate a Sigma rule to all supported backend, pipeline, and output format combinations at once.
# %% Any combination that is not supported will not be included in the results
# %% This is useful for testing and comparing the output of different backends and pipelines
queries = SigmAIQBackend.create_all_and_translate(copy(sigma_rule))  # We won't print it, as its a lot of output
# print("\n All Translations: ", end="\n\n")
# pprint(queries)

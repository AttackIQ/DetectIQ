from sigma.backends.stix import stixBackend

from detectiq.sigmaiq.backends.sigmaiq_abstract_backend import (
    AbstractGenericSigmAIQBackendClass,
)


class SigmAIQStixBackend(AbstractGenericSigmAIQBackendClass, stixBackend):
    associated_pipelines = ["stix_2_0", "stix_shifter"]
    default_pipeline = "stix_2_0"

    # Remove "stix" format until its not broken :(
    formats = {"default": stixBackend.formats["default"]}

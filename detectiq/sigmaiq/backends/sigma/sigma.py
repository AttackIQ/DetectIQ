import json
from typing import List, Union

import yaml
from sigma.collection import SigmaCollection
from sigma.conversion.base import TextQueryBackend
from sigma.rule import SigmaRule

from detectiq.sigmaiq.backends.sigmaiq_abstract_backend import (
    AbstractGenericSigmAIQBackendClass,
)


class SigmAIQSigmaBackend(AbstractGenericSigmAIQBackendClass, TextQueryBackend):
    """SigmAIQ backend interface to output raw Sigma rule in various formats"""

    associated_pipelines = ["sigma_default"]
    default_pipeline = "sigma_default"
    custom_formats = {"yaml": "Default Sigma Rule output format", "json": "JSON style Sigma Rule Output"}

    # Override pySigma convert and convert_rule, since we are just outputting it as-is
    # in yaml or json format

    def translate(self, sigma_rule: Union[SigmaCollection, SigmaRule]):
        """Default implementation to translate a SigmaRule or SigmaCollection object into a Splunk query
        :param sigma_rule: SigmaRule or SigmaCollection object to translate, with or without ProcessingPipelines
        already applied to it. If a ProcessingPipeline is supplied to this class on __init__, it will automatically
        apply to the SigmaRule before translating.
        :type sigma_rule: Union[SigmaRule, SigmaCollection]
        :return: List of Splunk queries. In the case of a SigmaRule, the list will have one element.
        :rtype: list
        """
        if self.associated_pipelines and self.default_pipeline:
            self._ensure_proper_pipelines(sigma_rule)
        if isinstance(sigma_rule, SigmaRule):
            output = self._translate_rule(sigma_rule)
        else:
            output = self._translate_collection(sigma_rule)
        return output

    def convert(self, sigma_collection: SigmaCollection, **kwargs) -> List[str]:
        """Override TextBackend method. Outputs SigmaCollection object with each SigmaRule as yaml or json
        Valid output formats are as yaml or json
        :param sigma_collection: SigmaCollection of SigmaRule objects to convert to yaml or json
        :type sigma_collection: SigmaCollection
        :param **kwargs: other args
        :rtype: List[str]
        """
        output = []
        for rule in sigma_collection:
            output = output + self._translate_rule(rule)
        return output

    def convert_rule(self, sigma_rule: SigmaRule, **kwargs) -> List[str]:
        """Override TextBackend method. Outputs SigmaRule object converted to yaml or json str
        Valid output formats are as yaml or json
        :param sigma_rule: SigmaRule object to convert to yaml or json
        :type sigma_rule: SigmaRule
        :param **kwargs: other args
        :rtype: List[str]
        """
        if self.processing_pipeline:
            self.processing_pipeline.apply(sigma_rule)
        output = []
        return self.handle_output_format(sigma_rule, output)

    def handle_output_format(self, sigma_rule, output) -> List[str]:
        if self.custom_output_format == "json":
            output = [self.__to_json(sigma_rule)]
        elif self.custom_output_format == "yaml" or self.output_format == "default":
            output = [self.__to_yaml(sigma_rule)]
        return output

    @staticmethod
    def __to_json(sigma_rule) -> str:
        """Converts sigma rule to JSON str"""
        return json.dumps(sigma_rule.to_dict(), indent=2)

    @staticmethod
    def __to_yaml(sigma_rule) -> str:
        return yaml.dump(sigma_rule.to_dict(), sort_keys=False)

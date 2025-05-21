import re
from copy import copy, deepcopy

from importlib_resources import files
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule

from detectiq.sigmaiq.backends.sigmaiq_abstract_backend import (
    AbstractGenericSigmAIQBackendClass,
)

SAVEDSEARCHES_TEMPLATE = files("detectiq.sigmaiq.backends.splunk").joinpath("savedsearches_template.txt").read_text()


class SigmAIQSplunkBackend(AbstractGenericSigmAIQBackendClass, SplunkBackend):
    """SigmAIQ backend interface for the pySigma Splunk Backend library to translate a SigmaRule object
    to a Splunk search query"""

    custom_formats = {"stanza": "Enterprise Security savedsearches.conf stanza"}
    associated_pipelines = ["splunk_windows", "splunk_wineventlog", "splunk_windows_sysmon_acc", "splunk_cim_dm"]
    default_pipeline = "splunk_windows"

    def handle_output_format(self, sigma_rule, output):
        """Converts Splunk search to savedsearches.conf stanza if output_format given"""
        if self.custom_output_format == "stanza":
            output = self._convert_to_stanza(sigma_rule, output)
        return output

    def _convert_to_stanza(self, sigma_rule, output: list):
        """Converts a list of SigmaRule Splunk query outputs to savedsearches.conf stanzas to use in
        Splunk Enterprise Security Correlation Searches
        """
        # Convert SigmaRule to SigmaCollection just for ease of use
        sigma_rule_temp = copy(sigma_rule)
        if isinstance(sigma_rule_temp, SigmaRule):
            collection = SigmaCollection([sigma_rule_temp])
        else:
            collection = sigma_rule_temp

        stanzas = []
        for i, rule in enumerate(collection):
            title = rule.title
            search = output[i]
            tags = self._extract_mitre_tags(rule.tags)
            replacements = {
                "%TITLE_PLACEHOLDER%": title,
                "%MITRE_ATTACK_PLACEHOLDER%": f"{tags}",
                "%NOTABLE_TITLE_PLACEHOLDER%": title,
                "%DRILLDOWN_TITLE_PLACEHOLDER%": title,
                "%DRILLDOWN_SEARCH_PLACEHOLDER%": search,
                "%SEARCH_PLACEHOLDER%": search,
            }

            stanza = deepcopy(SAVEDSEARCHES_TEMPLATE)
            for k, v in replacements.items():
                stanza = stanza.replace(k, v)
            stanzas.append(stanza)
        return stanzas

    @staticmethod
    def _extract_mitre_tags(tags):
        """Takes tags from a SigmaRule and outputs them into a format that a Splunk Correlation Search stanza will
        recognize for the action.correlationsearch.annotations field:
        i.e.    action.correlationsearch.annotations = {"mitre_attack":["T1055.011","T1560.001","T1205.002","T1583"]}
        """
        mitre_tags = {"mitre_attack": []}
        if not tags:
            return mitre_tags
        for tag in tags:
            matches = re.match(r"^(attack\.)(t\d{4}(\.\d{3})?)", str(tag))
            if matches:
                mitre_tags["mitre_attack"].append(matches[2].upper())
        return mitre_tags

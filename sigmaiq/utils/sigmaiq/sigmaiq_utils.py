from datetime import datetime
from typing import Union

from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule


def _is_v1_schema(rule_data: dict) -> bool:
    """Check if the rule uses v1 schema patterns."""
    if not isinstance(rule_data, dict):
        return False

    # Check date format
    date_str = rule_data.get("date")
    if date_str and "/" in date_str:
        return True

    # Check modified format
    modified_str = rule_data.get("modified")
    if modified_str and "/" in modified_str:
        return True

    # Check tags format
    tags = rule_data.get("tags", [])
    for tag in tags:
        if any(ns in tag for ns in ["attack-", "attack_", "cve-", "detection-"]):
            return True

    # Check related field
    related = rule_data.get("related", [])
    for rel in related:
        if rel.get("type") == "obsoletes":
            return True

    return False


def _convert_to_v2_schema(rule_data: dict) -> dict:
    """Convert v1 schema rule to v2 schema."""
    rule_data = rule_data.copy()

    # Convert date and modified format
    if "date" in rule_data and "/" in rule_data["date"]:
        try:
            date_obj = datetime.strptime(rule_data["date"], "%Y/%m/%d")
            rule_data["date"] = date_obj.strftime("%Y-%m-%d")
        except ValueError:
            pass

    if "modified" in rule_data and "/" in rule_data["modified"]:
        try:
            date_obj = datetime.strptime(rule_data["modified"], "%Y/%m/%d")
            rule_data["modified"] = date_obj.strftime("%Y-%m-%d")
        except ValueError:
            pass

    # Convert tags
    if "tags" in rule_data:
        new_tags = []
        for tag in rule_data["tags"]:
            # Convert common namespace patterns
            tag = tag.replace("attack-", "attack.")
            tag = tag.replace("attack_", "attack.")
            tag = tag.replace("cve-", "cve.")
            tag = tag.replace("detection-", "detection.")
            new_tags.append(tag)
        rule_data["tags"] = new_tags

    # Convert related field
    if "related" in rule_data:
        for rel in rule_data["related"]:
            if rel.get("type") == "obsoletes":
                rel["type"] = "obsolete"

    return rule_data


def create_sigma_rule_obj(sigma_rule: Union[SigmaRule, SigmaCollection, dict, str, list]):
    """Checks sigma_rule to ensure it's a SigmaRule or SigmaCollection object. It can also be a valid Sigma rule
    representation in a dict or yaml str (or list of valid dicts/yaml strs) that can be used with SigmaRule class methods to
    create a valid SigmaRule object. The following checks are performed:
        - If the object is a SigmaRule or SigmaCollection object, return the object.
        - If the object is a list, we will recursively check each element in the list and return a SigmaCollection
        of the returned objects
        - If the object is a dict, use SigmaRule.from_dict(sigma_rule) to create a new SigmaRule object.
        - If the object is a str, use SigmaRule.from_yaml(sigma_rule) to create a new SigmaRule object.

    :param sigma_rule: A list of, or single SigmaRule, SigmaCollection, or valid dict/yaml str that will be
    returned as a SigmaRule or SigmaCollection object.
    :return: SigmaRule or SigmaCollection object as-is or created using SigmaRule classmethods.
    """

    if isinstance(sigma_rule, (SigmaRule, SigmaCollection)):
        return sigma_rule
    if isinstance(sigma_rule, list):
        rules = []
        for s in sigma_rule:
            result = create_sigma_rule_obj(s)
            if isinstance(result, SigmaCollection):
                rules.extend(result.rules)
            else:
                rules.append(result)
        return SigmaCollection(rules)
    if isinstance(sigma_rule, dict):
        # Check and convert v1 schema if needed
        if _is_v1_schema(sigma_rule):
            sigma_rule = _convert_to_v2_schema(sigma_rule)
        return SigmaRule.from_dict(sigma_rule)
    if isinstance(sigma_rule, str):
        # For YAML strings, we need to parse to dict first
        try:
            import yaml

            rule_dict = yaml.safe_load(sigma_rule)
            if _is_v1_schema(rule_dict):
                rule_dict = _convert_to_v2_schema(rule_dict)
            return SigmaRule.from_dict(rule_dict)
        except Exception as e:
            print(e)
            return SigmaRule.from_yaml(sigma_rule)
    raise TypeError(
        f"Invalid type '{type(sigma_rule)}' for `sigma_rule`. "
        f"Use a SigmaRule, SigmaCollection, dict, str, or list of these types instead."
    )

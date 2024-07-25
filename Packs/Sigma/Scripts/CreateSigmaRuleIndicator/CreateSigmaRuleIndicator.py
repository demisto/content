import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json

from sigma.parser.collection import SigmaCollectionParser
from sigma.configuration import SigmaConfiguration
from sigma.parser.exceptions import SigmaParseError


def create_relationship(indicator_value: str, product: str) -> None:
    """
    Creates a relationship in XSOAR between the Sigma rule indicator and the product.

    Args:
        indicator_value (str): The value of the Sigma rule indicator.
        product (str): The product name from the Sigma rule, which will be capitalized.
    """
    try:
        relationship = {
            "entity_a": indicator_value,
            "entity_a_type": "Sigma Rule Indicator",
            "relationship": "related-to",
            "entity_b": product.capitalize(),
            "entity_b_type": "Software"
        }
        demisto.executeCommand("CreateIndicatorRelationship", relationship)
    except Exception as e:
        return_error(f"Failed to create relationship: {str(e)}")


def parse_detection_field(detection: dict) -> list:
    """
    Parses the detection field from the Sigma rule and maps it into a grid field.

    Args:
        detection (dict): The detection field from the Sigma rule.

    Returns:
        list: A list of dictionaries representing the detection grid.
    """
    detection_grid = []
    for key, value in detection.items():
        for sub_key, sub_value in value.items():
            detection_grid.append({
                "selection": key,
                "keyandmodifiers": sub_key,
                "values": "\n".join(sub_value) if isinstance(sub_value, list) else sub_value
            })
    return detection_grid


def parse_and_create_indicator(rule_dict: dict) -> None:
    """
    Parses the Sigma rule dictionary and creates an indicator in XSOAR.

    Args:
        rule_dict (dict): The Sigma rule dictionary.
    """
    # Create fields mapping
    indicator = {
        "value": rule_dict.get("title", ""),
        "sigmaruleid": rule_dict.get("id", ""),
        "sigmarulestatus": rule_dict.get("status", ""),
        "author": rule_dict.get("author", ""),
        "sigmarulelevel": rule_dict.get("level", ""),
        "sigmarulelicense": rule_dict.get("license", ""),
        "tags": rule_dict.get("tags", []),
        "description": rule_dict.get("description", ""),
        "category": rule_dict.get("logsource", {}).get("category", ""),
        "product": rule_dict.get("logsource", {}).get("product", ""),
        "service": rule_dict.get("logsource", {}).get("service", ""),
        "definition": rule_dict.get("logsource", {}).get("definition", ""),
        "sigmaruleraw": json.dumps(rule_dict)
    }

    # Create publications grid field
    publications = []
    if "reference" in rule_dict:
        for ref in rule_dict["reference"]:
            publications.append({
                "link": ref,
                "source": "sigma rule",
                "title": rule_dict.get("title", ""),
                "date": rule_dict.get("date", "")
            })

    indicator["publications"] = publications

    # Parse and create the detection grid field
    detection = rule_dict.get("detection", {})
    indicator["sigmadetection"] = parse_detection_field(detection)

    # Create the indicator in XSOAR
    demisto.executeCommand("createIndicator", {
        "type": "Sigma Rule Indicator",
        "value": indicator["value"],
        "fields": indicator
    })

    # Create the relationship if product is available
    product = rule_dict.get("logsource", {}).get("product", "")
    if product:
        create_relationship(indicator["value"], product)


def main() -> None:
    """
    Main function that handles the Sigma rule import process and creates indicators and relationships in XSOAR.
    """
    try:
        # Get the arguments
        sigma_rule_str = demisto.args().get("sigma_rule_str", "")
        entry_id = demisto.args().get("entry_id", "")

        # Check if both arguments are empty
        if not sigma_rule_str and not entry_id:
            return_error("Either 'sigma_rule_str' or 'entry_id' must be provided.")

        if entry_id:
            # Get the file contents using entry_id
            res = demisto.getFilePath(entry_id)
            if not res:
                return_error(f"File entry {entry_id} not found")
            file_path = res['path']
            with open(file_path, 'r') as file:
                sigma_rule_str = file.read()

        # Parse the sigma rule
        try:
            parser = SigmaCollectionParser(sigma_rule_str, SigmaConfiguration())
            sigma_collection = parser.generate()
        except SigmaParseError as e:
            return_error(f"Failed to parse Sigma rule: {str(e)}")
            return

        for rule in sigma_collection.rules:
            rule_dict = rule.to_dict()
            parse_and_create_indicator(rule_dict)

    except Exception as e:
        return_error(f"Failed to import Sigma rule: {str(e)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

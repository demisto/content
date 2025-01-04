import re

from sigma.rule import SigmaRule
from sigma.exceptions import SigmaError
from sigma.modifiers import reverse_modifier_mapping

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_mitre_technique_name(mitre_id: str, indicator_type: str) -> str:
    """
    Searches XSOAR TIM for an 'Attack Pattern' indicator matching the given MITRE ID and returns the indicator value.

    Args:
        mitre_id (str): The MITRE ATT&CK ID to search for (e.g., T1562).
        indicator_type (str): The XSOAR indicator type (e.g. Attack Pattern)

    Returns:
        str: The indicator value if found, else an empty string.
    """
    try:
        query = f'type:"{indicator_type}" and {mitre_id}'
        demisto.debug(f'Querying for {query} in TIM')

        success, response = execute_command(command="SearchIndicator", args={"query": query}, fail_on_error=False)

        if not success:
            demisto.debug(f"Failed to execute findIndicators command: {get_error(response)}")
            return ""

        indicator = response[0].get("value", "")
        demisto.debug(f'Found the indicator - {indicator}')

        return indicator

    except Exception as e:
        demisto.debug(f"Error searching for Attack Pattern indicator: {str(e)}")
        return ""


def create_indicator_relationships(indicator: str, product: str, relationships: list[dict[str, str]]) -> None:
    """
    Create relationships between the Sigma rule indicator and its Product, CVEs and MITRE techniques

    Args:
        indicator (str): The value of the Sigma rule indicator.
        product (str): The name of the product the rule relates to.
        relationships (list of dicts): All values that are about to be related to the Sigma rule.
    """
    final_relationships = []

    if product:
        demisto.debug(f"Creating a relationship to {product}")
        final_relationships.append(create_relationship(indicator, product.capitalize(), "Software", relation_type="related-to"))

    for relationship in relationships:
        demisto.debug(f"Creating a new relationship to {relationship['value']} ({relationship['type']})")

        if relationship["type"] in ("Attack Pattern", "CVE", "Tool"):
            final_relationships.append(create_relationship(indicator,
                                                           relationship["value"],
                                                           relationship["type"],
                                                           relation_type="detects"))

    return_results(CommandResults(readable_output=f'Created A new Sigma Rule indicator:\n{indicator}',
                                  relationships=final_relationships))


def create_relationship(indicator_value: str, entity_b: str, entity_b_type: str, relation_type: str) -> EntityRelationship | None:
    """
    Creates a relationship in XSOAR between the Sigma rule indicator and the product.

    Args:
        indicator_value (str): The value of the Sigma rule indicator.
        entity_b (str): the value of entity b for the relationship.
        entity_b_type (str): entity b indicator type.
        relation_type (str): the type of the relationship (for example - "related-to").
    """
    try:
        relationship = EntityRelationship(
            entity_a=indicator_value,
            entity_a_type="Sigma Rule Indicator",
            name=relation_type,
            entity_b=entity_b,
            entity_b_type=entity_b_type
        )

    except Exception as e:
        demisto.debug(f"Failed to create relationship: {str(e)}")

    return relationship


def parse_detection_field(rule: SigmaRule) -> list:
    """
    Parses the detection field from the Sigma rule and maps it into a grid field.

    Args:
        rule (SigmaRule): The parsed Sigma rule.

    Returns:
        list: A list of dictionaries representing the detection grid.
    """
    grid = []
    row = {}

    def build_row(selection, data):
        row['selection'] = selection
        row['key'] = data.field or ''
        row['modifiers'] = ','.join([reverse_modifier_mapping[modifier.__name__] for modifier in data.modifiers])
        row['values'] = '\n'.join([f'({index}){value.to_plain()}' for index, value in enumerate(data.original_value, 1)])
        return row

    for selection, value in rule.detection.detections.items():
        for fields in value.detection_items:

            try:
                for field in fields.detection_items:
                    row = build_row(selection, field)
                    grid.append(row)
                    row = {}

            except AttributeError:
                row = build_row(selection, fields)
                grid.append(row)
                row = {}

    return grid


def parse_tags(tags: list) -> tuple[list[dict[str, str]], list[str], str]:
    relationships = []
    processed_tags = []
    tlp = 'CLEAR'

    for tag in tags.copy():
        if tag.namespace == "attack" and re.match(r"[ts]\d{4}", tag.name):

            if tag.name.lower().startswith("t"):
                indicator_type = "Attack Pattern"
                demisto.debug(f'Searching for the technique {tag.name} in TIM')
                mitre_name = get_mitre_technique_name(tag.name, indicator_type)
            else:
                indicator_type = "Tool"
                demisto.debug(f'Searching for the tool {tag.name} in TIM')
                mitre_name = get_mitre_technique_name(tag.name, indicator_type)

            if mitre_name:
                relationships.append({"value": mitre_name, "type": indicator_type})
                processed_tags.append(f'{tag.name.upper()} - {mitre_name}')

            else:
                processed_tags.append(f'{tag.name.upper()}')

        elif tag.namespace == 'attack':
            processed_tags.append(tag.name.replace("_", " ").replace("-", " ").title())

        elif tag.namespace == 'cve':
            demisto.debug(f'Found a CVE tag - {tag}')
            cve = tag.name.replace(".", "-").upper()

            if not cve.startswith('CVE-'):
                cve = f'CVE-{cve}'

            relationships.append({"value": cve, "type": "CVE"})
            processed_tags.append(cve)

        elif tag.namespace == 'tlp':
            tlp = tag.name.upper()

    return relationships, processed_tags, tlp


def parse_and_create_indicator(rule: SigmaRule, raw_rule: str) -> dict[str, Any]:
    """
    Parses the Sigma rule dictionary and creates an indicator in XSOAR.

    Args:
        rule (SigmaRule): The Sigma rule parsed.
        raw_rule (str): The rule in its raw YAML form.
    """

    # Create fields mapping
    indicator = {
        "type": "Sigma Rule",
        "value": rule.title,
        "creationdate": f'{rule.date}',
        "sigmaruleid": f'{rule.id}',
        "sigmarulestatus": rule.status.name,
        "author": rule.author,
        "sigmarulelevel": rule.level.name,
        "description": rule.description,
        "category": rule.logsource.category,
        "product": rule.logsource.product,
        "service": rule.logsource.service,
        "sigmaruleraw": raw_rule,
        "sigmacondition": [{"condition": condition} for condition in rule.detection.condition],
        "sigmadetection": parse_detection_field(rule),
        "sigmafalsepositives": [{"reason": fp} for fp in rule.falsepositives],
        "publications": [{"link": ref,
                          "source": "Sigma Rule",
                          "title": rule.title,
                          "date": f'{rule.date}'} for ref in rule.references]
    }

    if hasattr(rule.logsource, "custom_attributes"):
        indicator["definition"] = rule.logsource.custom_attributes["definition"]

    if rule.custom_attributes:
        indicator["sigmarulelicense"] = rule.custom_attributes.get("license", None)

    relationships, tags, tlp = parse_tags(rule.tags)
    indicator["tags"] = tags
    indicator["tlp"] = tlp

    if indicator["sigmarulelevel"].lower() in ("high", "critical"):
        indicator["verdict"] = "Malicious"

    indicator = {key: value for key, value in indicator.items() if value is not None}

    return {"indicator": indicator, "relationships": relationships}


def main() -> None:
    """
    Main function that handles the Sigma rule import process and creates indicators and relationships in XSOAR.
    """
    indicators = []

    try:
        # Get the arguments
        args = demisto.args()
        sigma_rule_str = args.get("sigma_rule_str", "")
        entry_id = args.get("entry_id", "")
        create_indicators = argToBoolean(args.get("create_indicators", "True"))

        # Check if both arguments are empty
        if not sigma_rule_str and not entry_id:
            return_error("Either 'sigma_rule_str' or 'entry_id' must be provided.")

        if entry_id:
            # Get the file contents using entry_id
            res = demisto.getFilePath(entry_id)
            if not res:
                return_error(f"File entry {entry_id} not found")
            file_path = res['path']
            with open(file_path) as file:
                sigma_rule_str = file.read()

        # Parse the sigma rule
        sigma_rule = SigmaRule.from_yaml(sigma_rule_str)

        indicators.append(parse_and_create_indicator(sigma_rule, sigma_rule_str))

        if create_indicators:
            for indicator in indicators:
                xsoar_indicator = indicator["indicator"]
                execute_command("createNewIndicator", xsoar_indicator)
                create_indicator_relationships(xsoar_indicator["value"],
                                               xsoar_indicator["product"],
                                               indicator["relationships"])

        else:
            for indicator in indicators:
                return_results(f'{indicator["indicator"]}')

    except SigmaError as e:
        return_error(f"Failed to parse Sigma rule: {str(e)}")

    except Exception as e:
        return_error(f"Failed to import Sigma rule: {str(e)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()

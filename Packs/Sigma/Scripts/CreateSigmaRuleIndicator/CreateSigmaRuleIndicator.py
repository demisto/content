import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import re

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError


def get_mitre_technique_name(mitre_id: str) -> str:
    """
    Searches XSOAR TIM for an 'Attack Pattern' indicator matching the given MITRE ID and returns the indicator value.

    Args:
        mitre_id (str): The MITRE ATT&CK ID to search for (e.g., T1562).

    Returns:
        str: The indicator value if found, else an empty string.
    """
    try:
        query = f'type:"Attack Pattern" and {mitre_id}'
        demisto.debug(f'Querying for {query} in TIM')
        
        response = demisto.executeCommand("SearchIndicator", {"query": query})
        
        if is_error(response):
            demisto.debug(f"Failed to execute findIndicators command: {get_error(response)}")
            return ""

        indicator = response[0].get("Contents", [{}])[0].get("value", "")
        demisto.debug(f'Found the indicator - {indicator}')
        
        return indicator
    
    except Exception as e:
        demisto.debug(f"Error searching for Attack Pattern indicator: {str(e)}")
        return ""


def create_indicator_relationships(indicator, product, techniques, cves) -> None:
    # Create the relationship if product is available
    
    relationships = []
    
    if product:
        relationships.append(create_relationship(indicator, product.capitalize(), "Software"))
    
    for technique in techniques:
        relationships.append(create_relationship(indicator, technique, "Attack Pattern"))
    
    for cve in cves:
        relationships.append(create_relationship(indicator, cve, "CVE"))
    
    return_results(CommandResults(readable_output=f'Created A new Sigma Rule indicator:\n{indicator}',
                                  relationships=relationships))


def create_relationship(indicator_value: str, entity_b: str, entity_b_type: str) -> EntityRelationship|None:
    """
    Creates a relationship in XSOAR between the Sigma rule indicator and the product.

    Args:
        indicator_value (str): The value of the Sigma rule indicator.
        product (str): The product name from the Sigma rule, which will be capitalized.
    """
    try:
        relationship = EntityRelationship(
            entity_a = indicator_value,
            entity_a_type = "Sigma Rule Indicator",
            name = "related-to",
            entity_b = entity_b,
            entity_b_type = entity_b_type
        )
        
        return relationship
        
    except Exception as e:
        demisto.debug(f"Failed to create relationship: {str(e)}")


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
        if key == 'condition':
            continue
        
        if isinstance(value, str):
            value = [value]
            
        if isinstance(value, list):
            formatted_values = "\n".join([f"({i+1}) {v}" for i, v in enumerate(value)])
            modifiers = key.split("|")[1:]
            detection_grid.append({
                "selection": key,
                "key": "",
                "modifiers": ",".join(modifiers),
                "values": formatted_values
            })
        
        elif isinstance(value, dict):
            for sub_key, sub_value in value.items():
                modifiers = sub_key.split("|")[1:]
                sub_key = sub_key.split("|")[0]
            
                if isinstance(sub_value, list):
                    formatted_values = "\n".join([f"({i+1}) {v}" for i, v in enumerate(sub_value)])
            
                else:
                    formatted_values = f"(1) {sub_value}"
            
                detection_grid.append({
                    "selection": key,
                    "key": sub_key,
                    "modifiers": ",".join(modifiers),
                    "values": formatted_values
                })
    
    return detection_grid


def parse_tags(tags: list) -> tuple[list[str], list[str], list[str]]:
    techniques = []
    cves = []
    
    for tag in tags.copy():
        if re.match(r"attack.t\d{4}", tag):
            tags.remove(tag)
            mitre_id = tag.replace("attack.", "")  # Get only the technique id
            demisto.debug(f'Searching for the technique {mitre_id} in TIM')
            mitre_name = get_mitre_technique_name(mitre_id)
            
            if mitre_name:
                techniques.append(mitre_name)
                tags.append(f'{mitre_id.upper()} - {mitre_name}')
            
            else:
                tags.append(f'{mitre_id.upper()}')
        
        elif tag.startswith('attack.'):
            tags.remove(tag)
            tags.append(tag.replace('attack.', '').replace('-', ' ').title())
        
        elif re.match(r"cve[-.]\d{4}", tag):
            demisto.debug(f'Found a CVE tag - {tag}')
            cve = tag.replace(".", "-").upper()
            cves.append(cve)
            tags.append(cve)
    
    return techniques, cves, tags


def parse_and_create_indicator(rule_dict: dict) -> None:
    """
    Parses the Sigma rule dictionary and creates an indicator in XSOAR.

    Args:
        rule_dict (dict): The Sigma rule dictionary.
    """
    
    # Create fields mapping
    indicator = {
        "type": "Sigma Rule",
        "value": rule_dict.get("title", ""),
        "sigmaruleid": rule_dict.get("id", ""),
        "sigmarulestatus": rule_dict.get("status", ""),
        "author": rule_dict.get("author", ""),
        "sigmarulelevel": rule_dict.get("level", ""),
        "sigmarulelicense": rule_dict.get("license", ""),
        "description": rule_dict.get("description", ""),
        "category": rule_dict.get("logsource", {}).get("category", ""),
        "product": rule_dict.get("logsource", {}).get("product", ""),
        "service": rule_dict.get("logsource", {}).get("service", ""),
        "definition": rule_dict.get("logsource", {}).get("definition", ""),
        "sigmaruleraw": json.dumps(rule_dict),
        "sigmacondition": [{"condition": rule_dict.get("detection",{}).get("condition", "")}],
        "tags": rule_dict["tags"],
        "sigmadetection": parse_detection_field(rule_dict.get("detection", {})),
        "sigmafalsepositives": [{"reason": fp} for fp in rule_dict.get("falsepositives", [])],
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
    techniques, cves, tags = parse_tags(rule_dict["tags"])
    indicator["tags"] = tags
    
    # Create the indicator in XSOAR
    demisto.executeCommand("createNewIndicator", indicator)
    create_indicator_relationships(indicator["value"], indicator["product"], techniques, cves)


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
            sigma_collection = SigmaCollection.from_yaml(sigma_rule_str)

        except SigmaError as e:
            return_error(f"Failed to parse Sigma rule: {str(e)}")
            return

        for rule in sigma_collection.rules:
            rule_dict = rule.to_dict()
            parse_and_create_indicator(rule_dict)

    except Exception as e:
        return_error(f"Failed to import Sigma rule: {str(e)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

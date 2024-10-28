import demistomock as demisto
from CommonServerPython import *

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

def get_mitre_technique_name(mitre_id: str, indicator_type: str) -> dict[str, str]:
    """
    Searches XSOAR TIM for an 'Attack Pattern' indicator matching the given MITRE ID and returns the indicator value.

    Args:
        mitre_id (str): The MITRE ATT&CK ID to search for (e.g., T1562).
        indicator_type (str): The XSOAR indicator type (e.g. Attack Pattern)

    Returns:
        str: The indicator value if found, else an empty string.
    """
    try:
        technique_names = {}
        query = f'mitreid:{mitre_id}'
        demisto.debug(f'Querying for {query} in TIM')

        success, response = execute_command(command="SearchIndicator",
                                            args={"query": query, "add_fields_to_context": "mitreid"},
                                            fail_on_error=False)

        if not success:
            demisto.debug(f"Failed to execute findIndicators command: {get_error(response)}")
            return {}

        if response:
            demisto.debug(f"Search indicators response: {response}")
            for indicator in response:
                if isinstance(indicator, str):
                    indicator = json.loads(indicator)

                technique_names[indicator["mitreid"]] = indicator["value"]

        return technique_names

    except Exception as e:
        demisto.debug(f"Error searching for Attack Pattern indicator: {str(e)}")
        return {}


def get_mitre_results(items):
    return execute_command('mitre-get-indicator-name', {'attack_ids': items})


def is_valid_attack_pattern(items) -> list:
    mitre_ids = items.upper().split(",")
    results = []
    techniques = get_mitre_technique_name(mitre_id=",".join(mitre_ids), indicator_type="Attack Pattern")
    for mitre_id in mitre_ids:
        if mitre_id not in techniques:
            demisto.debug(f"Invalid MITRE ID: {mitre_id}")
            results.append("")
        else:
            results.append(techniques[mitre_id])

    return results


def main():
    the_input = demisto.args().get('input')

    entries_list = is_valid_attack_pattern(the_input)

    if entries_list:
        return_results(entries_list)
    else:
        return_results([])

if __name__ in ("__builtin__", "builtins"):
    main()

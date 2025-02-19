import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_mitre_technique_name(mitre_id: str) -> dict[str, str]:
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
        query = f'mitreid:({mitre_id}) and type:(Tactic "Attack Pattern")'
        demisto.debug(f'Querying for {query} in TIM')

        success, response = execute_command(command="SearchIndicator",
                                            args={"query": query, "add_fields_to_context": "mitreid"},
                                            fail_on_error=False)

        if not success:
            demisto.debug(f"Failed to execute findIndicators command: {get_error(response)}")
            return {}

        if response and isinstance(response, list):
            demisto.debug(f"Search indicators response: {response}")
            for indicator in response:
                if isinstance(indicator, str):
                    indicator = json.loads(indicator)

                technique_names[indicator["mitreid"]] = indicator["value"]

        else:
            success, response = execute_command(command="IsIntegrationAvailable",
                                                args={"brandname": "MITRE ATT&CK v2"},
                                                fail_on_error=False)

            if isinstance(response, str) and response.lower() == "no":
                demisto.debug("Please set an instance of MITRE Att&ck Feed.")

        return technique_names

    except Exception as e:
        demisto.debug(f"Error searching for Attack Pattern indicator: {str(e)}")
        return {}


def is_valid_attack_pattern(items) -> list:
    mitre_ids = argToList(items)
    results = []
    techniques = get_mitre_technique_name(mitre_id=" ".join(mitre_ids))
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

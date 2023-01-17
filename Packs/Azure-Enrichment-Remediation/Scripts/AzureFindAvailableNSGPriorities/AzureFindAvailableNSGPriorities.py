import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def find_available_priorities(
    target_rule_priority: int,
    number_of_available_priorities_to_retrieve: int,
    list_of_priorities_from_rules: list,
) -> list:

    if not target_rule_priority:
        raise ValueError("target_rule_priority not specified.")
    elif target_rule_priority <= 100:
        raise ValueError("target_rule_priority must not be 100 or less.")
    elif target_rule_priority >= 4096:
        raise ValueError("target_rule_priority must not be 4096 or more.")

    if not number_of_available_priorities_to_retrieve:
        raise ValueError("number_of_available_priorities_to_retrieve not specified.")
    elif number_of_available_priorities_to_retrieve > 5 or number_of_available_priorities_to_retrieve <= 0:
        raise ValueError(
            "number_of_available_priorities_to_retrieve cannot be 0 or less, or more than 5. Please use a lower number."
        )

    if not list_of_priorities_from_rules:
        raise ValueError("list_of_priorities_from_rules not specified.")
    if isinstance(list_of_priorities_from_rules, int):
        list_of_priorities_from_rules = [list_of_priorities_from_rules]
    if not isinstance(list_of_priorities_from_rules, list):
        raise ValueError("list_of_priorities_from_rules must be a list.")
    elif len(list_of_priorities_from_rules) > 999:
        raise ValueError(
            "list_of_priorities_from_rules does not support list over 999 entries, please reduce the list."
        )

    list_of_numbers = list_of_priorities_from_rules
    target_number = target_rule_priority

    not_in_list = set(range(100, target_number)).difference(set(list_of_numbers))
    closest_numbers = sorted(not_in_list, key=lambda entry: abs(entry - target_number))[
        :number_of_available_priorities_to_retrieve
    ]

    if not closest_numbers:
        raise ValueError("No available priorities found.")

    return closest_numbers


def main():
    try:
        target_rule_priority = int(demisto.args().get("target_rule_priority"))
        number_of_available_priorities_to_retrieve = int(
            demisto.args().get("number_of_available_priorities_to_retrieve")
        )
        list_of_priorities_from_rules = demisto.args().get(
            "list_of_priorities_from_rules"
        )

        closest_numbers = find_available_priorities(
            target_rule_priority,
            number_of_available_priorities_to_retrieve,
            list_of_priorities_from_rules,
        )

        markdown = tableToMarkdown(
            "Available Azure NSG Priorities", closest_numbers, headers=["priorities"]
        )

        results = CommandResults(
            outputs_prefix="AvailableAzureNSGPriorities",
            readable_output=markdown,
            outputs=closest_numbers,
        )

        return_results(results)

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f"Failed to execute AzureFindAvailableNSGPriorities. Error: {str(ex)}"
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

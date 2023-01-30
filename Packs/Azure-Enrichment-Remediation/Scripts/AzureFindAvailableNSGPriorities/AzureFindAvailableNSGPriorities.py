import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def find_available_priorities(
    target_rule_priority: int,
    number_of_available_priorities_to_retrieve: int,
    list_of_priorities_from_rules: list,
) -> list:
    """This function gathers the below arguments to retrieve a list of available priorities
    from an Azure NSG that can be used to add rules to.

    Args:
        target_rule_priority (int): The priority of the rule you want to find available priorities before.
        number_of_available_priorities_to_retrieve (int): Number of available priorities to find.
        list_of_priorities_from_rules (list): List of existing rule priorities.

    Raises:
        ValueError: if target_rule_priority not specified.
        ValueError: if target_rule_priority is 100 or less.
        ValueError: if target_rule_priority is 4096 or more.
        ValueError: if number_of_available_priorities_to_retrieve not specified.
        ValueError: if number_of_available_priorities_to_retrieve is 0 or less, or more than 5.
        ValueError: if list_of_priorities_from_rules is not specified.
        ValueError: if list_of_priorities_from_rules is not a list.
        ValueError: if list_of_priorities_from_rules is over 999 entries.
        ValueError: if available priorities are not found.

    Returns:
        list: a number of available priorities before the offending rules' priority (target_rule_priority).
    """

    list_of_priorities_from_rules = validate_input(
        target_rule_priority,
        number_of_available_priorities_to_retrieve,
        list_of_priorities_from_rules,
    )

    not_in_list = set(range(100, target_rule_priority)).difference(
        set(list_of_priorities_from_rules)
    )
    closest_numbers = sorted(
        not_in_list, key=lambda entry: abs(entry - target_rule_priority)
    )[:number_of_available_priorities_to_retrieve]

    if (
        not closest_numbers
        or len(closest_numbers) != number_of_available_priorities_to_retrieve
    ):
        raise ValueError("Available priorities not found.")

    return closest_numbers


def validate_input(
    target_rule_priority: int,
    number_of_available_priorities_to_retrieve: int,
    list_of_priorities_from_rules: list,
):
    if not target_rule_priority:
        raise ValueError("target_rule_priority not specified.")
    elif target_rule_priority <= 100:
        raise ValueError("target_rule_priority must not be 100 or less.")
    elif target_rule_priority >= 4096:
        raise ValueError("target_rule_priority must not be 4096 or more.")

    if not number_of_available_priorities_to_retrieve:
        raise ValueError("number_of_available_priorities_to_retrieve not specified.")
    elif (
        number_of_available_priorities_to_retrieve > 5
        or number_of_available_priorities_to_retrieve <= 0
    ):
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

    return list_of_priorities_from_rules


def main():
    try:
        args = demisto.args()

        target_rule_priority = int(args.get("target_rule_priority"))
        number_of_available_priorities_to_retrieve = int(
            args.get("number_of_available_priorities_to_retrieve")
        )
        list_of_priorities_from_rules = argToList(
            args.get("list_of_priorities_from_rules")
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

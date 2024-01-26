import json
from typing import Any
from CommonServerPython import *
import demistomock as demisto


def get_slack_block_builder_entry(entries: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
    """
    Retrieves the entry which contains the SlackBlockBuilder response.

    Args:
    entries (List[Dict[str, Any]]): A list of entries from the war room.

    Returns:
    Dict[str, Any]: The last entry that matches the criteria or None if not found.
    """
    entries.reverse()
    for entry in entries:
        contents = entry.get('Contents', '')
        if 'xsoar-button-submit' in contents:
            return entry
    return None


def parse_entry(entry: dict[str, Any]) -> None:
    """
    Parses the entry content and returns the results.

    Args:
    entry (Dict[str, Any]): The entry to be parsed.

    Raises:
    json.JSONDecodeError: If the entry contents are not in valid JSON format.
    """
    try:
        json_content = json.loads(entry['Contents'])
        return_results({
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": json_content,
            "HumanReadable": "Successfully parsed the SlackBlockBuilder response.",
            "EntryContext": {"SlackBlockState": json_content}
        })
    except json.JSONDecodeError:
        return_error(f"The response is not a valid JSON format. Received the following response: {entry['Contents']}")


def main() -> None:
    """
    Main function to process the war room entries.
    """
    try:
        entries = demisto.executeCommand("getEntries", {})
        if entries and isinstance(entries, list) and entries:
            last_entry = get_slack_block_builder_entry(entries)
            if last_entry:
                parse_entry(last_entry)
            else:
                return_error("The response was not found.")
        else:
            return_error("No entries found.")
    except Exception as e:
        return_error(f"An error occurred: {str(e)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

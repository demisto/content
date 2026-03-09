"""GetListContent Automation/Transformer for Cortex XSOAR (aka Demisto)
This Automation returns the content of the List with the given name.
If type is JSON, the content of the list will be parsed as a JSON object
"""

from typing import Any
import traceback
import demistomock as demisto
from CommonServerPython import *  # noqa: F401 # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa: F401

""" STANDALONE FUNCTION """


def get_list_content_internal(list_name: str) -> str | None:
    content = None
    lists = json.loads(demisto.internalHttpRequest("GET", "/lists/").get("body", {}))
    for list_entry in lists:
        if list_entry["id"] == list_name:
            content = list_entry["data"]
            break

    return content


""" COMMAND FUNCTION """


def get_list_content(list_name: str, return_type: str) -> Any | None:
    list_data = get_list_content_internal(list_name)

    if not list_data:
        return None

    if return_type == "string":
        list_data = str(list_data)
    elif return_type == "json":
        list_data = json.loads(list_data)
    else:
        pass

    return list_data


def get_list_content_command(args: dict) -> Any | None:
    list_name = args.get("value")
    return_type = args.get("type", "string")
    if not list_name:
        raise DemistoException("Value must not be empty")

    content = get_list_content(list_name, return_type)
    return content


""" MAIN FUNCTION """


def main():
    try:
        return_results(get_list_content_command(demisto.args()))

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute GetListContent. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

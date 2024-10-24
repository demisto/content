import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Any
import traceback


def remove_block_list_from_xsoar() -> Any:
    """
    Removes a block list from XSOAR by deleting a specified list.

    This function fetches the list name from the arguments passed in the command
    and sends a request to the XSOAR API to delete the list.

    Args:
        None: The function uses demisto.args() to obtain the required parameters.

    Returns:
        res (Any): The response from the XSOAR API after attempting to delete the list.
    """
    listName = demisto.args().get("list_name")
    body = {"id": listName}
    res = demisto.executeCommand("demisto-api-post", {"uri": "/lists/delete", "body": body})
    print(res)
    return res


''' MAIN FUNCTION '''


def main():  # pragma: no cover
    """
    The main function for the script.

    It calls the `remove_block_list_from_xsoar()` function to remove a block list.
    If an error occurs, it logs the error and returns an appropriate message.
    """
    try:
        remove_block_list_from_xsoar()
    except Exception as excep:
        demisto.error(traceback.format_exc())  # Print the traceback for debugging
        return_error(f'Failed to execute DSPMRemoveSlackBlockList. Error: {str(excep)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()

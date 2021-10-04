import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback

''' STANDALONE FUNCTION '''


# Get Unusual Activity Group name from the list.
def get_unusual_activity_group_sta(args: Dict[str, Any]) -> CommandResults:

    list_name = args.get('list_name')
    original_result = demisto.executeCommand("getList", {"listName": list_name})[0]

    return CommandResults(
        readable_output=f'## {original_result["Contents"]}',
        outputs=original_result["Contents"],
        outputs_prefix='STA.GROUP',
        outputs_key_field=None
    )


''' MAIN FUNCTION '''


def main():
    """ main function, parses args. """

    try:
        return_results(get_unusual_activity_group_sta(demisto.args()))

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute STAFetchListContent script. Error: {str(ex)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

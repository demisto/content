import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' MAIN FUNCTION '''


def main():
    try:
        ids = demisto.args().get('ids')
        res = demisto.executeCommand("deleteRelationships", {'relationshipsIDsKey': ids})
        if is_error(res[0]):
            raise Exception("Error in DeleteIndicatorRelationships command - {}".format(res[0]["Contents"]))
        hr = f"The relationships {str(ids)} were deleted successfully."
        return_results(CommandResults(readable_output=hr))
    except Exception as ex:
        return_error(f'Failed to execute DeleteIndicatorRelationships. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

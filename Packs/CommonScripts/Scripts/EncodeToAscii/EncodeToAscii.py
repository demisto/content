import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' MAIN FUNCTION '''


def main():
    # Grab 'data' from Demisto Arguments
    data = demisto.args()['data']

    # Encode the data, ignoring characters
    try:
        encoded_data = data.encode('ascii', 'ignore').decode("utf-8")
    except Exception as e:
        return_error(f'There was an error encoding the data.\nError:\n{str(e)}')

    # Output the data and add results to war room
    return_results(CommandResults(
        readable_output=f'Success: {encoded_data}',
        outputs_prefix='asciiencode.encoded',
        outputs=encoded_data))


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

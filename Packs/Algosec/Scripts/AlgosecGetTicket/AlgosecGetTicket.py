import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        resp = demisto.executeCommand("algosec-get-ticket", demisto.args())

        if isError(resp[0]):
            return CommandResults(raw_response=resp)
        else:
            data = demisto.get(resp[0], "Contents.getTicketResponse")
            if data:
                raiseTable(data, 'ticket')
                for key in data:
                    if isinstance(data[key], dict):
                        if '-xmlns' in data[key]:
                            del data[key]['-xmlns']
                        data[key] = zoomField(data[key], '#text')
                data = flattenRow(data)
                return CommandResults(content_format=formats["table"],
                                      entry_type=entryTypes["note"],
                                      raw_response=data)
            else:
                return "No results."
    except Exception as e:
        err_msg = f'Encountered an error while running the script: [{e}]'
        return_error(err_msg, error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

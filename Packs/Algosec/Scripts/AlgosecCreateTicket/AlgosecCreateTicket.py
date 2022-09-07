import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def algosec_create_ticket():
    resp = demisto.executeCommand("algosec-create-ticket", demisto.args())

    if isError(resp[0]):
        return resp
    else:
        data = demisto.get(resp[0], "Contents.createTicketResponse")
        if data:
            data = data if isinstance(data, list) else [data]
            for item in data:
                for row in item:
                    if '#text' in item[row]:
                        item[row] = item[row]['#text']

            data = flattenTable(data)
            return {"ContentsFormat": formats["table"], "Type": entryTypes["note"], "Contents": data}
        else:
            return "No results."


def main():  # pragma: no cover
    try:
        return_results(algosec_create_ticket())
    except Exception as e:
        err_msg = f'Encountered an error while running the script: [{e}]'
        return_error(err_msg, error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

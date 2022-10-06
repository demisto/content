import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def netwitness_im_get_components():
    resp = demisto.executeCommand("netwitness-im-get-components", demisto.args())

    if isError(resp[0]):
        result = resp
    else:
        data = demisto.get(resp[0], "Contents.components")
        if data:
            data = flattenTable(data)
            result = {"ContentsFormat": formats["table"], "Type": entryTypes["note"], "Contents": data}
        else:
            result = "No results."
    return_results(result)


def main():  # pragma: no cover
    try:
        netwitness_im_get_components()
    except Exception as e:
        err_msg = f'Encountered an error while running the script: [{e}]'
        return_error(err_msg, error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

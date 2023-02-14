import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        listname = demisto.args()['list']
        context = demisto.context()
        res = demisto.executeCommand('demisto-api-post', {
            "uri": '/lists/save',
            "body": {
                'name': listname,
                'data': json.dumps(context),
                'type': "json"
            }
        })[0]['Contents']
        # If error saving, set the list
        if "Script failed to run" in res:
            demisto.executeCommand("setList", {
                'listName': listname,
                'listData': json.dumps(context)
            })
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"UnitTestSaveContextList: Exception failed to execute. Error: {str(ex)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

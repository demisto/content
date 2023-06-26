import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        listName = demisto.args()['list']
        results = demisto.executeCommand("getList", {'listName': listName})[0]['Contents']
        if "Item not found" not in results:
            fields = json.loads(results)
            if fields:
                # Set each field
                for key, val in fields.items():
                    if key != "name":
                        demisto.executeCommand("setIncident", {key: val})
        else:
            raise DemistoException(f"UnitTestLoadFieldsList: list '{listName}' not found")
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"UnitTestLoadFieldsList: Exception failed to execute. Error: {str(ex)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

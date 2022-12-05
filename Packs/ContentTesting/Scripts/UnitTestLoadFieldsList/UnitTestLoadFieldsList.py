import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        listname = demisto.args()['list']
        results = demisto.executeCommand("getList", {'listName': listname})[0]['Contents']
        if "Item not found" not in results:
            fields = json.loads(results)
            for key, val in fields.items():
                if key != "name":
                    demisto.executeCommand("setIncident", {key: val})
        else:
            raise DemistoException(f"UnitTestLoadFieldsList: list '{listname}' not found")
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"UnitTestLoadFieldsList: Exception failed to execute. Error: {str(ex)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

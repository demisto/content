import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        listName = demisto.args()['list']
        results = demisto.executeCommand("getList", {'listName': listName})[0]['Contents']
        if "Item not found" not in results:
            fields = json.loads(results)
            # Set context
            for key, val in fields.items():
                demisto.executeCommand("Set", {"key": key, "value": val})
        else:
            raise DemistoException(f"UnitTestLoadContextList: list '{listName}' not found")
    except Exception as ex:
        raise ex


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

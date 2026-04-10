import demistomock as demisto  # noqa
from CommonServerPython import *  # noqa


def main():
    try:
        result = demisto.executeCommand("code42-file-events-table", args={"include": "incident"})
        table = result[0]["HumanReadable"]
        entry = {
            "Type": entryTypes["note"],
            "Contents": table,
            "ContentsFormat": formats["markdown"],
        }
        return_results(entry)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute BaseScript. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

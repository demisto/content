import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def LoadList(listname: str) -> dict:
    results = demisto.executeCommand("getList", {'listName': listname})[0]['Contents']
    fields = {}
    if "Item not found" not in results and (results is not None or results != ""):
        if results != "":
            fields = json.loads(results)
    return (fields)


def main():
    try:
        metricslist = demisto.args()["listname"]
        metrics = LoadList(metricslist)
        if metrics:
            return_results("# " + json.dumps(int(metrics.get("YEAR", ""))))
        else:
            return_results("# No Data for Last Year")
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"XMetricsYear - exception failed to execute. Error: {str(ex)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

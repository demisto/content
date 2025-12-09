import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import traceback


""" MAIN FUNCTION """


def get_index(json_data, array_val):
    element_index = json_data.index(array_val)
    return element_index


def main():
    try:
        json_data = argToList(demisto.args()["value"])
        array_val = demisto.args()["array_value"]
        res = get_index(json_data, array_val)
        demisto.results(res)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute BaseScript. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

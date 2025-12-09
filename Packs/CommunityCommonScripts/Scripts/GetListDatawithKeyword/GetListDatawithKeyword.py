import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import traceback

result_data = []


def get_data(key_word, json_data):
    for i in range(len(json_data)):
        for _key, value in json_data[i].items():
            if key_word in value:
                result_data.append(json_data[i])
                break

    return result_data


""" MAIN FUNCTION """


def main():
    try:
        key_word = demisto.args()["Keyword"]
        json_data = argToList(demisto.args()["value"])
        res = get_data(key_word, json_data)

        md = tableToMarkdown("List Data", res)
        demisto.results(
            {
                "Type": entryTypes["note"],
                "Contents": res,
                "ContentsFormat": formats["json"],
                "HumanReadable": md,
                "ReadableContentsFormat": formats["markdown"],
                "EntryContext": {"ListData": res},
            }
        )
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute BaseScript. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

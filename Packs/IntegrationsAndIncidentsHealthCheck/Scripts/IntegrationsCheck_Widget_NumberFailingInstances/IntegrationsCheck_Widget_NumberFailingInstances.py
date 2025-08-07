import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    list_data = demisto.executeCommand("getList", {"listName": "XSOAR Health - Failed Instance Names"})
    list_contents_attribute = list_data[0].get("Contents", "")
    if "Item not found" in list_contents_attribute:
        list_content = [""]
    else:
        list_content = list(list_contents_attribute.split(","))
    failing_incident_count = len(list_content)

    if list_content == [""]:
        demisto.results(0)

    else:
        demisto.results(failing_incident_count)


if __name__ in ["__main__", "builtin", "builtins"]:
    main()

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    query = demisto.args().get("query")
    size = demisto.args().get("size")

    if size:
        incidents = demisto.executeCommand("SearchIncidentsV2", {"query": query, "size": size})
    else:
        incidents = demisto.executeCommand("SearchIncidentsV2", {"query": query})

    try:
        incidents_data = incidents[0].get("Contents")[0].get("Contents").get("data")
        ids = []

        for item in incidents_data:
            i = item.get("id")
            ids.append(i)

        text_ids = ",".join(ids)
        demisto.executeCommand("core-delete-incidents", {"ids": text_ids})
    except TypeError:
        demisto.results("No incidents to delete according to the query")

    except ValueError as err:
        if "core-delete-incidents" in str(err):
            raise Exception("Please enable Core REST API integration")


if __name__ in ["__main__", "builtin", "builtins"]:
    main()

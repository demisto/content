import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def parse_data(list_json):
    list_table = []

    if list_json and isinstance(list_json, dict):
        list_json = [list_json]

    if isinstance(list_json, list):
        for instance in list_json:
            list_table.append(
                {
                    "Incident Creation Date": instance.get("creationdate", "").split(".")[0].replace("T", " "),
                    "Incident ID": instance.get("incidentid"),
                    "Incident Owner": instance.get("owner"),
                    "Number of Errors": instance.get("numberoferrors"),
                    "Playbook Name": instance.get("playbookname"),
                    "Task ID": instance.get("taskid"),
                    "Task Name": instance.get("taskname"),
                    "Command Name": instance.get("commandname"),
                }
            )

        return {"total": len(list_table), "data": list_table}

    else:
        data = {
            "total": 1,
            "data": [
                {
                    "Incident Creation Date": r"N/A",
                    "Incident ID": r"N/A",
                    "Incident Owner": r"N/A",
                    "Number of Errors": r"N/A",
                    "Playbook Name": r"N/A",
                    "Task ID": r"N/A",
                    "Task Name": r"N/A",
                    "Command Name": r"N/A",
                }
            ],
        }

        return data


def main():
    list_name = "XSOAR Health - Failed Incidents Table"
    list_json = None

    res = demisto.executeCommand("getList", {"listName": list_name})
    if is_error(res):
        demisto.debug(f'Could not load list "{list_name}":\n{get_error(res)}')
    else:
        list_content = res[0].get("Contents", "")
        if list_content:
            list_json = json.loads(list_content)

    data = parse_data(list_json)
    return_results(data)


if __name__ in ["__main__", "builtin", "builtins"]:
    main()

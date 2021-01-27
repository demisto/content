import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def parse_data(list_json):
    list_table = []

    if isinstance(list_json, list):
        for instance in list_json:
            list_table.append({
                "Incident Creation Date": instance.get('creationdate', '').split(".")[0],
                "Incident ID": instance.get('incidentid'),
                "Incident Owner": instance.get('owner'),
                "Number of Errors": instance.get('numberoferrors'),
                "Playbook Name": instance.get('playbookname'),
                "Task ID": instance.get('taskid'),
                "Task Name": instance.get('taskname'),
                "Command Name": instance.get('commandname')
            })

        return {'total': len(list_table), 'data': list_table}

    elif isinstance(list_json, dict):
        list_table.append({
            "Incident Creation Date": list_json.get('creationdate', '').split(".")[0],
            "Incident ID": list_json.get('incidentid'),
            "Incident Owner": list_json.get('owner'),
            "Number of Errors": list_json.get('numberoferrors'),
            "Playbook Name": list_json.get('playbookname'),
            "Task ID": list_json.get('taskid'),
            "Task Name": list_json.get('taskname'),
            "Command Name": list_json.get('commandname')
        })

        return {'total': len(list_table), 'data': list_table}

    else:
        data = {"total": 1, "data": [{
            "Incident Creation Date": "N\A",
            "Incident ID": "N\A",
            "Incident Owner": "N\A",
            "Number of Errors": "N\A",
            "Playbook Name": "N\A",
            "Task ID": "N\A",
            "Task Name": "N\A",
            "Command Name": "N\A"
        }]}

        return data


def main():
    list_data = demisto.executeCommand("getList", {"listName": "XSOAR Health - Failed Incidents Table"})
    list_content = list_data[0].get('Contents', '')

    if list_content:
        list_json = json.loads(list_content)
    else:
        list_json = None

    data = parse_data(list_json)
    demisto.results(data)


if __name__ in ["__main__", "builtin", "builtins"]:
    main()

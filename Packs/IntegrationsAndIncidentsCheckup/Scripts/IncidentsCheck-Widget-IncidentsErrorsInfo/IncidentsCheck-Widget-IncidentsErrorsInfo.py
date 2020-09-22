import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

listData = demisto.executeCommand("getList", {"listName": "XSOAR Health - Failed Incidents Table"})
listContent = listData[0].get('Contents')
listJson = json.loads(listContent)
listTable = []
if isinstance(listJson, list):
    for instance in listJson:
        listTable.append({
            "Incident Creation Date": instance.get('creationdate'),
            "Incident ID": instance.get('incidentid'),
            "Incident Owner": instance.get('owner'),
            "Number of Errors": instance.get('numberoferrors'),
            "Playbook Name": instance.get('playbookname'),
            "Task ID": instance.get('taskid'),
            "Task Name": instance.get('taskname'),
            "Command Name": instance.get('commandname')
        })
    demisto.results({'total': len(listTable), 'data': listTable})

elif isinstance(listJson, dict):
    listTable.append({
        "Incident Creation Date": instance.get('creationdate'),
        "Incident ID": instance.get('incidentid'),
        "Incident Owner": instance.get('owner'),
        "Number of Errors": instance.get('numberoferrors'),
        "Playbook Name": instance.get('playbookname'),
        "Task ID": instance.get('taskid'),
        "Task Name": instance.get('taskname'),
        "Command Name": instance.get('commandname')
    })
    demisto.results({'total': len(listTable), 'data': listTable})

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
    demisto.results(data)

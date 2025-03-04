import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json


"""
Use the ArcherCreateIncidentExample script to create a incident object (applicationId = 75) in Archer.
The script gets the arguments required to create the incident, such as category, summary, and so on.
It creates the JSON object for the request body and call the command archer-create-record with the relevant data.
To add additional fields to the script, execute the command !archer-get-application-fields applicationId=75 to
see the fields for incident object and add it to the script code inside the data dict.
"""


def main():
    summary = demisto.args().get("summary")
    priority = demisto.args().get("priority")
    category = demisto.args().get("category")

    data = {"Incident Summary": summary, "Priority": [priority], "Category": [category]}

    create_record_res = demisto.executeCommand("archer-create-record", {"applicationId": 75, "fieldsToValues": json.dumps(data)})

    return_outputs(create_record_res[0].get("HumanReadable"), create_record_res[0].get("EntryContext"), {})


if __name__ == "__builtin__" or __name__ == "builtins":
    main()

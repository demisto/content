import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json


"""
Use the IvantiHeatCreateIncidentExample script to create a incident object (JSON) in Ivanti Heat.
The script gets the arguments required to create the incident, such as category, summary, and so on.
It creates the JSON object and sets it inside the IvantiHeat.CreateIncidentJSON context path.
To create a incident in Ivanti, execute the script and call the “ivanti-heat-object-create” command where the
fields argument value equals the script output:
!ivanti-heat-object-create object-type=problems fields=${IvantiHeat.CreateIncidentJSON}
To add additional fields to the script, log in to the Ivanti platform and go to:
Settings > Buisness objects > incident > Fields, and add the field name to the data dictionary above.
Then add the new field argument to the script. See the Ivanti documentation for more information on creating object:
*tenant-url*/help/admin/Content/Configure/API/Create-a-Business-Object.htm
"""


def main():
    category = demisto.args().get('category')
    service = demisto.args().get('service')
    owner = demisto.args().get('owner')
    team = demisto.args().get('team')
    summary = demisto.args().get('summary')
    description = demisto.args().get('description')
    customer = demisto.args().get('customer')

    data = {
        "Category": category,
        "Service": service,
        "Owner": owner,
        "OwnerTeam": team,
        "Subject": summary,
        "Symptom": description,
        "ProfileLink": customer
    }
    return_outputs(json.dumps(data, indent=4), {'IvantiHeat.CreateIncidentJSON': json.dumps(data)}, data)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()

import json

import demistomock as demisto
from CommonServerPython import *


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

import json

import demistomock as demisto
from CommonServerPython import *

PRIORITY_DICT = {'Low': 471, 'Medium': 472, 'High': 473}
CATEGORY_DICT = {'Fraud': 1161, 'IT': 1162, 'Physical': 1163, 'Threat': 1164}


def main():
    summary = demisto.args().get('summary')
    priority = demisto.args().get('priority')
    category = demisto.args().get('category')

    priority = PRIORITY_DICT[priority]
    category = CATEGORY_DICT[category]

    data = {
        "Incident Summary": summary,
        "Priority": {"ValuesListIds": [priority]},
        "Category": {"ValuesListIds": [category]}
    }

    create_record_res = demisto.executeCommand(
        "archer-create-record", {'applicationId': 75, 'fieldsToValues': json.dumps(data)})

    return_outputs(create_record_res[0].get('HumanReadable'), create_record_res[0].get('EntryContext'), {})


if __name__ == "__builtin__" or __name__ == "builtins":
    main()

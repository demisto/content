import json

import demistomock as demisto
from CommonServerPython import *


def main():
    summary = demisto.args().get('summary')
    priority = demisto.args().get('priority')
    category = demisto.args().get('category')

    data = {
        "Incident Summary": summary,
        "Priority": [priority],
        "Category": [category]
    }

    create_record_res = demisto.executeCommand("archer-create-record",
                                               {'applicationId': 75, 'fieldsToValues': json.dumps(data)})

    return_outputs(create_record_res[0].get('HumanReadable'), create_record_res[0].get('EntryContext'), {})


if __name__ == "__builtin__" or __name__ == "builtins":
    main()

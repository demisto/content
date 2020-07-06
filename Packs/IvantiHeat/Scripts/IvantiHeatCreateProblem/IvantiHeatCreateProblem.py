import json

import demistomock as demisto
from CommonServerPython import *


def main():
    category = demisto.args().get('category')
    owner = demisto.args().get('owner')
    source = demisto.args().get('source')
    status = demisto.args().get('status')
    subject = demisto.args().get('subject')
    description = demisto.args().get('description')

    data = {
        "Category": category,
        "Source": source,
        "Owner": owner,
        "Status": status,
        "Subject": subject,
        "Description": description
    }
    return_outputs(json.dumps(data, indent=4), {'IvantiHeat.CreateProblemJSON': json.dumps(data)}, data)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()

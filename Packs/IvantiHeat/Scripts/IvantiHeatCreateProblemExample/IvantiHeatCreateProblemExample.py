import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json


"""
Use the IvantiHeatCreateProblemExample script to create a problem object (JSON) in Ivanti Heat.
The script gets the arguments required to create the problem, such as category, subject, and so on.
It creates the JSON object and sets it inside the IvantiHeat.CreateProblemJSON context path.
To create a problem in Ivanti, execute the script and call the “ivanti-heat-object-create” command where the
fields argument value equals the script output:
!ivanti-heat-object-create object-type=problems fields=${IvantiHeat.CreateProblemJSON}
To add additional fields to the script, log in to the Ivanti platform and go to:
Settings > Buisness objects > Problem > Fields, and add the field name to the data dictionary above.
Then add the new field argument to the script. See the Ivanti documentation for more information on creating object:
*tenant-url*/help/admin/Content/Configure/API/Create-a-Business-Object.htm
"""


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

import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident_id = demisto.incidents()[0].get('id')
file_name = f"{demisto.args().get('fileName')}.json"
data = demisto.executeCommand("getContext", {"id": incident_id})
demisto.results(fileResult(file_name, json.dumps(data[0].get('Contents', {}).get('context', {}))))

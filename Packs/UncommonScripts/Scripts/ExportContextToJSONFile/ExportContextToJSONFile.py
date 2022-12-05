import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# get the incident id
incident_id = demisto.incident().get('id')

# get the filename
file_name = f"{demisto.args().get('filename')}.json"

# get the data from context and return the file to the war room.
data = demisto.executeCommand("getContext", {"id": incident_id})
demisto.results(fileResult(file_name, json.dumps(data[0].get('Contents', {}).get('context', {}))))

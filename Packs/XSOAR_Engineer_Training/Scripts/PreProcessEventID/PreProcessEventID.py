import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import datetime, timedelta

# Times
now = datetime.now()
end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
start = datetime.strftime((now - timedelta(hours=3)), "%Y-%m-%dT%H:%M:%SZ")

# get incident data, and the event ID
incident = demisto.incident()
eventid = incident.get('CustomFields').get('eventid')
incident_type = incident.get('type')

# check to see if we have duplicates

# Debugging - Run this script in an Incident war room to test
# LOG("STARTING SEARCH")
# LOG(f"QUERY IS: eventid:{eventid} fromdate:{start} todate:{end}")
# LOG.print_log(verbose=True)

# find Incident with the same eventid, from now to 3 hours back
sameIncidents = demisto.executeCommand("getIncidents",
                                       {"query": f"type:{incident_type} and eventid:{eventid} and -category:job", "fromdate": start, "todate": end})

# create Incident by default, if another Incident is found, we'll return False to not create it.
res = True
if not isError(sameIncidents[0]):
    # if found sameIncidents found, add an entry to the war room, and drop this one
    sameIncidentsCount = sameIncidents[0]['Contents']['total']
    if sameIncidentsCount > 0:
        res = False
        otherIncidents = sameIncidents[0]['Contents']['data']
        entries = [{"Contents": f"Duplicate {incident_type} incident dropped from preprocessing: {incident.get('name')}"}]
        demisto.executeCommand("addEntries", {"id": otherIncidents[0]["id"], "entries": json.dumps(entries)})

demisto.results(res)

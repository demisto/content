import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# Post processing script for Splunk Notables
# This is an example script, should work...

# get close reason and notes
notes = demisto.args().get('closeNotes')
reason = demisto.args().get('closeReason')

# get incident details
inc = demisto.incidents()[0]
demisto_id = inc.get('id')
owner = inc.get('owner')

# UPDATE THIS, depending on where you getting the notable id.
splunkid = inc['CustomFields'].get('splunkeventid')

comment = f"XSOAR Incident {demisto_id}: {notes}"
status = 5

demisto.executeCommand("splunk-notable-event-edit", {"eventIDs": splunkid, "comment": comment, "status": status, "owner": owner})

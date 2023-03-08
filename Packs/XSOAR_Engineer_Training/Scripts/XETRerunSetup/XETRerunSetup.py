import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# delete the training setup completed list
delete_list = {"id": "training setup completed"}
demisto.executeCommand("demisto-api-post", {"uri": "/lists/delete", "body": delete_list})
return_results(demisto.executeCommand("setPlaybook", {"name": "XSOAR Engineer Training - Setup"}))

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import time


attachments = demisto.incidents()[0].get("attachment")
files = []
if attachments is not None:
    for attachment in attachments:
        files.append({"path": attachment["path"], "name": attachment["name"]})

    # The logic for finding the incident that we want to drop the new files to should be here
    incident = "123"
    demisto.executeCommand(
        "executeCommandAt", {"command": "CreateFileFromPathObject", "arguments": {"object": files}, "incidents": incident}
    )
    time.sleep(10)
demisto.results(False)

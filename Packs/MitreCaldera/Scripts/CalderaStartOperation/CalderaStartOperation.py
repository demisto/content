import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

demisto.executeCommand("taskComplete", {"id": "mitrecalderadatetimestart"})
command_results = CommandResults(
    readable_output="Starting the Caldera Operation",
    mark_as_note=True
)
return_results(command_results)

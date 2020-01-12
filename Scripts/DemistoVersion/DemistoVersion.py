from CommonServerPython import *

version = get_demisto_version()
return_outputs(tableToMarkdown("Demisto Version", version), {"DemistoVersion": version})

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

version = get_demisto_version()
return_outputs(tableToMarkdown("Demisto Version", version), {"DemistoVersion": version, "Why": "because"})

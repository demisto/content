import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
demisto.results(int(demisto.args().get("value")))

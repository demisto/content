import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

demisto.results(demisto.executeCommand("grr_get_hunts", demisto.args()))

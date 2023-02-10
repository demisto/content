import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

QUERY = "select * from users;"
demisto.results(demisto.executeCommand("OSQueryBasicQuery", {'query': QUERY, 'system': demisto.args()['system']}))

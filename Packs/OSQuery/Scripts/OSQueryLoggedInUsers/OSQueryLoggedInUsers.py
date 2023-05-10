import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

QUERY = "select liu.*, p.name, p.cmdline, p.cwd, p.root from logged_in_users liu, processes p where liu.pid = p.pid;"
demisto.results(demisto.executeCommand("OSQueryBasicQuery", {'query': QUERY, 'system': demisto.args()['system']}))

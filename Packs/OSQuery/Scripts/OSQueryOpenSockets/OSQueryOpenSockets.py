import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

QUERY = "select distinct pid, family, protocol, local_address, local_port, remote_address, remote_port, path " \
        "from process_open_sockets where path <> '' or remote_address <> '';"
demisto.results(demisto.executeCommand("OSQueryBasicQuery", {'query': QUERY, 'system': demisto.args()['system']}))

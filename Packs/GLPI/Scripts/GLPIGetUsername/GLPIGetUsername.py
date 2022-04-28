import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
user_id = demisto.args().get('value')
username = demisto.executeCommand('glpi-get-username', {"id": user_id})[0]['Contents']
demisto.results(str(username))

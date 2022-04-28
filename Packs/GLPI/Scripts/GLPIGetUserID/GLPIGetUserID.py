import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
username = demisto.args().get('value')
user_id = demisto.executeCommand('glpi-get-userid', {"name": username})[0]['Contents']
demisto.results(str(user_id))

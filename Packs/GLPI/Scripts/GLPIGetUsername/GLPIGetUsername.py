import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
user_id = demisto.args().get('value')
demisto.debug('Trying GLPI_USERID : ' + str(user_id))
username = demisto.executeCommand('glpi-get-username', {"id": user_id})[0]['Contents']
demisto.debug('GLPI USERNAME : ' + str(username))
demisto.results(str(username))

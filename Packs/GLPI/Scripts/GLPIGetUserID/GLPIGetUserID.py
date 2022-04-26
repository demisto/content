import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

username = demisto.args().get('value')
demisto.debug('Trying GLPI_USERNAME : ' + str(username))
user_id = demisto.executeCommand('glpi-get-userid', {"name": username})[0]['Contents']
demisto.debug('GLPI ID : ' + str(user_id))
demisto.results(str(user_id))

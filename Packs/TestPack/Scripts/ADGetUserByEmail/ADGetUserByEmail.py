import demistomock as demisto
from CommonServerPython import *

res = demisto.executeCommand('demo-utility-get-user-info', {'email_address': demisto.args()['email_address']})
demisto.results(res)

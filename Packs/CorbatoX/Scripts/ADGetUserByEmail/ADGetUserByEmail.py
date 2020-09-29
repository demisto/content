import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

res = demisto.executeCommand('demo-utility-get-user-info', {'email_address': demisto.args()['email_address']})
demisto.results(res)

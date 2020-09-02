from CommonServerPython import *

result = demisto.executeCommand('pt-get-pdns-details', {'query': demisto.args().get('indicator_value')})

demisto.results(result)

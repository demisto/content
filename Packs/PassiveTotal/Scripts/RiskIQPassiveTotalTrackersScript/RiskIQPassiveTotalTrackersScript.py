from CommonServerPython import *

result = demisto.executeCommand('pt-get-trackers', {'query': demisto.args().get('indicator_value')})

demisto.results(result)

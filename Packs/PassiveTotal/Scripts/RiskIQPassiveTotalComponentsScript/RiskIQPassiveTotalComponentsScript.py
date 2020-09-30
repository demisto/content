from CommonServerPython import *

result = demisto.executeCommand('pt-get-components', {'query': demisto.args().get('indicator_value')})

demisto.results(result)

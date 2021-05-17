import demistomock as demisto
from CommonServerPython import *

res = demisto.executeCommand('ssh', {'cmd': 'cat /var/log/demisto/docker.log', 'using': 'localhost'})
output = 'File: /var/log/demisto/docker.log\n'
output += res[0].get('Contents').get('output')

return_results(output)

import re

import demistomock as demisto
from CommonServerPython import *

file = '/var/log/demisto/server.log'

res = demisto.executeCommand('ssh', {'cmd': f'tail {file}', 'using': 'localhost'})
output = f'File: {file}\n'
output += res[0].get('Contents').get('output')
output = re.sub(r' \(source: .*\)', '', output)

return_results(output)

import re

import demistomock as demisto
from CommonServerPython import *

file = '/var/log/demisto/server.log'

try:
    res = demisto.executeCommand('ssh', {'cmd': f'tail {file}', 'using': 'localhost'})
except ValueError as e:
    demisto.error(str(e))
    return_error('The script could not execute the `ssh` command. Please create an instance of the'
                 '`RemoteAccess` integration and try to run the script again.')
output = f'File: {file}\n'
output += res[0].get('Contents').get('output')
output = re.sub(r' \(source: .*\)', '', output)

return_results(output)

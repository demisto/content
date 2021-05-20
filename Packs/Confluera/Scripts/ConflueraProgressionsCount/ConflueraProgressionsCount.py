from CommonServerPython import *
from CommonServerUserPython import *

# Executes confluera-fetch-progressions command/script
progressions_data = demisto.executeCommand('confluera-fetch-progressions', {'hours': '72'})

prog_count = 0
if progressions_data[1] and progressions_data[1]['Contents']:
    prog_count = len(progressions_data[1]['Contents'])

return_results(prog_count)

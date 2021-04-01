import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re
import json
count_lines = 0
human_readable = []

res = demisto.executeCommand('getFilePath', {'id': demisto.args()['entryID']})

if res[0]['Type'] == entryTypes['error']:
    demisto.results('File not found')
else:
    try:
        with open(res[0]['Contents']['path'], 'r') as f:
            data_line = f.readlines()

            for line in data_line:
                count_lines += 1

                if 'Total' in line:
                    result = re.search("\d+", line)
                    if result:
                        Total = result.group(0)

                # (?<=:).*
                if 'Busy' in line:
                    result = re.search("\d+", line)
                    if result:
                        Busy = result.group(0)

    except UnicodeDecodeError:
        demisto.results("Could not read file")


demisto.executeCommand("setIncident", {
    'workerstotal': Total,
    'workersbusy': Busy
})

from CommonServerPython import *
from CommonServerUserPython import *


# Executes confluera-fetch-detections command/script
detections_data = demisto.executeCommand('confluera-fetch-detections', {'hours': '72'})

det_count = 0

if detections_data[1] and detections_data[1]['Contents']:
    det_count = len(detections_data[1]['Contents'])

return_results(det_count)

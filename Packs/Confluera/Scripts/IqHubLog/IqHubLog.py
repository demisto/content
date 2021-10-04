from CommonServerPython import *
from CommonServerUserPython import *

# Executes confluera-fetch-detections command/script
detections_data = demisto.executeCommand('confluera-fetch-detections', {'hours': '72'})

if detections_data[0] and detections_data[0]['Contents'] and detections_data[0]['Contents']['Detections URL']:
    det_url = detections_data[0]['Contents']['Detections URL']
else:
    det_url = ''

if detections_data[1] and detections_data[1]['Contents']:
    det_count = len(detections_data[1]['Contents'])
else:
    det_count = 0

# Executes confluera-fetch-progressions command/script
progressions_data = demisto.executeCommand('confluera-fetch-progressions', {'hours': '72'})

if progressions_data[0] and progressions_data[0]['Contents'] and progressions_data[0]['Contents']['Progressions URL']:
    prog_url = progressions_data[0]['Contents']['Progressions URL']
else:
    prog_url = ''

if progressions_data[1] and progressions_data[1]['Contents']:
    prog_count = len(progressions_data[1]['Contents'])
else:
    prog_count = 0


data = [
    {
        'Count': 'Detections: ' + str(det_count),
        'URL': det_url
    },
    {
        'Count': 'Progressions:' + str(prog_count),
        'URL': prog_url
    }
]

return_results({
    'total': 2,
    'data': data
})

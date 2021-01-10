from CommonServerPython import *

incident = demisto.incident()
custom_fields = incident.get('CustomFields')
args = demisto.args()
details_type = args.get('type')
type_info = {
    "ship": {
        "title": "Ships",
        "key": "spacexships"
    },
    "rocket": {
        "title": "Rockets",
        "key": "spacexrockets"
    },
    "payload": {
        "title": "Payloads",
        "key": "spacexpayloads"
    },
    "site": {
        "title": "Sites",
        "key": "spacexsites"
    }

}
selected_type: dict = type_info.get(details_type)
title = selected_type['title']
data = custom_fields.get(selected_type['key'])
md = tableToMarkdown(f'{title}', data)
demisto.executeCommand("setIncident", {"spacexfurtherdetails": md})

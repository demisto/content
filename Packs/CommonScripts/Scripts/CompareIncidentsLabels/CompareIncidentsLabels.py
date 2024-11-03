import demistomock as demisto
from CommonServerPython import *

try:
    inc1 = demisto.args().get('incident_id_1')
    inc2 = demisto.args().get('incident_id_2')
    res = demisto.executeCommand("getIncidents", {'id': inc1})

    if any(is_error(entry) for entry in res):
        return_error(f"Unable to fetch incident {inc1}")

    inc1_data = res[0].get('Contents').get('data')

    res = demisto.executeCommand("getIncidents", {'id': inc2})
    if any(is_error(entry) for entry in res):
        return_error(f"Unable to fetch incident {inc2}")

    inc2_data = res[0].get('Contents').get('data')

    if inc1_data is None or inc2_data is None:
        return_error("One of the incidents does not exist.")

    inc1_labels = inc1_data[0].get('labels', [])
    inc2_labels = inc2_data[0].get('labels', [])
    in1not2 = []
    in2not1 = []
    for label in inc1_labels:
        if label not in inc2_labels:
            in1not2.append(label)
    for label in inc2_labels:
        if label not in inc1_labels:
            in2not1.append(label)

    md = tableToMarkdown(f"Labels of incident {inc1} but not of incident {inc2}", in1not2)
    md += "\n" + tableToMarkdown(f"Labels of incident  {inc2} but not of incident {inc1}", in2not1)

    if not in2not1 and not in1not2:
        md = "No different labels."
    return_outputs(md, {}, {})
except Exception as ex:
    return_error(f'An Error occured: {ex}', error=ex)

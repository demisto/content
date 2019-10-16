import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

loc = demisto.get(demisto.args()['indicator'], "CustomFields.geolocation")
err_msg = "No location data was available"

if not loc:
    return_error(err_msg)
try:
    lat, lng = loc.split(',')
except ValueError:
    return_error(err_msg)
demisto.results(
    {'ContentsFormat': formats['json'], 'Type': entryTypes['map'], 'Contents': {"lat": float(lat), "lng": float(lng)}})

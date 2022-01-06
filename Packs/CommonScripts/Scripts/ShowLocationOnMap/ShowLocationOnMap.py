from CommonServerPython import *

loc = demisto.get(demisto.args()['indicator'], "CustomFields.geolocation").strip()
err_msg = "No location data was available"
long_lat_regex = re.compile(
    r'^\s*[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?)\s*([,:])\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)\s*$')
if not loc:
    return_error(err_msg)
if not long_lat_regex.search(loc):
    return_error(f'Given loc format: {loc} does not match the expected format')
try:
    lat, lng = loc.split(',')
except ValueError:
    a = 2
    # Try by : if , didn't work
    try:
        lat, lng = loc.split(':')
    except ValueError:
        return_error(err_msg)
demisto.results(
    {'ContentsFormat': formats['json'], 'Type': entryTypes['map'], 'Contents': {"lat": float(lat), "lng": float(lng)}})

from CommonServerPython import *

loc = demisto.get(demisto.args().get('indicator') or {}, "CustomFields.geolocation")
if isinstance(loc, str):
    loc = loc.strip()
    long_lat_regex = re.compile(
        r'^\s*[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?)\s*([,:])\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)\s*$')
    if not loc:
        return_error("No location data was available")
    if not long_lat_regex.search(loc):
        return_error(f'Given loc format: {loc} does not match the expected format')
    try:
        lat, lng = loc.split(',')
    except ValueError:
        # Try by : if , didn't work. Safe to not wrap with try catch because regex above is protecting us
        lat, lng = loc.split(':')
    demisto.results(
        {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['map'],
            'Contents': {"lat": float(lat), "lng": float(lng)}
        }
    )
else:
    return_error('Location does not have the right format')

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incidents()
magnitude = incident[0].get('CustomFields', {}).get('magnitudeoffense', 0)  # define which incident field to use

if 8 <= magnitude <= 10:
    magnitude = str(magnitude)
    html = "<h1 style='color:#D13C3C;text-align:center;'>" + magnitude + "</h1>"

elif 4 <= magnitude <= 7:
    magnitude = str(magnitude)
    html = "<h1 style='color:#D17D00;text-align:center;'>" + magnitude + "</h1>"

else:
    magnitude = str(magnitude)
    html = "<h1 style='color:#1DB846;text-align:center;'>" + magnitude + "</h1>"


demisto.results({
    'ContentsFormat': formats['html'],
    'Type': entryTypes['note'],
    'Contents': html
})

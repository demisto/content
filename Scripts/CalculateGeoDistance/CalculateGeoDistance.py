import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import geopy.distance

entries = []

try:
    # Extract each set of coordinates and create a list
    src_coords_list = demisto.args()['src_coords'].split(",")
    dest_coords_list = demisto.args()['dest_coords'].split(",")

    # Convert each coordinate to a Float value and add to a tuple
    src_coords = (float(src_coords_list[0]), float(src_coords_list[1]))
    dest_coords = (float(dest_coords_list[0]), float(dest_coords_list[1]))

    # Compute distance between the set in miles
    geo_distance = round(geopy.distance.vincenty(src_coords, dest_coords).miles, 2)

    entries.append({
        "Type": entryTypes['note'],
        "Contents": geo_distance,
        "ContentsFormat": formats['text'],
        "HumanReadable": "Calculated Distance: {} miles.".format(str(geo_distance)),
        "EntryContext": {
            "Geo.Distance": geo_distance,
            "Geo.Coordinates": [src_coords, dest_coords]
        }
    })

except Exception as ex:
    entries.append({
        "Type": entryTypes["error"],
        "ContentsFormat": formats["text"],
        "Contents": "Error occurred while parsing output from command. Exception info:\n" + str(ex)
    })

demisto.results(entries)

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import geopy.distance
import urllib3

urllib3.disable_warnings()

try:
    # Extract each set of coordinates and create a list
    src_coords_list = argToList(demisto.args()["src_coords"])
    dest_coords_list = argToList(demisto.args()["dest_coords"])

    # Convert each coordinate to a Float value and add to a tuple
    src_coords = (float(src_coords_list[0]), float(src_coords_list[1]))
    dest_coords = (float(dest_coords_list[0]), float(dest_coords_list[1]))

    # Compute distance between the set in miles
    geo_distance = round(geopy.distance.geodesic(src_coords, dest_coords).miles, 2)
    hr = "Calculated Distance: {} miles.".format(str(geo_distance))
    context = {"Geo.Distance": geo_distance, "Geo.Coordinates": [src_coords, dest_coords]}

    return_outputs(hr, context, geo_distance)


except Exception as ex:
    return_error("Error occurred while parsing output from command. Exception info:\n" + str(ex))

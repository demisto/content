import demistomock as demisto  # noqa: F401
import geopy.distance
from CommonServerPython import *  # noqa: F401

requests.packages.urllib3.disable_warnings()

try:
    existing = demisto.get(demisto.context(), "ImpossibleTraveler.Events")
    EventsDict = {}
    for o in existing:
        EventsDict[o["location"]] = o
    DistanceList = []
    # Extract each set of coordinates and create a list
    src_coords_list = demisto.args()['src_coords']
    dest_coords_list = demisto.args()['dest_coords']
    for i in range(len(src_coords_list)):
        for dest in dest_coords_list[i:]:
            if src_coords_list[i] != dest:

                geo_distance = round(geopy.distance.geodesic(src_coords_list[i], dest).miles, 2)
                hr = 'Calculated Distance: {} miles.'.format(str(geo_distance))
                context = {
                    "distance": geo_distance,
                    "src_coords": src_coords_list[i],
                    "dest_coords": dest,
                    "source_ip": EventsDict[src_coords_list[i]]["ip"],
                    "source_country": EventsDict[src_coords_list[i]]["Country"],
                    "dest_ip": EventsDict[dest]["ip"],
                    "dest_country": EventsDict[dest]["Country"],
                    "timestamp": EventsDict[src_coords_list[i]]["event_timestamp"],
                    "identity": EventsDict[src_coords_list[i]]["identity_display_name"]
                }
                DistanceList.append(CommandResults(readable_output=hr, outputs=context,
                                    outputs_prefix="GeoEvents", outputs_key_field=""))

    return_results(DistanceList)

except Exception as ex:
    return_error('Error occurred while parsing output from command. Exception info:\n' + str(ex))

import demistomock as demisto  # noqa: F401
import geopy.distance
from CommonServerPython import *  # noqa: F401
import itertools
requests.packages.urllib3.disable_warnings()


def main():
    try:
        existing = [] #demisto.get(demisto.context(), "ImpossibleTraveler.Events")
        print('!')
        events_dict = {}
        for o in existing:
            events_dict[o["location"]] = o
        print('!')
        distance_list = []
        # Extract each set of coordinates and create a list
        args = demisto.args()
        print('!')
        src_coords_list = [(32.1, 42.3), (21.2, 43.2)]
        #dest_coords_list = args['dest_coords']
        for unique_pair in itertools.combinations(src_coords_list, 2):
            print(unique_pair)
            geo_distance = round(geopy.distance.geodesic(unique_pair[0], unique_pair[1]).miles, 2)
            hr = 'Calculated Distance: {} miles.'.format(str(geo_distance))
            context = {
                "distance": geo_distance,
                "src_coords": unique_pair[0],
                "dest_coords": unique_pair[1],
                # "source_ip": events_dict[unique_pair[0]]["ip"],
                # "source_country": events_dict[unique_pair[0]]["Country"],
                # "dest_ip": events_dict[unique_pair[1]]["ip"],
                # "dest_country": events_dict[unique_pair[1]]["Country"],
                # "timestamp": events_dict[unique_pair[0]]["event_timestamp"],
                # "identity": events_dict[unique_pair[0]]["identity_display_name"]
            }
            print(context)
            distance_list.append(CommandResults(readable_output=hr, outputs=context,
                                outputs_prefix="GeoEvents", outputs_key_field=""))

        return_results(distance_list)

    except Exception as ex:
        return_error('Error occurred while parsing output from command. Exception info:\n' + str(ex))


if __name__ == '__main__':
    main()

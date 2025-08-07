import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import itertools

import geopy.distance
import urllib3


urllib3.disable_warnings()


def get_distances_list(src_coords_list: list, events_dict: dict):
    distance_list = []
    for unique_pair in itertools.combinations(src_coords_list, 2):
        geo_distance = round(geopy.distance.geodesic(unique_pair[0], unique_pair[1]).miles, 2)
        hr = f"Calculated Distance: {str(geo_distance)} miles."
        context = {
            "distance": geo_distance,
            "src_coords": unique_pair[0],
            "dest_coords": unique_pair[1],
            "source_ip": events_dict[unique_pair[0]]["ip"],
            "source_country": events_dict[unique_pair[0]]["Country"],
            "dest_ip": events_dict[unique_pair[1]]["ip"],
            "dest_country": events_dict[unique_pair[1]]["Country"],
            "timestamp": events_dict[unique_pair[0]]["event_timestamp"],
            "identity": events_dict[unique_pair[0]]["identity_display_name"],
        }
        distance_list.append(
            CommandResults(readable_output=hr, outputs=context, outputs_prefix="GeoEvents", outputs_key_field="")
        )
    return distance_list


def verify_coords(args: dict):
    """
    Verify the two given coords lists are identical - we receive two lists (and not one) for BC reasons
    Args:
        args: the script's arguments
    """

    if not set(argToList(args["src_coords"])) == set(argToList(args["dest_coords"])):
        raise ValueError("The source coordination list and the destination coordination list should be identical.")


def generate_evetns_dict():
    existing = demisto.get(demisto.context(), "ImpossibleTraveler.Events")
    return {o["location"]: o for o in existing}


def main():
    try:
        events_dict = generate_evetns_dict()
        args = demisto.args()
        verify_coords(args)
        return_results(get_distances_list(argToList(args["src_coords"]), events_dict))

    except Exception as e:
        return_error("Error occurred while parsing output from command. Exception info:\n" + str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

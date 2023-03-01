import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def generate_unique_values_from_objects(object_list, key, keep_none):
    """Given a list of objects (dictionaries) and a key,
    generate a list of unique values of that key in the list of objects
    and return the unique values list.


    Args:
        object_list (List[Dict]): list of objects (dictionaries)
        key (Object): key of interest
        keep_none (bool): whether to keep None values
    """
    values = set()

    for obj in object_list:
        # Initially attempt to retrieve value using built-in object get method.
        # This accounts for keys that may contain dots that are NOT intended
        # to be retrieved from sub-keys.
        if key in obj:
            values.add(obj[key])
        # Otherwise, use demisto.get to access values.
        else:
            values.add(demisto.get(obj, key))

    if not keep_none:
        values.difference_update({None})

    # If no values were found, return error
    if not values:
        return_error("The objects provided did not contain the key of interest.")

    return list(values)


def main():  # pragma: no cover
    args = demisto.args()
    object_list = args.get("object_list")
    key = args.get("key_of_interest")
    keep_none = argToBoolean(args.get("keep_none"))

    values = generate_unique_values_from_objects(object_list, key, keep_none)

    return_results(CommandResults(
        outputs_prefix="unique_values",
        outputs_key_field="unique_values",
        outputs={"unique_values": values}))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

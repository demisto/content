import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""Given a list of objects (dictionaries) and a key, generate a list
of unique values of that key in the list of objects."""


def main():

    object_list = demisto.args().get("object_list")
    key = demisto.args().get("key_of_interest")
    keep_none = argToBoolean(demisto.args().get("keep_none"))

    values = set()

    for obj in object_list:
        # Initially attempt to retrieve value using built-in object get method.
        #
        # This accounts for keys that may contain dots that are NOT intended
        # to be retrieved from subkeys.
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

    return_results(CommandResults(
        outputs_prefix="unique_values",
        outputs_key_field="unique_values",
        outputs={"unique_values": list(values)}))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

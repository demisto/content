import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""Given a list of objects (dictionaries) and a key, generate a list
of unique values of that key in the list of objects."""


def main():

    object_list = demisto.args().get("object_list")
    key_of_interest = demisto.args().get("key_of_interest")
    keep_none = demisto.args().get("keep_none")

    # Convert string input to boolean
    if keep_none == "True":
        keep_none = True
    else:
        keep_none = False

    unique_values_by_key = []

    for object in object_list:
        # Initially attempt to retrieve value using built-in object get method.
        #
        # This accounts for keys that may contain dots that are NOT intended
        # to be retrieved from subkeys.
        if object.get(key_of_interest):
            unique_values_by_key.append(object.get(key_of_interest))
        # Otherwise, use demisto.get to access values.
        else:
            unique_values_by_key.append(demisto.get(object, key_of_interest))

    if keep_none:
        return_list = list(set(unique_values_by_key))
    else:
        return_list = list(set(filter(None, unique_values_by_key)))

    if unique_values_by_key:
        return_object = {"deduplicated_list": return_list}
    # If keep_none is true and the list ONLY contains None, they key was not in any object. Return error.
    elif keep_none and len(return_list) == 1 and return_list[0] is None:
        return_error("The objects provided did not contain the key of interest.")
    # If the list is empty (and keep_none is default, False), the key was not present in any object. Return error.
    else:
        return_error("The objects provided did not contain the key of interest.")

    results = CommandResults(
        outputs_prefix="DeduplicatedValues",
        outputs_key_field="deduplicated_list",
        outputs=return_object)

    return_results(results)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

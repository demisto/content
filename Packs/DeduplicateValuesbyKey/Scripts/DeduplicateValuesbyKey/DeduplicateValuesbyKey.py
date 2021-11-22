import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""Given a list of objects (dictionaries) and a key, generate a list
of unique values of that key in the list of objects."""


def main():

    object_list = demisto.args().get("object_list")
    key_of_interest = demisto.args().get("key_of_interest")

    unique_values_by_key = []

    for object in object_list:
        unique_values_by_key.append(object[key_of_interest])

    return_list = list(set(unique_values_by_key))

    return_object = {"deduplicated_list": return_list}

    results = CommandResults(
        outputs_prefix="DeduplicatedValues",
        outputs_key_field="deduplicated_list",
        outputs=return_object)

    return_results(results)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

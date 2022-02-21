import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
def key_to_json(keys, values):
    return_data = dict()
    try:
        for index in range(0, len(values)):
            return_data[keys[index]] = values[index]
    except Exception as err:
        return_error(f"There was an error - {err}")
    return return_data


def main():
    args = demisto.args()
    values = argToList(args.get('value'))
    keys = argToList(args.get('key'))

    if len(values) != len(keys):
        return_error("The length of the value and key are not the same")
    return_results(key_to_json(keys, values))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()

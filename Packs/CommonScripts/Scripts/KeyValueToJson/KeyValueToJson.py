import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
def key_to_json(keys, values):
    return_data = []
    if len(values) != len(keys):
        return_error("The length of the value and key are not the same")

    try:
        for index in range(0, len(keys)):
            these_values = values[index]
            if not isinstance(these_values, tuple) and not isinstance(these_values, tuple):
                try:
                    these_values = argToList(these_values)
                except Exception:
                    return_error("The values provided are not a tuple or list")
            for value in these_values:
                return_data.append(
                    {
                        keys[index]: value
                    }
                )
    except Exception as err:
        return_error(f"There was an error - {err}")
    return return_data


def main():
    args = demisto.args()
    values = argToList(args.get('value'))
    keys = argToList(args.get('key'))
    return_results(key_to_json(keys, values))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()

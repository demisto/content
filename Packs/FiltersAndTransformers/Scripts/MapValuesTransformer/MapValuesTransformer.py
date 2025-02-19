import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import json


def mapvalues(value, input_values, mapped_values):
    input_values = input_values.split(",")
    mapped_values = mapped_values.split(",")
    try:
        value = json.loads(value)
    except Exception:
        pass

    # Convert all to string
    value = str(value) if type(value) not in [dict, list] else value
    input_values[:] = [str(x) for x in input_values]
    mapped_values[:] = [str(x) for x in mapped_values]

    # If the provided input_value and mapper_values are not equal in length
    # then return an error

    if len(input_values) != len(mapped_values):
        return_error('Length of input_values and mapped_values are not the same')

    # Create a dictionary to look up values against
    mapper = dict()
    for index in range(0, len(input_values)):
        mapper[input_values[index]] = mapped_values[index]

    # If the input is a dictionary then attempt to convert each
    # "key: value" as a string into the value in the mapper
    if type(value) is dict:
        new_dict = dict()
        for k, v in value.items():
            key_value = f"{k}:{v}"
            key_value_space = f"{k}: {v}"
            if key_value in mapper:
                new_dict[k] = mapper[key_value]
            elif key_value_space in mapper:
                new_dict[k] = mapper[key_value_space]
            else:
                new_dict[k] = v
        value = json.dumps(new_dict)

    elif type(value) is list:
        for val in value:
            val = mapper[val] if val in mapper else val

    elif value in mapper:
        value = mapper[value]

    return value


def main():
    args = demisto.args()
    value = args.get('value')
    input_values = args.get('input_values')
    mapped_values = args.get('mapped_values')

    value = mapvalues(value, input_values, mapped_values)
    demisto.results(value)


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()

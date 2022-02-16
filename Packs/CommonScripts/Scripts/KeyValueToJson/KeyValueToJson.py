import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

args = demisto.args()
values = args.get('value')
keys = args.get('key')

if not isinstance(values, list):
    try:
        values = json.loads(values)
    except:
        pass
    if not isinstance(values, list):
        try:
            values = values.split(",")
        except:
            pass

if not isinstance(values, list):
    return_error("Canoot convert the input values into a list")

if not isinstance(keys, list):
    try:
        keys = json.loads(keys)
    except:
        pass
    if not isinstance(keys, list):
        try:
            keys = keys.split(",")
        except:
            pass

if not isinstance(keys, list):
    return_error("Canoot convert the input key into a list")

if len(values) != len(keys):
    return_error("The length of the value and key are not the same")

try:
    return_data = dict()
    for index in range(0, len(values)):
        return_data[keys[index]] = values[index]
except Exception as err:
    return_error(f"There was an error - {err}")

return_results(return_data)

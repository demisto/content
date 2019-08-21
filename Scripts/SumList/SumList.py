from CommonServerPython import *

value = demisto.args()["value"]

if isinstance(value, int):
    demisto.results(value)

elif isinstance(value, list):
    try:
        result = sum(value)
        demisto.results(result)
    except TypeError:
        return_error('This transformer applies only to numbers.')

elif isinstance(value, str):
    try:
        result = int(value)
        demisto.results(result)
    except TypeError:
        return_error('The string does not represnet a number.')

else:
    return_error('This transformer applies only to a list of numbers.')

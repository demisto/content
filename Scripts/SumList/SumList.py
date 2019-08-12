from CommonServerPython import *

value = demisto.args()["value"]

if isinstance(value, list):
    try:
        result = sum(value)
    except TypeError:
        return_error('This transformer applies only to numbers.')
else:
    return_error('This transformer applies only to a list of numbers.')

demisto.results(result)

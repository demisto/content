import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
value = demisto.args()["value"]

if isinstance(value, list):
    result = value
    try:
        result = sum(result)
    except TypeError:
        return_error('This transformer applies only to numbers.')
else:
    return_error('This transformer applies only to a list of numbers.')

demisto.results(result)

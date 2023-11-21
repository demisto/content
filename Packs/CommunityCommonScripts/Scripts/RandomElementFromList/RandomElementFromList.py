import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import random


input_list = argToList(demisto.args().get('value'), ',')
count = int(demisto.args().get('count', 1))

try:
    if input_list:
        return_results(random.sample(input_list, count))
    else:
        return_error("Please pass a valid list")
except Exception as e:
    return_error(str(e))

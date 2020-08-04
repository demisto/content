import random

import demistomock as demisto
from CommonServerPython import *

value = demisto.args()["value"]

if isinstance(value, list):
    res = value
    random.shuffle(res)
else:
    res = value

demisto.results(res)

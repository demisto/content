from itertools import chain

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

value = []
value = demisto.args()["value"]

list_out = list(chain.from_iterable(zip(value[1::2], value[::2])))

demisto.results(list_out)

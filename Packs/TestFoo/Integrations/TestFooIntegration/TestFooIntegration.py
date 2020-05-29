import demistomock as demisto
from CommonServerPython import *


def add(a, b):
    return a + b


demisto.results(add(5, 3))

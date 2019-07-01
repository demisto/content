import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
value = demisto.args()["value"]
chars = demisto.args().get("chars", "")

demisto.results(value.strip(chars))

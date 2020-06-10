from CommonServerPython import *
value = demisto.args()["value"]
chars = demisto.args().get("chars", "")

demisto.results(value.strip(chars))

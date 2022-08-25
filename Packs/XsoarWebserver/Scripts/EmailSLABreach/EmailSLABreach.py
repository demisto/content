import demistomock as demisto
from CommonServerPython import *
demisto.executeCommand("taskComplete", {"id": "EmailTimeout"})
demisto.executeCommand("resetTimer", {"timerField": "EmailUserSLA"})

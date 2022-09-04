import demistomock as demisto


demisto.executeCommand("taskComplete", {"id": "EmailTimeout"})
demisto.executeCommand("resetTimer", {"timerField": "EmailUserSLA"})

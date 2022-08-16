demisto.executeCommand("taskComplete", {"id": "EmailTimeout"})
demisto.executeCommand("resetTimer", {"timerField": "EmailUserSLA"})

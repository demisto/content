import demistomock as demisto


job_uuid = demisto.args().get('uuid')
emailsubject = demisto.args().get('emailsubject')
attachIDs = demisto.args().get('attachIDs', '')
context = demisto.context()
dt = demisto.dt(context, f"WS-ActionStatus(val.job_uuid=='{job_uuid}').link_tracker(val.response_received==false)")
for item in dt:
    demisto.executeCommand("send-mail", {"subject": emailsubject, "to": item['email'], "attachIDs": attachIDs,
                                         "htmlBody": item['emailhtml']})

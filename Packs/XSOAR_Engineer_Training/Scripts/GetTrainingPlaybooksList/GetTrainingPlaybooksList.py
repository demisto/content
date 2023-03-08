import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
result = demisto.executeCommand("demisto-api-post", {"uri":"/playbook/search","body":{"query":"tags:training"}})[0]["Contents"]["response"]
playbooks = [ {"Name":x.get("name",""),"Description":x.get("comment","")} for x in result["playbooks"] if "XSOAR Engineer Training" in x.get("name")]

# make the playbook clickable.
data = []
for playbook in playbooks:
    name = playbook.get("Name")
    fancy = {
        'Command': f'%%%{{"message":"{name}", "action":"setPlaybook", "params": {{"name":"{name}"}}}}%%%',
        'Description': playbook.get("Description")
    }
    data.append(fancy)

# return a MD entry for the dynamic section
results = CommandResults(readable_output=tableToMarkdown('Training Playbooks', data, headers=["Command","Description"]))
return_results(results)

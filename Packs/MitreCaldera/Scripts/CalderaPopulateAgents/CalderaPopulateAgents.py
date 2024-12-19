import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

res = demisto.executeCommand('caldera-get-agents', {})[0]['Contents']
if res:
    agents = [
        {
            "PAW": x.get('paw'),
            "Architecture": x.get('architecture'),
            "Platform": x.get('platform'),
            "Created": x.get('created'),
            "Deadman enabled": x.get('deadman_enabled'),
            "Display name": x.get('display_name'),
            "Last seen": x.get('last_seen'),
            "PID": x.get('pid'),
            "Username": x.get('username'),
            "Group": x.get('group'),
            "EXE name": x.get('exe_name'),
            "Location": x.get('location')
        }for x in res]
else:
    agents = []
command_results = CommandResults(
    readable_output=tableToMarkdown('Agents', agents)
)
return_results(command_results)

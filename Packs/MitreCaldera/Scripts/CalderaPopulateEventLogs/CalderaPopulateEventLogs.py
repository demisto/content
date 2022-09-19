import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incident()
custom_fields = incident.get('CustomFields')
operation_id = custom_fields.get('calderaoperationid')
if operation_id:
    results = demisto.executeCommand('caldera-get-operation-event-logs', {"operation_id": operation_id})
    res = results[0]['Contents']
    if isinstance(res, list):
        events = []
        if res:
            events = [
                {
                    "Collected": x.get('collected_timestamp'),
                    "Finished": x.get('finished_timestamp'),
                    "Command": x.get('command'),
                    "Status": x.get('status'),
                    "Platform": x.get('platform'),
                    "Executor": x.get('executor'),
                    "PID": x.get('pid'),
                    "Ability Name": x.get('ability_metadata', {}).get('ability_name'),
                    "Ability Description": x.get('ability_metadata', {}).get('ability_description'),
                    "Attack Tactic": x.get('attack_metadata', {}).get('tactic'),
                    "Attack Technique Name": x.get('attack_metadata', {}).get('technique_name'),
                    "Attack Technique ID": x.get('attack_metadata', {}).get('technique_id')
                }for x in res]
        command_results = CommandResults(
            readable_output=tableToMarkdown('Event Logs', events)
        )
    else:
        command_results = CommandResults(
            readable_output=tableToMarkdown('Event Logs', [])
        )
else:
    command_results = CommandResults(
        readable_output=tableToMarkdown('Operation Facts', [])
    )
return_results(command_results)

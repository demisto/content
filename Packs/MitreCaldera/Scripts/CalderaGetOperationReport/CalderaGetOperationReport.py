import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


incident = demisto.incident()
custom_fields = incident.get('CustomFields')
operation_id = custom_fields.get('calderaoperationid')
if operation_id:
    res = demisto.executeCommand('caldera-get-operation-report', {'operation_id': operation_id})[0]['Contents']

    if isinstance(res, dict) and "facts" in res:
        caldera_operation_facts = []

        facts: list = res.get('facts', [])

        for fact in facts:
            caldera_operation_facts.append(
                {
                    "created": fact.get('created'),
                    "techniqueid": fact.get('technique_id'),
                    "name": fact.get('name'),
                    "trait": fact.get('trait'),
                    "value": fact.get('value'),
                    "unique": fact.get('unique'),
                    "score": str(fact.get('score')),
                    "origintype": fact.get('origin_type'),
                    "collectedby": ", ".join(fact.get('collected_by', []))
                })
        command_results = CommandResults(
            readable_output=tableToMarkdown('Operation Facts', caldera_operation_facts)
        )
    else:
        command_results = CommandResults(
            readable_output="### Operation Facts\n\nNo data."
        )
else:
    command_results = CommandResults(
        readable_output="### Operation Facts\n\nNo Operation ID found."
    )

return_results(command_results)

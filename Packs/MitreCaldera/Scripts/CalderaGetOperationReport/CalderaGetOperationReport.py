import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

args = demisto.args()
operation_id = args.get('operation_id')

res = demisto.executeCommand('caldera-get-operation-report', {'operation_id': operation_id})[0]['Contents']

caldera_operation_facts = []

facts = res.get('facts')

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
demisto.executeCommand('setIncident', {'calderaoperationfacts': caldera_operation_facts})

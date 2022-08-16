import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

args = demisto.args()
incident = demisto.incident()
custom_fields = incident.get('CustomFields')
operation_id = custom_fields.get('calderaoperationid')
delete_operation = argToBoolean(args.get('calderadeleteoperation', False))
if delete_operation:
    demisto.executeCommand('caldera-delete-operation', {'operation_id': operation_id})

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

picklistValues = execute_command("salesforce-describe-sobject-field",
                                 {"sobject": "Case", "field": "Status"})[0]['Contents'].get('picklistValues', [])
demisto.results({'hidden': False, 'options': [value.get('label') for value in picklistValues]})

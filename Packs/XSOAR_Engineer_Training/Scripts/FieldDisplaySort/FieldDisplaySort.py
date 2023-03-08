import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# This is a field display script, that will sort single or multi-select fields on display.
# field is in the field argument
field = demisto.args()['field']['selectValues']
demisto.results({'hidden': False, 'options': sorted(field)})

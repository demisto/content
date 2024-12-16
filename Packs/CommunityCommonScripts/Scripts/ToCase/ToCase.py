import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
value = demisto.args()['value']
case = demisto.args().get('case', 'capital')
if case == 'swap':
    value = value.swapcase()
elif case == 'capital':
    value = value.capitalize()
elif case == 'title':
    value = value.title()
return_results(value)

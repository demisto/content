import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
value = demisto.args()['value']
case = demisto.args().get('case', 'capital')

match case:
	case 'swap':
		value = value.swapcase()
	case 'capital':
		value = value.capitalize()
	case 'title':
		value = value.title()

return_results(value)

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from time import strftime

def main():
	field_name = demisto.args().get('fieldName')
	t = strftime("%a, %d %b %Y %H:%M:%S %Z")
	res = demisto.executeCommand("setIncident", {field_name: t})
	return_results(res)


""" ENTRY POINT """

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
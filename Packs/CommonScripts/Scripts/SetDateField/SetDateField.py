import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from time import strftime

def main():

	try:
		field_name = demisto.args().get('fieldName')
		t = strftime("%a, %d %b %Y %H:%M:%S %Z")
		res = demisto.executeCommand("setIncident", {field_name: t})
		return_results(res)
	except Exception as e:
		return_error(f"Failed to execute SetDateField error when running setIncident {field_name}={t}: {str(e)}")


""" ENTRY POINT """

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
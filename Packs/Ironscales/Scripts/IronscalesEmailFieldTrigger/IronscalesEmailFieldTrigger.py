import demistomock as demisto
from CommonServerPython import *


def main():
    try:
        args = demisto.args()
        res = args.get("user").get("email")
        cmd_res = demisto.executeCommand(command="setIncident", args={"ironscalesresolveremailaddress": res})
        return_results(cmd_res)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

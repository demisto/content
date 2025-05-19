import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback
#import cortex_module_test.test_override_csp as cmt
from cortex_module_test import *


def main():
    try:
        args = demisto.args()
        number_to_test = args.get('number_to_test')
        print(arg_to_number(number_to_test))
        print(argToBoolean("True"))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback
#import cortex_module_test.test_override_csp as cmt
from cortex_module_test import *
# from cortex_module_test import test_override_csp
# test_override_csp.demisto = demisto


def main():
    try:
        #demisto.debug(f"global demisto is: {globals()["demisto"]}")
        args = demisto.args()
        number_to_test = args.get('number_to_test')
         # Tests that arg_to_number func is called from the cortex-module instead of the CSP
        print(arg_to_number(number_to_test))
        # Tests that the argToBoolean func is called from the CSUP when the decorator is used instead of from the cortex-module
        # for system scripts
        print(argToBoolean("True"))
        # # Tests functions which use the demisto object
        print(is_integration_command_execution())
        
        print(argToList("test1,test2"))

        demisto.debug("test demisto debug")
        
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


# Restrict the builtins available to the user
from RestrictedPython import compile_restricted
from RestrictedPython import safe_builtins


def py_dt(val):
    # Pass additional builtins
    safe_builtins['return_results'] = return_results
    safe_builtins['val'] = val

    source = '{}'.format(demisto.args().get('Python', "Python arg not found"))
    code = compile_restricted(source, '<string>', 'exec')
    exec(code, {'__builtins__': safe_builtins}, None)


if __name__ in ('__main__','__builtin__','builtins'):
    val = demisto.args().get('value', 'None')
    py_dt(val)

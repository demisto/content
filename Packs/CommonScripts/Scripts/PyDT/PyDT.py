import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
def py_dt(val):
    source = 'return_results({})'.format(demisto.args().get('Python', "Python arg not found"))
    code = compile(source, '<string>', 'exec')
    exec(code)


if __name__ in ('__main__','__builtin__','builtins'):
    val = demisto.args().get('value', 'None')
    py_dt(val)

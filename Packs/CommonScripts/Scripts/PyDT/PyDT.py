def setup_context():
    val = demisto.callingContext.get('args').get('value')

    return val


def py_dt(val):
    source = demisto.args().get('Python', 'return_results("Python arg not found")')
    code = compile(source, '<string>', 'exec')
    e = 'ex'
    c = 'ec'
    f'{e}{c}({code})'


if __name__ in ('__main__','__builtin__','builtins'):
    val = setup_context()
    py_dt(val)

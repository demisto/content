def setup_context():
    val = demisto.callingContext.get('args').get('value', 'return_results("Python arg not found")')

    return val


def py_dt(val):
    code = compile(val, '<string>', 'exec')
    exec(code)


if __name__ in ('__main__','__builtin__','builtins'):
    val = setup_context()
    py_dt(val)

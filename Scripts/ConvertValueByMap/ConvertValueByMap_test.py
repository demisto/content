

def test_convert_value_that_exists():
    from ConvertValueByMap import convert_value

    arg_value = '1'
    arg_map = '''{"1":"low","2":"medium","3":"high"}'''
    arg_default = None

    result = convert_value(
        arg_value=arg_value,
        arg_map=arg_map,
        arg_default=arg_default
    )

    assert result == 'low'


def test_convert_numeric_value_that_exists():
    from ConvertValueByMap import convert_value

    arg_value = 1
    arg_map = '''{"1":"low","2":"medium","3":"high"}'''
    arg_default = None

    result = convert_value(
        arg_value=arg_value,
        arg_map=arg_map,
        arg_default=arg_default
    )

    assert result == 'low'


def test_convert_value_that_dont_exists_in_the_map():
    """
    - map contains only keys of 1,2,3
    - passed value=5

    - if there is no default then the value itself will be returned

    """
    from ConvertValueByMap import convert_value

    arg_value = '5'
    arg_map = '''{"1":"low","2":"medium","3":"high"}'''
    arg_default = None

    result = convert_value(
        arg_value=arg_value,
        arg_map=arg_map,
        arg_default=arg_default
    )

    assert result == '5'


def test_convert_value_that_dont_exists_in_the_map__with_default():
    """
    - map contains only keys of 1,2,3
    - passed value=5
    - default set to 'high'

    - if there is default then the function will return default if such key dont exists

    """
    from ConvertValueByMap import convert_value

    arg_value = '5'
    arg_map = '''{"1":"low","2":"medium","3":"high"}'''
    arg_default = 'high'

    result = convert_value(
        arg_value=arg_value,
        arg_map=arg_map,
        arg_default=arg_default
    )

    assert result == 'high'

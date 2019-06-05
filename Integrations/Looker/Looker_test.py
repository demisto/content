import demistomock as demisto


def test_parse_filters_arg(mocker):
    mocker.patch.object(demisto, 'params', return_value={'url': ''})

    from Looker import parse_filters_arg

    assert parse_filters_arg('') is None
    assert parse_filters_arg('e=f') == {'e': 'f'}
    assert parse_filters_arg('e=f, g') == {'e': 'f, g'}
    assert parse_filters_arg('e=f; g = h') == {'e': 'f', 'g': 'h'}
    assert parse_filters_arg('a_b.c_d= e f g h ') == {'a_b.c_d': 'e f g h'}

    for test_input in ('a', 'a;', ' ; a', 'a; b', 'e=f; g = ', 'e=f; g'):
        try:
            parse_filters_arg(test_input)
            raise AssertionError(f'Negative test failed on input: {test_input}')
        except ValueError:
            continue

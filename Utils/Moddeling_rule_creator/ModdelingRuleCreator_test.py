from generate_modeling_rules import *
import pytest


def test_replace_last_char():
    assert replace_last_char('hello,\n') == 'hello;\n'


def test_create_xif_header(mocker):
    mocker.patch('generate_modeling_rules.DATASET_NAME', 'blabla')
    res = (
        '[MODEL: dataset=blabla]\n'
        '| alter\n'
    )
    assert create_xif_header() == res


@pytest.mark.parametrize('input, res', (['string', 'String'],
                         ['int', 'Number'],
                         ['ggg', 'String']))
def test_convert_raw_type_to_xdm_type(input, res):
    assert convert_raw_type_to_xdm_type(input) == res


@pytest.mark.parametrize('path, res', (['hello', ('string', False)],
                                       ['test.bla', ('int', False)],
                                       ['test.gg.hh', ('int', True)],
                                       ['arr', ('bool', True)],
                                       ['y.j', ('string', False)],
                                       ['t', ('string', False)],
                                       ['r', ('string', False)]))
def test_extract_raw_type_data(path, res):
    event = {'hello': 'hello',
             'test': {'bla': 3,
                      'gg': {'hh': [5, 6]}},
             'arr': [True, False, False],
             'y': {'j': {'h': 'k'}},
             't': None}
    assert extract_raw_type_data(event, path) == res


def test_extract_raw_type_data_empty_event():
    event = {}
    with pytest.raises(ValueError):
        extract_raw_type_data(event, 'bla')


def test_extract_raw_type_data_event_not_dict():
    event = True
    with pytest.raises(ValueError):
        extract_raw_type_data(event, 'bbb')


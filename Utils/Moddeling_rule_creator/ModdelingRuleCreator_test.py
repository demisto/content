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

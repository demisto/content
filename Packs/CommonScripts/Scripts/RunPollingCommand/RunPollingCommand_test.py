# coding=utf-8

import pytest
from RunPollingCommand import prepare_arg_dict


IDS_ARGS = [
    # sanity
    (
        ('ids', ['a', 'b', 'c'], None, None),
        {'ids': 'a,b,c'},
    ),
    # single ID
    (
        ('ids', 'a', None, None),
        {'ids': 'a'},
    ),
    # numeric IDs
    (
        ('ids', [1, 2, 3], None, None),
        {'ids': '1,2,3'},
    ),
    # extra args
    (
        ('ids', ['a', 'b', 'c'], u'arg1', u'value1'),
        {'ids': 'a,b,c', 'arg1': 'value1'},
    ),
    # extra args
    (
        ('ids', ['a', 'b', 'c'], [u'arg1', u'arg2'], [u'value1', u'value2']),
        {'ids': 'a,b,c', 'arg1': 'value1', 'arg2': 'value2'},
    ),
    # extra args
    (
        ('ids', ['a', 'b', 'c'], u'arg1, arg2,arg3', [u'value1', u'value2', u'value3']),
        {'ids': 'a,b,c', 'arg1': 'value1', 'arg2': 'value2', 'arg3': 'value3'},
    ),
    (
        ('ids', ['שלום'], 'היי, arg2,arg3', ['ביי', 'value2', 'value3']),
        {'ids': 'שלום', 'היי': 'ביי', 'arg2': 'value2', 'arg3': 'value3'},
    )
]


@pytest.mark.parametrize('inputs, expected_args', IDS_ARGS)
def test_prepare_arg_dict(inputs, expected_args):
    args = prepare_arg_dict(*inputs)
    assert args == expected_args


def test_prepare_arg_dict__error():
    with pytest.raises(ValueError):
        prepare_arg_dict('ids', 'a', u'arg1', None)

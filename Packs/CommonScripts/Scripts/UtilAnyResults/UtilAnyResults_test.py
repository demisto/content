from UtilAnyResults import *


def test_util_any_results_list(mocker):
    mocker.patch.object(demisto, 'get', return_value=['a', 'b', 'c'])
    assert util_any_results({}) == ['yes']


def test_util_any_results_str(mocker):
    mocker.patch.object(demisto, 'get', return_value='abc')
    assert util_any_results({}) == ['yes']


def test_util_any_results_str_lst(mocker):
    mocker.patch.object(demisto, 'get', return_value='[a, b, c]')
    assert util_any_results({}) == ['yes']


def test_util_any_results_str_empty_lst(mocker):
    mocker.patch.object(demisto, 'get', return_value='[]')
    assert util_any_results({}) == ['no']


def test_util_any_results_int(mocker):
    mocker.patch.object(demisto, 'get', return_value=1)
    assert util_any_results({}) == ['no']

import EWSv2
import logging

RETURN_ERROR_TARGET = 'EWSv2.return_error'


def test_keys_to_camel_case():
    assert EWSv2.keys_to_camel_case('this_is_a_test') == 'thisIsATest'
    # assert keys_to_camel_case(('this_is_a_test', 'another_one')) == ('thisIsATest', 'anotherOne')
    obj = {}
    obj['this_is_a_value'] = 'the_value'
    obj['this_is_a_list'] = []
    obj['this_is_a_list'].append('list_value')
    res = EWSv2.keys_to_camel_case(obj)
    assert res['thisIsAValue'] == 'the_value'
    assert res['thisIsAList'][0] == 'listValue'


def test_start_logging():
    EWSv2.start_logging()
    logging.getLogger().debug("test this")
    assert "test this" in EWSv2.log_stream.getvalue()


def test_parse_fetch_time_to_minutes_no_error():
    EWSv2.FETCH_TIME = '3 hours'
    res = EWSv2.parse_fetch_time_to_minutes()
    assert res == 180


def test_parse_fetch_time_to_minutes_invalid_time_integer(mocker):
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)

    EWSv2.FETCH_TIME = 'abc hours'
    EWSv2.parse_fetch_time_to_minutes()
    err_msg = return_error_mock.call_args[0][0]
    assert err_msg == "Error: Invalid fetch time, need to be a positive integer with the time unit afterwards " \
                      "e.g '2 months, 4 days'."


def test_parse_fetch_time_to_minutes_invalid_time_unit(mocker):
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)

    EWSv2.FETCH_TIME = '3 hoursss'
    EWSv2.parse_fetch_time_to_minutes()
    err_msg = return_error_mock.call_args[0][0]
    assert err_msg == 'Error: Invalid time unit.'

from datetime import datetime

import pytest
import OTRS
import demistomock as demisto


@pytest.mark.parametrize(argnames='queue, expected_time_arg', argvalues=[
    ('Any', '2000-01-02 00:00:01'),
    ('queue_1,queue_2', '2000-01-01 00:00:01'),
])
def test_correct_time_in_fetch_incidents_(mocker, queue, expected_time_arg):
    """
    Given -
        fetch incident when queue is specified in params
    When -
        run the fetch incident command
    Then -
        assert the created_after arg in search_ticket are as expected
        day before the last_run if queue is specified and equal to last_run if not specified
    """

    mocker.patch.object(OTRS, 'FETCH_QUEUE', queue)
    mocker.patch.object(demisto, 'getLastRun', return_value={'time': '2000-01-02 00:00:00', 'last_fetched_ids': []})
    mocker.patch.object(demisto, 'params', return_value={})
    mocker.patch.object(OTRS, 'search_ticket', return_value=[])
    mocker.patch.object(OTRS, 'parse_date_range', return_value=(datetime.strptime('2020-10-10', '%Y-%m-%d'), None))
    mocker.patch.object(demisto, 'setLastRun')

    # run
    OTRS.fetch_incidents()

    # validate
    created_after = OTRS.search_ticket.call_args[1]['created_after']
    assert expected_time_arg == datetime.strftime(created_after, '%Y-%m-%d %H:%M:%S')


@pytest.mark.parametrize(argnames='last_run_obj, expected_last_run', argvalues=[
    ({}, {'time': '2020-10-10 00:00:00', 'last_fetched_ids': []}),
    ({'time': '2000-01-01 00:00:00', 'last_fetched_ids': ['1']},
     {'time': '2000-01-01 00:00:01', 'last_fetched_ids': []}),
])
@pytest.mark.parametrize(argnames='queue, expected_queue_arg', argvalues=[
    ('Any', None),
    ('queue_1,queue_2', ['queue_1', 'queue_2']),
])
def test_fetch_incidents__queue_specified(mocker,
                                          last_run_obj,
                                          expected_last_run,
                                          queue,
                                          expected_queue_arg):
    """
    Given -
        fetch incident when queue is specified in params
    When -
        run the fetch incident command
    Then -
        assert the created_after arg in search_ticket are as expected
        assert the last run was as expected

    """

    mocker.patch.object(OTRS, 'FETCH_QUEUE', queue)
    mocker.patch.object(demisto, 'getLastRun', return_value=last_run_obj)
    mocker.patch.object(demisto, 'params', return_value={})
    mocker.patch.object(OTRS, 'search_ticket', return_value=[])
    mocker.patch.object(OTRS, 'parse_date_range', return_value=(datetime.strptime('2020-10-10', '%Y-%m-%d'), None))
    mocker.patch.object(demisto, 'setLastRun')

    # run
    OTRS.fetch_incidents()

    # validate
    demisto.setLastRun.assert_called_with(expected_last_run)
    assert expected_queue_arg == OTRS.search_ticket.call_args[1]['queue']

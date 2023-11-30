import pytest
from freezegun import freeze_time
from InfobloxBloxOneThreatDefenseEventCollector import *


class TestBloxOneTDEventCollectorClient:
    def test_fetch_url(self, requests_mock):
        request_mock_get = requests_mock.get('/api/dnsdata/v2/dns_event', json={"result": []})
        BloxOneTDEventCollectorClient('').fetch_events(0, 0)
        assert request_mock_get.called_once

    def test_event_time_mapping(self, requests_mock):
        event_time = 'the event time'
        requests_mock.get('/api/dnsdata/v2/dns_event', json={
            "result": [{'event_time': event_time}]
        })
        event = BloxOneTDEventCollectorClient('').fetch_events(0, 0)[0]
        assert event['event_time'] == event['_time'] == event_time


class TestFetchEventsCommand:

    data_test_fetch_events_command = [
        ({'from_ts': 1680307140}, {'from_ts': 1680307200}, 3),
        ({'from_ts': 1680307140}, {'from_ts': 1680307140, 'offset': 5}, 5),
        ({'from_ts': 1680307140, 'offset': 5}, {'from_ts': 1680307140, 'offset': 10}, 5),
        ({'from_ts': 1680307140, 'offset': 10}, {'from_ts': 1680307200}, 2),
    ]

    @freeze_time('2023-04-01T00:00:00.000Z')
    @pytest.mark.parametrize('last_run, expected_next_run, events_length', data_test_fetch_events_command)
    def test_fetch_events_command(self, last_run, expected_next_run, events_length, requests_mock, mocker):
        requests_mock.get('/api/dnsdata/v2/dns_event', json={
            "result": [{'event_time': 'event_time'}] * events_length
        })
        set_last_run = mocker.patch.object(demisto, 'setLastRun')
        send_events_to_xsiam_mock = mocker.patch('InfobloxBloxOneThreatDefenseEventCollector.send_events_to_xsiam')
        fetch_events_command(
            BloxOneTDEventCollectorClient(''),
            {'max_fetch': 5}, last_run
        )
        set_last_run.assert_called_once_with(expected_next_run)
        send_events_to_xsiam_mock.assert_called_once_with(
            [{'_time': 'event_time', 'event_time': 'event_time'}] * events_length, 'Infoblox BloxOne', 'Threat Defense')

    @freeze_time('2023-04-01T00:00:00.000Z')
    def test_fetch_events_first_fetch(self, requests_mock, mocker):
        get_events_api_call = requests_mock.get('/api/dnsdata/v2/dns_event', json={
            "result": [{'event_time': 'event_time'}]
        })
        send_events_to_xsiam_mock = mocker.patch('InfobloxBloxOneThreatDefenseEventCollector.send_events_to_xsiam')
        fetch_events_command(
            BloxOneTDEventCollectorClient(''),
            {'max_fetch': 5, 'first_fetch': '5 min'}, {}
        )
        send_events_to_xsiam_mock.assert_called_once_with(
            [{'_time': 'event_time', 'event_time': 'event_time'}], 'Infoblox BloxOne', 'Threat Defense')
        assert get_events_api_call.last_request.qs['t0'][0] == '1680306900'

    def test_fetch_events_with_invalid_first_fetch(self, requests_mock, mocker):
        with pytest.raises(DemistoException):
            fetch_events_command(
                BloxOneTDEventCollectorClient(''),
                {'first_fetch': 'this is a test and it should raise an error'}, {}
            )


class TestGetEventsCommand:
    def test_get_events_command_without_send_to_xsiam(self, requests_mock, mocker):
        send_events_to_xsiam_mock = mocker.patch('InfobloxBloxOneThreatDefenseEventCollector.send_events_to_xsiam')
        get_events_api_call = requests_mock.get('/api/dnsdata/v2/dns_event', json={
            "result": [{'event_time': 'event_time'}]
        })
        get_events_command(BloxOneTDEventCollectorClient(''), {'from': 1, 'to': 2})
        assert get_events_api_call.called_once
        assert get_events_api_call.last_request.qs['t0'][0] == '1'
        assert get_events_api_call.last_request.qs['t1'][0] == '2'
        assert send_events_to_xsiam_mock.call_count == 0

    def test_get_events_command_and_send_to_xsiam(self, requests_mock, mocker):
        send_events_to_xsiam_mock = mocker.patch('InfobloxBloxOneThreatDefenseEventCollector.send_events_to_xsiam')
        get_events_api_call = requests_mock.get('/api/dnsdata/v2/dns_event', json={
            "result": [{'event_time': 'event_time'}]
        })
        get_events_command(BloxOneTDEventCollectorClient(''), {'from': 1, 'to': 2, 'should_push_events': 'yes'})
        assert get_events_api_call.called_once
        assert get_events_api_call.last_request.qs['t0'][0] == '1'
        assert get_events_api_call.last_request.qs['t1'][0] == '2'
        send_events_to_xsiam_mock.assert_called_once_with(
            [{'_time': 'event_time', 'event_time': 'event_time'}], 'Infoblox BloxOne', 'Threat Defense')


class TestParseFromTsFromParams:
    data_test_parse_from_ts_from_params_with_valid_params = [
        (None, 1680220800),
        ('5 min', 1680306900),
    ]

    @freeze_time('2023-04-01T00:00:00.000Z')
    @pytest.mark.parametrize('first_fetch, expected_from_ts', data_test_parse_from_ts_from_params_with_valid_params)
    def test_parse_from_ts_from_params_with_valid_params(self, first_fetch, expected_from_ts):
        assert parse_from_ts_from_params(first_fetch) == expected_from_ts

    def test_parse_from_ts_from_params_with_invalid_params(self):
        with pytest.raises(DemistoException):
            parse_from_ts_from_params('this is a test and it should raise an error')


class TestCommandTestModule:
    def test_default_flow(self, requests_mock):
        requests_mock.get('/api/dnsdata/v2/dns_event', json={
            "result": [{'event_time': 'event_time'}]
        })
        assert command_test_module(BloxOneTDEventCollectorClient(''), {}) == 'ok'

    def test_valid_first_fetch(self, requests_mock):
        requests_mock.get('/api/dnsdata/v2/dns_event', json={
            "result": [{'event_time': 'event_time'}]
        })
        assert command_test_module(BloxOneTDEventCollectorClient(''), {'first_fetch': '5 min'}) == 'ok'

    def test_invalid_first_fetch(self, requests_mock):
        requests_mock.get('/api/dnsdata/v2/dns_event', json={
            "result": [{'event_time': 'event_time'}]
        })
        with pytest.raises(DemistoException):
            command_test_module(BloxOneTDEventCollectorClient(''), {'first_fetch': 'invalid'})

    def test_invalid_creds(self, requests_mock):
        requests_mock.get('/api/dnsdata/v2/dns_event', status_code=401, json={'i dont': 'really care'})
        with pytest.raises(DemistoException):
            command_test_module(BloxOneTDEventCollectorClient(''), {'first_fetch': 'invalid'})


def demisto_input_mocker(mocker, command, params={}, args={}):
    mocker.patch.object(demisto, 'command', return_value=command)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value=args)


@pytest.fixture()
def return_error_mock(mocker):
    return mocker.patch('InfobloxBloxOneThreatDefenseEventCollector.return_error')


@pytest.fixture()
def return_results_mock(mocker):
    return mocker.patch('InfobloxBloxOneThreatDefenseEventCollector.return_results')


class TestMain:
    def test_command_not_implemented(self, mocker, return_error_mock):
        demisto_input_mocker(mocker, 'not_implemented')
        main()
        return_error_mock.assert_called_once()
        assert 'command not_implemented is not implemented.' in return_error_mock.call_args.args[0]

    def test_unauthenticated(self, mocker, return_error_mock, requests_mock):
        demisto_input_mocker(mocker, 'test-module')
        requests_mock.get('/api/dnsdata/v2/dns_event', status_code=401, json={'i dont': 'really care'})
        main()
        return_error_mock.assert_called_once()
        assert return_error_mock.call_args.args[0] == 'authentication error please check your API key and try again.'

    def test_test_module_happy_flow(self, mocker, return_results_mock, requests_mock):
        demisto_input_mocker(mocker, 'test-module')
        requests_mock.get('/api/dnsdata/v2/dns_event', json={
            "result": []
        })
        main()
        return_results_mock.assert_called_once_with('ok')

    def test_fetch_events_happy_flow(self, mocker, requests_mock):
        demisto_input_mocker(mocker, 'fetch-events')
        requests_mock.get('/api/dnsdata/v2/dns_event', json={
            "result": [{'event_time': 'event_time'}]
        })
        send_events_to_xsiam_mock = mocker.patch('InfobloxBloxOneThreatDefenseEventCollector.send_events_to_xsiam')
        main()
        send_events_to_xsiam_mock.assert_called_once_with(
            [{'_time': 'event_time', 'event_time': 'event_time'}], 'Infoblox BloxOne', 'Threat Defense')

    def test_get_events_and_send_to_server_happy_flow(self, mocker, requests_mock, return_results_mock):
        demisto_input_mocker(mocker, 'bloxone-td-event-collector-get-events',
                             args={'from': 'from', 'to': 'to', 'should_push_events': 'yes'})
        requests_mock.get('/api/dnsdata/v2/dns_event', json={
            "result": [{'event_time': 'event_time'}]
        })
        send_events_to_xsiam_mock = mocker.patch('InfobloxBloxOneThreatDefenseEventCollector.send_events_to_xsiam')
        main()
        send_events_to_xsiam_mock.assert_called_once_with(
            [{'_time': 'event_time', 'event_time': 'event_time'}], 'Infoblox BloxOne', 'Threat Defense')
        assert return_results_mock.call_args.args[0].outputs == [{'_time': 'event_time', 'event_time': 'event_time'}]
        assert return_results_mock.call_args.args[0].outputs_prefix == "TestGetEvents"

    def test_get_events_without_send_to_server_happy_flow(self, mocker, requests_mock, return_results_mock):
        demisto_input_mocker(mocker, 'bloxone-td-event-collector-get-events',
                             args={'from': 'from', 'to': 'to', 'should_push_events': 'no'})
        requests_mock.get('/api/dnsdata/v2/dns_event', json={
            "result": [{'event_time': 'event_time'}]
        })
        send_events_to_xsiam_mock = mocker.patch('InfobloxBloxOneThreatDefenseEventCollector.send_events_to_xsiam')
        main()
        assert send_events_to_xsiam_mock.call_count == 0
        assert return_results_mock.call_args.args[0].outputs == [{'_time': 'event_time', 'event_time': 'event_time'}]
        assert return_results_mock.call_args.args[0].outputs_prefix == "TestGetEvents"

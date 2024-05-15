import datetime
import pytest
import demistomock as demisto
from unittest.mock import patch
from CommonServerPython import arg_to_datetime, CommandResults, tableToMarkdown, pascalToSpace, DemistoException
from OracleCloudInfrastructureEventCollector import DATE_FORMAT, Client
from freezegun import freeze_time
import json


@pytest.fixture
def dummy_client(mocker):
    """
    Returns a dummy client for testing.
    """
    mocker.patch.object(Client, 'build_singer_object', return_value='dummy_singer_object')
    mocker.patch.object(Client, 'build_audit_base_url', return_value='dummy_audit_base_url')
    return Client(
        verify_certificate=False, proxy=False, region='dummy_region', tenancy_ocid='dummy_tenancy_ocid',
        private_key='dummy_private_key', user_ocid='dummy_use_ocid', key_fingerprint='dummy_key_fingerprint',
        compartment_id='', private_key_type='PKCS#8'
    )


def mock_demisto(mocker, mock_params, mock_args, command, mock_last_run):
    """ Mocks demisto module for testing.

    Args:
        mock_params (dict): Mocked integration parameters.
        mock_args (args): Mocked command arguments.
        command (str): Mocked command.
        mock_last_run (dict): Mocked last run.
    """
    mocker.patch.object(demisto, 'params', return_value=mock_params)
    mocker.patch.object(demisto, 'args', return_value=mock_args)
    mocker.patch.object(demisto, 'command', return_value=command)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'getLastRun', return_value=mock_last_run)


class MockResponse:
    """
    Represents a response from the Oracle Cloud Infrastructure API.
    """
    class HeadersClass:
        def __init__(self):
            self._store = {'opc-next-page': ''}

    def __init__(self, content):
        self.content = json.dumps(content)
        self.headers = self.HeadersClass()


class TestClientRelatedFunctions:
    """ Tests the Client related functions. """

    def test_build_singer_object(self, mocker):
        """
        Given:
            - Valid Client object parameters are provided.
        When:
            - Building a singer object during the Client initialization.
        Then:
            - Make sure the singer object is built successfully.
        """
        mocker.patch.object(Client, 'build_audit_base_url', return_value='dummy_audit_base_url')
        mocker.patch('OracleCloudInfrastructureEventCollector.Signer', return_value='dummy_singer_object')
        mocker.patch.object(Client, 'validate_private_key_syntax', return_value='dummy_validated_private_key')
        client = Client(
            verify_certificate=False, proxy=False, region='dummy_region', tenancy_ocid='dummy_tenancy_ocid',
            private_key='dummy_private_key', user_ocid='dummy_use_ocid', key_fingerprint='dummy_key_fingerprint',
            compartment_id='', private_key_type='PKCS#8'
        )

        assert client.build_singer_object(
            user_ocid='dummy_use_ocid', private_key='dummy_private_key', key_fingerprint='dummy_key_fingerprint',
            tenancy_ocid='dummy_tenancy_ocid', private_key_type='PKCS#8') == 'dummy_singer_object'

    def test_build_singer_object_fail(self, mocker):
        """
        Given:
            - Invalid Client object parameters are provided.
        When:
            - Building a singer object during the Client initialization.
        Then:
            - Make sure the singer object will not be built, and a DemistoException will be raised with a relevant message.
        """
        mocker.patch.object(Client, 'build_audit_base_url', return_value='dummy_audit_base_url')
        mocker.patch('OracleCloudInfrastructureEventCollector.Signer', side_effect=Exception('dummy_exception'))
        mocker.patch.object(Client, 'validate_private_key_syntax', return_value='dummy_validated_private_key')

        with pytest.raises(DemistoException, match='Could not create a valid OCI singer object'):
            Client(
                verify_certificate=False, proxy=False, region='dummy_region', tenancy_ocid='dummy_tenancy_ocid',
                private_key='dummy_private_key', user_ocid='dummy_use_ocid', key_fingerprint='dummy_key_fingerprint',
                compartment_id='', private_key_type='PKCS#8'
            )

    @patch('OracleCloudInfrastructureEventCollector.PORT', '000')
    def test_build_audit_base_url(self, mocker):
        """
        Given:
            - Valid Client object parameters are provided.
        When:
            - Building audit base url during the Client initialization.
        Then:
            - Make sure the audit base url is built successfully.
        """
        mocker.patch.object(Client, 'build_singer_object', return_value='dummy_singer_object')
        mocker.patch('OracleCloudInfrastructureEventCollector.is_region', return_value=True)
        client = Client(
            verify_certificate=False, proxy=False, region='dummy_region', tenancy_ocid='dummy_tenancy_ocid',
            private_key='dummy_private_key', user_ocid='dummy_use_ocid', key_fingerprint='dummy_key_fingerprint',
            compartment_id='', private_key_type='PKCS#8'
        )

        assert client.build_audit_base_url('dummy_region') == 'https://audit.dummy_region.oraclecloud.com/000/auditEvents'

    @patch('OracleCloudInfrastructureEventCollector.PORT', '000')
    def test_build_audit_base_url_fail(self, mocker):
        """
        Given:
            - Invalid Client object parameters are provided.
        When:
            - Building audit base url during the Client initialization.
        Then:
            - Make sure the audit base url will not be built, and a DemistoException will be raised with a relevant message.
        """
        mocker.patch.object(Client, 'build_singer_object', return_value='dummy_singer_object')
        mocker.patch('OracleCloudInfrastructureEventCollector.is_region', return_value=False)
        with pytest.raises(DemistoException, match='Could not create a valid OCI configuration'):
            Client(
                verify_certificate=False, proxy=False, region='dummy_region', tenancy_ocid='dummy_tenancy_ocid',
                private_key='dummy_private_key', user_ocid='dummy_use_ocid', key_fingerprint='dummy_key_fingerprint',
                compartment_id='', private_key_type='PKCS#8'
            )

    case_validate_private_key = (
        '-----BEGIN PRIVATE KEY-----\nCONTENT\n-----END PRIVATE KEY-----',
        'PKCS#8',
        '-----BEGIN PRIVATE KEY-----\nCONTENT\n-----END PRIVATE KEY-----')
    case_doubled_new_line_private_key = (
        '-----BEGIN PRIVATE KEY-----\n\nCONTENT\n\n-----END PRIVATE KEY-----',
        'PKCS#8',
        '-----BEGIN PRIVATE KEY-----\nCONTENT\n-----END PRIVATE KEY-----')
    case_escaped_private_key = (
        '-----BEGIN PRIVATE KEY-----\\nCONTENT\\n-----END PRIVATE KEY-----',
        'PKCS#8',
        '-----BEGIN PRIVATE KEY-----\nCONTENT\n-----END PRIVATE KEY-----')
    case_escaped_and_doubled_new_line_private_key = (
        '-----BEGIN PRIVATE KEY-----\\n\nCONTENT\n\\n-----END PRIVATE KEY-----',
        'PKCS#8',
        '-----BEGIN PRIVATE KEY-----\nCONTENT\n-----END PRIVATE KEY-----')
    case_validate_private_key_PKCS1 = (
        '-----BEGIN RSA PRIVATE KEY-----\nCONTENT\n-----END RSA PRIVATE KEY-----',
        'PKCS#1',
        '-----BEGIN RSA PRIVATE KEY-----\nCONTENT\n-----END RSA PRIVATE KEY-----')

    @pytest.mark.parametrize('private_key, private_key_type, expected_result',
                             [case_validate_private_key,
                              case_doubled_new_line_private_key,
                              case_escaped_private_key,
                              case_escaped_and_doubled_new_line_private_key,
                              case_validate_private_key_PKCS1])
    def test_validate_private_key_syntax(self, mocker, private_key, private_key_type, expected_result):
        """
        Given:
            - A private key parameter and a private_key_type are provided.
        When:
            - Creating a Client object.
        Then:
            - Make sure the private key is validated successfully.
        """
        mocker.patch.object(Client, 'build_singer_object', return_value='dummy_singer_object')
        mocker.patch.object(Client, 'build_audit_base_url', return_value='dummy_audit_base_url')
        client = Client(
            verify_certificate=False, proxy=False, region='dummy_region', tenancy_ocid='dummy_tenancy_ocid',
            private_key='dummy_private_key', user_ocid='dummy_use_ocid', key_fingerprint='dummy_key_fingerprint',
            compartment_id='', private_key_type=private_key_type
        )

        assert client.validate_private_key_syntax(private_key, private_key_type) == expected_result


class TestEventRelatedFunctions:
    """ Tests for the event related functions. """

    dummy_datetime = arg_to_datetime('2023-01-01T10:10:10.000Z', settings={'RETURN_AS_TIMEZONE_AWARE': False})

    def test_add_time_key_to_events(self):
        """
        Given:
            - case 1: An empty list of events.
            - case 2: A list of events containing an event with eventTime key.
            - case 3: A list of events containing an event without eventTime key.

        When:
            - Fetching events.

        Then:
            - Make sure any events containing eventTime key are returned with an additional key named _time.
        """
        from OracleCloudInfrastructureEventCollector import add_time_key_to_events
        dummy_time = '2023-01-01T10:10:10.000Z'
        dummy_events_list: list = []
        assert add_time_key_to_events(dummy_events_list) == []

        dummy_events_list.append({'eventTime': dummy_time})
        assert add_time_key_to_events(dummy_events_list) == [{'eventTime': dummy_time, '_time': dummy_time}]

        dummy_events_list.append({'dummy_data': 'dummy_data'})
        assert add_time_key_to_events(dummy_events_list) == [
            {'eventTime': dummy_time, '_time': dummy_time},
            {'dummy_data': 'dummy_data'}]

    def test_get_last_event_time(self):
        """
        Given:
            - case 1: An empty list of events.
            - case 2: A list of events containing an event with larger eventTime key value than first_fetch_time.

        When:
            - Getting the last event time.

        Then:
            - Make sure the most recent event time is returned in the correct format.
            - Make sure that 1 millisecond to the most recent event time.
        """
        from OracleCloudInfrastructureEventCollector import get_last_event_time
        first_fetch_dummy_time = arg_to_datetime(arg='2023-01-01T10:10:10.000Z')
        larger_dummy_time = arg_to_datetime(arg='2023-01-01T12:10:10.000Z')
        smaller_dummy_time = arg_to_datetime(arg='2023-01-01T08:11:10.000Z')

        dummy_event_list: list = []
        if not isinstance(first_fetch_dummy_time, datetime.datetime) or not isinstance(larger_dummy_time, datetime.datetime):
            raise ValueError('Test Failed: datetime value is None, while a datetime object is expected.')
        assert get_last_event_time(
            events=dummy_event_list, first_fetch_time=first_fetch_dummy_time) == first_fetch_dummy_time.strftime(DATE_FORMAT)

        dummy_event_list.extend([{'eventTime': smaller_dummy_time}, {'eventTime': larger_dummy_time}])
        assert get_last_event_time(events=dummy_event_list, first_fetch_time=first_fetch_dummy_time) == (
            larger_dummy_time + datetime.timedelta(milliseconds=1)).strftime(DATE_FORMAT)

    case_last_run_is_none = (
        None, '2023-01-01T10:10:10.000',
        arg_to_datetime(arg='2023-01-01T10:10:10.000Z', settings={'RETURN_AS_TIMEZONE_AWARE': False}))
    case_last_run_and_first_fetch_param_are_none = (None, None, None)
    case_last_run_is_bigger = (
        '2023-01-01T12:10:10.000Z', '2023-01-01T10:10:10.000',
        arg_to_datetime(arg='2023-01-01T12:10:10.000Z', settings={'RETURN_AS_TIMEZONE_AWARE': False}))
    case_first_fetch_param_is_bigger = (
        '2023-01-01T10:10:10.000Z', '2023-01-01T12:10:10.000',
        arg_to_datetime(arg='2023-01-01T12:10:10.000Z', settings={'RETURN_AS_TIMEZONE_AWARE': False}))

    @pytest.mark.parametrize('last_run, first_fetch_param, expected_time', [
        case_last_run_is_none,
        case_last_run_and_first_fetch_param_are_none,
        case_last_run_is_bigger,
        case_first_fetch_param_is_bigger
    ])
    def test_get_fetch_time(self, last_run, first_fetch_param, expected_time):
        """
        Given:
            - case 1: last_run is None and first_fetch_param is not None.
            - case 2: last_run and first_fetch_param are None.
            - case 3: last_run is bigger than first_fetch_param.
            - case 4: first_fetch_param is bigger than last_run.
        When:
            - Calculating the fetch time.
        Then:
            - Make sure the fetch time is the bigger value between last_run and first_fetch_param.
        """
        from OracleCloudInfrastructureEventCollector import get_fetch_time
        assert get_fetch_time(last_run, first_fetch_param) == expected_time

    def test_events_to_command_results(self):
        """
        Given:
            - A list of events.
        When:
            - Using the oracle-cloud-infrastructure-get-events command.
        Then:
            - Make sure the human readable output in the war room is as expected.
        """
        from OracleCloudInfrastructureEventCollector import events_to_command_results
        dummy_events_list = [{'dummy_data1': 'dummy_data'}, {'dummy_data1': 'dummy_data'}]
        expected_result = CommandResults(
            readable_output=tableToMarkdown(
                'Oracle Cloud Infrastructure Events', dummy_events_list, removeNull=True,
                headerTransform=pascalToSpace), raw_response=dummy_events_list)
        assert events_to_command_results(events=dummy_events_list).readable_output == expected_result.readable_output

    def test_add_millisecond_to_timestamp(self):
        """
        Given:
            - A valid timestamp in the correct format.
        When:
            - Calculating the next fetch time.
        Then:
            - Make sure the returned timestamp is 1 millisecond bigger than the given timestamp and in the correct format.
        """
        from OracleCloudInfrastructureEventCollector import add_millisecond_to_timestamp
        assert add_millisecond_to_timestamp('2023-01-01T10:10:10.000Z') == '2023-01-01T10:10:10.001000Z'

    def test_add_millisecond_to_timestamp_fail(self, mocker):
        """
        Given:
            - A timestamp in the wrong format.
        When:
            - Calculating the next fetch time.
        Then:
            - Make sure the function raises an error.
        """
        from OracleCloudInfrastructureEventCollector import add_millisecond_to_timestamp
        mocker.patch('OracleCloudInfrastructureEventCollector.arg_to_datetime', return_value=None)
        with pytest.raises(DemistoException) as e:
            add_millisecond_to_timestamp('dummy_time')
            assert str(e.value) == 'Datetime conversion failed.'

    @freeze_time('2023-01-01T10:10:10.000Z')
    def test_audit_log_api_request(self, mocker, dummy_client):
        """
        Given:
            - Valid request parameters.
        When:
            - Making an audit log API request.
        Then:
            - Make sure the request is sent with the correct parameters.
        """
        from OracleCloudInfrastructureEventCollector import audit_log_api_request
        mocked_http_request = mocker.patch.object(dummy_client, '_http_request', return_value={'data': 'dummy_data'})
        audit_log_api_request(dummy_client, start_time='2023-01-01T10:10:10.000Z', next_page='dummy_next_page')
        expected_params = {
            'compartmentId': dummy_client.compartment_id,
            'startTime': '2023-01-01T10:10:10.000Z',
            'endTime': datetime.datetime.now().strftime(DATE_FORMAT),
            'next_page': 'dummy_next_page'
        }
        assert mocked_http_request.called_with(expected_params)

    @freeze_time('2023-01-01T10:10:10.000Z')
    def test_audit_log_api_request_check_compartment_id(self, mocker):
        """
        Given:
            - Valid request parameters.
        When:
            - Making an audit log API request.
        Then:
            - Make sure the request is sent with the correct parameters, especcially the correct compartment_id.
        """
        from OracleCloudInfrastructureEventCollector import audit_log_api_request
        mocker.patch.object(Client, 'build_audit_base_url', return_value='dummy_audit_base_url')
        mocker.patch('OracleCloudInfrastructureEventCollector.Signer', return_value='dummy_singer_object')
        mocker.patch.object(Client, 'validate_private_key_syntax', return_value='dummy_validated_private_key')
        client = Client(
            verify_certificate=False, proxy=False, region='dummy_region', tenancy_ocid='dummy_tenancy_ocid',
            private_key='dummy_private_key', user_ocid='dummy_use_ocid', key_fingerprint='dummy_key_fingerprint',
            compartment_id='dummy_compartment_id', private_key_type='PKCS#8'
        )
        mocked_http_request = mocker.patch.object(client, '_http_request', return_value={'data': 'dummy_data'})
        audit_log_api_request(client, start_time='2023-01-01T10:10:10.000Z', next_page='dummy_next_page')
        expected_params = {
            'compartmentId': client.compartment_id,
            'startTime': '2023-01-01T10:10:10.000Z',
            'endTime': datetime.datetime.now().strftime(DATE_FORMAT),
            'next_page': 'dummy_next_page'
        }
        assert client.compartment_id == 'dummy_compartment_id'
        assert mocked_http_request.called_with(expected_params)

    @pytest.mark.parametrize('events', ([{'dummy_data': 'dummy_data'}], []))
    def test_handle_fetched_events(self, mocker, events):
        """
        Given:
            - case 1: A non-empty list of fetched events.
            - case 2: An empty list of fetched events.
        When:
            - Sending the fetched events to XSIAM.
        Then:
            - Make sure the events are sent to XSIAM as expected.
        """
        from OracleCloudInfrastructureEventCollector import handle_fetched_events
        mocked_send_events_to_xsiam = mocker.patch('OracleCloudInfrastructureEventCollector.send_events_to_xsiam')
        mocked_demisto_set_last_run = mocker.patch('OracleCloudInfrastructureEventCollector.demisto.setLastRun')
        handle_fetched_events(events=events, last_event_time='2023-01-01T10:10:10.000Z')
        assert mocked_send_events_to_xsiam.called
        assert mocked_send_events_to_xsiam.call_args.args[0] == events
        assert mocked_send_events_to_xsiam.call_args[1] == {'vendor': 'oracle', 'product': 'cloud_infrastructure'}
        if events:
            assert mocked_demisto_set_last_run.called
            assert mocked_demisto_set_last_run.call_args.args[0] == {'lastRun': '2023-01-01T10:10:10.000Z'}

    case_empty_list_of_events = (
        [],
        dummy_datetime,
        5,
        [],
        '2023-01-01T10:10:10.000000Z')
    case_list_with_one_event = (
        [{'eventTime': '2023-01-01T11:10:10.000Z'}],
        dummy_datetime,
        5,
        [{'eventTime': '2023-01-01T11:10:10.000Z', '_time': '2023-01-01T11:10:10.000Z'}],
        '2023-01-01T11:10:10.001000Z')
    case_list_with_two_events = (
        [{'eventTime': '2023-01-01T11:10:10.000Z'},
         {'eventTime': '2023-01-01T12:10:10.000Z'}],
        dummy_datetime,
        5,
        [{'eventTime': '2023-01-01T11:10:10.000Z', '_time': '2023-01-01T11:10:10.000Z'},
         {'eventTime': '2023-01-01T12:10:10.000Z', '_time': '2023-01-01T12:10:10.000Z'}],
        '2023-01-01T12:10:10.001000Z')

    @pytest.mark.parametrize('event_list, first_fetch_time, max_fetch, expected_events, expected_last_event_time',
                             [case_empty_list_of_events, case_list_with_one_event, case_list_with_two_events])
    def test_get_events(
            self, mocker, dummy_client, event_list, first_fetch_time, max_fetch, expected_events,
            expected_last_event_time):
        """
        Given:
            - case 1: An empty list of events is returned from the audit log API.
            - case 2: A list with one event is returned from the audit log API.
            - case 3: A list with two or more events is returned from the audit log API.
        When:
            - Fetching events from the audit log API.
        Then:
            - Make sure the events are returned in the correct format as a list of dictionaries.
            - Make sure the last event time is returned in the correct date format.
            - All events with eventTime key are added with _time key.
        """
        from OracleCloudInfrastructureEventCollector import get_events
        mocked_response = MockResponse(content=event_list)
        mocker.patch('OracleCloudInfrastructureEventCollector.audit_log_api_request', return_value=mocked_response)
        events, last_event_time = get_events(
            client=dummy_client, first_fetch_time=first_fetch_time, max_fetch=max_fetch, push_events_on_error=False)
        assert (events, last_event_time) == (expected_events, expected_last_event_time)

    def test_get_events_fail_without_events(self, mocker, dummy_client, dummy_datetime=dummy_datetime):
        """
        Given:
            - An API request fails, and no new events are currently available.
        When:
            - Fetching events from the audit log API.
        Then:
            - Make sure an exception is raised.
        """
        from OracleCloudInfrastructureEventCollector import get_events
        mocker.patch('OracleCloudInfrastructureEventCollector.audit_log_api_request', side_effect=Exception)
        if not isinstance(dummy_datetime, datetime.datetime):
            raise ValueError('first_date_time is not a datetime object')
        with pytest.raises(Exception):
            get_events(client=dummy_client, first_fetch_time=dummy_datetime, max_fetch=5)

    def test_get_events_fail_with_events(self, mocker, dummy_client, dummy_datetime=dummy_datetime):
        """
        Given:
            - An API request fails, and new events are available.
        When:
            - Fetching events from the audit log API.
        Then:
            - Make sure the new events are handled and returned to XSIAM.
            - Make sure an exception is raised.
        """
        from OracleCloudInfrastructureEventCollector import get_events
        mocked_response = MockResponse(content=[{'eventTime': '2023-01-01T11:10:10.000Z'}])
        mocked_response.headers._store['opc-next-page'] = 'next_page'
        mocker.patch('OracleCloudInfrastructureEventCollector.audit_log_api_request',
                     side_effect=[mocked_response, Exception])
        first_date_time = dummy_datetime
        if not isinstance(first_date_time, datetime.datetime):
            raise ValueError('first_date_time is not a datetime object')
        with pytest.raises(Exception):
            get_events(client=dummy_client, first_fetch_time=first_date_time, max_fetch=5, push_events_on_error=False)


class TestFetchEventsFlows:
    """ Test class for the fetch events flows. """
    params = {'tenancy_ocid': 'dummy_tenancy_ocid',
              'user_ocid': 'dummy_user_ocid',
              'region': 'dummy_region',
              'max_fetch': '5',
              'first_fetch': '3 day',
              'credentials': {"identifier": "dummy_key_fingerprint",
                              "password": "dummy_private_key"}
              }

    case_first_fetch_with_events = (
        [{'eventTime': '2023-01-01T09:10:10.000Z'},
         {'eventTime': '2023-01-01T10:10:10.000Z'},
         {'eventTime': '2023-01-01T11:10:10.000Z'}],
        [{'eventTime': '2023-01-01T09:10:10.000Z', '_time': '2023-01-01T09:10:10.000Z'},
         {'eventTime': '2023-01-01T10:10:10.000Z', '_time': '2023-01-01T10:10:10.000Z'},
         {'eventTime': '2023-01-01T11:10:10.000Z', '_time': '2023-01-01T11:10:10.000Z'}],
        '2023-01-01T11:10:10.001000Z',
        params,
        {})

    case_second_fetch_with_events = (
        [{'eventTime': '2023-01-01T09:10:10.000Z'},
         {'eventTime': '2023-01-01T10:10:10.000Z'},
         {'eventTime': '2023-01-01T11:10:10.000Z'}],
        [{'eventTime': '2023-01-01T09:10:10.000Z', '_time': '2023-01-01T09:10:10.000Z'},
         {'eventTime': '2023-01-01T10:10:10.000Z', '_time': '2023-01-01T10:10:10.000Z'},
         {'eventTime': '2023-01-01T11:10:10.000Z', '_time': '2023-01-01T11:10:10.000Z'}],
        '2023-01-01T11:10:10.001000Z',
        params,
        {'lastRun': '2023-01-01T08:10:10.001000Z'})

    case_second_fetch_no_events = ([], [], '2023-01-01T08:10:10.001000Z', params,
                                   {'lastRun': '2023-01-01T08:10:10.001000Z'})

    case_first_fetch_no_events = ([], [], '2022-12-29T08:10:10.001000Z', params, {})

    @freeze_time('2023-01-01T08:10:10.001000Z')
    @pytest.mark.parametrize('event_list, expected_list, expected_time, params, last_run',
                             [case_first_fetch_with_events,
                              case_second_fetch_with_events,
                              case_second_fetch_no_events,
                              case_first_fetch_no_events])
    def test_fetch_events(self, mocker, dummy_client, event_list, expected_list, expected_time, params, last_run):
        """
        Given:
            - case 1: first fetch with events
            - case 2: second fetch with events
            - case 3: second fetch with no events
            - case 4: first fetch with no events
        When:
            - Fetching events from the audit log API using the fetch-events command.
        Then:
            - Make sure the new events are handled and returned to XSIAM.
            - Make sure the last run time is updated if needed.
        """
        from OracleCloudInfrastructureEventCollector import main
        mock_demisto(mocker, mock_params=params, mock_args={}, command='fetch-events', mock_last_run=last_run)
        mocked_response = MockResponse(content=event_list)
        mocker.patch('OracleCloudInfrastructureEventCollector.audit_log_api_request', return_value=mocked_response)
        mocked_handle_fetched_events = mocker.patch('OracleCloudInfrastructureEventCollector.handle_fetched_events')
        main()
        mocked_handle_fetched_events.assert_called_once_with(expected_list, expected_time)

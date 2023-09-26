"""HelloWorld Integration for Cortex XSOAR - Unit Tests file

This file contains the Unit Tests for the HelloWorld Integration based
on pytest. Cortex XSOAR contribution requirements mandate that every
integration should have a proper set of unit tests to automatically
verify that the integration is behaving as expected during CI/CD pipeline.

Test Execution
--------------

Unit tests can be checked in 3 ways:
- Using the command `lint` of demisto-sdk. The command will build a dedicated
  docker instance for your integration locally and use the docker instance to
  execute your tests in a dedicated docker instance.
- From the command line using `pytest -v` or `pytest -vv`
- From PyCharm

Example with demisto-sdk (from the content root directory):
demisto-sdk lint -i Packs/HelloWorld/Integrations/HelloWorld

Coverage
--------

There should be at least one unit test per command function. In each unit
test, the target command function is executed with specific parameters and the
output of the command function is checked against an expected output.

Unit tests should be self contained and should not interact with external
resources like (API, devices, ...). To isolate the code from external resources
you need to mock the API of the external resource using pytest-mock:
https://github.com/pytest-dev/pytest-mock/

In the following code we configure requests-mock (a mock of Python requests)
before each test to simulate the API calls to the HelloWorld API. This way we
can have full control of the API behavior and focus only on testing the logic
inside the integration code.

We recommend to use outputs from the API calls and use them to compare the
results when possible. See the ``test_data`` directory that contains the data
we use for comparison, in order to reduce the complexity of the unit tests and
avoding to manually mock all the fields.

NOTE: we do not have to import or build a requests-mock instance explicitly.
requests-mock library uses a pytest specific mechanism to provide a
requests_mock instance to any function with an argument named requests_mock.

More Details
------------

More information about Unit Tests in Cortex XSOAR:
https://xsoar.pan.dev/docs/integrations/unit-testing

"""

import json
from CommonServerPython import DemistoException
from HelloWorld import (Client, ip_reputation_command, item_list_command, validate_api_key,
                        dedup_by_ids, incident_note_create_command)
import pytest


EXAMPLE_RES_LIST = [{
    "id": 1,
    "incident_id": 1000,
    "kind": "Realtime",
    "date": "2021-05-20T12:40:55.662949Z",
},
    {
    "id": 2,
    "incident_id": 2000,
    "kind": "Realtime",
    "date": "2021-05-20T12:40:56.662949Z"
},
    {
    "id": 3,
    "incident_id": 3000,
    "kind": "Realtime",
    "date": "2021-05-20T12:40:57.662949Z"
},
    {
    "id": 4,
    "incident_id": 4000,
    "kind": "Realtime",
    "date": "2021-05-20T12:40:58.662949Z"
},
]


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def create_mock_client():
    return Client(
        base_url='https://api.example.com',
        verify=False,
        headers={
            'Authentication': 'Token some_api_key'
        }
    )


def test_say_hello():
    """
    Tests helloworld-say-hello command function.

        Given:
            - No mock is needed here because the say_hello_command does not call any external API.

        When:
            - Running the 'say_hello_command'.

        Then:
            - Checks the output of the command function with the expected output.

    """
    from HelloWorld import Client, say_hello_command

    client = Client(base_url='https://test.com/api/v1', verify=False, auth=('test', 'test'))
    args = {
        'name': 'Dbot'
    }
    response = say_hello_command(client, args)

    assert response.outputs == 'Hello Dbot'


@ pytest.mark.parametrize('hello_world_severity, expected_xsoar_severity', [
    ('low', 1), ('medium', 2), ('high', 3), ('critical', 4), ('unknown', 0)


])
def test_convert_to_demisto_severity(hello_world_severity, expected_xsoar_severity):
    """
        Given:
            - A string represent an HelloWorld severity.

        When:
            - Running the 'convert_to_demisto_severity' function.

        Then:
            - Verify that the severity was translated to an XSOAR severity correctly.
    """
    from HelloWorld import convert_to_demisto_severity

    assert convert_to_demisto_severity(hello_world_severity) == expected_xsoar_severity


def test_api_key():
    """Validates an API key. Since this is tutorial, there is a dummy API key.

    When:
        - An API key is provided as a string argument
    Then:
        - The key is checked against known valid keys
        - If invalid, an exception is raised with clear message.
    """
    api_key = "some_api_key"

    with pytest.raises(DemistoException):
        validate_api_key(api_key)


@pytest.mark.parametrize("alerts, ids_to_compare, expected", [
    ([{"id": 1}, {"id": 2}], [2, 3], ([{"id": 1}], 1)),
    ([{"id": 2}, {"id": 3}], [2, 3], ([], 2)),
    ([{"id": 4}, {"id": 5}], [2, 3], ([{"id": 4}, {"id": 5}], 0))
])
def test_dedup_by_ids(alerts, ids_to_compare, expected):
    deduped, dups = dedup_by_ids(alerts, ids_to_compare)
    assert deduped == expected[0]
    assert dups == expected[1]


class TestIPCommand:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.mocked_client = create_mock_client()

    def test_ip_reputation_command_single_ip(self, mocker):
        args = {'ip': '8.8.8.8'}
        mocker.patch.object(self.mocked_client, 'get_ip_reputation', return_value={'attributes': {'reputation': 80}})

        result = ip_reputation_command(self.mocked_client, args, default_threshold=60, reliability='A - Completely reliable')

        assert len(result) == 1
        assert len(result[0].outputs) == 1  # type: ignore
        ip_output = result[0].to_context()['EntryContext']['IP(val.Address && val.Address == obj.Address)']
        assert ip_output
        assert ip_output[0]['Address'] == '8.8.8.8'

        dbot_output = result[0].to_context()['EntryContext'][
            'DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)']
        assert dbot_output[0]['Indicator'] == '8.8.8.8'
        assert dbot_output[0]['Score'] == 1

    def test_ip_reputation_command_multiple_ips(self, mocker):
        args = {'ip': ['8.8.8.8', '1.1.1.1']}
        mocker.patch.object(self.mocked_client, 'get_ip_reputation', side_effect=[
            {'attributes': {'reputation': 80}},
            {'attributes': {'reputation': 20}}])

        result = ip_reputation_command(self.mocked_client, args, default_threshold=60, reliability='A - Completely reliable')

        assert len(result) == 2
        dbot_output_1 = result[0].to_context()['EntryContext'][
            'DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)']
        assert dbot_output_1[0]['Score'] == 1
        assert dbot_output_1[0]['Indicator'] == '8.8.8.8'

        dbot_output_2 = result[1].to_context()['EntryContext'][
            'DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)']
        assert dbot_output_2[0]['Indicator'] == '1.1.1.1'
        assert dbot_output_2[0]['Score'] == 3

    def test_ip_reputation_command_invalid_ip(self):
        args = {'ip': 'invalid'}

        with pytest.raises(ValueError):
            ip_reputation_command(self.mocked_client, args, default_threshold=60, reliability='A - Completely reliable')


class TestItemListCommand:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.mocked_client = create_mock_client()

    # DEVELOPER TIP
    # Using the parametrize fixture helps you generate many test cases on the same function,
    # to make sure you are fully covered.
    # Make sure to check all edge-cases such as empty responses, wrong inputs, etc.
    # When using parametrize its optional to add id, which will make test failure much more easy to debug.

    @pytest.mark.parametrize(
        'args, expected_limit, expected_severity',
        (
            pytest.param(
                {"incident_id": 1}, 1, None,
                id="given id"),  # expecting one record
            pytest.param(
                {"incident_id": 2, "severity": 'high'}, 1, 'high',
                id="given id and wrong severity"),  # expecting one record ignoring severity
            pytest.param(
                {"incident_id": 3, "limit": 5}, 1, None,
                id="given id, no severity and limit")  # expecting one record ignoring limit
        ))
    def test_incident_list_given_id(self, mocker, args, expected_limit, expected_severity):
        single_id_call_mock = mocker.patch.object(self.mocked_client, 'get_incident',
                                                  return_value={'id': 1, 'title': 'Incident 1'})

        result = item_list_command(self.mocked_client, args)

        assert result.readable_output.startswith('### Items List (Example Data)')
        assert len(result.outputs) == expected_limit
        single_id_call_mock.assert_called()
        single_id_call_mock.assert_called_once_with(args['incident_id'])

    @pytest.mark.parametrize(
        'args, expected_limit, expected_severity',
        (
            pytest.param(
                {"severity": 'high', "limit": 3}, 3, 'high',
                id="given limit and severity"),
            pytest.param(
                {"limit": 3}, 3, None,
                id="given only limit"),
            pytest.param(
                {}, 10, None,
                id="given empty args"),
        ))
    def test_incident_list(self, mocker, args, expected_limit, expected_severity):
        mocked_list_call = mocker.patch.object(self.mocked_client, 'get_item_list',
                                               return_value=[{'id': 1, 'title': 'Incident 1'},
                                                             {'id': 2, 'title': 'Incident 2'},
                                                             {'id': 3, 'title': 'Incident 3'}])

        result = item_list_command(self.mocked_client, args)

        mocked_list_call.assert_called()
        mocked_list_call.assert_called_once_with(limit=expected_limit, severity=expected_severity)
        assert result.readable_output.startswith('### Items List (Example Data)')  # type: ignore


class TestIncidentNoteCreate:

    @pytest.fixture(autouse=True)
    def init(self):
        self.client = create_mock_client()

    def test_success(self, mocker):
        args = {'incident_id': 123, 'note_text': 'Test note'}
        mocker.patch.object(self.client, 'create_note', return_value={'status': 'success'})

        result = incident_note_create_command(self.client, args)

        assert result.readable_output == 'Note was created successfully.'
        assert result.outputs['status'] == 'success'


# class TestFetchIncidents:
#
#     EXAMPLE_ALERTS = [{'id': 1, 'title': 'Incident 1'},
#                       {'id': 2, 'title': 'Incident 2'},
#                       {'id': 3, 'title': 'Incident 3'}]
#
#     @pytest.fixture(autouse=True)
#     def setup(self):
#         self.client = create_mock_client()
#
#     def test_first_run(self, mocker):
#         mocker.patch.object(self.client, 'get_incident_list_for_fetch', return_value=self.EXAMPLE_ALERTS)
#
#         last_run : dict = {}
#         first_fetch = '2021-01-01T00:00:00Z'
#
#         next_run, incidents = fetch_incidents(
#             self.client,
#             max_results=50,
#             last_run=last_run,
#             first_fetch_time=first_fetch
#         )
#
#         # Assertions
#         assert len(incidents) == 3
#         assert incidents[0]['name'] == 'test'
#         # etc
#
#     def test_subsequent_run(self, mock_client):
#         last_run = {'last_fetch': '2021-01-01T01:00:00Z'}
#         first_fetch = '2021-01-01T00:00:00Z'
#
#         next_run, incidents = fetch_incidents(self.client,
#                                               max_results=2, last_run=last_run, first_fetch_time=first_fetch)
#
#         # Assertions
#         assert incidents[0]['date'] > last_run['last_fetch']
#         # etc

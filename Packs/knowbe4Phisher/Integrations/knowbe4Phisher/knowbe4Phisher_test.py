import knowbe4Phisher as phisher
import pytest
from test_data.mock_tests import *
import json


def util_load_json(path):
    with open(path, mode='r', encoding='utf-8') as f:
        return json.load(f)


client = phisher.Client(base_url='https://eu.test.com/graphql', verify=False,
                        headers={'Authorization': 'Bearer  + key', 'Content-Type': 'application/json'},
                        proxy=False, first_fetch_time="100 days")


@pytest.mark.parametrize("test_input, expected", create_request_test)
def test_create_request(test_input, expected):
    """
        Given:
        - A human readable query for GQL

        When:
        - Creating GQL request

        Then:
        - Ensure that query created as expected
        """
    res = phisher.create_gql_request(test_input)
    assert res == expected


calculate_events = [
    ('\\" reported_at:[2021-07-01T16:51:45Z TO *]\\"', '13', pagination_response[0]),
    ('\\" reported_at:[2021-07-01T16:51:45Z TO *]\\"', '31', pagination_response[1])]


@pytest.mark.parametrize("query, expected, return_value", calculate_events)
def test_caclulate_event(mocker, query, expected, return_value):
    """
        Given:
        - A result of api response from PhishER that contains number of messages

        When:
         - When calculating number of events before fetch

        Then:
         - Ensure that the number of messages is returned as expected
        """
    mocker.patch.object(client, "phisher_gql_request", return_value=return_value)
    result = phisher.calculate_number_of_events(client, query)
    assert result == expected


test_fetch = [({"last_fetch": None}, "30 days", '50', expected_fetch[0], response_fetch[0]),
              ({"last_fetch": None}, "30 days", '50', expected_fetch[1], response_fetch[1])]


@pytest.mark.parametrize("last_run, first_fetch, max_fetch, expected, respon", test_fetch)
def test_fetch_incidents(mocker, last_run, first_fetch, max_fetch, expected, respon):
    """
        Given:
        - Phisher Integration Parameters

        When:
        - Fetching incidents.

        Then:
        - Ensure that the incidents returned are as expected.
        """
    mocker.patch.object(client, "phisher_gql_request", return_value=respon)
    _, result = phisher.fetch_incidents(client, last_run, first_fetch, max_fetch)
    assert result == expected


def test_time_creation():
    """
        Given:
        - Events example from Phisher Response

        When:
        - when fetching messages from Phisher - fetch or list of all messages

        Then:
        - Ensure that the event time is extracted as expected
        """
    result = phisher.get_created_time(events_example)
    assert result == expected_time


mock_responses = util_load_json('test_data/test_responses.json')
command_results = util_load_json('test_data/mock_responses.json')


@pytest.mark.parametrize(
    'function_to_test, function_to_mock, args, key', [
        (phisher.phisher_message_list_command, 'phisher_gql_request', {}, 'message_list_all'),
    ])
def test_commands_with_results(mocker, function_to_test, function_to_mock, args, key):
    expected_res = mock_responses[key]
    mocker.patch.object(client, function_to_mock, return_value=command_results[key])
    result: CommandResults = function_to_test(client, args)
    assert result.outputs == expected_res


@pytest.mark.parametrize(
    'function_to_test, function_to_mock, args, key',
    [
        (phisher.phisher_create_comment_command, 'phisher_gql_request', {"id": "cff35e34-aeb6-4263-b592-c68fc03ea7cb",
                                                                         "comment": "Infinity Test"}, "create_comment"),
        (phisher.phisher_update_message_command, 'phisher_gql_request', {"id": "cff35e34-aeb6-4263-b592-c68fc03ea7cb",
                                                                         "category": "SPAM", "status": "RESOLVED", "severity":
                                                                         "HIGH"}, "update_message"),
        (phisher.phisher_create_tags_command, 'phisher_gql_request', {"id": "cff35e34-aeb6-4263-b592-c68fc03ea7cb",
                                                                      "tags": "Test Tag"}, "create_tags"),
        (phisher.phisher_delete_tags_command, 'phisher_gql_request', {"id": "cff35e34-aeb6-4263-b592-c68fc03ea7cb",
                                                                      "tags": "Test Tag"}, "delete_tags")
    ])
def test_commands_no_results(mocker, function_to_test, function_to_mock, args, key):
    expected_res = mock_responses[key]
    mocker.patch.object(client, function_to_mock, return_value=command_results[key])
    result = function_to_test(client, args)
    assert result == expected_res

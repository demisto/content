import json
from datetime import datetime, timedelta
from freezegun import freeze_time

import pytest
from WorkdayEventCollector import Client, DATE_FORMAT


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


class TestFetchActivity:
    @pytest.fixture(autouse=True)
    def create_client(self, mocker):
        self.base_url = "https://test.com"
        self.tenant_name = "test"
        self.token_url = f'{self.base_url}/ccx/oauth2/{self.tenant_name}/token'
        mocker.patch.object(Client, 'get_access_token', return_value="1234")
        self.client = Client(base_url=self.base_url,
                             refresh_token='refresh_token',
                             client_id="test12",
                             client_secret="test_sec1234",
                             token_url=self.token_url,
                             verify=False,
                             proxy=False,
                             headers={
                                 'Accept': 'application/json',
                                 'Content-Type': 'application/json'
                             },
                             max_fetch=25000)

    @staticmethod
    def create_response_by_limit(from_date, to_date, offset, user_activity_entry_count=False, limit=1):
        single_response = util_load_json('test_data/single_loggings_response.json')
        return [single_response.copy() for i in range(limit)]

    @staticmethod
    def create_response_with_duplicates(request_time, limit, number_of_different_time, id_to_start_from):
        """
        Creates response with different requestTime and ids.
        Args:
            request_time: request time to start from.
            limit: number of responses
            number_of_different_time: number of responses with different requestTime
            id_to_start_from: id to start from

        """
        single_response = util_load_json('test_data/single_loggings_response.json')
        request_time_date_time = datetime.strptime(request_time, DATE_FORMAT)
        output = []

        def create_single(single_response, time, id, output):
            single_response['requestTime'] = time
            single_response['taskId'] = str(id)
            output.append(single_response)
            id += 1
            return output, id

        for i in range(limit - number_of_different_time):
            output, id_to_start_from = create_single(single_response.copy(), request_time, id_to_start_from, output)
        for i in range(limit - number_of_different_time, limit):
            new_time = datetime.strftime(request_time_date_time + timedelta(seconds=10), DATE_FORMAT)
            output, id_to_start_from = create_single(single_response.copy(),
                                                     new_time,
                                                     id_to_start_from,
                                                     output)
        return output

    @pytest.mark.parametrize("loggings_to_fetch", [1, 4, 6], ids=["Single", "Part", "All"])
    def test_get_max_fetch_activity_logging(self, loggings_to_fetch, requests_mock, mocker):
        """
        Given: number of logging to fetch.
        When: running get activity logging command or fetch.
        Then: return the correct number of loggings.

        """
        from WorkdayEventCollector import get_max_fetch_activity_logging
        mocker.patch.object(Client, 'get_activity_logging_request', side_effect=self.create_response_by_limit)
        res = get_max_fetch_activity_logging(client=self.client, logging_to_fetch=loggings_to_fetch,
                                             from_date="2023-04-15T07:00:00.000Z",
                                             to_date="2023-04-16T07:00:00.000Z")
        assert len(res) == loggings_to_fetch

    DUPLICATED_ACTIVITY_LOGGINGS = [
        (('2023-04-15T07:00:00Z', 5, 2, 0), 5, {}),
        (('2023-04-15T07:00:00Z', 5, 1, 0), 4, {'last_log': 0})]

    @pytest.mark.parametrize("args, len_of_activity_loggings, last_run",
                             DUPLICATED_ACTIVITY_LOGGINGS)
    def test_remove_duplicated_activity_logging(self, args, len_of_activity_loggings, last_run):
        """
        Given: responses with potential duplications from last fetch.
        When: running fetch command.
        Then: return last responses with the latest requestTime to check if there are duplications.

        """
        from WorkdayEventCollector import remove_duplications
        loggings = self.create_response_with_duplicates(*args)
        if 'last_log' in last_run:
            last_run['last_log'] = loggings[last_run.get('last_log')]
        activity_loggings = remove_duplications(loggings, last_run)
        assert len(activity_loggings) == len_of_activity_loggings

    def test_remove_milliseconds_from_time_of_logging(self):
        """
            Given: loggings with time string with milliseconds
            When: Fetching loggings from Workday
            Then: Remove the milliseconds.

        """
        from WorkdayEventCollector import remove_milliseconds_from_time_of_logging
        activity_logging: dict = util_load_json('test_data/single_loggings_response.json')
        requests_time = '2023-04-24T07:00:00.123Z'
        final_time = '2023-04-24T07:00:00Z'
        activity_logging['requestTime'] = requests_time

        assert remove_milliseconds_from_time_of_logging(activity_logging) == final_time

    def test_get_activity_logging_command(self, mocker):
        """
        Given: params to run get_activity_logging_command
        When: running the command
        Then: Accurate response and readable output is returned.
        """
        from WorkdayEventCollector import get_activity_logging_command
        mocker.patch.object(Client, 'get_activity_logging_request', side_effect=self.create_response_by_limit)
        activity_loggings, res = get_activity_logging_command(client=self.client,
                                                              from_date='2023-04-15T07:00:00Z',
                                                              to_date='2023-04-16T07:00:00Z',
                                                              limit=4,
                                                              offset=0)
        assert len(activity_loggings) == 4
        assert "Activity Logging List" in res.readable_output

    @freeze_time("2023-04-15 08:00:00")
    def test_fetch_activity_logging(self, mocker):
        """
        Tests the fetch_events function

        Given:
            - first_fetch_time
        When:
            - Running the 'fetch_activity_logging' function.
        Then:
            - Validates that the function generates the correct API requests with the expected parameters.
            - Validates that the function returns the expected events and next_run timestamps.
        """
        from WorkdayEventCollector import fetch_activity_logging

        first_fetch_time = datetime.strptime('2023-04-12T07:00:00Z', DATE_FORMAT)
        fetched_events = util_load_json('test_data/fetch_activity_loggings.json')
        http_responses = mocker.patch.object(Client, "get_activity_logging_request", side_effect=[
            fetched_events.get('fetch_loggings_before'),
            fetched_events.get('fetch_loggings'),
        ])

        activity_loggings, new_last_run = fetch_activity_logging(self.client,
                                                                 last_run={},
                                                                 first_fetch=first_fetch_time,
                                                                 max_fetch=3)

        assert http_responses.call_args_list[0][1] == {'limit': 3,
                                                       'offset': 0,
                                                       'from_date': '2023-04-12T07:00:00Z',
                                                       'to_date': '2023-04-15T08:00:00Z'}
        assert http_responses.call_args_list[1][1] == {'limit': 2,
                                                       'offset': 1,
                                                       'from_date': '2023-04-12T07:00:00Z',
                                                       'to_date': '2023-04-15T08:00:00Z'}

        assert activity_loggings == fetched_events.get('fetched_events')
        assert new_last_run.get('last_fetch_time') == '2023-04-15T07:00:00Z'
        assert new_last_run.get('last_log').get('taskId') == '3'

        # assert no new results when given the last_run:
        fetched_events = util_load_json('test_data/fetch_activity_loggings.json')
        http_responses = mocker.patch.object(Client, "get_activity_logging_request", side_effect=[
            fetched_events.get('fetch_loggings'),
            []
        ])

        activity_loggings, new_last_run = fetch_activity_logging(self.client,
                                                                 last_run=new_last_run,
                                                                 first_fetch=first_fetch_time,
                                                                 max_fetch=3)
        assert http_responses.call_args_list[0][1] == {'limit': 3,
                                                       'offset': 0,
                                                       'from_date': '2023-04-15T07:00:00Z',
                                                       'to_date': '2023-04-15T08:00:00Z'}
        assert activity_loggings == []
        assert new_last_run.get('last_fetch_time') == '2023-04-15T07:00:00Z'
        assert new_last_run.get('last_log').get('taskId') == '3'

    @pytest.mark.parametrize("max_fetch, instance_returned", [(6000, 1), (15000, 2), (60000, 6)])
    def test_instance_returned_request(self, mocker, max_fetch, instance_returned):
        self.client.max_fetch = max_fetch
        http_request = mocker.patch.object(Client, 'http_request')
        self.client.get_activity_logging_request(from_date='2023-04-15T07:00:00Z',
                                                 to_date='2023-04-15T08:00:00Z')
        params_sent = http_request.call_args_list[0][1].get('params', {})
        assert params_sent.get('instancesReturned') == instance_returned

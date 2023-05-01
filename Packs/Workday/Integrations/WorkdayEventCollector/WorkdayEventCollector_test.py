import json
import io
from datetime import datetime, timedelta

import pytest
from WorkdayEventCollector import Client, DATE_FORMAT


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


class TestFetchActivity:
    def setup_method(self):
        self.base_url = "https://test.com"
        self.tenant_name = "test"
        self.client = Client(base_url=self.base_url,
                             tenant_name=self.tenant_name,
                             client_id="test12",
                             client_secret="test_sec1234",
                             refresh_token="test_token",
                             verify=False,
                             proxy=False,
                             headers={
                                 'Accept': 'application/json',
                                 'Content-Type': 'application/json'
                             })

    @staticmethod
    def create_response_by_limit(from_date, to_date, offset, user_activity_entry_count=False, limit=1):
        single_response = util_load_json('test_data/single_loggings_response.json')
        return [single_response.copy()] * limit

    @staticmethod
    def create_response_with_duplicates(request_time, limit, number_of_different_time, id_to_start_from):
        single_response = util_load_json('test_data/single_loggings_response.json')
        request_time_date_time = datetime.strptime(request_time, DATE_FORMAT)
        output = []

        def create_single(single_response, time, id, output):
            single_response['requestTime'] = time
            single_response['taskId'] = id
            output.append(single_response)
            id += 1
            return output, id

        for i in range(limit - number_of_different_time):
            output, id_to_start_from = create_single(single_response, request_time, id_to_start_from, output)
        for i in range(limit - number_of_different_time, limit):
            new_time = datetime.strftime(request_time_date_time + timedelta(seconds=10), DATE_FORMAT)
            output, id_to_start_from = create_single(single_response,
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
        requests_mock.post(f"{self.base_url}/ccx/oauth2/{self.tenant_name}/token", json={"access_token": "1234"})
        res = get_max_fetch_activity_logging(client=self.client, logging_to_fetch=loggings_to_fetch,
                                             from_date="2023-04-15T07:00:00.000Z",
                                             to_date="2023-04-16T07:00:00.000Z")
        assert len(res) == loggings_to_fetch

    DUPLICATED_ACTIVITY_LOGGINGS = [
        (('2023-04-15T07:00:00Z', 5, 2, 0), 5, {}, '2023-04-15T07:00:00Z'),
        (('2023-04-15T07:00:00Z', 5, 1, 0), 4, {'last_fetched_loggings': {'1'}}, '2023-04-15T07:00:00Z')]

    @pytest.mark.parametrize("args, len_of_response, last_run, time_to_check", DUPLICATED_ACTIVITY_LOGGINGS)
    def test_remove_duplicated_activity_logging(self, args, len_of_response, last_run, time_to_check):
        from WorkdayEventCollector import remove_duplicated_activity_logging
        loggings = self.create_response_with_duplicates(*args)
        res = remove_duplicated_activity_logging(loggings, last_run, time_to_check)
        assert len(res) == len_of_response

    def test_get_activity_logging_command(self):
        """

        """
        from WorkdayEventCollector import Client, get_activity_logging_command

        client = Client(base_url='some_mock_url', verify=False)
        args = {
            'dummy': 'this is a dummy response'
        }
        response = get_activity_logging_command(client, args)

        mock_response = util_load_json('test_data/activity_loging_repsonse.json')

        assert response.outputs == mock_response

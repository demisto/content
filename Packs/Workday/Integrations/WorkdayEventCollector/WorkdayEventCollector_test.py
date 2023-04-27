import json
import io
import pytest
from WorkdayEventCollector import Client


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


class AccessToken:
    def __init__(self):
        self.text = {'access_token': '1234'}


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
                             proxy=False)

    def create_access(self, headers, data):
        return AccessToken()
    @pytest.mark.parametrize("loggings_to_fetch", [1, 4, 6], ids=["Single", "Part", "All"])
    def test_get_max_fetch_activity_logging(self, loggings_to_fetch, requests_mock):
        from WorkdayEventCollector import get_max_fetch_activity_logging
        mock_response = util_load_json('test_data/multiple_logings_response.json')
        requests_mock.get(f'{self.base_url}/activityLogging', json=mock_response)
        requests_mock.post(f"{self.base_url}/ccx/oauth2/{self.tenant_name}/token", text=self.create_access)
        res = get_max_fetch_activity_logging(client=self.client, logging_to_fetch=loggings_to_fetch,
                                             from_date="2023-04-15T07:00:00.000Z",
                                             to_date="2023-04-16T07:00:00.000Z")
        assert len(res) == loggings_to_fetch

    # def test_get_activity_logging_command(self):
    #     """
    #
    #     """
    #     from WorkdayEventCollector import Client, get_activity_logging_command
    #
    #     client = Client(base_url='some_mock_url', verify=False)
    #     args = {
    #         'dummy': 'this is a dummy response'
    #     }
    #     response = get_activity_logging_command(client, args)
    #
    #     mock_response = util_load_json('test_data/activity_loging_repsonse.json')
    #
    #     assert response.outputs == mock_response

import time
import Logzio
import json
from Logzio import BASE_URL

SEARCH_LOGS_RESPONSE_EMPTY_BODY = {
    "hits": {
        "hits": []
    }
}

TRIGGERED_RULES_RESPONSE_BODY = {
    "results": [
        {
            "alertEventId": "bbbbb-ddddddddd",
            "severity": "HIGH",
            "alertId": 564789,
            "alertWindowEndDate": 1581418327.791,
            "eventDate": time.time() - (50 * 60),
            "alertWindowStartDate": 1581414727.791,
            "name": "Test Alert 2",
            "hits": 0
        },
        {
            "alertEventId": "aaaaa-vvvv-wwww-gggg-333333333",
            "severity": "MEDIUM",
            "alertId": 12345,
            "alertWindowEndDate": 1581418327.791,
            "eventDate": (time.time() - (30 * 60)),
            "alertWindowStartDate": 1581414727.791,
            "name": "Test Alert 1",
            "hits": 0
        }
    ]
}

TRIGGERED_RULES_EMPTY_RESPONSE_BODY = {
    "results": []
}

RULE_LOGS_RESPONSE_BODY = {
    "total": 3,
    "results": [
        {
            "rule": "test rule",
            "type": "falco",
            "output": "Error File below",
            "message": "{\"output\":\"17:46:16.520316598: Error File below / or /root opened for writing\"}",
            "@timestamp": "2020-03-29T14:46:17.236Z",
        },
        {
            "rule": "test rule",
            "type": "falco",
            "output": "Error File below",
            "message": "{\"output\":\"17:46:16.520316598: Error File below / or /root opened for writing\"}",
            "@timestamp": "2020-03-29T14:46:14.236Z",
        }
    ],
    "pagination": {
        "pageNumber": 1,
        "pageSize": 2
    }
}


class TestLogzio:

    def test_logzio_fetch_incidents(self, requests_mock):
        requests_mock.post(f"{BASE_URL}{Logzio.TRIGGERED_RULES_API_SUFFIX}",
                           json=TRIGGERED_RULES_RESPONSE_BODY)
        client = Logzio.Client("us", "fake-security-token", "fake-operational-token", False, False)
        search = "Test"
        severities = ["HIGH", "MEDIUM"]
        first_fetch_time = '1 hours'

        # First fetch checks
        inc, next_run = Logzio.fetch_incidents(client, {}, search, severities, first_fetch_time)
        request_body = requests_mock.request_history[0].json()

        assert "searchTerm" in request_body["filter"]
        assert request_body["filter"]["searchTerm"] == "Test"
        assert "timeRange" in request_body["filter"]
        assert "severities" in request_body["filter"]
        assert len(request_body["filter"]["severities"]) == 2
        time_range = request_body["filter"]["timeRange"]
        assert (time.time() - 60 * 60) > time_range["fromDate"]
        assert len(inc) == 2
        assert "eventDate" in inc[1]["rawJSON"]
        assert "last_fetch" in next_run
        raw_json = json.loads(inc[1]["rawJSON"])
        assert next_run["last_fetch"] == raw_json["eventDate"] + 0.1

        # Second fetch checks
        requests_mock.post(f"{BASE_URL}{Logzio.TRIGGERED_RULES_API_SUFFIX}",
                           json=TRIGGERED_RULES_EMPTY_RESPONSE_BODY)
        inc, next_run2 = Logzio.fetch_incidents(client, next_run, search, severities, first_fetch_time)

        assert len(inc) == 0
        assert next_run == next_run2

    def test_logzio_search_logs_command(self, requests_mock):
        client = Logzio.Client("us", "fake-security-token", "fake-operational-token", False, False)
        args = {
            "query": "name:test",
            "size": 20,
            "from_time": "1581261159",
            "to_time": "1581174759"

        }

        requests_mock.post(f"{BASE_URL}{Logzio.SEARCH_LOGS_API_SUFFIX}", json=SEARCH_LOGS_RESPONSE_EMPTY_BODY)
        Logzio.search_logs_command(client, args)
        request_body = requests_mock.request_history[0].json()

        assert request_body["size"] == 20
        assert "query" in request_body["query"]["bool"]["must"][0]["query_string"]
        assert request_body["query"]["bool"]["must"][0]["query_string"]["query"] == "name:test"
        time_range = request_body["query"]["bool"]["must"][1]["range"]["@timestamp"]
        assert time_range["to"] == "1581174759"
        assert time_range["from"] == "1581261159"

    def test_logzio_search_command_human_date(self, requests_mock):
        client = Logzio.Client("us", "fake-security-token", "fake-operational-token", False, False)
        args = {
            "from_time": "2020-03-29T14:46:17.236Z",
            "to_time": "2020-03-29T18:46:17.236Z"
        }

        requests_mock.post(f"{BASE_URL}{Logzio.SEARCH_LOGS_API_SUFFIX}", json=SEARCH_LOGS_RESPONSE_EMPTY_BODY)
        Logzio.search_logs_command(client, args)
        request_body = requests_mock.request_history[0].json()

        time_range = request_body["query"]["bool"]["must"][1]["range"]["@timestamp"]
        assert time_range["to"] == 1585507577000
        assert time_range["from"] == 1585493177000

    def test_logzio_get_rule_logs(self, requests_mock):
        client = Logzio.Client("us", "fake-security-token", "fake-operational-token", False, False)
        args = {
            "id": 123,
            "size": 100,
            "page_size": 2
        }

        requests_mock.post(f"{BASE_URL}{Logzio.SEARCH_RULE_LOGS_API_SUFFIX}",
                           json=RULE_LOGS_RESPONSE_BODY)

        Logzio.get_rule_logs_by_id_command(client, args)

        assert len(requests_mock.request_history) == 2
        request_body = requests_mock.request_history[0].json()

        assert "alertEventId" in request_body["filter"]
        assert request_body["filter"]["alertEventId"] == 123
        assert "pageNumber" in request_body["pagination"]
        assert request_body["pagination"]["pageNumber"] == 1
        assert "pageSize" in request_body["pagination"]
        assert request_body["pagination"]["pageSize"] == 2

        request_body2 = requests_mock.request_history[1].json()
        assert "pageNumber" in request_body2["pagination"]
        assert request_body2["pagination"]["pageNumber"] == 2

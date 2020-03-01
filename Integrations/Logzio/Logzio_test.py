import time
import Logzio
import json

BASE_URL = "https://api.logz.io/"
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
            "name": "Test Alert 2"
        },
        {
            "alertEventId": "aaaaa-vvvv-wwww-gggg-333333333",
            "severity": "MEDIUM",
            "alertId": 12345,
            "alertWindowEndDate": 1581418327.791,
            "eventDate": (time.time() - (30 * 60)),
            "alertWindowStartDate": 1581414727.791,
            "name": "Test Alert 1"
        }
    ]
}

TRIGGERED_RULES_EMPTY_RESPONSE_BODY = {
    "results": []
}
# client = Logzio.Client("https://api.logz.io/", "us", "ac4f3246-c684-4194-9ac9-709b33bc33a9",
#                 "c9b842c7-8527-486f-82de-5bbd8fcb805a", True, False)
# Logzio.test_module(client)
# inc, last = Logzio.fetch_incidents(client, {}, None, ["MEDIUM", "HIGH"], '24 hours')
# print(inc)
# print(last)
# while True:
#     time.sleep(60)
#     inc, last = Logzio.fetch_incidents(client, last, None, ["MEDIUM", "HIGH"], '1 hours')
#     print(inc)
#     print(last)
#
args = {
    # "query": "*",
    "key1": "EPOevent.SoftwareInfo.Event.CommonFields.SourceURL",
    "value1": "http:",
    "size": 10
    # "from_time": 1580289841000
    # "to_time": 1580376254000
}


# Logzio.search_logs_by_fields_command(client, args)
class TestLogzio:

    def test_logzio_fetch_incidents(self, requests_mock):
        requests_mock.post("{}{}".format(BASE_URL, Logzio.TRIGGERED_RULES_API_SUFFIX),
                           json=TRIGGERED_RULES_RESPONSE_BODY)
        client = Logzio.Client(BASE_URL, "us", "fake-security-token", "fake-operational-token", False, False)
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
        requests_mock.post("{}{}".format(BASE_URL, Logzio.TRIGGERED_RULES_API_SUFFIX),
                           json=TRIGGERED_RULES_EMPTY_RESPONSE_BODY)
        inc, next_run2 = Logzio.fetch_incidents(client, next_run, search, severities, first_fetch_time)

        assert len(inc) == 0
        assert next_run == next_run2

    def test_logzio_search_logs_command(self, requests_mock):
        client = Logzio.Client(BASE_URL, "us", "fake-security-token", "fake-operational-token", False, False)
        args = {
            "query": "name:test",
            "size": 20,
            "from_time": 1581261159,
            "to_time": 1581174759
        }

        requests_mock.post("{}{}".format(BASE_URL, Logzio.SEARCH_LOGS_API_SUFFIX), json=SEARCH_LOGS_RESPONSE_EMPTY_BODY)
        Logzio.search_logs_command(client, args)
        request_body = requests_mock.request_history[0].json()

        assert request_body["size"] == 20
        assert "query" in request_body["query"]["bool"]["must"][0]["query_string"]
        assert request_body["query"]["bool"]["must"][0]["query_string"]["query"] == "name:test"
        time_range = request_body["query"]["bool"]["must"][1]["range"]["@timestamp"]
        assert time_range["to"] == 1581174759
        assert time_range["from"] == 1581261159
#
# # print search_logs_by_fields_command(client, args)

    def test_logzio_get_rule_logs(self, requests_mock):
        client = Logzio.Client(BASE_URL, "us", "fake-security-token", "fake-operational-token", False, False)
        args = {
            "id": 123
        }

        requests_mock.post("{}{}".format(BASE_URL, Logzio.SEARCH_RULE_LOGS_API_SUFFIX),
                           json=SEARCH_LOGS_RESPONSE_EMPTY_BODY)

        Logzio.get_rule_logs_by_id_command(client, args)
        request_body = requests_mock.request_history[0].json()

        assert "id" in request_body
        assert request_body["id"] == 123


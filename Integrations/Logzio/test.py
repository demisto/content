import time
import httpretty
import Logzio
import unittest
import json

BASE_URL = "api.logz.io/"
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
                        "eventDate": time.time() - (50*60),
                        "alertWindowStartDate": 1581414727.791,
                        "name": "Test Alert 2"
                    },
                    {
                        "alertEventId": "aaaaa-vvvv-wwww-gggg-333333333",
                        "severity": "MEDIUM",
                        "alertId": 12345,
                        "alertWindowEndDate": 1581418327.791,
                        "eventDate": time.time() - (30*60),
                        "alertWindowStartDate": 1581414727.791,
                        "name": "Test Alert 1"
                    }
    ]
}

TRIGGERED_RULES_EMPTY_RESPONSE_BODY = {
    "results": []
}
# client = Logzio.Client("api.logz.io/", "us", "ac4f3246-c684-4194-9ac9-709b33bc33a9",
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
# args = {
#     # "query": "*",
#     "key1": "EPOevent.SoftwareInfo.Event.CommonFields.SourceURL",
#     "value1": "http:",
#     "size": 10
#     # "from_time": 1580289841000
#     # "to_time": 1580376254000
# }
#
# Logzio.search_logs_by_fields_command(client, args)


class TestLogzio(unittest.TestCase):

    # @httpretty.activate
    # def test_logzio_get_api_url(self):

    @httpretty.activate
    def test_logzio_fetch_incidents(self):
        httpretty.register_uri(httpretty.POST, "{}{}".format(BASE_URL, Logzio.TRIGGERED_RULES_API_SUFFIX),
                               body=json.dumps(TRIGGERED_RULES_RESPONSE_BODY),
                               status=200, content_type="application/json")
        client = Logzio.Client(BASE_URL, "us", "fake-security-token", "fake-operational-token", False, False)
        search = "Test"
        severities = ["HIGH", "MEDIUM"]
        first_fetch_time = '1 hours'

        # First fetch checks
        inc, next_run = Logzio.fetch_incidents(client, {}, search, severities, first_fetch_time)
        request = httpretty.HTTPretty.last_request
        body = json.loads(request.body.decode("utf-8"))

        self.assertTrue("searchTerm" in body["filter"])
        self.assertEqual(body["filter"]["searchTerm"], "Test")
        self.assertTrue("timeRange" in body["filter"])
        self.assertTrue("severities" in body["filter"])
        self.assertEqual(len(body["filter"]["severities"]), 2)
        time_range = body["filter"]["timeRange"]
        self.assertTrue(time.time() - 60*60 > time_range["fromDate"])
        self.assertEqual(len(inc), 2)
        self.assertTrue("eventDate" in inc[1]["rawJSON"])
        self.assertTrue("last_fetch" in next_run)
        raw_json = json.loads(inc[1]["rawJSON"])
        self.assertEqual(next_run["last_fetch"], raw_json["eventDate"] + 0.1)

        # Second fetch checks
        httpretty.register_uri(httpretty.POST, "{}{}".format(BASE_URL, Logzio.TRIGGERED_RULES_API_SUFFIX),
                               body=json.dumps(TRIGGERED_RULES_EMPTY_RESPONSE_BODY),
                               status=200, content_type="application/json")
        inc, next_run2 = Logzio.fetch_incidents(client, next_run, search, severities, first_fetch_time)
        self.assertEqual(len(inc), 0)
        self.assertEqual(next_run, next_run2)


    @httpretty.activate
    def test_logzio_search_logs_command(self):

        client = Logzio.Client(BASE_URL, "us", "fake-security-token", "fake-operational-token", False, False)
        args = {
            "query": "name:test",
            "size": 20,
            "from_time": 1581261159,
            "to_time": 1581174759
        }

        httpretty.register_uri(httpretty.POST, "{}{}".format(BASE_URL, Logzio.SEARCH_LOGS_API_SUFFIX),
                               body=json.dumps(SEARCH_LOGS_RESPONSE_EMPTY_BODY),
                               status=200, content_type="application/json")
        Logzio.search_logs_command(client, args)
        request = httpretty.HTTPretty.last_request
        body = json.loads(request.body.decode("utf-8"))
        self.assertEqual(body["size"], 20)
        self.assertTrue("query" in body["query"]["bool"]["must"][0]["query_string"])
        self.assertEqual(body["query"]["bool"]["must"][0]["query_string"]["query"], "name:test")
        time_range = body["query"]["bool"]["must"][1]["range"]["@timestamp"]
        self.assertEqual(time_range["to"], 1581174759)
        self.assertEqual(time_range["from"], 1581261159)
# print search_logs_by_fields_command(client, args)


if __name__ == '__main__':
    unittest.main()

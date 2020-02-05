import demistomock as demisto
from CommonServerPython import *

import urllib3
import requests
import json

# Disable insecure warnings
urllib3.disable_warnings()
''' CLIENT CLASS'''

DEFAULT_LIMIT = 50
MAX_LOGZIO_DOCS = 1000
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
TRIGGERED_ALERTS_ENDPOINT_SUFFIX = "v1/alerts/triggered-alerts"
SEARCH_API_SUFFIX = "v1/search"


class Client:
    def __init__(self, logzio_url, region, security_api_token, op_api_token, verify, proxies):
        self.base_url = logzio_url
        self.security_api_token = security_api_token
        self.op_api_token = op_api_token
        self.region = region
        self.verify = verify
        self.proxies = proxies


    def fetch_triggered_rules(self, search=None, severities=None, tags=None):
        url = self.get_triggered_alerts_api()
        payload = {
            "size": 50,
            "sortBy": "DATE",
            "sortOrder": "DESC",
            "search": search,
            "severities": severities,
            "tags": tags
        }
        remove_nulls_from_dictionary(payload)
        payload_string = json.dumps(payload)

        headers = {
            'X-API-TOKEN': self.security_api_token,
            'Content-Type': "application/json",
        }

        response = requests.request("POST", url, data=payload_string, headers=headers, verify=self.verify, proxies=self.proxies)
        if response.status_code != 200:
            return_error('Error in API call [%d] - %s' % (response.status_code, response.reason))

        return response.json()

    def search_logs(self, query, size, from_time, to_time):
        payload = {
            "query": {
                "bool": {
                    "must": [{
                        "query_string": {
                            "query": query
                        }
                    }]
                }
            },
            "size": size
        }
        print (json.dumps(payload))
        if from_time != "" or to_time != "":
            time_filter = {}
            if from_time != "":
                time_filter["from"] = from_time
                time_filter["include_lower"] = True
            if to_time != "":
                time_filter["to"] = to_time
                time_filter["include_upper"] = True
            payload["query"]["bool"]["must"].append(
                {
                    "range": {"@timestamp": time_filter}
                }
            )

        headers = {
            'Content-Type': 'application/json',
            'X-API-TOKEN': self.op_api_token
        }

        response = requests.request("POST", self.get_search_api(), headers=headers, data=json.dumps(payload))
        if response.status_code != 200:
            return_error('Error in API call [%d] - %s' % (response.status_code, response.reason))
        return response.json()["hits"]["hits"]

    def get_triggered_alerts_api(self):
        return "{}{}".format(self.get_base_api_url(), TRIGGERED_ALERTS_ENDPOINT_SUFFIX)

    def get_search_api(self):
        return "{}{}".format(self.get_base_api_url(), SEARCH_API_SUFFIX)

    def get_base_api_url(self):
        return self.base_url.replace("api.", "api{}.".format(self.get_region_code()))

    def get_region_code(self):
        if self.region != "us" and self.region != "":
            return "-{}".format(self.region)
        return ""


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(client):
    try:
        client.fetch_triggered_rules()
        return 'ok'
    except Exception as e:
        return 'Test failed: {}'.format(e)


def fetch_triggered_rules_command(client, args):
    search = args.get('search')
    severities = args.get('severities')
    tags = args.get('tags')
    resp = client.fetch_triggered_rules(search, severities, tags)
    outputs = {
        'rules': resp
    }
    readable = "##{}".format(resp)
    return readable, outputs, resp


def search_logs_command(client, args):
    query = args.get('query')
    size = args.get('size', 1000)
    from_time = args.get('from_time')
    to_time = args.get('to_time')
    resp = client.search_logs(query, size, from_time, to_time)
    outputs = {
        'logs': resp
    }
    readable = "##{}".format(resp)
    return readable, outputs, resp


def search_logs_by_fields_command(client, args):
    size = args.get('size', 1000)
    from_time = args.get('from_time')
    to_time = args.get('to_time')
    params = {}
    for i in range(1, 3):
        params[args.get('key%s' % i)] = args.get('value%s' % i)
    remove_nulls_from_dictionary(params)
    query = " AND ".join(["{}:{}".format(key, params[key]) for key in params])
    resp = client.search_logs(query, size, from_time, to_time)
    outputs = {
        'logs': resp
    }
    readable = "##{}".format(resp)
    return readable, outputs, resp


def fetch_incidents(client, last_run, search, severities, tags, first_fetch_time):
    incidents = []

    start_query_time = last_run.get("last_fetch")
    if not start_query_time:
        start_query_time, _ = parse_date_range(first_fetch_time, date_format=DATE_FORMAT, utc=True)
    raw_events = client.fetch_triggered_rules(search=search, severities=severities, tags=tags)
    for event in raw_events['results']:
        event_date = datetime.fromtimestamp(event["eventDate"])
        event_date_string = event_date.strftime(DATE_FORMAT)
        incident = {
            "name": event["name"],
            "rawJSON": json.dumps(event),
            "occurred": event_date_string
        }
        incidents.append(incident)
    return incidents


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    try:
        security_api_token = demisto.params().get('security_api_token')
        op_api_token = demisto.params().get('operational_api_token')
        region = demisto.params().get('region')
        url = demisto.params().get('url')
        first_fetch_time = demisto.params().get('fetch_time', '1 hours')
        severities = demisto.params().get('severities')
        search = demisto.params().get('search')
        tags = demisto.params().get('tags')
        verify = not demisto.params().get('insecure', False)
        proxies = handle_proxy()

        client = Client(url, region, security_api_token, op_api_token, verify, proxies)
        command = demisto.command()
        # demisto.log('Command being called is {}'.format(command))
        # Run the commands
        if command == 'logzio-fetch-triggered-rules':
            readable, outputs, resp = fetch_triggered_rules_command(client, demisto.args())
            return_outputs(readable, outputs, resp)
        elif command == 'logzio-search-logs':
            readable, outputs, resp = search_logs_command(client, demisto.args())
            return_outputs(readable, outputs, resp)
        elif command == 'logzio-search-logs-by-fields':
            readable, outputs, resp = search_logs_by_fields_command(client, demisto.args())
            return_outputs(readable, outputs, resp)
        elif demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)
        elif demisto.command() == 'fetch-incidents':
            incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                search=search,
                severities=severities,
                tags=tags
            )
            # demisto.setLastRun({'start_time': datetime.now()})
            demisto.incidents(incidents)

    except Exception as e:
        # demisto.log(str(e))
        return_error('Failed to execute command. Error: {}'.format(str(e)))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

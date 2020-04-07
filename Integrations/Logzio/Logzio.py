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
ONE_MINUTE = 60
ONE_HOUR = ONE_MINUTE * 60
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
BASE_URL = "https://api.logz.io/"
TRIGGERED_RULES_API_SUFFIX = "v2/security/rules/events/search"
SEARCH_LOGS_API_SUFFIX = "v1/search"
SEARCH_RULE_LOGS_API_SUFFIX = "v2/security/rules/events/logs/search"


class Client:
    def __init__(self, region, security_api_token, op_api_token, verify, proxies):
        self.security_api_token = security_api_token
        self.op_api_token = op_api_token
        self.region = region
        self.verify = verify
        self.proxies = proxies

    def fetch_triggered_rules(self, search=None, severities=None, start_time=time.time()):
        url = self.get_triggered_rules_api()
        payload = {
            "pagination": {
                "pageNumber": 1,
                "pageSize": 50
            },
            "sort": [
                {
                    "field": "DATE",
                    "descending": False
                }
            ],
            "filter": {
                "searchTerm": search,
                "severities": severities,
                "timeRange": {
                    "fromDate": start_time,
                    "toDate": time.time() - (ONE_MINUTE * 3)  # 3 Minutes delay for missing/incomplete indexing
                }
            }
        }
        remove_nulls_from_dictionary(payload["filter"])
        remove_nulls_from_dictionary(payload)
        response = execute_api(url, payload, self.security_api_token)
        result = None
        try:
            result = response.json()
        except Exception as e:
            return_error('Could not parse response to json: %s' % response.text, e)
        return result

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
        response = execute_api(self.get_search_api(), payload, self.op_api_token)
        try:
            return response.json()["hits"]["hits"]
        except Exception as e:
            return_error('Could not parse response to json: %s' % response.text, e)

    def get_rule_logs(self, id, size, page_size=1000):
        payload = {
                      "filter": {
                        "alertEventId": id
                      },
                      "pagination": {
                        "pageNumber": 1,
                        "pageSize": page_size
                      }
                  }
        response = execute_api(self.get_rule_logs_api(), payload, self.security_api_token)
        try:
            total = response.json()["total"]
            results = response.json()["results"]
            if total > page_size and size > page_size:
                for i in range(2, (min(size, total) + page_size - 1) // page_size + 1):  # Ceiling division
                    payload["pagination"]["pageNumber"] = i
                    response = execute_api(self.get_rule_logs_api(), payload, self.security_api_token)
                    results += response.json()["results"]
            return results
        except Exception as e:
            return_error('Could not parse response to json: %s' % response.text, e)

    def get_triggered_rules_api(self):
        return self.get_api_url(TRIGGERED_RULES_API_SUFFIX)

    def get_search_api(self):
        return self.get_api_url(SEARCH_LOGS_API_SUFFIX)

    def get_rule_logs_api(self):
        return self.get_api_url(SEARCH_RULE_LOGS_API_SUFFIX)

    def get_api_url(self, api_suffix):
        return "{}{}".format(self.get_base_api_url(), api_suffix)

    def get_base_api_url(self):
        return BASE_URL.replace("api.", "api{}.".format(self.get_region_code()))

    def get_region_code(self):
        if self.region != "us" and self.region != "":
            return "-{}".format(self.region)
        return ""


''' COMMANDS + REQUESTS FUNCTIONS '''


def execute_api(url, payload, api_token):
    headers = {
        'Content-Type': 'application/json',
        'X-API-TOKEN': api_token
    }
    response = requests.request("POST", url, headers=headers, data=json.dumps(payload))
    if response.status_code != 200:
        return_error('Error in API call [%d] - %r: %r' % (response.status_code, response.reason, response.content))
    return response


def test_module(client):
    try:
        client.fetch_triggered_rules()
        return 'ok'
    except Exception as e:
        return 'Test failed: {}'.format(e)


def search_logs_command(client, args):
    query = args.get('query')
    size = args.get('size', 1000)
    from_time = args.get('from_time')
    to_time = args.get('to_time')
    resp = client.search_logs(query, size, from_time, to_time)
    content = [res["_source"] for res in resp]
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': content,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Logs", content),
        'EntryContext': {
            'Logzio.Logs.Count': len(content),
            'Logzio.Logs.Results': content
        }
    }


def search_logs_by_fields_command(client, args):
    size = args.get('size', 1000)
    from_time = args.get('from_time', "")
    to_time = args.get('to_time', "")
    params = {}
    for i in range(1, 3):
        params[args.get('key%s' % i)] = args.get('value%s' % i)
    remove_nulls_from_dictionary(params)
    query = " AND ".join(["{}:\"{}\"".format(key, params[key]) for key in params])
    resp = client.search_logs(query, size, from_time, to_time)
    content = [res["_source"] for res in resp]
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': content,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Logs", content),
        'EntryContext': {
            'Logzio.Logs.Count': len(content),
            'Logzio.Logs.Results': content
        }
    }


def get_rule_logs_by_id_command(client, args):
    id = args.get("id")
    size = args.get("size", 100)
    page_size = args.get("page_size", 1000)
    resp = client.get_rule_logs(id, size, page_size)
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': resp,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Logs", resp),
        'EntryContext': {
            'Logzio.Logs.Results': resp
        }
    }


def fetch_incidents(client, last_run, search, severities, first_fetch_time):
    incidents = []
    next_run = last_run
    start_query_time = last_run.get("last_fetch")
    if not start_query_time:
        start_query_time, _ = parse_date_range(first_fetch_time, date_format=DATE_FORMAT, utc=False, to_timestamp=True)
        start_query_time = start_query_time / 1000
        next_run["last_fetch"] = max(start_query_time, time.time() - ONE_HOUR)
    raw_events = client.fetch_triggered_rules(search=search, severities=severities,
                                              start_time=start_query_time)
    for event in raw_events["results"]:
        if "groupBy" in event:
            for field in event["groupBy"]:
                event[field] = event["groupBy"][field]
            del event["groupBy"]
        del event["hits"]  # this field is incorrect
        event_date = datetime.fromtimestamp(event["eventDate"])
        event_date_string = event_date.strftime(DATE_FORMAT)
        incident = {
            "name": event["name"],
            "rawJSON": json.dumps(event),
            "occurred": event_date_string
        }
        incidents.append(incident)
    if incidents:
        latest_event_timestamp = raw_events['results'][-1]["eventDate"]
        next_run["last_fetch"] = latest_event_timestamp + 0.1  # The addition here is so we won't have duplicates
    return incidents, next_run


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    try:
        security_api_token = demisto.params().get('security_api_token')
        op_api_token = demisto.params().get('operational_api_token')
        region = demisto.params().get('region')
        first_fetch_time = demisto.params().get('fetch_time', '1 hours')
        severities = demisto.params().get('severities')
        search = demisto.params().get('search')
        verify = not demisto.params().get('insecure', False)
        proxies = handle_proxy()

        client = Client(region, security_api_token, op_api_token, verify, proxies)
        command = demisto.command()
        # Run the commands
        if command == 'logzio-search-logs':
            demisto.results(search_logs_command(client, demisto.args()))
        elif command == 'logzio-search-logs-by-fields':
            demisto.results(search_logs_by_fields_command(client, demisto.args()))
        elif command == 'logzio-get-logs-by-rule-id':
            demisto.results(get_rule_logs_by_id_command(client, demisto.args()))
        elif demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)
        elif demisto.command() == 'fetch-incidents':
            incidents, next_run = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                search=search,
                severities=severities,
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

    except Exception as e:
        return_error('Failed to execute command. Error: {}'.format(str(e)))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

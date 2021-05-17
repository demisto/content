import demistomock as demisto
from CommonServerPython import *

import urllib3
import json
import dateparser
import time

# Disable insecure warnings
urllib3.disable_warnings()

''' CLIENT CLASS'''

DEFAULT_LIMIT = 50
MAX_LOGZIO_DOCS = 1000
ONE_MINUTE = 60
ONE_HOUR = ONE_MINUTE * 60
DEFAULT_TIMEOUT_SEC = 2
MAX_REQUEST_TIMEOUT = 15
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
BASE_URL = "https://api.logz.io/"
TRIGGERED_RULES_API_SUFFIX = "v2/security/rules/events/search"
SEARCH_LOGS_API_SUFFIX = "v1/search"
SEARCH_RULE_LOGS_API_SUFFIX = "v2/security/rules/events/logs/search"
SEVERITIES_DICT = {
    "UNCLASSIFIED": 0,
    "INFO": 0.5,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "SEVERE": 4
}


class Client(BaseClient):
    def __init__(self, region, security_api_token, op_api_token, verify, proxy, max_fetch=DEFAULT_LIMIT):
        self.security_api_token = security_api_token
        self.op_api_token = op_api_token
        self.region = region
        self.max_fetch = max_fetch
        super(Client, self).__init__(self.get_base_api_url(), verify, proxy)

    def fetch_triggered_rules(self, search=None, severities=None, start_time=time.time()):
        payload = {
            "pagination": {
                "pageNumber": 1,
                "pageSize": self.max_fetch
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
        return self.execute_api(TRIGGERED_RULES_API_SUFFIX, payload, self.security_api_token)

    def search_logs(self, query, size, from_time, to_time, timeout=DEFAULT_TIMEOUT_SEC):
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
        if from_time is not None or to_time is not None:
            time_filter = {}
            if from_time is not None:
                if not from_time.isdigit():
                    orig_time = from_time
                    from_time = dateparser.parse(from_time, settings={'TIMEZONE': 'UTC'})
                    if from_time is None:
                        raise Exception("Counld not parse from_time parameter: {}".format(orig_time))
                    from_time = int(time.mktime(from_time.timetuple())) * 1000
                time_filter["from"] = from_time
                time_filter["include_lower"] = True
            if to_time is not None:
                if not to_time.isdigit():
                    orig_time = from_time
                    to_time = dateparser.parse(to_time, settings={'TIMEZONE': 'UTC'})
                    if to_time is None:
                        raise Exception("Counld not parse from_time parameter: {}".format(orig_time))
                    to_time = int(time.mktime(to_time.timetuple())) * 1000
                time_filter["to"] = to_time
                time_filter["include_upper"] = True
            payload["query"]["bool"]["must"].append(
                {
                    "range": {"@timestamp": time_filter}
                }
            )
        response = self.execute_api(SEARCH_LOGS_API_SUFFIX, payload, self.op_api_token, timeout)
        return response.get("hits", {}).get("hits", {})

    def get_rule_logs(self, id, size, page_size=MAX_LOGZIO_DOCS, timeout=DEFAULT_TIMEOUT_SEC):
        payload = {
            "filter": {
                "alertEventId": id
            },
            "pagination": {
                "pageNumber": 1,
                "pageSize": page_size
            }
        }
        response = self.execute_api(SEARCH_RULE_LOGS_API_SUFFIX, payload, self.security_api_token, timeout)
        total = response.get("total", 0)
        results = response.get("results", [])
        if total > page_size and size > page_size:
            for i in range(2, (min(size, total) + page_size - 1) // page_size + 1):  # Ceiling division
                payload["pagination"]["pageNumber"] = i
                response = self.execute_api(SEARCH_RULE_LOGS_API_SUFFIX, payload, self.security_api_token, timeout)
                results += response.get("results", [])
        return results

    def get_base_api_url(self):
        return BASE_URL.replace("api.", "api{}.".format(self.get_region_code()))

    def get_region_code(self):
        if self.region != "us" and self.region != "":
            return "-{}".format(self.region)
        return ""

    def execute_api(self, url_suffix, payload, api_token, timeout=None):
        if timeout is None or float(timeout) > 15:
            timeout = 15
        headers = {
            'Content-Type': 'application/json',
            'X-API-TOKEN': api_token
        }
        return BaseClient._http_request(self, "POST", url_suffix, headers=headers, data=json.dumps(payload),
                                        ok_codes=(200,), timeout=float(timeout))


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(client):
    try:
        client.fetch_triggered_rules()
        client.search_logs('*', 10, None, None)
        return 'ok'
    except Exception as e:
        return 'Test failed: {}'.format(e)


def get_formatted_logs(response):
    content = []
    for log in response:
        if '@timestamp' in log:
            log['timestamp'] = log["@timestamp"]
        content.append(log)
    if len(content) == 0:
        context = None
        readable = '### No logs were found'
    else:
        context = {
            'Logzio.Result': content
        }
        readable = tableToMarkdown("Logs", content)
    return readable, context


def search_logs_command(client, args):
    if client.op_api_token is None:
        raise Exception("Operational API Token wasn't provided, cannot perform search")
    query = args.get('query')
    size = args.get('size', MAX_LOGZIO_DOCS)
    from_time = args.get('from_time')
    to_time = args.get('to_time')
    timeout = args.get("timeout", DEFAULT_TIMEOUT_SEC)
    resp = [log["_source"] for log in client.search_logs(query, size, from_time, to_time, timeout)]
    readable, context = get_formatted_logs(resp)
    return_outputs(readable, context, resp)


def get_rule_logs_by_id_command(client, args):
    if client.security_api_token is None:
        raise Exception("Security API Token wasn't provided, cannot perform search")
    id = args.get("id")
    size = int(args.get("size", 100))
    page_size = int(args.get("page_size", MAX_LOGZIO_DOCS))
    timeout = int(args.get("timeout", DEFAULT_TIMEOUT_SEC))
    resp = client.get_rule_logs(id, size, page_size, timeout)
    readable, context = get_formatted_logs(resp)
    return_outputs(readable, context, resp)


def fetch_incidents(client, last_run, search, severities, first_fetch_time):
    if client.security_api_token is None:
        raise Exception("Security API Token wasn't provided, cannot fetch incidents")
    incidents = []
    next_run = last_run
    start_query_time = last_run.get("last_fetch")
    if not start_query_time:
        start_query_time, _ = parse_date_range(first_fetch_time, date_format=DATE_FORMAT, utc=False, to_timestamp=True)
        start_query_time = start_query_time / 1000
        next_run["last_fetch"] = max(start_query_time, time.time() - ONE_HOUR)
    raw_events = client.fetch_triggered_rules(search=search, severities=severities,
                                              start_time=start_query_time)
    for event in raw_events.get("results", []):
        if "groupBy" in event:
            for field in event["groupBy"]:
                event[field] = event["groupBy"][field]
            del event["groupBy"]
        if "hits" in event:
            del event["hits"]  # this field is incorrect
        event_date = datetime.fromtimestamp(event["eventDate"])
        event_date_string = event_date.strftime(DATE_FORMAT)
        event['datasource'] = 'Logz.Io'
        incident = {
            "name": event.get("name", ""),
            "rawJSON": json.dumps(event),
            "occurred": event_date_string,
            "severity": SEVERITIES_DICT[event.get("severity", "UNCLASSIFIED")]
        }
        incidents.append(incident)
    if incidents:
        last_incident = raw_events.get('results', [{}])[-1]
        latest_event_timestamp = last_incident.get("eventDate", last_run.get("last_fetch"))
        next_run["last_fetch"] = latest_event_timestamp + 0.1  # The addition here is so we won't have duplicates
    return incidents, next_run


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    try:
        security_api_token = demisto.params().get('security_api_token')
        op_api_token = demisto.params().get('operational_api_token')
        if security_api_token is None and op_api_token is None:
            raise ValueError('No tokens were provided. Please provide either Logz.io Operational API token,'
                             ' Logz.io Security API token, or both.')
        region = demisto.params().get('region')
        first_fetch_time = demisto.params().get('fetch_time', '1 hours')
        severities = demisto.params().get('severities')
        search = demisto.params().get('search')
        max_fetch = demisto.params().get('fetch_count', DEFAULT_LIMIT)
        verify = not demisto.params().get('insecure', False)
        proxy = demisto.params().get('proxy', False)

        client = Client(region, security_api_token, op_api_token, verify, proxy, max_fetch)
        command = demisto.command()
        # Run the commands
        if command == 'logzio-search-logs':
            search_logs_command(client, demisto.args())
        elif command == 'logzio-get-logs-by-event-id':
            get_rule_logs_by_id_command(client, demisto.args())
        elif demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_outputs(test_module(client))
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

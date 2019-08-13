import demistomock as demisto

from CommonServerPython import *

''' IMPORTS '''

from datetime import datetime, timedelta
import json
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

ALL_EVENTS = "All"
ISSUES_EVENTS = "Issues"
BLOCKED_CLICKS = "Blocked Clicks"
PERMITTED_CLICKS = "Permitted Clicks"
BLOCKED_MESSAGES = "Blocked Messages"
DELIVERED_MESSAGES = "Delivered Messages"

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"


class Client:
    def __init__(self, proofpoint_url, api_version, verify, service_principal, secret):
        self.base_url = "{}/{}/siem".format(proofpoint_url, api_version)
        self.verify = verify
        self.service_principal = service_principal
        self.secret = secret

    def http_request(self, method, url_suffix, params=None, data=None):
        full_url = self.base_url + url_suffix

        res = requests.request(
            method,
            full_url,
            verify=self.verify,
            params=params,
            json=data,
            auth=(self.service_principal, self.secret)
        )

        if res.status_code not in [200, 204]:
            raise ValueError('Error in API call to Proofpoint TAP [%d]. Reason: %s' % (res.status_code, res.text))

        try:
            return res.json()
        except Exception:
            raise ValueError(
                "Failed to parse http response to JSON format. Original response body: \n{}".format(res.text))

    def get_events(self, interval=None, since_time=None, since_seconds=None, threat_type=None, threat_status=None,
                   event_type_filter="All"):

        if not interval and not since_time and not since_seconds:
            raise ValueError("Required to pass interval or sinceTime or sinceSeconds.")

        query_params = {
            "format": "json"
        }

        if interval:
            query_params["interval"] = interval

        if since_time:
            query_params["sinceTime"] = since_time

        if since_seconds:
            query_params["sinceSeconds"] = since_seconds

        if threat_status:
            query_params["threatStatus"] = threat_status

        if threat_type:
            query_params["threatType"] = threat_type

        url_route = {
            "All": "/all",
            "Issues": "/issues",
            "Blocked Clicks": "/clicks/blocked",
            "Permitted Clicks": "/clicks/permitted",
            "Blocked Messages": "/messages/blocked",
            "Delivered Messages": "/messages/delivered"
        }[event_type_filter]

        events = self.http_request("GET", url_route, params=query_params)

        return events


def test_module(client, first_fetch_time, event_type_filter):
    """
    Performs basic get request to get item samples
    """
    since_time, _ = parse_date_range(first_fetch_time, date_format=DATE_FORMAT, utc=True)
    client.get_events(since_time=since_time, event_type_filter=event_type_filter)

    # test was successful
    return 'ok'


def get_events_command(client, args):
    interval = args.get("interval")
    threat_type = argToList(args.get("threatType"))
    threat_status = args.get("threatStatus")
    since_time = args.get("sinceTime")
    since_seconds = int(args.get("sinceSeconds"))
    event_type_filter = args.get("eventTypes")

    raw_events = client.get_events(interval, since_time, since_seconds, threat_type, threat_status, event_type_filter)

    return (
        tableToMarkdown("Proofpoint Events", raw_events),
        {
            'Proofpoint.MessagesDelivered(val.GUID == obj.GUID)': raw_events.get("messagesDelivered"),
            'Proofpoint.MessagesBlocked(val.GUID == obj.GUID)': raw_events.get("messagesBlocked"),
            'Proofpoint.ClicksBlocked(val.GUID == obj.GUID)': raw_events.get("clicksBlocked"),
            'Proofpoint.ClicksPermitted(val.GUID == obj.GUID)': raw_events.get("clicksPermitted")
        },
        raw_events
    )


def fetch_incidents(client, last_run, first_fetch_time, event_type_filter, threat_type, threat_status):
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch')

    # Handle first time fetch, fetch incidents retroactively
    if last_fetch is None:
        # date format 2016-05-01T12:00:00Z
        last_fetch, _ = parse_date_range(first_fetch_time, date_format=DATE_FORMAT, utc=True)

    incidents = []
    raw_events = client.get_events(since_time=last_fetch, event_type_filter=event_type_filter,
                                   threat_status=threat_status, threat_type=threat_type)

    for raw_event in raw_events.get("messagesDelivered", []):
        raw_event["type"] = "messages delivered"
        event_guid = raw_events.get("GUID", "")
        incident = {
            "name": "Proofpoint - Message Delivered - {}".format(event_guid),
            "rawJSON": json.dumps(raw_event)
        }

        if raw_event["messageTime"] > last_fetch:
            last_fetch = raw_event["messageTime"]

        for threat in raw_event.get("threatsInfoMap", []):
            if threat["threatTime"] > last_fetch:
                last_fetch = threat["threatTime"]

        incidents.append(incident)

    for raw_event in raw_events.get("messagesBlocked", []):

        raw_event["type"] = "messages blocked"
        event_guid = raw_events.get("GUID", "")
        incident = {
            "name": "Proofpoint - Message Blocked - {}".format(event_guid),
            "rawJSON": json.dumps(raw_event)
        }

        if raw_event["messageTime"] > last_fetch:
            last_fetch = raw_event["messageTime"]

        for threat in raw_event.get("threatsInfoMap", []):
            if threat["threatTime"] > last_fetch:
                last_fetch = threat["threatTime"]

        incidents.append(incident)

    for raw_event in raw_events.get("clicksPermitted", []):
        raw_event["type"] = "clicks permitted"
        event_guid = raw_events.get("GUID", "")
        incident = {
            "name": "Proofpoint - Click Permitted - {}".format(event_guid),
            "rawJSON": json.dumps(raw_event)
        }

        if raw_event["clickTime"] > last_fetch:
            last_fetch = raw_event["clickTime"]

        if raw_event["threatTime"] > last_fetch:
            last_fetch = raw_event["threatTime"]

        incidents.append(incident)

    for raw_event in raw_events.get("clicksBlocked", []):
        raw_event["type"] = "clicks blocked"
        event_guid = raw_events.get("GUID", "")
        incident = {
            "name": "Proofpoint - Click Blocked - {}".format(event_guid),
            "rawJSON": json.dumps(raw_event)
        }

        if raw_event["clickTime"] > last_fetch:
            last_fetch = raw_event["clickTime"]

        if raw_event["threatTime"] > last_fetch:
            last_fetch = raw_event["threatTime"]

        incidents.append(incident)

    last_fetch_datetime = datetime.strptime(last_fetch, DATE_FORMAT)
    last_fetch_datetime = last_fetch_datetime + timedelta(seconds=1)
    next_run = {'last_fetch': last_fetch_datetime.strftime(DATE_FORMAT)}

    return next_run, incidents


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    service_principal = demisto.params().get('credentials').get('identifier')
    secret = demisto.params().get('credentials').get('password')

    # Remove trailing slash to prevent wrong URL path to service
    server_url = demisto.params()['url'][:-1] \
        if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
    api_version = demisto.params().get('api_version')

    verify_certificate = not demisto.params().get('insecure', False)

    # How many time before the first fetch to retrieve incidents
    fetch_time = demisto.params().get('fetch_time', '3 days')

    threat_status = argToList(demisto.params().get('threat_status'))

    threat_type = argToList(demisto.params().get('threat_type'))

    event_type_filter = demisto.params().get('events_type')

    # Remove proxy if not set to true in params
    handle_proxy()

    LOG('Command being called is %s' % (demisto.command()))

    try:
        client = Client(server_url, api_version, verify_certificate, service_principal, secret)

        if demisto.command() == 'test-module':
            results = test_module(client, fetch_time, event_type_filter)
            return_outputs(results, None)

        elif demisto.command() == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=fetch_time,
                event_type_filter=event_type_filter,
                threat_status=threat_status,
                threat_type=threat_type
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'proofpoint-get-events':
            return_outputs(*get_events_command(client, demisto.args()))

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

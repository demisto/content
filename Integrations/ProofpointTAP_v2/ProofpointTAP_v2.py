import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''
from typing import Dict, Tuple
from datetime import datetime, timedelta
import json
import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

ALL_EVENTS = "All"
ISSUES_EVENTS = "Issues"
BLOCKED_CLICKS = "Blocked Clicks"
PERMITTED_CLICKS = "Permitted Clicks"
BLOCKED_MESSAGES = "Blocked Messages"
DELIVERED_MESSAGES = "Delivered Messages"

DEFAULT_LIMIT = 50
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

""" Helper functions """


def get_now():
    """ A wrapper function of datetime.now
    helps handle tests

    Returns:
        datetime: time right now
    """
    return datetime.now()


def get_fetch_times(last_fetch):
    """ Get list of every hour since last_fetch
    Args:
        last_fetch (datetime or str): last_fetch time

    Returns:
        List[str]: list of str represents every hour since last_fetch
    """
    now = get_now()
    times = list()
    time_format = "%Y-%m-%dT%H:%M:%SZ"
    if isinstance(last_fetch, str):
        times.append(last_fetch)
        last_fetch = datetime.strptime(last_fetch, time_format)
    elif isinstance(last_fetch, datetime):
        times.append(last_fetch.strftime(time_format))
    while now - last_fetch > timedelta(minutes=59):
        last_fetch += timedelta(minutes=59)
        times.append(last_fetch.strftime(time_format))
    return times


class Client:
    def __init__(self, proofpoint_url, api_version, verify, service_principal, secret, proxies):
        self.base_url = proofpoint_url
        self.api_version = api_version
        self.verify = verify
        self.service_principal = service_principal
        self.secret = secret
        self.proxies = proxies

    def http_request(self, method, url_suffix, params=None, data=None, forensics_api=False):
        if forensics_api:
            full_url = urljoin(self.base_url, '/v2/forensics')
        else:
            full_url = urljoin(urljoin(self.base_url, self.api_version), url_suffix)

        res = requests.request(
            method,
            full_url,
            verify=self.verify,
            params=params,
            json=data,
            auth=(self.service_principal, self.secret),
            proxies=self.proxies
        )

        if res.status_code not in [200, 204]:
            raise ValueError(f'Error in API call to Proofpoint TAP {res.status_code}. Reason: {res.text}')

        try:
            return res.json()
        except Exception:
            raise ValueError(f"Failed to parse http response to JSON format. Original response body: \n{res.text}")

    def get_events(self, interval=None, since_time=None, since_seconds=None, threat_type=None, threat_status=None,
                   event_type_filter="All"):

        if not interval and not since_time and not since_seconds:
            raise ValueError("Required to pass interval or sinceTime or sinceSeconds.")

        query_params = {
            "format": "json"
        }
        query_params.update(
            assign_params(
                interval=interval,
                sinceTime=since_time,
                sinceSeconds=since_seconds,
                threatStatus=threat_status,
                threatType=threat_type
            )
        )

        url_route = {
            "All": "/all",
            "Issues": "/issues",
            "Blocked Clicks": "/clicks/blocked",
            "Permitted Clicks": "/clicks/permitted",
            "Blocked Messages": "/messages/blocked",
            "Delivered Messages": "/messages/delivered"
        }[event_type_filter]

        events = self.http_request("GET", urljoin('siem', url_route), params=query_params)

        return events

    def get_forensics(self, threat_id=None, campaign_id=None, include_campaign_forensics=None):
        if threat_id and campaign_id:
            raise DemistoException('threadId and campaignID supplied, supply only one of them')
        if include_campaign_forensics and campaign_id:
            raise DemistoException('includeCampaignForensics can be true only with threadId')
        params = assign_params(
            threatId=threat_id,
            campaingId=campaign_id,
            includeCampaignForensics=include_campaign_forensics)
        return self.http_request('GET', None, params=params, forensics_api=True)


def test_module(client, first_fetch_time, event_type_filter):
    """
    Performs basic get request to get item samples
    """
    since_time, _ = parse_date_range(first_fetch_time, date_format=DATE_FORMAT, utc=True)
    client.get_events(since_time=since_time, event_type_filter=event_type_filter)

    # test was successful
    return 'ok'


def build_context_attachment(what: dict) -> Dict:
    return assign_params(
        SHA256=what.get('sha256'),
        MD5=what.get('md5'),
        Blacklisted=what.get('blacklisted'),
        Offset=what.get('offset'),
        Size=what.get('size'),
    )


def build_context_cookie(what: dict) -> dict:
    return assign_params(
        Action=what.get('action'),
        Domain=what.get('domain'),
        Key=what.get('key'),
        Value=what.get('value'),
    )


def build_context_dns(what: dict) -> dict:
    return assign_params(
        Host=what.get('host'),
        CNames=what.get('cnames'),
        IP=what.get('ips'),
        NameServers=what.get('nameservers'),
        NameServersList=what.get('nameserversList'),
    )


def build_context_mutex(what: dict) -> dict:
    return assign_params(
        Name=what.get('name'),
        Path=what.get('path')
    )


def build_context_ids(what: dict) -> dict:
    return assign_params(
        Name=what.get('name'),
        SignatureID=what.get('signatureId')
    )


def build_context_network(what: dict) -> dict:
    return assign_params(
        Action=what.get('action'),
        IP=what.get('ip'),
        Port=what.get('port'),
        Protocol=what.get('type')
    )


def build_context_process(what: dict) -> dict:
    return assign_params(
        Action=what.get('action'),
        Path=what.get('path'),
    )


def build_context_dropper(what: dict) -> dict:
    return assign_params(
        Path=what.get('path'),
        URL=what.get('url'),
        Rule=what.get('rule'),
    )


def build_context_registry(what: dict) -> dict:
    return assign_params(
        Name=what.get('name'),
        Action=what.get('action'),
        Key=what.get('key'),
        Value=what.get('value'),
    )


def build_context_file(what: dict) -> dict:
    return assign_params(
        Path=what.get('path'),
        Action=what.get('action'),
        SHA256=what.get('sha256'),
        MD5=what.get('md5'),
        Size=what.get('size'),
    )


def build_context_url(what: dict) -> dict:
    return assign_params(
        URL=what.get('url'),
        Blacklisted=what.get('blacklisted'),
        SHA256=what.get('sha256'),
        MD5=what.get('md5'),
        Size=what.get('size'),
        HTTPStatus=what.get('httpStatus'),
        IP=what.get('ip'),
    )


def get_forensic_command(client: Client, args: Dict) -> Tuple[str, dict, dict]:
    """
    Args:
        client:
        args: demisto.args()
    Returns:
        Outputs
    """
    forensic_types = {
        'attachment': 'Attachment',
        'cookie': 'Cookie',
        'dns': 'DNS',
        'dropper': 'Dropper',
        'file': 'File',
        'ids': 'IDS',
        'mutex': 'Mutex',
        'network': 'Network',
        'process': 'Process',
        'registry': 'Registry',
        'url': 'URL'
    }
    threat_id = args.get('threatId')
    campaign_id = args.get('campaignId')
    include_campaign_forensics = args.get('includeCampaignForensics') == 'true'
    limit = args.get('limit', DEFAULT_LIMIT)
    raw_response = client.get_forensics(
        threat_id=threat_id,
        campaign_id=campaign_id,
        include_campaign_forensics=include_campaign_forensics
    )
    reports = raw_response.get('reports', [])
    if len(reports) > limit:
        reports = reports[:limit]
    reports_context = list()
    for report in reports:
        report_context = assign_params(
            Scope=report.get('scope'),
            Type=report.get('type'),
            ID=report.get('id')
        )
        for evidence in report.get('forensics', []):
            evidence_type = evidence.get('type')
            evidence_type = forensic_types.get(evidence_type)
            if evidence_type:
                # Create list in report
                if evidence_type not in report_context:
                    report_context[evidence_type] = list()
                what = evidence.get('what', {})
                basic_report = assign_params(
                    Time=evidence.get('time'),
                    Display=evidence.get('display'),
                    Malicious=evidence.get('malicious'),
                )
                basic_report['Platform'] = [{
                    'Name': platform.get('name'),
                    'OS': platform.get('os'),
                    'Version': platform.get('version')
                } for platform in evidence.get('platforms', [])]

                if evidence_type == 'Attachment':
                    basic_report.update(build_context_attachment(what))
                    report_context[evidence_type].append(basic_report)
                elif evidence_type == 'Cookie':
                    basic_report.update(build_context_cookie(what))
                    report_context[evidence_type].append(basic_report)
                elif evidence_type == 'DNS':
                    basic_report.update(build_context_dns(what))
                    report_context['DNS'].append(basic_report)
                elif evidence_type == 'Dropper':
                    basic_report.update(build_context_dropper(what))
                    report_context['Dropper'].append(basic_report)
                elif evidence_type == 'File':
                    basic_report.update(build_context_file(what))
                    report_context['File'].append(basic_report)
                elif evidence_type == 'IDS':
                    basic_report.update(build_context_ids(what))
                    report_context['IDS'].append(basic_report)
                elif evidence_type == 'Mutex':
                    basic_report.update(build_context_mutex(what))
                    report_context['Mutex'].append(basic_report)
                elif evidence_type == 'Network':
                    basic_report.update(build_context_network(what))
                    report_context['Network'].append(basic_report)
                elif evidence_type == 'Process':
                    basic_report.update(build_context_process(what))
                    report_context['Process'].append(basic_report)
                elif evidence_type == 'Registry':
                    basic_report.update(build_context_registry(what))
                    report_context['Registry'].append(basic_report)
                elif evidence_type == 'URL':
                    basic_report.update(build_context_url(what))
                    report_context['URL'].append(basic_report)
        reports_context.append(report_context)
    outputs = {'Proofpoint.Report(var.ID === obj.ID)': reports_context}
    readable_outputs = tableToMarkdown(
        f'Forensic results from ProofPoint for ID: {threat_id or campaign_id}',
        reports_context,
        headers=['ID', 'Scope', 'Type']
    )
    return readable_outputs, outputs, raw_response


@logger
def get_events_command(client, args):
    interval = args.get("interval")
    threat_type = argToList(args.get("threatType"))
    threat_status = args.get("threatStatus")
    since_time = args.get("sinceTime")
    since_seconds = int(args.get("sinceSeconds")) if args.get("sinceSeconds") else None
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


@logger
def fetch_incidents(client, last_run, first_fetch_time, event_type_filter, threat_type, threat_status, limit=50):
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch')

    # Handle first time fetch, fetch incidents retroactively
    if not last_fetch:
        last_fetch, _ = parse_date_range(first_fetch_time, date_format=DATE_FORMAT, utc=True)
    incidents: list = []
    fetch_times = get_fetch_times(last_fetch)
    fetch_time_count = len(fetch_times)
    for index, fetch_time in enumerate(fetch_times):
        if index < fetch_time_count - 1:
            raw_events = client.get_events(interval=fetch_time + "/" + fetch_times[index + 1],
                                           event_type_filter=event_type_filter,
                                           threat_status=threat_status, threat_type=threat_type)
        else:
            raw_events = client.get_events(interval=fetch_time + "/" + get_now().strftime(DATE_FORMAT),
                                           event_type_filter=event_type_filter,
                                           threat_status=threat_status, threat_type=threat_type)

        message_delivered = raw_events.get("messagesDelivered", [])
        for raw_event in message_delivered:
            raw_event["type"] = "messages delivered"
            event_guid = raw_events.get("GUID", "")
            incident = {
                "name": "Proofpoint - Message Delivered - {}".format(event_guid),
                "rawJSON": json.dumps(raw_event)
            }
            last_event_fetch = raw_event["messageTime"]

            threat_info_map = raw_event.get("threatsInfoMap", [])
            for threat in threat_info_map:
                if threat["threatTime"] > last_fetch:
                    last_event_fetch = last_event_fetch if last_event_fetch > threat["threatTime"] else threat[
                        "threatTime"]
            incident['occurred'] = last_event_fetch
            incidents.append(incident)

        message_blocked = raw_events.get("messagesBlocked", [])
        for raw_event in message_blocked:
            raw_event["type"] = "messages blocked"
            event_guid = raw_events.get("GUID", "")
            incident = {
                "name": "Proofpoint - Message Blocked - {}".format(event_guid),
                "rawJSON": json.dumps(raw_event)
            }
            last_event_fetch = raw_event["messageTime"]

            threat_info_map = raw_event.get("threatsInfoMap", [])
            for threat in threat_info_map:
                if threat["threatTime"] > last_fetch:
                    last_fetch = threat["threatTime"]
                    last_event_fetch = last_event_fetch if last_event_fetch > threat["threatTime"] else threat[
                        "threatTime"]

            incident['occurred'] = last_event_fetch
            incidents.append(incident)

        clicks_permitted = raw_events.get("clicksPermitted", [])
        for raw_event in clicks_permitted:
            raw_event["type"] = "clicks permitted"
            event_guid = raw_events.get("GUID", "")
            incident = {
                "name": "Proofpoint - Click Permitted - {}".format(event_guid),
                "rawJSON": json.dumps(raw_event),
                "occurred": raw_event["clickTime"] if raw_event["clickTime"] > raw_event["threatTime"] else raw_event[
                    "threatTime"]
            }
            incidents.append(incident)

        clicks_blocked = raw_events.get("clicksBlocked", [])
        for raw_event in clicks_blocked:
            raw_event["type"] = "clicks blocked"
            event_guid = raw_events.get("GUID", "")
            incident = {
                "name": "Proofpoint - Click Blocked - {}".format(event_guid),
                "rawJSON": json.dumps(raw_event),
                "occurred": raw_event["clickTime"] if raw_event["clickTime"] > raw_event["threatTime"] else raw_event[
                    "threatTime"]
            }
            incidents.append(incident)

    # limit incidents to the limit given
    incidents.sort(key=lambda a: a.get('occurred'))
    if len(incidents) > limit:
        incidents = incidents[:limit]

    # Cut the milliseconds from last fetch if exists
    last_fetch = incidents[-1].get('occurred')
    last_fetch = last_fetch[:-5] + 'Z' if last_fetch[-5] == '.' else last_fetch
    last_fetch_datetime = datetime.strptime(last_fetch, DATE_FORMAT)
    last_fetch = (last_fetch_datetime + timedelta(seconds=1)).strftime(DATE_FORMAT)
    next_run = {'last_fetch': last_fetch}
    return next_run, incidents


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    service_principal = params.get('credentials', {}).get('identifier')
    secret = params.get('credentials', {}).get('password')

    # Remove trailing slash to prevent wrong URL path to service
    server_url = params['url'][:-1] if (params['url'] and params['url'].endswith('/')) else params['url']
    api_version = params.get('api_version')

    verify_certificate = not params.get('insecure', False)
    # How many time before the first fetch to retrieve incidents
    fetch_time = params.get('fetch_time', '60 minutes')

    threat_status = argToList(params.get('threat_status'))

    threat_type = argToList(params.get('threat_type'))

    event_type_filter = params.get('events_type')

    fetch_limit = 50
    # Remove proxy if not set to true in params
    proxies = handle_proxy()

    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        client = Client(server_url, api_version, verify_certificate, service_principal, secret, proxies)
        commands = {
            'proofpoint-get-events': get_events_command,
            'proofpoint-get-forensics': get_forensic_command
        }
        if command == 'test-module':
            results = test_module(client, fetch_time, event_type_filter)
            return_outputs(results)

        elif command == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=fetch_time,
                event_type_filter=event_type_filter,
                threat_status=threat_status,
                threat_type=threat_type,
                limit=fetch_limit
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command in commands:
            return_outputs(*commands[command](client, demisto.args()))

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

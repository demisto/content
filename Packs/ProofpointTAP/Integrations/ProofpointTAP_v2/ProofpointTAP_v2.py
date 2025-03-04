import demistomock as demisto
from CommonServerPython import *

from datetime import datetime, timedelta
import json
import requests
import urllib3
import dateparser

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


def get_now():
    """ A wrapper function for datetime.now
    helps handle tests
    Returns:
        datetime: time right now
    """
    return datetime.now()


def get_fetch_times(last_fetch):
    """ Get list of every hour since last_fetch. last is now.
    Args:
        last_fetch (datetime or str): last_fetch time
    Returns:
        List[str]: list of str represents every hour since last_fetch
    """
    now = get_now()
    times = []
    time_format = DATE_FORMAT
    if isinstance(last_fetch, str):
        times.append(last_fetch)
        last_fetch = datetime.strptime(last_fetch, time_format)
    elif isinstance(last_fetch, datetime):
        times.append(last_fetch.strftime(time_format))
    while now - last_fetch > timedelta(minutes=59):
        last_fetch += timedelta(minutes=59)
        times.append(last_fetch.strftime(time_format))
    times.append(now.strftime(time_format))
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
        if campaign_id:
            params = assign_params(campaignId=campaign_id)
        else:
            params = assign_params(threatId=threat_id, includeCampaignForensics=include_campaign_forensics)
        return self.http_request('GET', None, params=params, forensics_api=True)

    def get_clicks(self, clicks_type: str, interval: str, threat_status: str = None) -> dict:
        """
        Retrieves clicks on malicious URLs in the specified time period. Clicks can either be blocked or permitted.

        Args:
            interval (str): ISO8601-formatted interval date. The minimum interval is 30 seconds. The maximum interval is one hour.
            threat_status (str): The status of the threat. Can be: active, cleared or falsePositive.
            clicks_type (str): The type of the click. Can be either "blocked" or "permitted".

        Returns:
            dict: API response from ProofpointTAP.

        """
        params = remove_empty_elements({"interval": interval,
                                        "threatStatus": threat_status,
                                        "format": "json"})
        return self.http_request("GET", f'/siem/clicks/{clicks_type}', params=params)

    def get_messages(self, messages_type: str, interval: str, threat_status: str = None,
                     threat_type: str = None) -> dict:
        """
        Retrieves events for messages in the specified time period. Messages can either be blocked or delivered.

        Args:
            interval (str): ISO8601-formatted interval date. The minimum interval is 30 seconds. The maximum interval is one hour.
            threat_status (str): The status of the threat. Can be: active, cleared or falsePositive.
            threat_type (str): The type of the threat. Can be: url, attachment or message.
            messages_type (str): The type of the messages. Can be either "blocked" or "delivered"

        Returns:
            dict: API response from ProofpointTAP.

        """
        params = remove_empty_elements({"interval": interval,
                                        "threatStatus": threat_status,
                                        "threatType": threat_type,
                                        "format": "json"})
        return self.http_request("GET", f'/siem/messages/{messages_type}', params=params)

    def list_campaigns(self, interval: str, page: str = None, limit: str = None) -> dict:
        """
        Retrieves a list of IDs of campaigns active in a time window.
        Args:
            interval (str): ISO8601-formatted interval date. The minimum interval is 30 seconds. The maximum interval is one day.
            limit (str): The maximum number of campaign IDs to produce in the response.
            page (str): The page of results to return, in multiples of the specified size.

        Returns:
            dict: API response from ProofpointTAP.

        """
        params = remove_empty_elements({"interval": interval,
                                        "page": page,
                                        "size": limit,
                                        "format": "json"})
        return self.http_request("GET", '/campaign/ids', params=params)

    def get_campaign(self, campaign_id: str) -> dict:
        """
        Retrieves information for a given campaign.
        Args:
            campaign_id (str): The ID of the required campaign.
        Returns:
            dict: API response from ProofpointTAP.
        """
        return self.http_request("GET", f'/campaign/{campaign_id}')

    def list_most_attacked_users(self, window: str, limit: str = None, page: str = None) -> dict:
        """
        Retrieves a list of the most attacked users in the organization for a given period.
        Args:
            window (str): The number of days for which the information will be retrieved.
            limit (str): The maximum number of VAPs to produce.
            page (str): The page of results to return, in multiples of the specified size.
        Returns:
            dict: API response from ProofpointTAP.
        """
        params = remove_empty_elements({"window": window,
                                        "size": limit,
                                        "page": page})
        return self.http_request("GET", '/people/vap', params=params)

    def get_top_clickers(self, window: str, limit: str = None, page: str = None) -> dict:
        """
        Retrieves a list of the top clickers in the organization for a given period.
        Args:
            window (str): The number of days for which the information will be retrieved.
            limit (str): The maximum number of top clickers to produce.
            page (str): The page of results to return, in multiples of the specified size.
        Returns:
            dict: API response from ProofpointTAP.
        """
        params = remove_empty_elements({"window": window,
                                        "size": limit,
                                        "page": page})
        return self.http_request("GET", '/people/top-clickers', params=params)

    def url_decode(self, url_list: list) -> dict:
        """
        Decode URLs that have been rewritten by TAP to their original, target URL.
        Args:
            url_list (list): List of encoded URLs.
        Returns:
            dict: API response from ProofpointTAP.
        """
        data = {"urls": url_list}
        return self.http_request("POST", '/url/decode', data=data)

    def list_issues(self, interval: str, threat_status: str = None, threat_type: str = None) -> dict:
        """
        Retrieves events for permitted clicks on malicious URLs and delivered messages in the specified time period.
        Args:
            interval (str): ISO8601-formatted interval date. The minimum interval is 30 seconds. The maximum interval is one hour.
            threat_status (str): The status of the threat. Can be: active, cleared or falsePositive.
            threat_type (str): The type of the threat. Can be: url, attachment or messageText.
        Returns:
            dict: API response from ProofpointTAP.
        """
        params = remove_empty_elements({"interval": interval,
                                        "threatStatus": threat_status,
                                        "threatType": threat_type,
                                        "format": "json"})
        return self.http_request("GET", '/siem/issues', params=params)


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication.
    Args:
        client (Client): ProofpointTAP API client.
    Returns:
        str : 'ok' if test passed, anything else will fail the test.
    """

    try:
        client.get_top_clickers(window='90')
    except Exception as exception:
        if 'Unauthorized' in str(exception) or 'authentication' in str(exception):
            return 'Authorization Error: make sure API Credentials are correctly set'

        if 'connection' in str(exception):
            return 'Connection Error: make sure Server URL is correctly set'
        raise exception

    return 'ok'


def build_context_attachment(what: dict) -> dict:
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


def build_context_behavior(forensics_data: dict) -> dict:
    """
    Build forensics behavior evidence type objects in order to update the command report context.
    Args:
        forensics_data (dict): Forensics data. A map of values associated with the specific evidence type.

    Returns:
        dict: Dictionary from given kwargs without empty values.

    """
    return assign_params(
        Path=forensics_data.get('path'),
        URL=forensics_data.get('url'),
    )


def build_context_screenshot(forensics_data: dict) -> dict:
    """
    Build forensics screenshot evidence type objects in order to update the command report context.
    Args:
        forensics_data (dict): Forensics data. A map of values associated with the specific evidence type.

    Returns:
        dict: Dictionary from given kwargs without empty values.

    """
    return assign_params(
        URL=forensics_data.get('url'),
    )


def get_forensic_command(client: Client, args: dict) -> tuple[str, dict, dict]:
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
        'url': 'URL',
        'behavior': 'Behavior',
        'screenshot': 'Screenshot'
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
    reports_context = []
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
                    report_context[evidence_type] = []
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
                elif evidence_type == 'Behavior':
                    basic_report.update(build_context_behavior(what))
                    report_context['Behavior'].append(basic_report)
                elif evidence_type == 'Screenshot':
                    basic_report.update(build_context_screenshot(what))
                    report_context['Screenshot'].append(basic_report)
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


def validate_first_fetch_time(first_fetch_time: str):
    """
        validate that the start time is less than 7 days ago
        Args:
            first_fetch_time(str) - the start date time that needs to be validated.
        Returns:
            A valid datetime for the start_query_time
        """
    dt_start_query_time = arg_to_datetime(first_fetch_time) or get_now() - timedelta(hours=1)
    seven_days_ago = get_now() - timedelta(days=7)
    if dt_start_query_time <= seven_days_ago:
        raise DemistoException('The First fetch time range is more than 7 days ago. Please update this parameter since '
                               'Proofpoint supports a maximum 1 week fetch back.')
    else:
        demisto.debug(f'The {first_fetch_time=} is less than 7 days ago.')


def fetch_incidents(
    client,
    last_run,
    first_fetch_time,
    event_type_filter,
    threat_type,
    threat_status,
    limit=DEFAULT_LIMIT,
    integration_context=None,
    raw_json_encoding: str | None = None,
) -> tuple[dict, list, list]:
    incidents = []
    end_query_time = ''
    # check if there're incidents saved in context
    if integration_context:
        remained_incidents = integration_context.get("incidents")
        demisto.debug(f'remained_incidents: {len(remained_incidents)}')
        # return incidents if exists in context.
        if remained_incidents:
            return last_run, remained_incidents[:limit], remained_incidents[limit:]
    # Get the last fetch time, if exists
    start_query_time = last_run.get("last_fetch")
    # Handle first time fetch, fetch incidents retroactively
    if not start_query_time:
        start_query_time, _ = parse_date_range(first_fetch_time, date_format=DATE_FORMAT, utc=True)
    fetch_times = get_fetch_times(start_query_time)
    for i in range(len(fetch_times) - 1):
        start_query_time = fetch_times[i]
        end_query_time = fetch_times[i + 1]
        demisto.debug(f'{start_query_time=}  {end_query_time=}')
        raw_events = client.get_events(interval=start_query_time + "/" + end_query_time,
                                       event_type_filter=event_type_filter,
                                       threat_status=threat_status, threat_type=threat_type)

        message_delivered = raw_events.get("messagesDelivered", [])
        demisto.debug(f'Fetched {len(message_delivered)} messagesDelivered events')
        for raw_event in message_delivered:
            raw_event["type"] = "messages delivered"
            event_guid = raw_event.get("GUID", "")
            if raw_json_encoding:
                raw_json = json.dumps(raw_event, ensure_ascii=False).encode(raw_json_encoding).decode()
            else:
                raw_json = json.dumps(raw_event)
            incident = {
                "name": f"Proofpoint - Message Delivered - {event_guid}",
                "rawJSON": raw_json,
                "occurred": raw_event["messageTime"],
                "haIntegrationEventID": str(event_guid)
            }
            demisto.debug(f'Event Time: {incident.get("occurred")}')
            incidents.append(incident)

        message_blocked = raw_events.get("messagesBlocked", [])
        demisto.debug(f'Fetched {len(message_blocked)} messagesBlocked events')
        for raw_event in message_blocked:
            raw_event["type"] = "messages blocked"
            event_guid = raw_event.get("GUID", "")
            if raw_json_encoding:
                raw_json = json.dumps(raw_event, ensure_ascii=False).encode(raw_json_encoding).decode()
            else:
                raw_json = json.dumps(raw_event)
            incident = {
                "name": f"Proofpoint - Message Blocked - {event_guid}",
                "rawJSON": raw_json,
                "occured": raw_event["messageTime"],
            }
            demisto.debug(f'Event Time: {incident.get("occurred")}')
            incidents.append(incident)

        clicks_permitted = raw_events.get("clicksPermitted", [])
        demisto.debug(f'Fetched {len(clicks_permitted)} clicks_permitted events')
        for raw_event in clicks_permitted:
            raw_event["type"] = "clicks permitted"
            event_guid = raw_event.get("GUID", "")
            if raw_json_encoding:
                raw_json = json.dumps(raw_event, ensure_ascii=False).encode(raw_json_encoding).decode()
            else:
                raw_json = json.dumps(raw_event)
            incident = {
                "name": f"Proofpoint - Click Permitted - {event_guid}",
                "rawJSON": raw_json,
                "occurred": raw_event["clickTime"] if raw_event["clickTime"] > raw_event["threatTime"] else raw_event[
                    "threatTime"]
            }
            demisto.debug(f'Event Time: {incident.get("occurred")}')
            incidents.append(incident)

        clicks_blocked = raw_events.get("clicksBlocked", [])
        demisto.debug(f'Fetched {len(clicks_blocked)} clicks_blocked events')
        for raw_event in clicks_blocked:
            raw_event["type"] = "clicks blocked"
            event_guid = raw_event.get("GUID", "")
            if raw_json_encoding:
                raw_json = json.dumps(raw_event, ensure_ascii=False).encode(raw_json_encoding).decode()
            else:
                raw_json = json.dumps(raw_event)
            incident = {
                "name": f"Proofpoint - Click Blocked - {event_guid}",
                "rawJSON": raw_json,
                "occurred": raw_event["clickTime"] if raw_event["clickTime"] > raw_event["threatTime"] else raw_event[
                    "threatTime"]
            }
            demisto.debug(f'Event Time: {incident.get("occurred")}')
            incidents.append(incident)

    # Cut the milliseconds from last fetch if exists
    end_query_time = end_query_time[:-5] + 'Z' if end_query_time[-5] == '.' else end_query_time
    next_run = {"last_fetch": end_query_time}
    demisto.debug(f'{last_run}=')
    return next_run, incidents[:limit], incidents[limit:]


def handle_interval(time_range: datetime, is_hours_interval: bool = True, is_days_interval: bool = False):
    """
    Create a list of interval objects from the current time over time range.
    Most of ProofpointTAP requests required interval string in order to retrieve information from the API requests.
    interval objects will be in the following format: '2021-04-27T09:00:00Z/2021-04-27T10:00:00Z'
    Args:
        time_range (datetime): Last interval time.
        is_days_interval (bool): If True, create hours interval objects.
        is_hours_interval (bool): If True, create days interval objects.
    Returns:
        list: List of hour interval items.
    """

    current_time = datetime.utcnow()
    intervals = []
    if current_time - time_range > timedelta(
            days=7):  # The maximum time range of Proofpoint TAP API requests is 7 days minus one minute.
        time_range += timedelta(minutes=1)

    if is_days_interval:
        while current_time - time_range > timedelta(days=1):
            start = time_range.strftime(DATE_FORMAT)
            time_range += timedelta(days=1)
            intervals.append(f'{start}/{time_range.strftime(DATE_FORMAT)}')

    if is_hours_interval:
        while current_time - time_range > timedelta(hours=1):
            start = time_range.strftime(DATE_FORMAT)
            time_range += timedelta(hours=1)
            intervals.append(f'{start}/{time_range.strftime(DATE_FORMAT)}')

    return intervals


def get_clicks_command(client: Client, is_blocked: bool, interval: str = None, threat_status: str = None,
                       time_range: str = None) -> CommandResults:
    """
    Retrieves clicks on malicious URLs in the specified time period. Clicks can either be blocked or permitted.
    Args:
        client (Client): ProofpointTAP API client.
        is_blocked (bool): Indicates the clicks type.
        interval (str): ISO8601-formatted interval date. The minimum interval is thirty seconds. The maximum interval is one hour.
        threat_status (str): The status of the threat. Can be: active, cleared or falsePositive.
        time_range (str): Time range, for example: 1 week, 2 days, 3 hours etc.
    Returns:
        CommandResults: raw response, outputs, and readable outputs.
    """
    clicks_type = 'blocked' if is_blocked else 'permitted'
    if not (interval or time_range):
        raise Exception('Must provide interval or time_range.')
    if interval and time_range:
        raise Exception('Must provide only one of the arguments interval or time_range.')
    if time_range and dateparser.parse("7 days") > dateparser.parse(time_range):  # type: ignore
        raise Exception('The maximum time range is 7 days')
    if time_range and dateparser.parse("30 seconds") < dateparser.parse(time_range):  # type: ignore
        raise Exception('The minimum time range is thirty seconds.')

    if time_range and dateparser.parse("1 hour") < dateparser.parse(time_range):  # type: ignore
        end = datetime.utcnow().strftime(DATE_FORMAT)
        start = dateparser.parse(time_range).strftime(DATE_FORMAT)  # type: ignore
        intervals = [f'{start}/{end}']
    else:
        intervals = handle_interval(dateparser.parse(time_range)) if time_range else [interval]  # type: ignore

    outputs = []
    raw_responses = []
    for interval_string in intervals:
        raw_response = client.get_clicks(clicks_type, interval_string, threat_status)

        clicks_path = ['clicksBlocked'] if clicks_type == 'blocked' else ['clicksPermitted']
        if dict_safe_get(raw_response, clicks_path):
            outputs.extend(dict_safe_get(raw_response, clicks_path))
            raw_responses.append(raw_response)

    readable_output = tableToMarkdown(f'{clicks_type.title()} Clicks',
                                      outputs, headers=['id', 'senderIP', 'recipient', 'classification', 'threatID',
                                                        'threatURL', 'threatStatus', 'threatTime',
                                                        'clickTime', 'campaignId', 'userAgent'],
                                      headerTransform=pascalToSpace
                                      )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'Proofpoint.Clicks{clicks_type.capitalize()}',
        outputs=outputs,
        outputs_key_field=['GUID', 'id'],
        raw_response=raw_responses
    )


def create_messages_output(messages_list: list) -> list:
    """
    Creates and filters the required fields of messages output.
    Args:
        messages_list (list): List of retrieved messages.
    Returns:
        list:  List of messages with the required fields.
    """
    outputs = []
    message_keys = ['spamScore', 'phishScore', 'threatsInfoMap', 'messageTime', 'impostorScore', 'malwareScore',
                    'cluster', 'subject', 'quarantineFolder', 'quarantineRule', 'policyRoutes', 'modulesRun',
                    'messageSize', 'messageParts', 'completelyRewritten', 'id', 'sender', 'recipient', 'senderIP',
                    'messageID', 'GUID']

    header_fields = ['headerFrom', 'headerReplyTo', 'fromAddress', 'fromAddress', 'ccAddresses',
                     'replyToAddress', 'toAddresses', 'xmailer']

    for message in messages_list:
        message_header = {}
        for field in header_fields:
            message_header[field] = message[field]

        message_output = {key: value for key, value in message.items() if key in message_keys}
        message_output['Header'] = message_header
        outputs.append(message_output)

    return outputs


def create_threats_objects(messages: list) -> list:
    """
    Creates list of threats items of messages.

    Args:
        messages (list): List of messages items.

    Returns:
        list: List of threats items.

    """
    threats_info_map = []
    message_keys = ['sender', 'recipient', 'subject']
    for message in messages:
        for threat in message.get('threatsInfoMap'):
            threat_object = {key: value for key, value in message.items() if key in message_keys}
            threat_object.update(threat)
            threats_info_map.append(threat_object)

    return threats_info_map


def get_messages_command(client: Client, is_blocked: bool, interval: str = None, threat_status: str = None,
                         threat_type: str = None, time_range: str = None) -> CommandResults:
    """
    Retrieves events for messages in the specified time period. Messages can either be blocked or delivered.
    Args:
        client (Client): ProofpointTAP API client.
        is_blocked (bool): Indicates the messages type.
        interval (str): ISO8601-formatted interval date. The minimum interval is thirty seconds. The maximum interval is one hour.
        threat_status (str): The status of the threat. Can be: active, cleared or falsePositive.
        threat_type (str): The type of the threat. Can be: url, attachment or message.
        time_range (str): Time range, for example: 1 week, 2 days, 3 hours etc.
    Returns:
        CommandResults: raw response, outputs, and readable outputs.
    """
    messages_type = 'blocked' if is_blocked else 'delivered'

    if not (interval or time_range):
        raise Exception('Must provide interval or time_range.')
    if interval and time_range:
        raise Exception('Must provide only one of the arguments interval or time_range.')
    if time_range and dateparser.parse("7 days") > dateparser.parse(time_range):  # type: ignore
        raise Exception('The maximum time range is 7 days')
    if time_range and dateparser.parse("30 seconds") < dateparser.parse(time_range):  # type: ignore
        raise Exception('The minimum time range is thirty seconds.')

    if time_range and dateparser.parse("1 hour") < dateparser.parse(time_range):  # type: ignore
        end = datetime.utcnow().strftime(DATE_FORMAT)
        start = dateparser.parse(time_range).strftime(DATE_FORMAT)  # type: ignore
        intervals = [f'{start}/{end}']
    else:
        intervals = handle_interval(dateparser.parse(time_range)) if time_range else [interval]  # type: ignore
    outputs = []
    raw_responses = []
    for interval_string in intervals:
        raw_response = client.get_messages(messages_type, interval_string, threat_status, threat_type)

        messages_path = ['messagesBlocked'] if messages_type == 'blocked' else ['messagesDelivered']
        if dict_safe_get(raw_response, messages_path):
            outputs.extend(create_messages_output(dict_safe_get(raw_response, messages_path)))
            raw_responses.append(raw_response)

    threats_info_map = create_threats_objects(outputs)

    messages_readable_output = tableToMarkdown(f'{messages_type.title()} Messages',
                                               outputs,
                                               headers=['senderIP', 'sender', 'recipient', 'subject', 'messageSize',
                                                        'messageTime', 'malwareScore', 'phishScore', 'spamScore'],
                                               headerTransform=pascalToSpace
                                               )

    threats_info_readable_output = tableToMarkdown(f'{messages_type.title()} Messages Threats Information',
                                                   threats_info_map,
                                                   headers=['sender', 'recipient', 'subject', 'classification',
                                                            'threat', 'threatStatus', 'threatUrl', 'threatID',
                                                            'threatTime', 'campaignID'],
                                                   headerTransform=pascalToSpace)

    readable_output = messages_readable_output + "\n" + threats_info_readable_output

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'Proofpoint.Messages{messages_type.capitalize()}',
        outputs=outputs,
        outputs_key_field=['GUID', 'id'],
        raw_response=raw_responses
    )


def list_campaigns_command(client: Client, interval: str = None, limit: str = None, page: str = None,
                           time_range: str = None) -> CommandResults:
    """
    Retrieves a list of IDs of campaigns active in a time window.
    Args:
        client (Client): ProofpointTAP API client.
        interval (str): ISO8601-formatted interval date. The minimum interval is thirty seconds. The maximum interval is one day.
        limit (str): The maximum number of campaign IDs to produce in the response.
        page (str): The page of results to return, in multiples of the specified size.
        time_range (str): Time range, for example: 1 week, 2 days, 3 hours etc.
    Returns:
        CommandResults: raw response, outputs, and readable outputs.
    """

    if not (interval or time_range):
        raise Exception('Must provide interval or time_range.')
    if interval and time_range:
        raise Exception('Must provide only one of the arguments interval or time_range.')
    if time_range and dateparser.parse("7 days") > dateparser.parse(time_range):  # type: ignore
        raise Exception('The maximum time range is 7 days')
    if time_range and dateparser.parse("30 seconds") < dateparser.parse(time_range):  # type: ignore
        raise Exception('The minimum time range is thirty seconds.')

    if time_range and dateparser.parse("1 hour") < dateparser.parse(time_range):  # type: ignore
        end = datetime.utcnow().strftime(DATE_FORMAT)
        start = dateparser.parse(time_range).strftime(DATE_FORMAT)  # type: ignore
        intervals = [f'{start}/{end}']
    else:
        intervals = handle_interval(dateparser.parse(time_range),  # type: ignore
                                    is_days_interval=True) if time_range else [  # type: ignore
            interval]  # type: ignore

    outputs = []
    raw_responses = []
    request_error = []
    for interval_string in intervals:
        try:
            raw_response = client.list_campaigns(interval_string, page, limit)
        except ValueError:  # In case there are no campaigns for the interval,  the request returns status code 404
            # which causes an error in http_request function
            request_error.append(
                {'interval': interval_string, "message": f'Not found campaigns data from {interval_string}'})
            continue

        if dict_safe_get(raw_response, ["campaigns"]):
            outputs.extend(dict_safe_get(raw_response, ["campaigns"]))
            raw_responses.append(raw_response)

    readable_output = tableToMarkdown('Campaigns List',
                                      outputs, headers=['id', 'lastUpdatedAt'],
                                      headerTransform=pascalToSpace
                                      )

    if request_error:
        readable_output += "\n" + tableToMarkdown('Errors',
                                                  request_error, headers=['interval', 'message'],
                                                  headerTransform=pascalToSpace
                                                  )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Proofpoint.Campaign',
        outputs=outputs,
        outputs_key_field='id',
        raw_response=raw_responses
    )


def get_campaign_command(client: Client, campaign_id: str) -> CommandResults | str:
    """
    Retrieves information for a given campaign.
    Args:
        client (Client): ProofpointTAP API client.
        campaign_id (str): The ID of the required campaign.
    Returns:
        CommandResults: raw response, outputs, and readable outputs.
    """
    try:
        raw_response = client.get_campaign(campaign_id)
    except ValueError:
        return 'Campaign Id not found'

    campaign_general_fields = ['id', 'name', 'description', 'startDate', 'notable']
    campaign_fields = ['families', 'techniques', 'actors', 'brands', 'malware']

    outputs = {}
    outputs['campaignMembers'] = dict_safe_get(raw_response, ['campaignMembers'])
    outputs['info'] = {key: value for key, value in raw_response.items() if key in campaign_general_fields}
    outputs.update({key: value for key, value in raw_response.items() if key in campaign_fields})
    fields_readable_output = ""
    for field in campaign_fields:
        fields_readable_output += "\n" + tableToMarkdown(field.capitalize(),
                                                         dict_safe_get(outputs, [field]), headers=['id', 'name'],
                                                         headerTransform=pascalToSpace
                                                         )

    campaign_info_output = tableToMarkdown('Campaign Information',
                                           outputs['info'],
                                           headers=['id', 'name', 'description', 'startDate', 'notable'],
                                           headerTransform=pascalToSpace
                                           )
    campaign_members_output = tableToMarkdown('Campaign Members',
                                              outputs['campaignMembers'],
                                              headers=['id', 'threat', 'type'],
                                              headerTransform=pascalToSpace
                                              )

    readable_output = campaign_info_output + "\n" + campaign_members_output + fields_readable_output

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Proofpoint.Campaign',
        outputs=outputs,
        outputs_key_field='id',
        raw_response=raw_response
    )


def create_families_objects(users: list, statistics_key: str) -> list:
    """
    Creates list of threat families items of users.

    Args:
        statistics_key (str): Dictionary key of users statistics.
        users (list): List of users items.

    Returns:
        list: List of threats items

    """
    threat_families = []
    for user in users:
        emails = dict_safe_get(user, ["identity", "emails"])
        for family in dict_safe_get(user, [statistics_key, "families"]):
            families_object = {'Mailbox': emails, 'Threat Family Name': family.get('name'),
                               'Threat Score': family.get('score')}
            threat_families.append(families_object)

    return sorted(threat_families, key=lambda x: (x.get('Threat Score', 0), x.get('Mailbox')), reverse=True)


def list_most_attacked_users_command(client: Client, window: str, limit: str = None,
                                     page: str = None) -> CommandResults:
    """
    Retrieves a list of the most attacked users in the organization for a given period.
    Args:
        client (Client): ProofpointTAP API client.
        window (str): The number of days for which the information will be retrieved.
        limit (str): The maximum number of VAPs to produce.
        page (str): The page of results to return, in multiples of the specified size.
    Returns:
        CommandResults: raw response, outputs, and readable outputs.
    """

    raw_response = client.list_most_attacked_users(window, limit, page)
    outputs = raw_response
    threat_families = create_families_objects(dict_safe_get(outputs, ["users"]), "threatStatistics")

    most_attacked_users_output = tableToMarkdown('Most Attacked Users Information',
                                                 outputs,
                                                 headers=['totalVapUsers', 'interval', 'averageAttackIndex',
                                                          'vapAttackIndexThreshold'],
                                                 headerTransform=pascalToSpace
                                                 )

    threat_families_output = tableToMarkdown('Threat Families', threat_families,
                                             headers=['Mailbox', 'Threat Family Name', 'Threat Score'],
                                             headerTransform=pascalToSpace)

    readable_output = most_attacked_users_output + "\n" + threat_families_output

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Proofpoint.Vap',
        outputs=outputs,
        raw_response=raw_response,
        outputs_key_field='interval'
    )


def get_top_clickers_command(client: Client, window: str, limit: str = None, page: str = None) -> CommandResults:
    """
    Retrieves a list of the top clickers in the organization for a given period.
    Args:
        client (Client): ProofpointTAP API client.
        window (str): The number of days for which the information will be retrieved.
        limit (str): The maximum number of top clickers to produce.
        page (str): The page of results to return, in multiples of the specified size.
    Returns:
        CommandResults: raw response, outputs, and readable outputs.
    """
    raw_response = client.get_top_clickers(window, limit, page)

    outputs = raw_response
    threat_families = create_families_objects(dict_safe_get(outputs, ["users"]), "clickStatistics")

    top_clickers_output = tableToMarkdown('Top Clickers Users Information',
                                          outputs,
                                          headers=['totalTopClickers', 'interval'],
                                          headerTransform=pascalToSpace
                                          )

    threat_families_output = tableToMarkdown('Threat Families',
                                             threat_families,
                                             headers=['Mailbox', 'Threat Family Name', 'Threat Score'],
                                             headerTransform=pascalToSpace)

    readable_output = top_clickers_output + threat_families_output

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Proofpoint.Topclickers',
        outputs=outputs,
        raw_response=raw_response,
        outputs_key_field='interval'
    )


def url_decode_command(client: Client, urls: str) -> CommandResults:
    """
    Decode URLs that have been rewritten by TAP to their original, target URL.
    Args:
        client (Client): ProofpointTAP API client.
        urls (str): Encoded URLs.
    Returns:
        CommandResults: raw response, outputs, and readable outputs.
    """
    raw_response = client.url_decode(argToList(urls))
    outputs = dict_safe_get(raw_response, ["urls"])

    readable_output = tableToMarkdown('URLs decoded information',
                                      outputs,
                                      headers=['encodedUrl', 'decodedUrl'],
                                      headerTransform=pascalToSpace)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Proofpoint.URL',
        outputs_key_field='encodedUrl',
        outputs=outputs,
        raw_response=raw_response
    )


def list_issues_command(client: Client, interval: str = None, threat_status: str = None,
                        threat_type: str = None, time_range: str = None) -> list:
    """
    Retrieves events for permitted clicks on malicious URLs and delivered messages in the specified time period.
    Args:
        client (Client): ProofpointTAP API client.
        interval (str): ISO8601-formatted interval date. The minimum interval is thirty seconds. The maximum interval is one hour.
        threat_status (str): The status of the threat. Can be: active, cleared or falsePositive.
        threat_type (str): The type of the threat. Can be: url, attachment or messageText.
        time_range (str): Time range, for example: 1 week, 2 days, 3 hours etc.
    Returns:
        list: List of CommandResults objects.
    """

    if not (interval or time_range):
        raise Exception('Must provide interval or time_range.')
    if interval and time_range:
        raise Exception('Must provide only one of the arguments interval or time_range.')
    if time_range and dateparser.parse("7 days") > dateparser.parse(time_range):  # type: ignore
        raise Exception('The maximum time range is 7 days')
    if time_range and dateparser.parse("30 seconds") < dateparser.parse(time_range):  # type: ignore
        raise Exception('The minimum time range is thirty seconds.')

    if time_range and dateparser.parse("1 hour") < dateparser.parse(time_range):  # type: ignore
        end = datetime.utcnow().strftime(DATE_FORMAT)
        start = dateparser.parse(time_range).strftime(DATE_FORMAT)  # type: ignore
        intervals = [f'{start}/{end}']
    else:
        intervals = handle_interval(dateparser.parse(time_range)) if time_range else [interval]  # type: ignore

    messages_outputs = []
    messages_raw_responses = []
    clicks_outputs = []
    clicks_raw_responses = []
    command_results_list = []

    for interval_string in intervals:
        raw_response = client.list_issues(interval_string, threat_status, threat_type)

        messages = dict_safe_get(raw_response, ['messagesDelivered'])

        if messages:
            messages_outputs.extend(create_messages_output(messages))
            messages_raw_responses.append(raw_response)

        clicks = dict_safe_get(raw_response, ['clicksPermitted'])

        if clicks:
            clicks_outputs.extend(clicks)
            clicks_raw_responses.append(raw_response)

    threats_info_map = create_threats_objects(messages_outputs)

    delivered_messages_output = tableToMarkdown('Delivered Messages',
                                                messages_outputs,
                                                headers=['senderIP', 'sender', 'recipient', 'subject', 'messageSize',
                                                         'messageTime', 'malwareScore', 'phishScore', 'spamScore'],
                                                headerTransform=pascalToSpace
                                                )

    threats_info_output = tableToMarkdown('Delivered Messages Threats Info Map:',
                                          threats_info_map, headers=['sender', 'recipient', 'subject', 'classification',
                                                                     'threat', 'threatStatus', 'threatUrl', 'threatID',
                                                                     'threatTime', 'campaignID'],
                                          headerTransform=pascalToSpace)

    messages_readable_output = delivered_messages_output + "\n" + threats_info_output

    command_results_list.append(CommandResults(
        readable_output=messages_readable_output,
        outputs_prefix='Proofpoint.MessagesDelivered',
        outputs=messages_outputs,
        outputs_key_field=['GUID', 'id'],
        raw_response=messages_raw_responses
    ))

    clicks_readable_output = tableToMarkdown('Permitted click from list-issues command result:',
                                             clicks_outputs,
                                             headers=['id', 'senderIP', 'recipient', 'classification', 'threatID',
                                                      'threatURL', 'threatStatus', 'threatTime',
                                                      'clickTime', 'campaignId', 'userAgent'],
                                             headerTransform=pascalToSpace
                                             )

    command_results_list.append(CommandResults(
        readable_output=clicks_readable_output,
        outputs_prefix='Proofpoint.ClicksPermitted',
        outputs=clicks_outputs,
        outputs_key_field=['GUID', 'id'],
        raw_response=clicks_raw_responses
    ))

    return command_results_list


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

    raw_json_encoding = params.get('raw_json_encoding')

    fetch_limit = min(int(params.get('limit', DEFAULT_LIMIT)), DEFAULT_LIMIT)
    # Remove proxy if not set to true in params
    proxies = handle_proxy()

    command = demisto.command()
    args = demisto.args()
    demisto.info(f'Command being called is {command}')
    demisto.debug(f'{fetch_time=}')
    try:
        client = Client(server_url, api_version, verify_certificate, service_principal, secret, proxies)
        commands = {
            'proofpoint-get-events': get_events_command,
            'proofpoint-get-forensics': get_forensic_command
        }
        if command == 'test-module':
            validate_first_fetch_time(fetch_time)
            return_outputs(test_module(client))

        elif demisto.command() == 'fetch-incidents':
            integration_context = demisto.getIntegrationContext()
            next_run, incidents, remained_incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=fetch_time,
                event_type_filter=event_type_filter,
                threat_status=threat_status,
                threat_type=threat_type,
                limit=fetch_limit,
                integration_context=integration_context,
                raw_json_encoding=raw_json_encoding,
            )
            # Save last_run, incidents, remained incidents into integration
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
            # preserve context dict
            demisto.setIntegrationContext({"incidents": remained_incidents})

        elif command in commands:
            return_outputs(*commands[command](client, args))

        elif command == 'proofpoint-get-events-clicks-blocked':
            return_results(get_clicks_command(client, is_blocked=True, **args))

        elif command == 'proofpoint-get-events-clicks-permitted':
            return_results(get_clicks_command(client, is_blocked=False, **args))

        elif command == 'proofpoint-get-events-messages-blocked':
            return_results(get_messages_command(client, is_blocked=True, **args))

        elif command == 'proofpoint-get-events-messages-delivered':
            return_results(get_messages_command(client, is_blocked=False, **args))

        elif command == 'proofpoint-list-campaigns':
            return_results(list_campaigns_command(client, **args))

        elif command == 'proofpoint-get-campaign':
            return_results(get_campaign_command(client, **args))

        elif command == 'proofpoint-list-most-attacked-users':
            return_results(list_most_attacked_users_command(client, **args))

        elif command == 'proofpoint-get-top-clickers':
            return_results(get_top_clickers_command(client, **args))

        elif command == 'proofpoint-url-decode':
            return_results(url_decode_command(client, **args))

        elif command == 'proofpoint-list-issues':
            return_results(list_issues_command(client, **args))

    except Exception as exception:
        if command == 'test-module':
            return_error(str(exception))
        return_error(f'Failed to execute {command} command. Error: {str(exception)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

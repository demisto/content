import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import re
import json
import traceback
from typing import Any, cast
import html
from functools import reduce

''' CONSTANTS '''
# disable-secrets-detection-start
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
FEED_URL = 'https://api.intel471.com/v1'
TITAN_PORTAL_URL = 'https://titan.intel471.com/'
MAX_INCIDENTS_TO_FETCH = 100
INTEL471_SEVERITIES = ['Low', 'Medium', 'High', 'Critical']
INCIDENT_TYPE = 'Intel 471 Watcher Alert'
DEMISTO_VERSION = demisto.demistoVersion()
CONTENT_PACK = f'Intel471 Feed/{str(get_pack_version())}'
INTEGRATION = 'Intel471 Watcher Alerts'
USER_AGENT = f'XSOAR/{DEMISTO_VERSION["version"]}.{DEMISTO_VERSION["buildNumber"]} - {CONTENT_PACK} - {INTEGRATION}'
TAG_RE = re.compile(r'<[^>]+>')
# disable-secrets-detection-end

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def search_alerts(self, watcher_group_uids: Optional[str],
                      max_results: Optional[int],
                      start_time: Optional[int],
                      last_alert_uid: Optional[str]) -> dict:
        """Searches for Intel 471 Watcher Alerts using the '/get_alerts' API endpoint

        All the parameters are passed directly to the API as HTTP POST parameters in the request

        :type watcher_group_uids: ``Optional[str]``
        :param watcher_group_uids: the uid(s) of the watcher group(s) for which alerts should be fetched

        :type max_results: ``Optional[int]``
        :param max_results: maximum number of results to return

        :type start_time: ``Optional[int]``
        :param start_time: start timestamp (epoch in seconds) for the alert search

        :type last_alert_uid: ``Optional[str]``
        : param last_alert_uid: uid of the most recent alert already acquired

        :return: Dict containing the found Intel 471 Watcher alerts
        :rtype: ``Dict``
        """

        request_params: dict[str, Any] = {}

        request_params['showRead'] = 'true'
        request_params['displayWatchers'] = 'true'
        request_params['markAsRead'] = 'false'
        request_params['sort'] = 'earliest'

        if watcher_group_uids:
            for watcher_group_uid in watcher_group_uids.replace(' ', '').split(','):
                request_params['watcherGroup'] = watcher_group_uid

        if max_results:
            request_params['count'] = max_results

        # Only need to set a from timestamp if no last alert uid is set.
        if last_alert_uid:
            request_params['offset'] = last_alert_uid
        else:
            if start_time:
                request_params['from'] = start_time

        return self._http_request(
            method='GET',
            url_suffix='/alerts',
            auth=self._auth,
            params=request_params
        )


''' HELPER FUNCTIONS '''


def convert_to_demisto_severity(severity: str) -> int:
    """Maps Intel 471 severity to Cortex XSOAR severity

    Converts the Intel 471 alert severity level ('Low', 'Medium',
    'High', 'Critical') to Cortex XSOAR incident severity (1 to 4)
    for mapping.

    :type severity: ``str``
    :param severity: severity as returned from the Intel 471 API (str)

    :return: Cortex XSOAR Severity (1 to 4)
    :rtype: ``int``
    """

    # In this case the mapping is straightforward, but more complex mappings
    # might be required in your integration, so a dedicated function is
    # recommended. This mapping should also be documented.
    return {
        'Low': IncidentSeverity.LOW,
        'Medium': IncidentSeverity.MEDIUM,
        'High': IncidentSeverity.HIGH,
        'Critical': IncidentSeverity.CRITICAL
    }[severity]


def remove_tags(html: str) -> str:
    return TAG_RE.sub('', html)


def deep_get(dictionary, path, default: Any) -> Any:
    result: Any

    keys = path.split('.')
    value = reduce(lambda d, key: d[int(key)] if isinstance(d, list) else d.get(key) if d else default, keys, dictionary)
    if value:
        result = value
    else:
        result = default

    return result


def get_report_type(url: str) -> str:
    report_type = 'REPORT:\n'

    if 'inforep' in url:
        report_type = 'INFO REPORT:\n'
    elif 'fintel' in url:
        report_type = 'FINTEL:\n'
    elif 'spotrep' in url:
        report_type = 'SPOT REPORT:\n'

    return report_type


def compose_incident_title(alert: dict) -> str:
    title: str = ''

    if alert.get('actor', None):
        title = 'ACTOR:\n'
        handles: list = alert.get('actor', {}).get('handles', [])
        if handles:
            title += ','.join(handles)
    elif alert.get('breachAlert', None):
        title = 'BREACH ALERT:\n' + deep_get(alert, 'breachAlert.data.breach_alert.title', '')
    elif alert.get('credential', None):
        title = 'CREDENTIAL:\n' + deep_get(alert, 'credential.data.credential_login', '')
    elif alert.get('credential_occurrence', None):
        title = 'CREDENTIAL OCCURRENCE:\n' + deep_get(alert, 'credential_occurrence.data.credential.credential_login', '')
    elif alert.get('credential_set', None):
        title = 'CREDENTIAL SET:\n' + deep_get(alert, 'credential_set.data.name', '')
    elif alert.get('cveReport', None):
        title = 'CVE REPORT:\n' + deep_get(alert, 'cveReport.data.cve_report.name', '')
    elif alert.get('entity', None):
        title = 'ENTITY:\n' + deep_get(alert, 'entity.value', '')
    elif alert.get('event', None):
        title = 'MALWARE EVENT:\n' + deep_get(alert, 'event.data.threat.data.family', '') + ' - ' + \
                deep_get(alert, 'event.data.event_type', '')
    elif alert.get('indicator', None):
        title = 'MALWARE INDICATOR:\n' + deep_get(alert, 'indicator.data.threat.data.family', '') + \
                ' - ' + deep_get(alert, 'indicator.data.context.description', '')
    elif alert.get('instantMessage', None):
        title = 'INSTANT MESSAGE:\n' + html.unescape(' '.join(remove_tags(deep_get(alert,
                                                     'instantMessage.data.message.text', '')).strip().split())[:100])
    elif alert.get('ioc', None):
        title = 'IOC:\n' + deep_get(alert, 'ioc.value', '')
    elif alert.get('post', None):
        title = 'FORUM POST:\n' + html.unescape(' '.join(remove_tags(deep_get(alert, 'post.message', '')).strip().split())[:100])
    elif alert.get('report', None):
        title = get_report_type(deep_get(alert, 'report.portalReportUrl', '')) + deep_get(alert, 'report.subject', '')
    elif alert.get('spotReport', None):
        title = 'SPOT REPORT:\n' + deep_get(alert, 'spotReport.data.spot_report.spot_report_data.title', '')
    else:
        title = 'UNKNOWN ALERT TYPE:\n' + 'UID: ' + alert.get('uid', '')

    return title


def compose_titan_url(alert: dict) -> str:
    titan_url: str = ''

    if alert.get('actor', None):
        handles: list = alert.get('actor', {}).get('handles', [])
        if handles:
            titan_url = TITAN_PORTAL_URL + 'search/Actor:' + handles[0] + '/actors?ordering=latest&period_of_time=all'
    elif alert.get('breachAlert', None):
        titan_url = TITAN_PORTAL_URL + 'report/breach_alert/' + deep_get(alert, 'breachAlert.uid', '')
    elif alert.get('credential', None):
        titan_url = TITAN_PORTAL_URL + 'credential/' + deep_get(alert, 'credential.uid', '')
    elif alert.get('credential_occurrence', None):
        titan_url = TITAN_PORTAL_URL + 'credential/' + deep_get(alert, 'credential_occurrence.data.credential.uid', '')
    elif alert.get('credential_set', None):
        titan_url = TITAN_PORTAL_URL + 'credential_set/' + deep_get(alert, 'credential_set.uid', '')
    elif alert.get('cveReport', None):
        titan_url = TITAN_PORTAL_URL + 'report/cve/' + deep_get(alert, 'cveReport.uid', '')
    elif alert.get('entity', None):
        titan_url = TITAN_PORTAL_URL
    elif alert.get('event', None):
        titan_url = TITAN_PORTAL_URL + 'malware/event/' + deep_get(alert, 'event.uid', '')
    elif alert.get('indicator', None):
        titan_url = TITAN_PORTAL_URL + 'malware/indicator/' + deep_get(alert, 'indicator.data.uid', '')
    elif alert.get('instantMessage', None):
        thread_uid_instant_message: str = deep_get(alert, 'instantMessage.data.channel.uid', '')
        message_uid: str = deep_get(alert, 'instantMessage.data.message.uid', '')
        titan_url = TITAN_PORTAL_URL + 'ims_thread/' + thread_uid_instant_message + '?message_uid=' + message_uid
    elif alert.get('ioc', None):
        titan_url = TITAN_PORTAL_URL + 'search/IOC%7C*:' + deep_get(alert, 'ioc.value', '') + \
                                       '?ordering=latest&period_of_time=all'
    elif alert.get('post', None):
        thread_uid_post: str = deep_get(alert, 'post.links.thread.uid', '')
        post_uid: str = deep_get(alert, 'post.uid', '')
        titan_url = TITAN_PORTAL_URL + 'post_thread/' + thread_uid_post + '?post_uid=' + post_uid
    elif alert.get('report', None):
        titan_url = deep_get(alert, 'report.portalReportUrl', '')
    elif alert.get('spotReport', None):
        titan_url = TITAN_PORTAL_URL + 'report/spotrep/' + deep_get(alert, 'spotReport.data.spot_report.uid', '')
    else:
        titan_url = TITAN_PORTAL_URL

    return titan_url


def compose_incident_watcher_details(alert: dict, watcher_groups: list) -> tuple[str, str]:
    watcher_group_description: str = ''
    watcher_group_uid: str = alert.get('watcherGroupUid', None)
    watcher_group: dict = [wg for wg in watcher_groups if wg['uid'] == watcher_group_uid][0]
    if watcher_group:
        watcher_group_description = watcher_group.get('name', '')

    watcher_description: str = ''
    watcher_uid: str = alert.get('watcherUid', '')
    watchers: list = []
    if watcher_group.get('watchers', None):
        watchers = watcher_group.get('watchers', [])
        watcher: dict = [w for w in watchers if w['uid'] == watcher_uid][0]
        if watcher:
            watcher_description = watcher.get('description', '')

    return watcher_group_description, watcher_description


def compose_incident_details(alert: dict, watcher_groups: list) -> str:
    details: str = ''

    if alert.get('actor', None):
        details += 'Source Object: ACTOR'
        details += '\n\n' + 'Actor Details:'
        actor_details: dict = deep_get(alert, 'actor.links', {})
        actor_details_str: str = json.dumps(actor_details, indent=2, sort_keys=False)
        details += '\n' + actor_details_str
    elif alert.get('breachAlert', None):
        details += 'Source Object: BREACH ALERT'
        details += '\n' + 'Title: ' + deep_get(alert, 'breachAlert.data.breach_alert.title', '')
        details += '\n' + 'Confidence: ' + deep_get(alert, 'breachAlert.data.breach_alert.confidence.lovel', '') + \
                          ' (' + deep_get(alert, 'breachAlert.data.breach_alert.confidence.description', '') + ')'
        details += '\n' + 'Actor/Group: ' + deep_get(alert, 'breachAlert.data.breach_alert.actor_or_group', '')
        details += '\n\n' + 'Victim Details:'
        victim_details: dict = deep_get(alert, 'breachAlert.data.breach_alert.victim', {})
        victim_details_str: str = json.dumps(victim_details, indent=2, sort_keys=False)
        details += '/n' + victim_details_str
    elif alert.get('credential', None):
        details += 'Source Object: CREDENTIAL'
        details += '\n' + 'Credential Login: ' + deep_get(alert, 'credential.data.credential_login', '')
        details += '\n' + 'Detection Domain: ' + deep_get(alert, 'credential.data.detection_domain', '')
        details += '\n' + 'Password Strength: ' + deep_get(alert, 'credential.data.password.strength', '')
        affiliations_list_credential: list = alert.get('credential', {}).get('data', {}).get('affiliations', [])
        affiliations_credential: str = ','.join(affiliations_list_credential)
        details += '\n' + 'Affiliations: ' + affiliations_credential
    elif alert.get('credential_occurrence', None):
        details += 'Source Object: CREDENTIAL OCCURRENCE'
        details += '\n' + 'Credential Login: ' + deep_get(alert, 'credential_occurrence.data.credential.credential_login', '')
        details += '\n' + 'Detection Domain: ' + deep_get(alert, 'credential_occurrence.data.credential.detection_domain', '')
        details += '\n' + 'Password Strength: ' + deep_get(alert, 'credential_occurrence.data.credential.password.strength', '')
        affiliations_list_credential_occurrence: list = alert.get('credential_occurrence', {}).get('data', {}) \
                                                             .get('credential', {}).get('affiliations', [])
        affiliations_credential_occurrence: str = ','.join(affiliations_list_credential_occurrence)
        details += '\n' + 'Affiliations: ' + affiliations_credential_occurrence
        details += '\n' + 'Credential Set: ' + deep_get(alert, 'credential_occurrence.data.credential_set.name', '')
    elif alert.get('credential_set', None):
        details += 'Source Object: CREDENTIAL SET'
        details += '\n' + 'Name: ' + deep_get(alert, 'credential_set.data.name', '')
        details += '\n\n' + html.unescape(' '.join(remove_tags(str(alert)).strip().split()))
    elif alert.get('cveReport', None):
        details += 'Source Object: CVE REPORT'
        details += '\n' + 'CVE: ' + deep_get(alert, 'cveReport.data.cve_report.name', '')
        details += '\n' + 'Risk Level: ' + deep_get(alert, 'cveReport.data.cve_report.risk_level', '')
        details += '\n' + 'Vendor: ' + deep_get(alert, 'cveReport.data.cve_report.vendor_name', '')
        details += '\n' + 'Product: ' + deep_get(alert, 'cveReport.data.cve_report.product_name', '')
        details += '\n' + 'Exploit Available: ' + str(deep_get(alert, 'cveReport.data.cve_report.exploit_status.available',
                                                                      'False'))
        details += '\n' + 'Exploit Weaponized: ' + str(deep_get(alert, 'cveReport.data.cve_report.exploit_status.weaponized',
                                                                       'False'))
        details += '\n' + 'Exploit Productized: ' + str(deep_get(alert, 'cveReport.data.cve_report.exploit_status.productized',
                                                                        'False'))
        details += '\n' + 'Patch Status: ' + str(deep_get(alert, 'cveReport.data.cve_report.patch_status', ''))
        details += '\n' + 'Countermeasures: ' + str(deep_get(alert, 'cveReport.data.cve_report.counter_measures', ''))
        details += '\n\n' + 'Summary: ' + deep_get(alert, 'cveReport.data.cve_report.summary', '')
    elif alert.get('entity', None):
        details += 'Source Object: ENTITY'
        details += '\n' + 'Entity: ' + deep_get(alert, 'entity.value', '')
        details += '\n\n' + html.unescape(' '.join(remove_tags(str(alert)).strip().split()))
    elif alert.get('event', None):
        details += 'Source Object: MALWARE EVENT'
        details += '\n' + 'Malware Family: ' + deep_get(alert, 'event.data.threat.data.family', '')
        details += '\n' + 'Malware Family Version: ' + deep_get(alert, 'event.data.threat.data.version', '')
        details += '\n' + 'Mitre Tactics: ' + deep_get(alert, 'event.data.mitre_tactics', '')
        details += '\n' + 'Event Type: ' + deep_get(alert, 'event.data.event_type', '')
        details += '\n\n' + 'Event Details:'
        event_details: dict = deep_get(alert, 'event.data.event_data', '')
        event_details_str: str = json.dumps(event_details, indent=2, sort_keys=False)
        details += '\n' + event_details_str
    elif alert.get('indicator', None):
        details += 'Source Object: MALWARE INDICATOR'
        details += '\n' + 'Malware Family: ' + deep_get(alert, 'indicator.data.threat.data.family', '')
        details += '\n' + 'Malware Family Version: ' + deep_get(alert, 'indicator.data.threat.data.version', '')
        details += '\n' + 'Context: ' + deep_get(alert, 'indicator.data.context.description', '')
        details += '\n' + 'Mitre Tactics: ' + deep_get(alert, 'indicator.data.mitre_tactics', '')
        details += '\n' + 'Confidence Level: ' + deep_get(alert, 'indicator.data.confidence', '')
        details += '\n' + 'Indicator Type: ' + deep_get(alert, 'indicator.data.indicator_type', '')
        details += '\n\n' + 'Indicator Details:'
        indicator_details: dict = deep_get(alert, 'indicator.data.indicator_data', '')
        indicator_details_str: str = json.dumps(indicator_details, indent=2, sort_keys=False)
        details += '\n' + indicator_details_str
    elif alert.get('instantMessage', None):
        details += 'Source Object: INSTANT MESSAGE'
        details += '\n' + 'Service: ' + deep_get(alert, 'instantMessage.data.server.service_type', '')
        details += '\n' + 'Channel: ' + deep_get(alert, 'instantMessage.data.channel.name', '')
        details += '\n' + 'Actor: ' + deep_get(alert, 'instantMessage.data.actor.handle', '')
        details += '\n\n' + html.unescape(' '.join(remove_tags(deep_get(alert, 'instantMessage.data.message.text',
                                                                               '')).strip().split()))
    elif alert.get('ioc', None):
        details += 'Source Object: IOC'
        details += '\n' + 'Type: ' + deep_get(alert, 'ioc.type', '')
        details += '\n' + 'IOC: ' + deep_get(alert, 'ioc.value', '')
    elif alert.get('post', None):
        details += 'Source Object: FORUM POST'
        details += '\n' + 'Forum: ' + deep_get(alert, 'post.links.forum.name', '')
        details += '\n' + 'Thread Topic: ' + deep_get(alert, 'post.links.thread.topic', '')
        details += '\n' + 'Actor: ' + deep_get(alert, 'post.links.authorActor.handle', '')
        details += '\n\n' + html.unescape(' '.join(remove_tags(deep_get(alert, 'post.message', '')).strip().split()))
    elif alert.get('report', None):
        details += 'Source Object: ' + get_report_type(deep_get(alert, 'report.portalReportUrl', ''))
        details += 'Source Characterization ' + deep_get(alert, 'report.sourceCharacterization', '')
        details += '\n\n' + 'Subject: ' + deep_get(alert, 'report.subject', '')
    elif alert.get('spotReport', None):
        details += 'Source Object: SPOT REPORT'
        details += '\n\n' + deep_get(alert, 'spotReport.data.spot_report.spot_report_data.text', '')
        purported_victims_details: dict = deep_get(alert, 'spotReport.data.spot_report.spot_report_data.victims', '')
        if purported_victims_details:
            purported_victims_details_str: str = json.dumps(purported_victims_details, indent=2, sort_keys=False)
            details += '\n\n' + 'Purported Victims:'
            details += '\n' + purported_victims_details_str
    else:
        details += 'Source Object: UNKNOWN ALERT TYPE'
        details += '\n\n' + html.unescape(' '.join(remove_tags(str(alert)).strip().split()))

    return details


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    message: str = ''
    try:
        watcher_group_uids = demisto.params().get('watcher_group_uids', None)

        max_results = arg_to_number(
            arg=demisto.params().get('max_fetch'),
            arg_name='max_fetch',
            required=False
        )
        if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
            max_results = MAX_INCIDENTS_TO_FETCH

        first_fetch_time = arg_to_datetime(
            arg=demisto.params().get('first_fetch', '7 days'),
            arg_name='First fetch time',
            required=True
        )
        first_fetch_timestamp = int(first_fetch_time.timestamp()) * 1000 if first_fetch_time else None
        # Using assert as a type guard (since first_fetch_time is always an int when required=True)
        assert isinstance(first_fetch_timestamp, int)

        last_alert_uid: str = ''

        alerts_wrapper: dict = client.search_alerts(
            watcher_group_uids=watcher_group_uids,
            max_results=max_results,
            start_time=first_fetch_timestamp,
            last_alert_uid=last_alert_uid
        )

        if alerts_wrapper.get('alerts'):
            message = 'ok'
        else:
            raise DemistoException('Unable to obtain Watcher Alerts.')

    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def fetch_incidents(client: Client, max_results: int, last_run: dict[str, int],
                    first_fetch_time: int,
                    watcher_group_uids: Optional[str], severity: str, last_alert_uid: str
                    ) -> tuple[str, dict[str, int], list[dict]]:

    # Get the last fetch time, if exists
    # last_run is a dict with a single key, called last_fetch
    last_fetch: int = last_run.get('last_fetch', 0)
    # Handle first fetch time
    if last_fetch == 0:
        # if missing, use what provided via first_fetch_time
        last_fetch = first_fetch_time * 1000
    else:
        # otherwise use the stored last fetch
        last_fetch = int(last_fetch)

    # for type checking, making sure that latest_created_time is int
    latest_created_time = cast(int, last_fetch)

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: list[dict[str, Any]] = []

    # Get the CSV list of severities from severity
    # severity = ','.join(INTEL471_SEVERITIES[INTEL471_SEVERITIES.index(severity):])

    alerts_wrapper: dict = client.search_alerts(
        watcher_group_uids=watcher_group_uids,
        max_results=max_results,
        start_time=last_fetch,
        last_alert_uid=last_alert_uid
    )

    latest_alert_uid: str = ''

    if alerts_wrapper.get('alerts'):
        watcher_groups: list = []
        if alerts_wrapper.get('watcherGroups'):
            watcher_groups = alerts_wrapper.get('watcherGroups', [])

        alerts: list = alerts_wrapper.get('alerts', [])
        for alert in alerts:
            # If no created_time set is as epoch (0). We use time in ms so we must
            # convert it from the Titan API response
            incident_created_time = int(alert.get('foundTime', '0'))

            # to prevent duplicates, we are only adding incidents with creation_time > last fetched incident
            # if last_fetch:
            #     if incident_created_time <= last_fetch:
            #         continue

            incident_name: str = compose_incident_title(alert)
            titan_url: str = compose_titan_url(alert)
            watcher_group_description, watcher_description = compose_incident_watcher_details(alert, watcher_groups)
            incident_details: str = compose_incident_details(alert, watcher_groups)

            incident = {
                'name': incident_name,
                'details': incident_details,
                'occurred': timestamp_to_datestring(incident_created_time),
                'rawJSON': json.dumps(alert),
                'type': INCIDENT_TYPE,  # Map to a specific XSOAR incident Type
                'severity': convert_to_demisto_severity(alert.get('severity', 'Medium')),
                'CustomFields': {
                    'titanurl': titan_url,
                    'titanwatchergroup': watcher_group_description,
                    'titanwatcher': watcher_description
                }
            }

            incidents.append(incident)

            latest_alert_uid = alert.get('uid', '')

            # Update last run and add incident if the incident is newer than last fetch
            if incident_created_time > latest_created_time:
                latest_created_time = incident_created_time

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': latest_created_time}

    return latest_alert_uid, next_run, incidents


''' MAIN FUNCTION '''


def main() -> None:
    base_url = FEED_URL
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = arg_to_datetime(
        arg=demisto.params().get('first_fetch', '7 days'),
        arg_name='First fetch time',
        required=True
    )
    first_fetch_timestamp: int = int(first_fetch_time.timestamp()) if first_fetch_time else 0
    # Using assert as a type guard (since first_fetch_time is always an int when required=True)
    assert isinstance(first_fetch_timestamp, int)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers: dict = {
            'user-agent': USER_AGENT
        }

        username = demisto.params().get('credentials', {}).get('identifier')
        password = demisto.params().get('credentials', {}).get('password')

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            auth=(username, password),
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            watcher_group_uids = demisto.params().get('watcher_group_uids', None)
            severity = demisto.params().get('severity', 'Medium')

            # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
            max_results = arg_to_number(
                arg=demisto.params().get('max_fetch'),
                arg_name='max_fetch',
                required=False
            )
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH

            last_alert_uid: str = demisto.getIntegrationContext().get('last_alert_uid', '')

            latest_alert_uid, next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=first_fetch_timestamp,
                watcher_group_uids=watcher_group_uids,
                severity=severity,
                last_alert_uid=last_alert_uid
            )

            # update the integration context
            if latest_alert_uid:
                demisto.setIntegrationContext({'last_alert_uid': latest_alert_uid})

            # saves next_run for the time fetch-incidents is invoked
            demisto.setLastRun(next_run)
            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to create
            demisto.incidents(incidents)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

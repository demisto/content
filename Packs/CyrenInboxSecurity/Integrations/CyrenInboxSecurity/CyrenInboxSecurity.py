import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""CyrenInboxSecurity Integration for Cortex XSOAR (aka Demisto)

Cyren Inbox Security
--------------------

Sample parameters
API endpoint: https://marketing.plutoserv.com/
feed_id: sample
token: sample

If you need an API Key to test it out please reach out to your
Cyren representative at https://www.cyren.com

"""

import json
import urllib3
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50
HELLOWORLD_SEVERITIES = ['Low', 'Medium', 'High', 'Critical']
MAX_URL_DB_SIZE = 1000


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this CyrenInboxSecurity implementation, no special attributes defined
    """

    def get_info(self, feed_id: str) -> Dict[str, Any]:
        """Gets the current status of the Cyren incident feed using the '/incidents?info' API endpoint

        :return: dict containing the incident feed  status
        :rtype: ``Dict[str, Any]``
        """

        request_params: Dict[str, Any] = {
            'feedId': feed_id,
        }

        return self._http_request(
            method='GET',
            url_suffix='/info',
            params=request_params
        )

    def get_data(self, feed_id: str, offset: int, count: int) -> Dict[str, Any]:
        """Returns a list of Cyren incidents using the '/incidents' API endpoint

        All the parameters are passed directly to the API as HTTP POST parameters in the request

        :type alert_status: ``Optional[str]``
        :param alert_status: status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'

        :type severity: ``Optional[str]``
        :param severity:
            severity of the alert to search for. Comma-separated values.
            Options are: "Low", "Medium", "High", "Critical"

        :type alert_type: ``Optional[str]``
        :param alert_type: type of alerts to search for. There is no list of predefined types

        :type max_results: ``Optional[int]``
        :param max_results: maximum number of results to return

        :type start_time: ``Optional[int]``
        :param start_time: start timestamp (epoch in seconds) for the alert search

        :return: list containing the found CyrenInboxSecurity alerts as dicts
        :rtype: ``List[Dict[str, Any]]``
        """

        request_params: Dict[str, Any] = {
            'offset': offset,
            'count': count,
            'feedId': feed_id,
            'format': 'json',
        }

        return self._http_request(
            method='GET',
            url_suffix='/data',
            params=request_params
        )


''' HELPER FUNCTIONS '''


def convert_to_demisto_severity(severity: int) -> int:
    """Maps CyrenInboxSecurity severity to Cortex XSOAR severity

    Converts the CyrenInboxSecurity confidence levels (1, 2,
    3) to Cortex XSOAR incident severity (1 to 4)
    for mapping. Note, there are only 3 Cyren confidence levels

    :type severity: ``int``
    :param severity: severity as returned from the CyrenInboxSecurity API (int)

    :return: Cortex XSOAR Severity (2 to 4)
    :rtype: ``int``
    """

    # In this case the mapping is straightforward, but more complex mappings
    # might be required in your integration, so a dedicated function is
    # recommended. This mapping should also be documented.
    return {
        0: IncidentSeverity.LOW,
        1: IncidentSeverity.MEDIUM,
        2: IncidentSeverity.HIGH,
        3: IncidentSeverity.CRITICAL
    }[severity]


def remove_backslash(url: str) -> str:
    """

    Args:
        url: a string representing a url

    Returns: the string without last '/' if such exists.

    """
    url.strip()
    if url.endswith('/'):
        return url[:-1]
    return url


def add_urls_to_instance(new_urls):
    """
    save list of urls to instance context

    """
    # raise NameError(new_urls)

    # retrieve existing list
    data = get_integration_context()
    if not data:
        data = {
            "list": []
        }

    url_db = data['list']
    for u in new_urls:
        url_fixed = remove_backslash(u)
        if url_fixed in url_db:
            continue

        # add new url to db
        url_db.append(url_fixed)

        # If DB is too big, remove entries oldest to newest.
        if len(url_db) > MAX_URL_DB_SIZE:
            url_db.pop(0)

    # write out updated DB
    context = {"list": url_db,
               "timestamp": date_to_timestamp(datetime.now(), DATE_FORMAT)}
    set_integration_context(context)


''' COMMAND FUNCTIONS '''


def test_module(client: Client, feed_id: str) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: CyrenInboxSecurity client to use

    :type name: ``str``
    :param name: name to append to the 'Hello' string

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    # INTEGRATION DEVELOPER TIP
    # Client class should raise the exceptions, but if the test fails
    # the exception text is printed to the Cortex XSOAR UI.
    # If you have some specific errors you want to capture (i.e. auth failure)
    # you should catch the exception here and return a string with a more
    # readable output (for example return 'Authentication Error, API Key
    # invalid').
    # Cortex XSOAR will print everything you return different than 'ok' as
    # an error
    try:
        client.get_info(feed_id=feed_id)
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure Token is correctly set'
        else:
            raise e
    return 'ok'


def get_info_command(client: Client, instance_name: str, feed_id: str) -> str:
    try:
        response = client.get_info(feed_id=feed_id)
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure Token is correctly set'
        else:
            raise e

    readable_output = tableToMarkdown(f'{instance_name}: Information for Feed {feed_id}', response)
    # raise NameError(readable_output)
    return CommandResults(
        readable_output=readable_output
    )


def bypassing_instance(instance):
    return CommandResults(
        readable_output="bypassing instance: " + instance
    )


def simulate_fetch_command(client: Client, instance_name: str, feed_id: str, max_results: int, last_run: Dict[str, int],
                           incident_types_filter: List[str], threat_types_filter: List[str], verbose: bool) -> str:

    # Get the last fetch offset, if exists
    # last_run is a dict with a single key, called last_fetch
    last_fetch = last_run.get('last_fetch', None)
    # Handle first fetch
    if last_fetch is None:
        # if missing, start from 0, which goes back a max of 24 hours
        last_fetch = 0
    else:
        # otherwise use the stored last fetch, add one to move beyond it.
        last_fetch = int(last_fetch) + 1

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: List[Dict[str, Any]] = []

    # get incidents from cyren
    cyren_incidents = client.get_data(
        feed_id=feed_id,
        offset=last_fetch,
        count=100,
    )

    # raise NameError(cyren_incidents)
    # demisto.log("Incident Type Filters: " + json.dumps(incident_types_filter))
    # demisto.log("Threat Type Filters: " + json.dumps(threat_types_filter))

    # determine which filters are turned on
    any_incidents = (incident_types_filter == None or len(incident_types_filter) == 0)
    any_threats = (threat_types_filter == None or len(threat_types_filter) == 0)

    counts = {"incident totals": {}, "threat totals": {}, "passed incident filter": {}, "passed threat filter": {}, "processed": 0}
    for this_incident in cyren_incidents["records"]:
        this_payload = this_incident["payload"]
        last_fetch = this_incident["offset"]
        incident_type = this_payload["incident_type"]
        threat_type = this_payload["threat_type"]
        counts["incident totals"][f'{incident_type} ({threat_type})'] = counts["incident totals"].get(
            f'{incident_type} ({threat_type})', 0) + 1
        counts["threat totals"][threat_type] = counts["threat totals"].get(threat_type, 0) + 1

        if any_incidents or incident_type in incident_types_filter:
            counts["passed incident filter"][incident_type] = counts["passed incident filter"].get(incident_type, 0) + 1
        else:
            continue

        if any_threats or threat_type in threat_types_filter:
            counts["passed threat filter"][threat_type] = counts["passed threat filter"].get(threat_type, 0) + 1
        else:
            continue

        counts["processed"] = counts["processed"] + 1
        if counts["processed"] == max_results:
            break

        if verbose:
            demisto.log(
                f'Raw JSON for Cyren incident type: "{incident_type}" with a threat type of: "{threat_type}"\n' + json.dumps(this_incident, indent=2))

    readable_output = (
        f'## Simulated Fetch for Instance: {instance_name}\n'
        + tableToMarkdown(f'I. Feed Totals', counts["incident totals"])
        + tableToMarkdown(f'II. First Filter: Incident Type {json.dumps(incident_types_filter)}', counts["passed incident filter"])
        + tableToMarkdown(f'III. Second Filter: Threat Type {json.dumps(threat_types_filter)}', counts["passed threat filter"])
        + f'### Processed {counts["processed"]} incidents.\n'
        + f'Max Results: {max_results}\n'
        + f'*** end of simulation ***'
    )

    #raise NameError(readable_output)

    return CommandResults(
        readable_output=readable_output
    )


def fetch_incidents_2(client: Client, feed_id: str, max_results: int, last_run: Dict[str, int],
                      incident_types_filter: List[str], threat_types_filter: List[str]) -> Tuple[Dict[str, int], List[dict]]:

    # Get the last fetch offset, if exists
    # last_run is a dict with a single key, called last_fetch
    last_fetch = last_run.get('last_fetch', None)
    # Handle first fetch
    if last_fetch is None:
        # if missing, start from 0, which goes back a max of 24 hours
        last_fetch = 0
    else:
        # otherwise use the stored last fetch, add one to move beyond it.
        last_fetch = int(last_fetch) + 1

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: List[Dict[str, Any]] = []

    # get incidents from cyren
    cyren_incidents = client.get_data(
        feed_id=feed_id,
        offset=last_fetch,
        count=100,
    )

    # determine which filters are turned on
    any_incidents = (incident_types_filter == None or len(incident_types_filter) == 0)
    any_threats = (threat_types_filter == None or len(threat_types_filter) == 0)

    # keep track of what we've done
    processed_count = 0
    new_urls = []

    for this_incident in cyren_incidents["records"]:
        this_payload = this_incident["payload"]

        last_fetch = this_incident["offset"]
        incident_type = this_payload["incident_type"]
        threat_type = this_payload["threat_type"]
        name_detail = ""
        if incident_type == "admin" or incident_type == "feedback":
            name_detail = '(' + incident_type + ')'

        incident_name = "Cyren Inbox Security - %s %s" % (threat_type, name_detail)
        incident_created_time_ms = this_incident["timestamp"]

        # add to Cyren reputation dbs, if applicable
        if this_payload["threat_indicators"] is not None:
            for threat in this_payload["threat_indicators"]:
                if threat["type"] == "url":
                    new_urls.append(threat["value"])

        # check filters. incident type comes before threat type
        if not (any_incidents or incident_type in incident_types_filter):
            continue
        if not (any_threats or threat_type in threat_types_filter):
            continue

        # build the incident
        incident = {
            'name': incident_name,
            # 'details': this_incident['name'],
            'occurred': timestamp_to_datestring(incident_created_time_ms),
            'rawJSON': json.dumps(this_incident),
            # 'type': 'Cyren Inbox Security',  # Map to a specific XSOAR incident Type
            'severity': convert_to_demisto_severity(this_incident.get('confidence', 1)),
            # 'CustomFields': {  # Map specific XSOAR Custom Fields
            #     'cyreninboxsecurityid': this_incident.get('alert_id'),
            #     'cyreninboxsecuritystatus': this_incident.get('alert_status'),
            #     'cyreninboxsecuritytype': this_incident.get('alert_type')
            # }
        }

        incidents.append(incident)

        # are we done? maxed out?
        processed_count = processed_count + 1
        if processed_count == max_results:
            break

    # add new URLs
    add_urls_to_instance(new_urls)

    # add new file hashes

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': last_fetch}
    return next_run, incidents


def dump_urls_command():
    data = get_integration_context()
    if not data:
        data = {
            "list": []
        }

    url_db = data['list']

    markdown = f"### {demisto.integrationInstance()} - URL List\n"
    for url in url_db:
        markdown += f"{url}\n"

    return CommandResults(readable_output=markdown)


def url_command(client: Client, **kwargs) -> CommandResults:
    url_object_list = []
    data = get_integration_context()
    if not data:
        data = {
            "list": ["www.google.com"]
        }

    url_list_from_user = argToList(kwargs.get('url'))
    markdown = f"### {demisto.integrationInstance()} - URL Query\n"
    urls_in_db = data.get('list', [])
    for url in url_list_from_user:
        url_fixed = remove_backslash(url)
        if url_fixed in urls_in_db:
            dbotscore = Common.DBotScore.BAD
            desc = 'Match found in Cyren database'
            markdown += f"URL: {url}\nCAT: &#x1F534; **malware,phishing & fraud**\n"
        else:
            dbotscore = Common.DBotScore.NONE
            desc = ""
            markdown += f"URL: {url}\nCAT: **unknown**\n"

        dbot = Common.DBotScore(url, DBotScoreType.URL, 'Cyren Inbox Security', dbotscore, desc)
        url_object_list.append(Common.URL(url, dbot))

    return CommandResults(indicators=url_object_list, readable_output=markdown)


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    instance_name = demisto.integrationInstance()
    feed_id = demisto.params().get('feed_id')
    token = demisto.params().get('token')
    url = demisto.params().get('url')
    threat_types_filter = demisto.params().get('threat_types', None)
    incident_types_filter = demisto.params().get('incident_types', None)
    # raise NameError(incident_types_filter)

    if url.lower().find('plutoserv.com') != -1:
        # sample server url part https://marketing.plutoserv.com
        url_part = "/toolbox/services/cis/demisto/v1/feed"
    else:
        # prod server url part https://awseu.apollo-prod.cyren.cloud
        url_part = "/timberwolf-data-provider/v1/feed"

    # get the service API url
    base_url = urljoin(url, url_part)

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
    max_results = arg_to_number(
        arg=demisto.params().get('max_fetch'),
        arg_name='max_fetch',
        required=False
    )
    if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
        max_results = MAX_INCIDENTS_TO_FETCH

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = arg_to_datetime(
        arg=demisto.params().get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    first_fetch_timestamp = int(first_fetch_time.timestamp()) if first_fetch_time else None
    # Using assert as a type guard (since first_fetch_time is always an int when required=True)
    assert isinstance(first_fetch_timestamp, int)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers = {
            'Authorization': f'Bearer {token}'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, feed_id)
            return_results(result)

        elif demisto.command() == 'cyreninboxsecurity-info':
            return_results(get_info_command(client, instance_name, feed_id))

        elif demisto.command() == 'url':
            return_results(url_command(client, **demisto.args()))

        elif demisto.command() == 'cyreninboxsecurity-dump-urls':
            return_results(dump_urls_command())

        elif demisto.command() == 'fetch-incidents':
            next_run, incidents = fetch_incidents_2(
                client=client,
                feed_id=feed_id,
                max_results=max_results,
                last_run=demisto.getLastRun(),
                incident_types_filter=incident_types_filter,
                threat_types_filter=threat_types_filter
            )

            # saves next_run for the time fetch-incidents is invoked
            # note: setLastRun only works during fetch-incidents, not for other commands.
            demisto.setLastRun(next_run)
            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to create
            demisto.incidents(incidents)

        elif demisto.command() == 'cyreninboxsecurity-simulate-fetch':
            # raise NameError(instance_name)
            if instance_name != demisto.args().get('instance_name', instance_name):
                return bypassing_instance(instance_name)
            verbose = False if demisto.args().get('verbose', "no") == "no" else True

            return_results(
                simulate_fetch_command(client, instance_name, feed_id, max_results,
                                       demisto.getLastRun(), incident_types_filter, threat_types_filter, verbose)
            )

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
''' IMPORTS '''
from typing import Dict, Tuple, List
from datetime import UTC
import urllib3

urllib3.disable_warnings()

"""Cyberpion Integration for Cortex XSOAR (aka Demisto)
"""


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%d %H:%M:%S.%f %Z'
DEFAULT_MAX_INCIDENTS_TO_FETCH = 200
CONNECTION_TIMEOUT = 30.0
READ_TIMEOUT = 30.0
VALID_STATUS_CODES = (200,)
NUM_OF_RETRIES = 3
BACKOFF_FACTOR = 1.0  # see documentation in CommonServerPython._http_request
ACTION_ITEM_TYPE_NAME = 'cyberpion_action_item'

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def get_domain_state(self, domain: str):
        params = {
            'verbosity': 'details',
            'domain': domain
        }
        demisto.debug(f'getting domain state for domain- {domain}')
        http_response = self._http_request(
            method='GET',
            url_suffix='/domainstate/',
            params=params,
            resp_type='json',
            ok_codes=VALID_STATUS_CODES,
            timeout=(CONNECTION_TIMEOUT, READ_TIMEOUT),
            retries=NUM_OF_RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            raise_on_status=True
        )
        if 'results' not in http_response:
            raise Exception(f'bad response from server!. response: {json.dumps(http_response, indent=2)}')
        http_response = http_response['results']
        if len(http_response) == 0:
            demisto.error(f'no response from server for domain: {domain}')
            return {}
        http_response = http_response[0]
        demisto.debug(f'after getting domain state for domain- {domain}')
        reverse_ips = http_response.get('ips')
        if reverse_ips is None:
            raise Exception(f'in server\'s response: ips is none. response: {json.dumps(http_response, indent=2)}')
        if type(reverse_ips) is dict:
            formatted_reverse_ips = '\n'.join(
                [f'{k}: {v}' for k, v in reverse_ips.items()])
        else:
            formatted_reverse_ips = reverse_ips
        http_response['ips'] = formatted_reverse_ips
        domain_types = http_response.get('domain_types')
        if domain_types is None:
            raise Exception(
                f'in server\'s response: domain_types is none. response: {json.dumps(http_response, indent=2)}')
        domain_info = ''
        for idx, domain_type in enumerate(domain_types, start=1):
            domain_info += f'{idx}.\n'
            domain_info += '\n'.join(
                [f'{k}: {v}' for k, v in domain_type.items()])
        http_response['domain_types'] = domain_info
        return http_response

    def get_action_items(self,
                         min_severity: int,
                         alert_types: list = None,
                         show_only_active=True,
                         max_fetch: int = None,
                         last_fetched_creation_time: str = None,
                         domain: str = None
                         ) -> List[dict]:
        params = {
            'verbosity': 'details',
            'urgency__gte': min_severity,
            'ordering': 'creation_time',
            'is_open': 'true' if show_only_active else 'false'
        }
        if alert_types:
            params['category'] = ','.join(alert_types)
        if max_fetch:
            params['page_size'] = max_fetch
        if last_fetched_creation_time:
            params['creation_time__gt'] = last_fetched_creation_time
        if domain:
            params['domain'] = domain
        http_responses = []
        # call API
        params['page'] = str(1)
        demisto.debug(f'getting action items, domain={domain}')
        http_response = self._http_request(
            method='GET',
            url_suffix='/actionitems/',
            params=params,
            resp_type='json',
            ok_codes=VALID_STATUS_CODES,
            timeout=(CONNECTION_TIMEOUT, READ_TIMEOUT),
            retries=NUM_OF_RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            raise_on_status=True
        )
        demisto.debug(f'after getting action items, domain={domain}')
        if 'results' not in http_response:
            raise Exception('failed to read action items.\nError: got response without \'results\' key')
        results = http_response['results']
        for idx, action_item in enumerate(results):
            technical_det = action_item.get('technical_details', {})
            if technical_det is None:
                raise Exception(f'technical details is none. {json.dumps(action_item, indent=2)}')
            if type(technical_det) is dict:
                formatted_technical_details = '\n'.join(
                    [f'{k}: {v}' for k, v in technical_det.items()])
            else:
                formatted_technical_details = technical_det
            results[idx]['technical_details'] = formatted_technical_details
            results[idx]['alert_type'] = ACTION_ITEM_TYPE_NAME
        http_responses.append(results)
        demisto.debug(f'finished getting action items, number of pages: {len(http_responses)}, domain={domain}')
        final_results = []
        for response in http_responses:
            final_results += response
        return final_results

    def get_domain_action_items(self, domain: str,
                                min_severity: int,
                                alert_types: list = None,
                                show_only_active=True
                                ) -> Dict[str, Any]:
        # call API
        return {
            "Domain": domain,
            "Vulnerabilities": self.get_action_items(domain=domain,
                                                     min_severity=min_severity,
                                                     alert_types=alert_types,
                                                     show_only_active=show_only_active,
                                                     max_fetch=None)
        }


''' HELPER FUNCTIONS '''


def convert_to_demisto_severity(severity: float) -> int:
    """Maps Cyberpion severity to Cortex XSOAR severity

    Converts the Cyberpion alert severity level (1 to 10, float) to Cortex XSOAR incident severity (1 to 4)
    for mapping.

    :type severity: ``float``
    :param severity: severity as returned from the Cyberpion API (float)

    :return: Cortex XSOAR Severity (1 to 4)
    :rtype: ``int``
    """

    # In this case the mapping is straightforward, but more complex mappings
    # might be required in your integration, so a dedicated function is
    # recommended. This mapping should also be documented.
    if 0 <= severity <= 2.5:
        return 1
    elif 2.6 <= severity <= 5:
        return 2
    elif 5.1 <= severity <= 7.5:
        return 3
    elif 7.6 <= severity <= 10:
        return 4
    raise Exception('value of severity is not between 0-10. invalid value of severity: {}'.format(severity))


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

    try:
        client.get_domain_action_items(domain='company1.com', min_severity=2)
        client.get_action_items(max_fetch=2, min_severity=1, alert_types=['PKI'])
        client.get_domain_state('company1.com')
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def fetch_incidents(client: Client,
                    max_fetch: int,
                    min_severity: int,
                    alert_types: list,
                    show_only_active: bool,
                    first_fetch: str = None
                    ) -> Tuple[Dict[str, str], List[dict]]:
    """This function retrieves new alerts every interval (default is 1 minute).

    :type client: ``Client``
    :param Client: Cyberpion integration client to use

    :type max_fetch: ``int``
    :param max_fetch: Maximum numbers of incidents per fetch

    :type min_severity: `int`
    :param min_severity:
        minimum severity of the alert to search for.
        Options are 1 to 10

    :type alert_types: ``List[str]``
    :param alert_type:
        type of alerts to search for. There is no list of predefined types

    :type first_fetch: `str`
    :param first_fetch:
        first date to fetch from. if null, all incidents will be fetched

    :return:
        A tuple containing two elements:
            next_run (``Dict[str, str]``): Contains the timestamp that will be
                    used in ``last_run`` on the next fetch.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR

    :rtype: ``Tuple[Dict[str, int], List[dict]]``
    """

    last_run_dict = demisto.getLastRun()
    if 'last_fetch' in last_run_dict:
        last_fetch = last_run_dict['last_fetch']
        demisto.debug('last fetch: {}'.format(str(last_fetch)))
    else:
        demisto.debug('no previous data... this means this is the first time we are fetching incidents')
        last_fetch = first_fetch
    demisto.debug("Cyberpion fetch incidents last run time\\first fetch: {}".format(
        str(last_fetch) if last_fetch else 'fetching all incidents, without time filter'))
    action_items = client.get_action_items(
        max_fetch=max_fetch,
        min_severity=min_severity,
        alert_types=alert_types,
        show_only_active=show_only_active,
        last_fetched_creation_time=last_fetch
    )
    incidents = []
    for action_item in action_items:
        creation_date = action_item['creation_time']  # must be string of a DATE_FORMAT
        iso_format_data = datetime.strptime(creation_date, DATE_FORMAT).replace(
            tzinfo=UTC).isoformat()
        incident = {
            'name': '{} - {}'.format(action_item['title'], action_item['domain']),
            # name is required field, must be set
            'occurred': iso_format_data,
            'rawJSON': json.dumps(action_item),
            'severity': convert_to_demisto_severity(action_item['urgency']),
        }
        # put in last_incident_date the last action_items creation date. assuming it's ordered by creation date
        # last_incident_date = creation_date
        incidents.append(incident)
    # last incident's time added to new_last_run_dict, so we can next time ask for incidents with creation_time__gt this time
    if len(action_items) > 0:
        last_incident_date = action_items[-1]['creation_time']
    else:
        # if no action items from last_incident_date to now, keep asking next time for (new incidents) from
        # last_incident_date and on
        last_incident_date = last_fetch
    new_last_run_dict = {'last_fetch': last_incident_date}
    return new_last_run_dict, incidents


def get_domain_state_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    domain = args.get('domain')
    if not domain:
        raise ValueError('no domain specified')
    demisto.debug(f'getting domain state {domain}')
    domain_state = client.get_domain_state(domain)
    demisto.debug(f'creating domain state table for domain {domain}')
    markdown = '### Cyberpion\n'
    markdown += tableToMarkdown('Domain State', domain_state, headers=[
        "id",
        "domain",
        "ips",
        "risk_rank",
        "vuln_count",
        "cname_chain",
        "domain_types",
        "discovery_date",
    ])
    demisto.debug(f'finished creating domain state table for domain {domain}')

    return CommandResults(
        readable_output=markdown,
        outputs_prefix='Cyberpion',
        outputs_key_field='id',
        outputs={"DomainState": domain_state}
    )


def get_domain_action_items_command(client: Client, args: Dict[str, Any], min_severity: int, alert_types: list = None,
                                    show_only_active: bool = True) -> CommandResults:
    domain = args.get('domain')
    if not domain:
        raise ValueError('no domain specified')
    demisto.debug(f'getting action items for domain {domain}')
    domain_data = client.get_domain_action_items(domain=domain,
                                                 min_severity=min_severity,
                                                 show_only_active=show_only_active,
                                                 alert_types=alert_types,
                                                 )
    demisto.debug(f'creating action items table data for domain {domain}')
    markdown = '### Cyberpion\n'
    markdown += tableToMarkdown('Action Items', domain_data['Vulnerabilities'], headers=[
        "domain",
        "category",
        "urgency",
        "is_open",
        "creation_time",
        "link",
        "title",
        "impact",
        "summary",
        "solution",
        "description",
        "technical_details"
    ])
    demisto.debug(f'finished creating table data for domain {domain}. returning command result')
    return CommandResults(
        readable_output=markdown,
        outputs_prefix='Cyberpion.DomainData',
        outputs_key_field='id',
        outputs=domain_data
    )


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # get the service API url
    base_url = demisto.params()['url']
    api_key = demisto.params()['apikey']
    min_severity = demisto.params()['minSeverity']  # mandatory
    alert_types = demisto.params()['categories']  # mandatory
    show_only_active = demisto.params()['ShowOnlyOpen']  # mandatory
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers = {
            'Authorization': 'Token {}'.format(api_key)
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        elif demisto.command() == 'cyberpion-get-domain-state':
            return_results(get_domain_state_command(client, demisto.args()))
        elif demisto.command() == 'cyberpion-get-domain-action-items':
            return_results(get_domain_action_items_command(client,
                                                           demisto.args(),
                                                           min_severity=min_severity,
                                                           alert_types=alert_types,
                                                           show_only_active=show_only_active))
        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            max_fetch = demisto.params().get('maxFetch')
            first_fetch: str = demisto.params().get('first_fetch')
            if first_fetch:
                months_back = datetime.now() - timedelta(days=30 * int(first_fetch))
                first_fetch = datetime.strftime(months_back, DATE_FORMAT)
            if not max_fetch:
                max_fetch = DEFAULT_MAX_INCIDENTS_TO_FETCH
            try:
                max_fetch = int(max_fetch)
                if max_fetch > 500 or max_fetch < 1:
                    raise ValueError()
            except ValueError:
                raise ValueError('max_fetch must be an integer between 1 to 500')
            if max_fetch > DEFAULT_MAX_INCIDENTS_TO_FETCH:
                max_fetch = DEFAULT_MAX_INCIDENTS_TO_FETCH

            new_last_run_dict, incidents = fetch_incidents(
                client=client,
                max_fetch=max_fetch,
                min_severity=min_severity,
                show_only_active=show_only_active,
                alert_types=alert_types,
                first_fetch=first_fetch
            )

            # create incidents
            demisto.incidents(incidents)
            # saves next_run for the time fetch-incidents is invoked
            demisto.setLastRun(new_last_run_dict)
        else:
            raise NotImplementedError(f'no such command: {demisto.command()}')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Cyberpion integration: Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

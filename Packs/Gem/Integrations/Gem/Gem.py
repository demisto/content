import re
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any
import jwt

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
PAGE_SIZE = 10
OK_CODES = (200, 201, 202)
MAX_ALERTS_TO_FETCH = 50

# ENDPOINTS
TOKEN_URL = 'https://login.gem.security/oauth/token'


# Get information Endpoints
THREATS_ENDPOINT = '/v1/threats'
THREAT_ENDPOINT = '/v1/threats/{id}'
INVENTORY_ENDPOINT = '/v1/inventory'
INVENTORY_ITEM_ENDPOINT = '/v1/inventory/{id}'

ALERTS_ENDPOINT = '/triage/investigation/timeline/configuration'
BREAKDOWN_ENDPOINT = '/triage/investigation/timeline/breakdown'
FETCH_ENDPOINT = '/integrations/notification'

# Actions Endpoints
UPDATE_THREAT_ENDPOINT = '/v1/threats/{id}/status'

RUN_ACTION_ENDPOINT = '/triage/containment/entity/run-action'
ADD_TIMELINE_EVENT_ENDPOINT = '/detection/threats/{id}/add_timeline_event'


''' CLIENT CLASS '''


class GemClient(BaseClient):
    """This class defines a client to interact with the Gem API
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool, client_id: str, client_secret: str):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, ok_codes=OK_CODES)
        self._client_id = client_id
        self._client_secret = client_secret
        try:
            self._auth_token = self._get_token()
        except Exception as e:
            raise DemistoException(f'Failed to get token. Error: {str(e)}')

    def _get_token(self):
        """
        Retrieves the authentication token for the Gem integration.

        If the token is not found in the integration context or if it is expired,
        a new token is generated and returned.

        Returns:
            str: The authentication token.
        """
        ctx = get_integration_context()

        if not ctx or not ctx.get('auth_token'):
            # No token in integration context, probably first run
            auth_token = self._generate_token()
        else:
            # Token exists, check if it's expired and generate a new one if needed
            auth_token = ctx.get('auth_token')
            decoded_jwt = jwt.decode(auth_token, options={"verify_signature": False})  # type: ignore

            token_expiration = datetime.fromtimestamp(decoded_jwt['exp'])

            if token_expiration < datetime.now():
                auth_token = self._generate_token()

        return auth_token

    def http_request(self, method: str, url_suffix='', full_url=None, headers=None, json_data=None, params=None, auth=True):
        """
        Sends an HTTP request to the specified URL, adding the required headers and authentication token.

        Args:
            method (str): The HTTP method to use (e.g., GET, POST, PUT, DELETE).
            url_suffix (str, optional): The URL suffix to append to the base URL. Defaults to ''.
            full_url (str, optional): The full URL to send the request to. If provided, `url_suffix` will be ignored.
            Defaults to None.
            headers (dict, optional): Additional headers to include in the request. Defaults to None.
            json_data (dict, optional): JSON data to include in the request body. Defaults to None.
            params (dict, optional): Query parameters to include in the request URL. Defaults to None.
            auth (bool, optional): Whether to include authentication headers. Defaults to True.

        Returns:
            dict: The response from the HTTP request.

        Raises:
            Exception: If the request fails.

        """
        if auth:
            headers = headers or {}
            headers['Authorization'] = f'Bearer {self._auth_token}'
        try:
            response = super()._http_request(
                method=method,
                url_suffix=url_suffix,
                full_url=full_url,
                headers=headers,
                json_data=json_data,
                params=params,
                raise_on_status=True
            )
            demisto.debug(f"Got response: {response}")
            return response
        except DemistoException as e:
            demisto.error(f"Failed to execute {method} request to {url_suffix}. Error: {str(e)}")
            raise Exception(f"Failed to execute {method} request to {url_suffix}. Error: {str(e)}")

    def _generate_token(self) -> str:
        """Generate an access token using the client id and secret
        :return: valid token
        """

        data = {
            'client_id': self._client_id,
            'client_secret': self._client_secret,
            'grant_type': 'client_credentials',
            "audience": "https://backend.gem.security"
        }

        headers = {
            'Content-Type': 'application/json'
        }

        token_res = self.http_request(
            method='POST',
            full_url=TOKEN_URL,
            headers=headers,
            json_data=data,
            auth=False
        )

        set_integration_context((get_integration_context() or {}).update({'auth_token': token_res.get('access_token')}))

        return token_res.get('access_token')

    def _filter_non_empty_params(self, params):
        return {k: v for k, v in params.items() if v is not None}

    def fetch_threats(self, maxincidents=None, start_time=None) -> list[dict]:
        """
        Fetches a list of threats from the Gem API.

        Args:
            maxincidents (int, optional): The maximum number of incidents to fetch. Defaults to None.
            start_time (str, optional): The start time to fetch incidents from. Defaults to None.

        Returns:
            list[dict]: A list of threat incidents.
        """
        params = {'limit': maxincidents, 'created__gt': start_time, 'ordering': 'created'}
        return self.http_request(
            method='GET',
            url_suffix=FETCH_ENDPOINT,
            params=self._filter_non_empty_params(params)

        )

    def get_resource_details(self, resource_id: str) -> dict:
        """
        Get inventory item details.

        :param resource_id: ID of the item to get.
        :return: Inventory item.
        """
        return self.http_request(
            method='GET',
            url_suffix=INVENTORY_ITEM_ENDPOINT.format(id=resource_id)
        )

    def get_threat_details(self, threat_id: str):
        """
        Get threat details

        :param threat_id: id of the threat to get
        :return: threat details
        """
        response = self.http_request(
            method='GET',
            url_suffix=THREAT_ENDPOINT.format(id=threat_id)
        )

        return response

    def get_alert_details(self, alert_id: str):
        """
        Get alert details

        :param alert_id: id of the alert to get
        :return: alert details
        """
        params = {"alert_id": alert_id}
        response = self.http_request(
            method='GET',
            url_suffix=ALERTS_ENDPOINT,
            params=self._filter_non_empty_params(params)
        )

        return response

    def list_threats(self, limit, time_start=None, time_end=None, ordering=None, status=None, ttp_id=None,
                     title=None, severity=None, entity_type=None, cloud_provider=None) -> list[dict]:
        """
        List threats
        :param time_start: time of first threat
        :param time_end: time of last threat
        :param limit: amount of threats
        :param ordering: how to order threats
        :param status: filter of threat status
        :param ttp_id: filter of threat ttp
        :param title: filter of threat title
        :param severity: filter of threat severity
        :param entity_type: filter of threat entity type
        :param cloud_provider: filter of threat cloud provider

        :return: threat list
        """

        results = []
        results_fetched = 0
        for p in range(1, int(limit / PAGE_SIZE) + 2):
            if limit == results_fetched:
                break
            if limit - results_fetched < PAGE_SIZE:
                demisto.debug(f"Fetching page #{p} page_size {limit - results_fetched}")
                params = {'start_time': time_start, 'end_time': time_end, 'page': p, 'page_size': limit - results_fetched,
                          'ordering': ordering,
                          'status': status, 'ttp_id': ttp_id, 'title': title, 'severity': severity, 'entity_type': entity_type,
                          'provider': cloud_provider}
                response = self.http_request(
                    method='GET',
                    url_suffix=THREATS_ENDPOINT,
                    params=self._filter_non_empty_params(params)

                )
                results_fetched = limit

            else:
                demisto.debug(f"Fetching page #{p} page_size {PAGE_SIZE}")
                params = {'start_time': time_start, 'end_time': time_end, 'page': p, 'page_size': PAGE_SIZE, 'ordering': ordering,
                          'status': status, 'ttp_id': ttp_id, 'title': title, 'severity': severity, 'entity_type': entity_type,
                          'provider': cloud_provider}
                response = self.http_request(
                    method='GET',
                    url_suffix=THREATS_ENDPOINT,
                    params=self._filter_non_empty_params(params)

                )
                if len(response['results']) < PAGE_SIZE:
                    demisto.debug(f"Fetched {len(response['results'])}")
                    results_fetched += len(response['results'])
                    results.extend(response['results'])
                    break

                results_fetched += PAGE_SIZE

            results.extend(response['results'])

        demisto.debug(f"Fetched {len(results)} threats")

        return results

    def list_inventory_resources(self, limit, include_deleted=None, region=None, resource_type=None,
                                 search=None) -> list[dict]:
        """List inventory resources

        Args:
            limit (int): How many resources to fetch
            include_deleted (boolean, optional): Should include deleted resources. Defaults to None.
            region (str, optional): Resources region. Defaults to None.
            resource_type (str, optional): Filter resource types. Defaults to None.
            search (str, optional): Filter search params. Defaults to None.

        Returns:
            list[dict]: List of inventory resources
        """
        results = []
        results_fetched = 0
        params = {'page_size': limit if limit < PAGE_SIZE else PAGE_SIZE, 'include_deleted': include_deleted, 'region': region,
                  'resource_type': resource_type, 'search': search}
        response = self.http_request(
            method='GET',
            url_suffix=INVENTORY_ENDPOINT,
            params=self._filter_non_empty_params(params)

        )
        results_fetched += len(response['results'])
        results.extend(response['results'])

        while response['next'] != "" and results_fetched < limit:
            page_size = limit - results_fetched if limit - results_fetched < PAGE_SIZE else PAGE_SIZE
            demisto.debug(f"Fetching page #{response['next']} page_size {page_size}")
            params = {'cursor': response['next'], 'page_size': page_size, 'include_deleted': include_deleted, 'region': region,
                      'resource_type': resource_type, 'search': search}
            response = self.http_request(
                method='GET',
                url_suffix=INVENTORY_ENDPOINT,
                params=self._filter_non_empty_params(params)

            )
            results_fetched += len(response['results'])
            results.extend(response['results'])

        demisto.debug(f"Fetched {len(results)} inventory resources")

        return results

    def _breakdown(self, breakdown_by, entity_id=None, entity_type=None, read_only=None, start_time=None, end_time=None) -> dict:

        params = {'breakdown_by': breakdown_by, 'entity_id': entity_id, 'entity_type': entity_type, 'read_only': read_only,
                  'start_time': start_time, 'end_time': end_time}
        response = self.http_request(
            method='GET',
            url_suffix=BREAKDOWN_ENDPOINT,
            params=self._filter_non_empty_params(params)
        )

        return response['table']

    def list_ips_by_entity(self, entity_id=None, entity_type=None, read_only=None, start_time=None,
                           end_time=None) -> dict:
        """
        Retrieves a dictionary of IP addresses associated with the specified entity.

        Args:
            entity_id (str): The ID of the entity.
            entity_type (str): The type of the entity.
            read_only (bool): Whether to retrieve read-only IP addresses.
            start_time (str): The start time for filtering IP addresses.
            end_time (str): The end time for filtering IP addresses.

        Returns:
            dict: A dictionary of IP addresses associated with the entity.
        """
        return self._breakdown(breakdown_by='source_ip', entity_id=entity_id, entity_type=entity_type, read_only=read_only,
                               start_time=start_time, end_time=end_time)

    def list_services_by_entity(self, entity_id=None, entity_type=None, read_only=None, start_time=None,
                                end_time=None) -> dict:
        """
        Retrieves a list of services associated with a specific entity.

        Args:
            entity_id (str): The ID of the entity.
            entity_type (str): The type of the entity.
            read_only (bool): Whether to retrieve read-only services only.
            start_time (str): The start time for filtering services.
            end_time (str): The end time for filtering services.

        Returns:
            dict: A dictionary containing the list of services associated with the entity.
        """
        return self._breakdown(breakdown_by='service', entity_id=entity_id, entity_type=entity_type, read_only=read_only,
                               start_time=start_time, end_time=end_time)

    def list_events_by_entity(self, entity_id=None, entity_type=None, read_only=None, start_time=None,
                              end_time=None) -> dict:
        """
        Retrieves a list of events associated with a specific entity.

        Args:
            entity_id (str): The ID of the entity.
            entity_type (str): The type of the entity.
            read_only (bool): Whether to retrieve read-only events only.
            start_time (str): The start time of the events.
            end_time (str): The end time of the events.

        Returns:
            dict: A dictionary containing the list of events.
        """
        return self._breakdown(breakdown_by='entity_event_out', entity_id=entity_id, entity_type=entity_type, read_only=read_only,
                               start_time=start_time, end_time=end_time)

    def list_accessing_entities(self, entity_id=None, entity_type=None, read_only=None, start_time=None,
                                end_time=None) -> dict:
        """
        Retrieves a list of accessing entities based on the provided parameters.

        Args:
            entity_id (str): The ID of the entity.
            entity_type (str): The type of the entity.
            read_only (bool): Specifies if the entity is read-only.
            start_time (datetime): The start time for filtering the accessing entities.
            end_time (datetime): The end time for filtering the accessing entities.

        Returns:
            dict: A dictionary containing the list of accessing entities.
        """
        return self._breakdown(breakdown_by='user_in', entity_id=entity_id, entity_type=entity_type, read_only=read_only,
                               start_time=start_time, end_time=end_time)

    def list_using_entities(self, entity_id=None, entity_type=None, read_only=None, start_time=None,
                            end_time=None) -> dict:
        """
        Retrieves a list of entities using the specified parameters.

        Args:
            entity_id (str, optional): The ID of the entity. Defaults to None.
            entity_type (str, optional): The type of the entity. Defaults to None.
            read_only (bool, optional): Specifies if the entity is read-only. Defaults to None.
            start_time (str, optional): The start time for filtering entities. Defaults to None.
            end_time (str, optional): The end time for filtering entities. Defaults to None.

        Returns:
            dict: A dictionary containing the list of entities.

        """
        return self._breakdown(breakdown_by='using_entities', entity_id=entity_id, entity_type=entity_type, read_only=read_only,
                               start_time=start_time, end_time=end_time)

    def list_events_on_entity(self, entity_id=None, entity_type=None, start_time=None, end_time=None, read_only=None) -> dict:
        """
        Retrieves a list of events associated with a specific entity.

        Args:
            entity_id (str): The ID of the entity.
            entity_type (str): The type of the entity.
            start_time (str): The start time of the events.
            end_time (str): The end time of the events.
            read_only (bool): Whether to retrieve read-only events only.

        Returns:
            dict: A dictionary containing the list of events.
        """
        return self._breakdown(breakdown_by='entity_event_in', entity_id=entity_id, entity_type=entity_type, read_only=read_only,
                               start_time=start_time, end_time=end_time)

    def list_accessing_ips(self, entity_id=None, entity_type=None, start_time=None, end_time=None, read_only=None) -> dict:
        """
        Retrieves a breakdown of accessing IPs for a given entity.

        Args:
            entity_id (str): The ID of the entity.
            entity_type (str): The type of the entity.
            start_time (str): The start time of the breakdown.
            end_time (str): The end time of the breakdown.
            read_only (bool): Whether to include read-only access in the breakdown.

        Returns:
            dict: A breakdown of accessing IPs.
        """
        return self._breakdown(breakdown_by='ip_access', entity_id=entity_id, entity_type=entity_type, read_only=read_only,
                               start_time=start_time, end_time=end_time)

    def update_threat_status(self, threat_id: str, status: Optional[str], verdict: Optional[str], reason: Optional[str] = None):
        """
        Update the threat status for a given threat ID.

        Args:
            threat_id (str): The ID of the threat to update.
            status (str): The new status of the threat.
            verdict (str): The new verdict of the threat.
            reason (str, optional): Additional information or reason for the update.

        Returns:
            dict: The response from the API call.
        """
        json_data = {'verdict': verdict, 'additional_info': reason, 'status': status}
        response = self.http_request(
            method='PATCH',
            url_suffix=UPDATE_THREAT_ENDPOINT.format(id=threat_id),
            json_data=json_data
        )

        return response

    def run_action_on_entity(self, action: str, entity_id: str, entity_type: str, alert_id: str,
                             resource_id: str) -> dict:
        """
        Runs an action on a specific entity.

        Args:
            action (str): The action to be performed on the entity.
            entity_id (str): The ID of the entity.
            entity_type (str): The type of the entity.
            alert_id (str): The ID of the alert associated with the entity.
            resource_id (str): The ID of the resource associated with the entity.

        Returns:
            dict: The response from the API.

        """
        params = {'action': action, 'entity_id': entity_id, 'entity_type': entity_type,
                  'alert_id': alert_id, 'resource_id': resource_id}

        response = self.http_request(
            method='POST',
            url_suffix=RUN_ACTION_ENDPOINT,
            params=self._filter_non_empty_params(params)
        )

        return response

    def add_timeline_event(self, threat_id: str, comment: str, timestamp: str) -> dict:
        """
        Adds a timeline event to a threat.

        Args:
            threat_id (str): The ID of the threat.
            comment (str): The comment for the timeline event.
            timestamp (str): The timestamp of the timeline event.

        Returns:
            dict: The response from the API.
        """
        params = {'title': "XSOAR comment", "description": comment, "timeline_event_type": "xsoar", "timestamp": timestamp}
        response = self.http_request(
            method='POST',
            url_suffix=ADD_TIMELINE_EVENT_ENDPOINT.format(id=threat_id),
            json_data=self._filter_non_empty_params(params)
        )

        return response


''' HELPER FUNCTIONS '''
# as per recommendation from @freylis, compile once only
CLEANR = re.compile('<.*?>')


def _cleanhtml(raw_html):
    """
    Cleans HTML tags from the given raw HTML string.

    Args:
        raw_html (str): The raw HTML string to be cleaned.

    Returns:
        str: The cleaned text without HTML tags.
    """
    cleantext = re.sub(CLEANR, '', raw_html)
    return cleantext.replace("\n", "")


def _clean_description(alert: dict) -> dict:
    """
    Cleans the description of the alert by removing HTML tags.

    Args:
        alert (dict): The alert dictionary.

    Returns:
        dict: The modified alert dictionary with cleaned description.
    """
    if alert['triage_configuration']['event_groups']:
        i = 0
        for e in alert['triage_configuration']['event_groups']:
            clean_description = _cleanhtml(e['description'])
            alert['triage_configuration']['event_groups'][i]['description'] = clean_description
            i += 1
    return alert


def init_client(params: dict) -> GemClient:
    """
    Initializes a new GemClient object
    """
    return GemClient(
        base_url=params['api_endpoint'],
        verify=not params.get('insecure', False),
        proxy=params.get('proxy', False),
        client_id=demisto.getParam('credentials')['identifier'] if demisto.getParam('credentials') else "",
        client_secret=demisto.getParam('credentials')['password'] if demisto.getParam('credentials') else ""
    )


''' COMMAND FUNCTIONS '''


def fetch_threats(client: GemClient, max_results: int, last_run: dict, first_fetch_time: str) -> tuple[dict, list[dict]]:
    """
    Fetches threats from the Gem platform within a specified time range.

    Args:
        client (GemClient): The Gem client object.
        max_results (int): Maximum number of results to fetch.
        last_run (dict): A dictionary containing information about the last run of the fetch.
        first_fetch_time (str): The earliest time from which to fetch threats, if there is no last run.

    Returns:
        tuple[dict, list[dict]]: A tuple containing the new last run and a list of incidents (threats).
    """
    last_fetch = last_run.get('last_fetch', None)
    if last_fetch is None:
        # if missing, use what provided via first_fetch_time
        last_fetch = first_fetch_time
    else:
        # otherwise use the stored last fetch
        last_fetch = last_fetch
    demisto.debug(f"Last fetch time: {last_fetch}")
    incidents: list[dict[str, Any]] = []

    for _ in range(0, int(max_results / PAGE_SIZE) + 1):
        results = client.fetch_threats(maxincidents=PAGE_SIZE, start_time=last_fetch)
        for r in results:
            incident = {
                'name': r['title'],        # name is required field, must be set
                'occurred': r['created'],  # must be string of a format ISO8601
                'dbotMirrorId': str(r['id']),  # must be a string
                'rawJSON': json.dumps(r)  # the original event, this will allow mapping of the event in the mapping stage.
            }
            incidents.append(incident)
        demisto.debug(f"Fetched {len(incidents)} incidents")
        if incidents:
            last_fetch = incidents[-1].get('occurred')

    demisto.debug(f"Last fetch time: {last_fetch}")
    assert last_fetch
    last_run['last_fetch'] = last_fetch

    return last_run, incidents


def test_module(params: dict[str, Any]) -> str:
    """
    Tests API connectivity and authentication.
    Return "ok" if test passed, anything else will fail the test.

    Args:
        params (Dict): Integration parameters

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    try:
        init_client(params)
    except Exception:
        raise DemistoException('Authentication failed')

    return 'ok'


def get_resource_details(client: GemClient, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves details of a specific resource from the Gem API.

    Args:
        client (GemClient): The Gem client object.
        args (dict): Command arguments, must contain 'resource_id'.

    Returns:
        CommandResults: Object containing the resource details for display in Cortex XSOAR.

    """
    resource_id = args.get('resource_id', "")

    result = client.get_resource_details(resource_id)

    return CommandResults(
        readable_output=tableToMarkdown('Inventory Item', result),
        outputs_prefix='Gem.InventoryItem',
        outputs_key_field='resource_id',
        outputs=result
    )


def get_threat_details(client: GemClient, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves details of a specific threat from the Gem API.

    Args:
        client (GemClient): The Gem client object.
        args (dict): Command arguments, must contain 'threat_id'.

    Returns:
        CommandResults: Object containing the threat details for display in Cortex XSOAR.

    """
    threat_id = args.get('threat_id', "")

    result = client.get_threat_details(threat_id=threat_id)

    return CommandResults(
        readable_output=tableToMarkdown('Threat', result),
        outputs_prefix='Gem.Threat',
        outputs_key_field='id',
        outputs=result
    )


def get_alert_details(client: GemClient, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves details of a specific alert from the Gem API.

    Args:
        client (GemClient): The Gem client object.
        args (dict): Command arguments, must contain 'alert_id'.

    Returns:
        CommandResults: Object containing the alert details for display in Cortex XSOAR.

    """
    alert_id = args.get('alert_id', "")

    result = client.get_alert_details(alert_id=alert_id)
    result = _clean_description(result)

    return CommandResults(
        readable_output=tableToMarkdown('Alert', result),
        outputs_prefix='Gem.Alert',
        outputs_key_field='id',
        outputs=result
    )


def list_inventory_resources(client: GemClient, args: dict[str, Any]) -> CommandResults:
    """
    Lists inventory resources from the Gem API based on provided arguments.

    Args:
        client (GemClient): The Gem client object.
        args (dict): Command arguments, may include 'limit', 'include_deleted', 'region',
                     'resource_type', and 'search'.

    Returns:
        CommandResults: Object containing the list of inventory resources for display in Cortex XSOAR.
    """
    limit = arg_to_number(args.get("limit")) or PAGE_SIZE
    include_deleted = args.get('include_deleted')
    region = args.get('region')
    resource_type = args.get('resource_type')
    search = args.get('search')

    result = client.list_inventory_resources(limit, include_deleted=include_deleted,
                                             region=region, resource_type=resource_type, search=search)

    return CommandResults(
        readable_output=tableToMarkdown('Inventory Items', result),
        outputs_prefix='Gem.InventoryItems',
        outputs_key_field='id',
        outputs=result
    )


def list_threats(client: GemClient, args: dict[str, Any]) -> CommandResults:
    """
    Lists threats from the Gem API based on provided time range and other optional filters.

    Args:
        client (GemClient): The Gem client object.
        args (dict): Command arguments, must include 'time_start' and 'time_end', and may include
                     'limit', 'ordering', 'status', 'ttp_id', 'title', 'severity', 'entity_type',
                     and 'cloud_provider'.

    Returns:
        CommandResults: Object containing the list of threats for display in Cortex XSOAR.

    """
    time_start = args.get('time_start')
    time_end = args.get('time_end')
    limit = arg_to_number(args.get("limit")) or PAGE_SIZE
    ordering = args.get('ordering')
    status = args.get('status')
    ttp_id = args.get('ttp_id')
    title = args.get('title')
    severity = args.get('severity')
    entity_type = args.get('entity_type')
    cloud_provider = args.get('cloud_provider')

    result = client.list_threats(time_start=time_start, time_end=time_end, limit=limit,
                                 ordering=ordering, status=status, ttp_id=ttp_id, title=title, severity=severity,
                                 entity_type=entity_type, cloud_provider=cloud_provider)

    demisto.debug(f"Got {len(result)} Threats")
    return CommandResults(
        readable_output=tableToMarkdown('Threats', result),
        outputs_prefix='Gem.ThreatsList',
        outputs_key_field='id',
        outputs=result
    )


def _breakdown_validate_params(client: GemClient, args: dict[str, Any]) -> tuple[Any, Any, Any | None, Any, Any]:
    """
    Validates and extracts parameters required for breakdown-related API requests.

    Args:
        client (GemClient): The Gem client object (unused in this function but included for consistency).
        args (dict): Command arguments, must include 'entity_id', 'entity_type', 'start_time', and 'end_time'.

    Returns:
        tuple: A tuple containing extracted parameters.

    """
    entity_id = args.get('entity_id')
    entity_type = args.get('entity_type')
    read_only = args.get('read_only')
    start_time = args.get('start_time')
    end_time = args.get('end_time')

    return entity_id, entity_type, read_only, start_time, end_time


def _parse_breakdown_result(result: dict) -> tuple[list[str], list[list[str]], list[dict]]:
    """
    Parses the result from a breakdown API response.

    Args:
        result (dict): The API response containing the breakdown results.

    Returns:
        tuple: A tuple containing parsed headers, rows for table display, and raw output data.
    """
    new_t = []

    for r in result['rows']:
        new_t.append(r['row'])

    return result['headers'], new_t, new_t


def list_ips_by_entity(client: GemClient, args: dict[str, Any]) -> CommandResults:
    """
    Lists IP addresses associated with a specific entity.

    Args:
        client (GemClient): The Gem client object.
        args (dict): Command arguments, including 'entity_id', 'entity_type', 'read_only', 'start_time', and 'end_time'.

    Returns:
        CommandResults: Object containing a list of IP addresses for display in Cortex XSOAR.
    """

    entity_id, entity_type, read_only, start_time, end_time = _breakdown_validate_params(client, args)

    result = client.list_ips_by_entity(entity_id=entity_id, entity_type=entity_type, read_only=read_only,
                                       start_time=start_time, end_time=end_time)
    headers, rows, outputs = _parse_breakdown_result(result)

    return CommandResults(
        readable_output=tableToMarkdown('IPs', rows, headers=headers),
        outputs_prefix='Gem.IP',
        outputs_key_field='SOURCEIPADDRESS',
        outputs=outputs
    )


def list_services_by_entity(client: GemClient, args: dict[str, Any]) -> CommandResults:
    """
    Lists services associated with a specific entity.

    Args:
        client (GemClient): The Gem client object.
        args (dict): Command arguments, including 'entity_id', 'entity_type', 'read_only', 'start_time', and 'end_time'.

    Returns:
        CommandResults: Object containing a list of services for display in Cortex XSOAR.
    """
    entity_id, entity_type, read_only, start_time, end_time = _breakdown_validate_params(client, args)

    result = client.list_services_by_entity(entity_id=entity_id, entity_type=entity_type, read_only=read_only,
                                            start_time=start_time, end_time=end_time)
    headers, rows, outputs = _parse_breakdown_result(result)

    return CommandResults(
        readable_output=tableToMarkdown('Services', rows, headers=headers),
        outputs_prefix='Gem.Entity.By.Services',
        outputs_key_field='SERVICE',
        outputs=outputs
    )


def list_events_by_entity(client: GemClient, args: dict[str, Any]) -> CommandResults:
    """
    Lists events associated with a specific entity.

    Args:
        client (GemClient): The Gem client object.
        args (dict): Command arguments, including 'entity_id', 'entity_type', 'read_only', 'start_time', and 'end_time'.

    Returns:
        CommandResults: Object containing a list of events for display in Cortex XSOAR.
    """
    entity_id, entity_type, read_only, start_time, end_time = _breakdown_validate_params(client, args)

    result = client.list_events_by_entity(entity_id=entity_id, entity_type=entity_type, read_only=read_only,
                                          start_time=start_time, end_time=end_time)
    headers, rows, outputs = _parse_breakdown_result(result)

    return CommandResults(
        readable_output=tableToMarkdown('Events by Entity', rows, headers=headers),
        outputs_prefix='Gem.Entity.By.Events',
        outputs_key_field='EVENTNAME',
        outputs=outputs
    )


def list_accessing_entities(client: GemClient, args: dict[str, Any]) -> CommandResults:
    """
    Lists entities that have accessed a specific entity.

    Args:
        client (GemClient): The Gem client object.
        args (dict): Command arguments, including 'entity_id', 'entity_type', 'read_only', 'start_time', and 'end_time'.

    Returns:
        CommandResults: Object containing a list of accessing entities for display in Cortex XSOAR.
    """

    entity_id, entity_type, read_only, start_time, end_time = _breakdown_validate_params(client, args)

    result = client.list_accessing_entities(entity_id=entity_id, entity_type=entity_type, read_only=read_only,
                                            start_time=start_time, end_time=end_time)
    headers, rows, outputs = _parse_breakdown_result(result)

    return CommandResults(
        readable_output=tableToMarkdown('Accessing Entities', rows, headers=headers),
        outputs_prefix='Gem.Entity.Accessing',
        outputs_key_field='',
        outputs=outputs
    )


def list_using_entities(client: GemClient, args: dict[str, Any]) -> CommandResults:
    """
    Lists entities using a specific entity.

    Args:
        client (GemClient): The Gem client object.
        args (dict): Command arguments, including 'entity_id', 'entity_type', 'read_only', 'start_time', and 'end_time'.

    Returns:
        CommandResults: Object containing a list of using entities for display in Cortex XSOAR.
    """

    entity_id, entity_type, read_only, start_time, end_time = _breakdown_validate_params(client, args)

    result = client.list_using_entities(entity_id=entity_id, entity_type=entity_type, read_only=read_only,
                                        start_time=start_time, end_time=end_time)
    headers, rows, outputs = _parse_breakdown_result(result)

    return CommandResults(
        readable_output=tableToMarkdown('Using Entities', rows, headers=headers),
        outputs_prefix='Gem.Entity.Using',
        outputs_key_field='ENTITY_ID',
        outputs=outputs
    )


def list_events_on_entity(client: GemClient, args: dict[str, Any]) -> CommandResults:
    """
    Lists events occurring on a specific entity.

    Args:
        client (GemClient): The Gem client object.
        args (dict): Command arguments, including 'entity_id', 'entity_type', 'read_only', 'start_time', and 'end_time'.

    Returns:
        CommandResults: Object containing a list of events on the entity for display in Cortex XSOAR.
    """

    entity_id, entity_type, read_only, start_time, end_time = _breakdown_validate_params(client, args)

    result = client.list_events_on_entity(entity_id=entity_id, entity_type=entity_type,
                                          start_time=start_time, end_time=end_time, read_only=read_only)
    headers, rows, outputs = _parse_breakdown_result(result)

    return CommandResults(
        readable_output=tableToMarkdown('Events on Entity', rows, headers=headers),
        outputs_prefix='Gem.Entity.On.Events',
        outputs_key_field='EVENTNAME',
        outputs=outputs
    )


def list_accessing_ips(client: GemClient, args: dict[str, Any]) -> CommandResults:
    """
    Lists IP addresses that have accessed a specific entity.

    Args:
        client (GemClient): The Gem client object.
        args (dict): Command arguments, including 'entity_id', 'entity_type', 'read_only', 'start_time', and 'end_time'.

    Returns:
        CommandResults: Object containing a list of accessing IP addresses for display in Cortex XSOAR.
    """

    entity_id, entity_type, read_only, start_time, end_time = _breakdown_validate_params(client, args)

    result = client.list_accessing_ips(entity_id=entity_id, entity_type=entity_type,
                                       start_time=start_time, end_time=end_time, read_only=read_only)
    headers, rows, outputs = _parse_breakdown_result(result)

    return CommandResults(
        readable_output=tableToMarkdown('IPs Accessing Entity', rows, headers=headers),
        outputs_prefix='Gem.Entity.Accessing.IPs',
        outputs_key_field='AS_NAME',
        outputs=outputs
    )


def update_threat_status(client: GemClient, args: dict[str, Any]):
    """
    Updates the status of a specified threat in the Gem system.

    Args:
        client (GemClient): The Gem client object.
        args (dict): Command arguments, must include 'threat_id', 'status', 'verdict', and optionally 'reason'.

    """
    threat_id = args.get('threat_id', "")
    status = args.get('status')
    verdict = args.get('verdict')
    reason = args.get('reason')

    client.update_threat_status(threat_id=threat_id, status=status, verdict=verdict, reason=reason)


def run_action_on_entity(client: GemClient, args: dict[str, Any]) -> CommandResults:

    action = args.get('action', "")
    entity_id = args.get('entity_id', "")
    entity_type = args.get('entity_type', "")
    alert_id = args.get('alert_id', "")
    resource_id = args.get('resource_id', "")

    result = client.run_action_on_entity(action=action, entity_id=entity_id, entity_type=entity_type, alert_id=alert_id,
                                         resource_id=resource_id,)

    return CommandResults(
        readable_output=tableToMarkdown('Run Result', result),
        outputs_prefix='Gem.Run',
        outputs_key_field='id',
        outputs=result
    )


def add_timeline_event(client: GemClient, args: dict[str, Any]) -> CommandResults:

    threat_id = args.get('threat_id', "")
    comment = args.get('comment', "")

    result = client.add_timeline_event(threat_id=threat_id, comment=comment, timestamp=datetime.now().strftime(DATE_FORMAT))
    return CommandResults(
        readable_output=tableToMarkdown('AddTimelineEvent Result', result),
        outputs_prefix='Gem.AddTimelineEvent',
        outputs_key_field='',
        outputs=result
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    demisto.debug(f"args {args}")
    demisto.debug(f"params {params}")

    demisto.debug(f'Command being called is {command}')
    try:
        if command == 'test-module':
            # This is the call made when pressing the integration Test button
            return_results(test_module(params))

        client = init_client(params)

        if command == 'gem-list-threats':
            return_results(list_threats(client, args))
        elif command == 'gem-get-threat-details':
            return_results(get_threat_details(client, args))
        elif command == 'gem-get-alert-details':
            return_results(get_alert_details(client, args))
        elif command == 'gem-list-inventory-resources':
            return_results(list_inventory_resources(client, args))
        elif command == 'gem-get-resource-details':
            return_results(get_resource_details(client, args))
        elif command == 'gem-list-ips-by-entity':
            return_results(list_ips_by_entity(client, args))
        elif command == 'gem-list-services-by-entity':
            return_results(list_services_by_entity(client, args))
        elif command == 'gem-list-events-by-entity':
            return_results(list_events_by_entity(client, args))
        elif command == 'gem-list-accessing-entities':
            return_results(list_accessing_entities(client, args))
        elif command == 'gem-list-using-entities':
            return_results(list_using_entities(client, args))
        elif command == 'gem-list-events-on-entity':
            return_results(list_events_on_entity(client, args))
        elif command == 'gem-list-accessing-ips':
            return_results(list_accessing_ips(client, args))
        elif command == 'gem-update-threat-status':
            return_results(update_threat_status(client, args))
        elif command == 'gem-run-action':
            return_results(run_action_on_entity(client, args))
        elif command == 'gem-add-timeline-event':
            return_results(add_timeline_event(client, args))
        elif command == 'fetch-incidents':
            # How much time before the first fetch to retrieve alerts
            first_fetch_time = arg_to_datetime(
                arg=params.get('first_fetch', '30 days'),
                arg_name='First fetch time',
                required=True
            )
            assert first_fetch_time

            max_results = arg_to_number(
                arg=params.get('max_fetch'),
                arg_name='max_fetch',
                required=False
            )
            if not max_results or max_results > MAX_ALERTS_TO_FETCH:
                max_results = MAX_ALERTS_TO_FETCH

            next_run, incidents = fetch_threats(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=datetime.strftime(first_fetch_time, DATE_FORMAT))

            demisto.debug(f'Fetched {len(incidents)} incidents')
            demisto.debug(f'Next run: {next_run}')
            # saves next_run for the time fetch-incidents is invoked
            demisto.setLastRun(next_run)
            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to create
            demisto.incidents(incidents)

        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

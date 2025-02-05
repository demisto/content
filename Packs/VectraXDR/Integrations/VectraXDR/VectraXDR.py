import copy
from collections.abc import Callable

import requests.auth
import urllib3
from urllib.parse import urlparse, parse_qs

from datetime import datetime
from requests.models import Response

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
STATUS_LIST_TO_RETRY = [429] + list(range(500, 600))
OK_CODES = (200, 201, 204, 401)
MAX_RETRIES = 3
BACKOFF_FACTOR = 15
FIRST_FETCH = '1 hour'
MAX_PAGE = 1
MAX_PAGE_SIZE = 50
ENTITY_AND_DETECTION_MAX_PAGE_SIZE = 5000
MAX_URGENCY_SCORE = 100
MIN_URGENCY_SCORE = 0
VALID_ENTITY_TYPE = ['account', 'host']
VALID_GROUP_TYPE = ['account', 'host', 'ip', 'domain']
VALID_IMPORTANCE_VALUE = ['high', 'medium', 'low', 'never_prioritize']
VALID_ENTITY_STATE = ['active', 'inactive']
DEFAULT_URGENCY_SCORE_LOW_THRESHOLD = 30
DEFAULT_URGENCY_SCORE_MEDIUM_THRESHOLD = 50
DEFAULT_URGENCY_SCORE_HIGH_THRESHOLD = 80
MAX_MIRRORING_LIMIT = 5000
MAX_OUTGOING_NOTE_LIMIT = 8000
PACK_VERSION = get_pack_version(pack_name='Vectra XDR') or '1.0.0'
UTM_PIVOT = f"?pivot=Vectra-XSOAR-{PACK_VERSION}"
EMPTY_ASSIGNMENT = [{"id": "", "date_assigned": "", "date_resolved": "", "assigned_to": {"username": ""},
                     "resolved_by": {"username": ""}, "assigned_by": {"username": ""}, "outcome": {"title": ""}}]
DETECTION_CATEGORY_TO_ARG = {
    'Command & Control': 'command',
    'Botnet': 'botnet',
    'Reconnaissance': 'reconnaissance',
    'Lateral Movement': 'lateral',
    'Exfiltration': 'exfiltration',
    'Info': 'info'
}
ERRORS = {
    'INVALID_OBJECT': 'Failed to parse {} object from response: {}',
    'INVALID_URGENCY_SCORE_THRESHOLD': 'Invalid urgency score thresholds for severity mapping. Please ensure that the '
                                       'urgency score thresholds follow the correct order: '
                                       'urgency_score_low_threshold < urgency_score_medium_threshold < '
                                       'urgency_score_high_threshold.',
    'INVALID_COMMAND_ARG_VALUE': "Invalid '{}' value provided. Please ensure it is one of the values from the "
                                 "following options: {}.",
    'REQUIRED_ARGUMENT': "Please provide valid value of the '{}'. It is required field.",
    'INVALID_INTEGER_VALUE': "'{}' value must be a non-zero and positive integer value.",
    'INVALID_NUMBER': '"{}" is not a valid number',
    'INVALID_PAGE_RESPONSE': 'page contains no results',
    'INVALID_MAX_FETCH': 'Invalid Max Fetch: {}. Max Fetch must be a positive integer ranging from 1 to 200.',
    'INVALID_PAGE_SIZE': "Invalid 'page size' provided. Please ensure that the page size value is between 1 and 5000.",
    'TRIAGE_AS_REQUIRED_WITH_DETECTION_IDS': "'triage_as' argument must be provided when using the 'detection_ids' "
                                             "argument. ",
    'INVALID_OUTCOME': "Invalid outcome value. Valid outcome values are: {}",
    'INVALID_SUPPORT_FOR_ARG': 'The argument "{}" must be set to "{}" when providing value for argument "{}".',
    'ENTITY_IDS_WITHOUT_TYPE': "When using the 'entity_ids' argument, 'entity_type' is required, and vice versa.",
}
ENDPOINTS = {
    'AUTH_ENDPOINT': '/oauth2/token',
    'USER_ENDPOINT': '/api/v3.3/users',
    'GROUP_ENDPOINT': '/api/v3.3/groups',
    'ENTITY_ENDPOINT': '/api/v3.3/entities',
    'DETECTION_ENDPOINT': '/api/v3.3/detections',
    'ADD_AND_LIST_ENTITY_NOTE_ENDPOINT': '/api/v3.3/entities/{}/notes',
    'UPDATE_AND_REMOVE_ENTITY_NOTE_ENDPOINT': '/api/v3.3/entities/{}/notes/{}',
    'ENTITY_TAG_ENDPOINT': '/api/v3.3/tagging/entity/{}',
    'ASSIGNMENT_ENDPOINT': '/api/v3.3/assignments',
    'UPDATE_ASSIGNMENT_ENDPOINT': '/api/v3.3/assignments/{}',
    'RESOLVE_ASSIGNMENT_ENDPOINT': '/api/v3.3/assignments/{}/resolve',
    'ASSIGNMENT_OUTCOME_ENDPOINT': '/api/v3.3/assignment_outcomes/',
    'DOWNLOAD_DETECTION_PCAP': '/api/v3.3/detections/{}/pcap'
}
USER_AGENT = f"VectraXDR-XSOAR-{PACK_VERSION}"
PAGE_SIZE = 200
ENTITY_IMPORTANCE = {
    'low': 0,
    'medium': 1,
    'high': 2
}
ENTITY_IMPORTANCE_LABEL = {
    0: 'Low',
    1: 'Medium',
    2: 'High'
}
SEVERITY = {
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4
}
MIRROR_DIRECTION = {
    'Incoming': 'In',
    'Outgoing': 'Out',
    'Incoming And Outgoing': 'Both'
}

""" CLIENT CLASS """


class VectraClient(BaseClient):
    """
    Client class to interact with the Vectra API.
    """

    def __init__(self, server_url: str, client_id: str, client_secret_key: str, verify: bool, proxy: bool):
        """
        Initializes the class instance.

        Args:
            server_url (str): The URL of the server.
            client_id (str): The client ID for authentication.
            client_secret_key (str): The client secret key for authentication.
            verify (bool): Indicates whether to verify the server's SSL certificate.
            proxy (bool): Indicates whether to use a proxy for the requests.
        """
        super().__init__(base_url=server_url, verify=verify, proxy=proxy)
        self.client_id = client_id
        self.client_secret_key = client_secret_key

        # Fetch cached integration context.
        integration_context = get_integration_context()
        self._token = integration_context.get("access_token") or self._generate_tokens()

    def http_request(self, method: str, url_suffix: str = '', params: dict[str, Any] = None,
                     data: dict[str, Any] = None, json_data: dict[str, Any] = None, response_type: str = 'response',
                     **kwargs):
        """
        Makes an HTTP request to the server.

        Args:
            method (str): The HTTP method (e.g., GET, POST, PUT, DELETE).
            url_suffix (str): The URL suffix to be appended to the base URL. Defaults to an empty string.
            params (dict): Query parameters to be appended to the URL. Defaults to None.
            data (object): Data to be sent in the request body. Defaults to None.
            json_data (dict): JSON data to be sent in the request body. Defaults to None.
            response_type (str): The expected response type. Defaults to None.
            **kwargs: Additional keyword arguments.

        Returns:
            object: The response object or None.
        """
        # Set the headers for the request, including the User-Agent and Authorization.
        headers = {
            'User-Agent': USER_AGENT,
            'Authorization': f'Bearer {self._token}'
        }
        demisto.debug(f'Making API request at {method} {url_suffix} with params:{params} and body:{data or json_data}')
        # Make the HTTP request using the _http_request method, passing the necessary parameters.
        res = self._http_request(method=method, url_suffix=url_suffix, headers=headers, data=data, json_data=json_data,
                                 params=params, retries=MAX_RETRIES, status_list_to_retry=STATUS_LIST_TO_RETRY,
                                 ok_codes=OK_CODES, backoff_factor=BACKOFF_FACTOR, resp_type='response',
                                 raise_on_status=True, **kwargs)
        # If the response status code indicates an authentication issue (e.g., 401),
        # generate a new access token using the refresh token and retry the request.
        if res.status_code in [401]:
            demisto.debug('Handling status code 401 by generating a new token using the refresh token.')
            self._token = self._generate_access_token_using_refresh_token()
            return self.http_request(method=method, url_suffix=url_suffix, params=params, response_type=response_type,
                                     data=data, json_data=json_data, **kwargs)
        try:
            result = None
            if response_type == 'json':
                result = res.json()
            if response_type == 'content':
                result = res.content()
            if response_type == 'response':
                result = res
            if response_type == 'text':
                result = res.text
        except ValueError as exception:
            raise DemistoException(ERRORS['INVALID_OBJECT']  # type: ignore[str-bytes-safe]
                                   .format(response_type, res.content), exception, res)
        # If the success response is received, then return it.
        if res.status_code in [200, 201, 204]:
            return result
        # Return None if the response status code does not indicate success.
        return None

    def _generate_tokens(self) -> str:
        """
        Generates access tokens using client credentials.

        Returns:
            str: The access token.
        """
        demisto.info("Generating new access token.")

        payload = 'grant_type=client_credentials'
        auth = requests.auth.HTTPBasicAuth(self.client_id, self.client_secret_key)
        headers = {
            'User-Agent': USER_AGENT,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }
        response = self._http_request(method='POST', url_suffix=ENDPOINTS['AUTH_ENDPOINT'], headers=headers,
                                      data=payload, auth=auth, retries=MAX_RETRIES, backoff_factor=BACKOFF_FACTOR,
                                      status_list_to_retry=STATUS_LIST_TO_RETRY, raise_on_status=True)

        access_token = response.get('access_token')
        refresh_token = response.get('refresh_token')
        set_integration_context({'access_token': access_token, 'refresh_token': refresh_token})
        return access_token

    def _generate_access_token_using_refresh_token(self) -> str:  # type: ignore
        """
        Generates a new access token using the refresh token.

        Returns:
            str: The access token.
        """
        context = get_integration_context()
        refresh_token = context.get('refresh_token')
        demisto.info("Generating new access token using refresh token.")

        payload = f'grant_type=refresh_token&refresh_token={refresh_token}'
        headers = {
            'User-Agent': USER_AGENT,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }
        response = self._http_request(method='POST', url_suffix=ENDPOINTS['AUTH_ENDPOINT'], headers=headers,
                                      data=payload, ok_codes=OK_CODES, retries=MAX_RETRIES,
                                      backoff_factor=BACKOFF_FACTOR,
                                      raise_on_status=True, resp_type='response')
        if response.status_code in [401]:
            return self._generate_tokens()
        elif response.status_code in [200, 201]:
            access_token = response.json().get('access_token')
            # set new access token
            set_integration_context({'access_token': access_token, 'refresh_token': refresh_token})
            return access_token

    def list_users_request(self, username: Optional[str], role=Optional[str],
                           last_login_timestamp=Optional[datetime]) -> dict:
        """
        List users.

        Args:
            username (Optional[str]): The optional username to filter with (default: None).
            role (Optional[str]): The optional user role to filter with (default: None).
            last_login_timestamp (Optional[str]): Filter users after the specified last login timestamp (default: None).

        Returns:
            Dict: Response from the API containing the users.
        """
        params = assign_params(username=username, role=role, last_login_gte=last_login_timestamp)
        return self.http_request(method='GET', url_suffix=ENDPOINTS['USER_ENDPOINT'], params=params,
                                 response_type='json')

    def list_entities_request(self, page: int = MAX_PAGE, page_size: int = MAX_PAGE_SIZE, is_prioritized: bool = None,
                              entity_type: str = None, last_modified_timestamp: Optional[datetime] = None,
                              last_detection_timestamp: Optional[datetime] = None,
                              tags: str = None, ordering: str = None, state: str = 'active') -> dict:
        """List entities.

        Args:
            page (int): The page number to retrieve (default: MAX_PAGE).
            page_size (int): The number of entities to retrieve per page (default: MAX_PAGE_SIZE).
            is_prioritized (bool): Filter entities by prioritization status (default: None).
            entity_type (str): Filter entities by type (default: None).
            last_modified_timestamp (str): Filter entities modified after the specified timestamp (default: None).
            last_detection_timestamp (str): Filter entities detected detection after the specified timestamp
            (default: None).
            tags (str): Filter entities by tags (default: None).
            ordering (str): Specify the ordering of the entities (default: None).
            state (str): Filter entities by state (default: 'active').

        Returns:
            Dict: Response from the API containing the list of entities.
        """
        params = assign_params(page=page, page_size=page_size, is_prioritized=is_prioritized, type=entity_type,
                               last_modified_timestamp_gte=last_modified_timestamp,
                               last_detection_timestamp_gte=last_detection_timestamp, tags=tags, state=state,
                               ordering=ordering)
        entities = self.http_request(method='GET', url_suffix=ENDPOINTS['ENTITY_ENDPOINT'], params=params,
                                     response_type='json')
        return entities

    def get_entity_request(self, entity_id: int = None, entity_type: str = None) -> dict:
        """Get entity by ID.

        Args:
            entity_id (int): The ID of the entity to retrieve.
            entity_type (str): Filter entity by type (default: None).

        Returns:
            Dict: Response from the API containing the entity information.
        """
        params = assign_params(type=entity_type)
        entity = self.http_request(method='GET', url_suffix="{}/{}".format(ENDPOINTS['ENTITY_ENDPOINT'], entity_id),
                                   params=params, response_type='json')
        return entity

    def list_detections_request(self, detection_category: str = None, detection_type: str = None, entity_id: int = None,
                                page: int = None, page_size: int = None, last_timestamp: Optional[datetime] = None,
                                tags: str = None, state: str = 'active', detection_name: str = None,
                                ids: str = None) -> dict:
        """
        List detections.

        Args:
            detection_category (str, optional): Filter by detection category.
            detection_type (str, optional): Filter by detection type.
            entity_id (int, optional): Filter by entity ID.
            page (int, optional): Page number of the results.
            page_size (int, optional): Number of results per page.
            last_timestamp (str, optional): Filter by last timestamp greater than or equal to the provided value.
            tags (str, optional): Filter by tags.
            state (str, optional): Filter by detection state.
            detection_name (str, optional): Filter by detection name.
            ids(str, optional): Filter by detections ids.

        Returns:
            Dict: Response from the API containing the list of detections.
        """
        params = assign_params(detection_category=detection_category, detection_type=detection_type,
                               entity_id=entity_id,
                               page=page, page_size=page_size, last_timestamp_gte=last_timestamp, tags=tags,
                               state=state, detection=detection_name, id=ids)
        detections = self.http_request(method='GET', url_suffix=ENDPOINTS['DETECTION_ENDPOINT'], params=params,
                                       response_type='json')
        return detections

    def list_entity_note_request(self, entity_id: int = None, entity_type: str = None) -> dict:
        """
        List entity notes.

        Args:
            entity_id (int): The ID of the entity to add the note to.
            entity_type (str): The type of the entity.

        Returns:
            Dict: Response from the API.
        """
        params = assign_params(type=entity_type)
        notes = self.http_request(method='GET',
                                  url_suffix=ENDPOINTS['ADD_AND_LIST_ENTITY_NOTE_ENDPOINT'].format(entity_id),
                                  params=params, response_type='json')
        return notes

    def add_entity_note_request(self, entity_id: int = None, entity_type: str = None, note: str = None) -> dict:
        """
        Add a note to an entity.

        Args:
            entity_id (int): The ID of the entity to add the note to.
            entity_type (str): The type of the entity.
            note (str): The note to add.

        Returns:
            Dict: Response from the API containing the added note.
        """
        params = assign_params(type=entity_type)
        data = {'note': note}
        notes = self.http_request(method='POST',
                                  url_suffix=ENDPOINTS['ADD_AND_LIST_ENTITY_NOTE_ENDPOINT'].format(entity_id),
                                  params=params, data=data, response_type='json')
        return notes

    def update_entity_note_request(self, entity_id: int = None, entity_type: str = None, note: str = None,
                                   note_id: int = None) -> dict:
        """
        Updates the note of an entity.

        Args:
            entity_id (int): The ID of the entity to update the note for.
            entity_type (str): The type of the entity.
            note (str): The updated note for the entity.
            note_id (int): The ID of the note to be updated.

        Returns:
            Dict: Response from the API containing the updated note details.
        """
        params = assign_params(type=entity_type)
        data = {'note': note}
        notes = self.http_request(method='PATCH',
                                  url_suffix=ENDPOINTS['UPDATE_AND_REMOVE_ENTITY_NOTE_ENDPOINT'].format(entity_id,
                                                                                                        note_id),
                                  params=params, data=data, response_type='json')
        return notes

    def remove_entity_note_request(self, entity_id: int = None, entity_type: str = None, note_id: int = None):
        """
        Removes a note from an entity.

        Args:
            entity_id (int): The ID of the entity to remove the note from.
            entity_type (str): The type of the entity.
            note_id (int): The ID of the note to be removed.

        Returns:
            Dict: Response from the API confirming the removal of the note.
        """
        params = assign_params(type=entity_type)
        res = self.http_request(method='DELETE',
                                url_suffix=ENDPOINTS['UPDATE_AND_REMOVE_ENTITY_NOTE_ENDPOINT'].format(entity_id,
                                                                                                      note_id),
                                params=params, response_type='response')
        return res

    def update_entity_tags_request(self, entity_id: int = None, entity_type: str = None, tags: List = None) -> dict:
        """
        Update tags to an entity.

        Args:
            entity_id (int): The ID of the entity to add the tags to.
            entity_type (str): The type of the entity.
            tags (List): Tags to set for entity.

        Returns:
            Dict: Response from the API containing the updated tags.
        """
        params = assign_params(type=entity_type)
        data = {'tags': tags}
        res = self.http_request(method='PATCH', url_suffix=ENDPOINTS['ENTITY_TAG_ENDPOINT'].format(entity_id),
                                params=params, json_data=data, response_type='json')
        return res

    def list_entity_tags_request(self, entity_id: int = None, entity_type: str = None) -> dict:
        """
        List tags for the specified entity.

        Args:
            entity_id (int): The ID of the entity to add tags.
            entity_type (str): The type of the entity.

        Returns:
            Dict: Response from the API containing the tags.
        """
        params = assign_params(type=entity_type)
        res = self.http_request(method='GET', url_suffix=ENDPOINTS['ENTITY_TAG_ENDPOINT'].format(entity_id),
                                params=params, response_type='json')
        return res

    def mark_or_unmark_detection_fixed_request(self, detection_ids: List[str], mark: str) -> dict:
        """
        Mark or unmark detections as fixed.

        Args:
            detection_ids (List[str]): List of detection IDs to mark or unmark as fixed.
            mark (str): True to mark as fixed, False to unmark as fixed.

        Returns:
            Dict: Response from the API.

        Raises:
            ValueError: If detection_ids is empty.
        """

        data = {
            "detectionIdList": detection_ids,
            "mark_as_fixed": mark
        }

        res = self.http_request(method='PATCH', url_suffix=ENDPOINTS['DETECTION_ENDPOINT'], json_data=data,
                                response_type='json')
        return res

    def list_assignments_request(self, account_ids: str = None, host_ids: str = None, resolution: str = None,
                                 resolved: bool = None, created_after: str = None,
                                 assignees: str = None, page: int = None, page_size: int = None) -> dict:
        """
        Retrieve a list of assignments based on the provided account IDs and host IDs.

        Args:
            account_ids (str, optional): A string containing comma-separated account IDs to filter assignments.
            host_ids (str, optional): A string containing comma-separated host IDs to filter assignments.
            resolution (str, optional): The resolution status of the assignments.
            resolved (bool, optional): Whether the assignments are resolved (True) or unresolved (False).
            created_after (str, optional): Filter assignments created after this date and time.
            assignees (str, optional): A string containing comma-separated assignee usernames to filter assignments.
            page (int, optional): Page number of the results.
            page_size (int, optional): Number of results per page.

        Returns:
            dict: Response from the API.
        """
        params = assign_params(accounts=account_ids, hosts=host_ids, resolution=resolution, resolved=resolved,
                               created_after=created_after, assignees=assignees, page=page, page_size=page_size)
        res = self.http_request(method='GET', url_suffix=ENDPOINTS['ASSIGNMENT_ENDPOINT'], params=params,
                                response_type='json')
        return res

    def add_entity_assignment_request(self, assign_to_user_id: Optional[int] = None,
                                      assign_host_id: Optional[int] = None,
                                      assign_account_id: Optional[int] = None) -> dict:
        """
        Send a request to add an entity assignment.

        Args:
            assign_to_user_id (str, optional): The ID of the user to whom the entity will be assigned.
                Defaults to None.
            assign_host_id (str, optional): The ID of the host to which the entity will be assigned.
                Defaults to None.
            assign_account_id (str, optional): The ID of the account to which the entity will be assigned.
                Defaults to None.

        Returns:
            dict: A dictionary containing the response from the API call. The structure of the dictionary
            depends on the specific implementation of the API.
        """
        body = assign_params(assign_to_user_id=assign_to_user_id, assign_host_id=assign_host_id,
                             assign_account_id=assign_account_id)
        res = self.http_request(method='POST', url_suffix=ENDPOINTS['ASSIGNMENT_ENDPOINT'], data=body,
                                response_type='json')
        return res

    def update_entity_assignment_request(self, assign_to_user_id: Optional[int] = None,
                                         assignment_id: Optional[int] = None) -> dict:
        """
        Send a request to update an existing entity assignment.

        Args:
            assign_to_user_id (Optional[int], optional): The ID of the user to whom the entity will be reassigned.
                Defaults to None.
            assignment_id (Optional[int], optional): The ID of the assignment to be updated.
                Defaults to None.

        Returns:
            dict: Response from the API.
        """
        body = assign_params(assign_to_user_id=assign_to_user_id)
        res = self.http_request(method='PUT', url_suffix=ENDPOINTS['UPDATE_ASSIGNMENT_ENDPOINT'].format(assignment_id),
                                data=body, response_type='json')
        return res

    def resolve_entity_assignment_request(self, assignment_id: Optional[int] = None, outcome: int = None,
                                          note: str = "Updated by XSOAR.",
                                          triage_as: str = None, detection_ids=None) -> dict:
        """
        Resolves an entity assignment.

        Args:
            assignment_id (str, optional): The ID of the assignment to resolve.
            outcome (int, optional): The outcome of the resolved assignment.
            note (str, optional): A note to add to the resolution (default is "Updated by XSOAR.").
            triage_as (str, optional): The triage status to set for the resolved assignment.
            detection_ids (List[str], optional): The IDs of detections associated with the assignment.

        Returns:
            dict: Response from the API.
        """
        body = assign_params(outcome=outcome, note=note, triage_as=triage_as, detection_ids=detection_ids)
        res = self.http_request(method='PUT', url_suffix=ENDPOINTS['RESOLVE_ASSIGNMENT_ENDPOINT'].format(assignment_id),
                                data=body, response_type='json')
        return res

    def list_assignment_outcomes_request(self, page: int = None, page_size: int = None) -> dict:
        """
        Send a request to retrieve a list of assignment outcomes.

        Args:
            page (int, optional): Page number of the results.
            page_size (int, optional): Number of results per page.

        Returns:
            dict: Response from the API.
        """
        params = assign_params(page=page, page_size=page_size)
        res = self.http_request(method='GET', url_suffix=ENDPOINTS['ASSIGNMENT_OUTCOME_ENDPOINT'], params=params,
                                response_type='json')
        return res

    def download_detection_pcap_request(self, detection_id: str = None) -> Response:
        """
        Send a request to download the packet capture (PCAP) associated with a Vectra detection.

        Args:
            detection_id (str, optional): The ID of the detection for which the PCAP should be downloaded.

        Returns:
            Response: Response from the API.
        """
        res = self.http_request(method='GET', url_suffix=ENDPOINTS['DOWNLOAD_DETECTION_PCAP'].format(detection_id),
                                response_type='response')
        return res

    def list_group_request(self, group_type: str, account_names: List[str], domains: List[str], host_ids: List[str],
                           host_names: List[str], importance: str, ips: List[str], description: str,
                           last_modified_timestamp: Optional[datetime], last_modified_by: str, group_name: str) -> dict:
        """
        List groups as per the specified parameters.

        Args:
            group_type (str): Filter by group type.
            account_names (List[str]): Filter groups associated with accounts.
            domains (List[str]): Filter groups associated with domains.
            host_ids (List[str]): Filter groups associated with hosts.
            host_names (List[str]): Filter groups associated with hosts.
            importance (str): User defined group importance.
            ips (List[str]): Filter groups associated with ips.
            description (List[str]): Filter by group description.
            last_modified_timestamp (Optional[datetime]):
                Filters for all groups modified on or after the given timestamp (GTE).
            last_modified_by (str): Filters groups by the user id who made the most recent modification.
            group_name (str): Filters by group name.

        Returns:
            Dict: Response from the API containing the tags.
        """
        params = assign_params(type=group_type, account_names=','.join(account_names), domains=','.join(domains),
                               host_ids=','.join(host_ids), host_names=','.join(host_names), importance=importance,
                               ips=','.join(ips), description=description, name=group_name,
                               last_modified_timestamp=last_modified_timestamp, last_modified_by=last_modified_by)
        res = self.http_request(method='GET', url_suffix=ENDPOINTS['GROUP_ENDPOINT'], params=params,
                                response_type='json')
        return res

    def get_group_request(self, group_id: int = None) -> dict:
        """Get group by ID.

        Args:
            group_id (int): The ID of the group to retrieve.

        Returns:
            Dict: Response from the API containing the group information.
        """
        group = self.http_request(method='GET', url_suffix="{}/{}".format(ENDPOINTS['GROUP_ENDPOINT'], group_id),
                                  response_type='json')
        return group

    def update_group_members_request(self, group_id: int = None, members: List = None) -> dict:
        """Update members in group.

        Args:
            group_id (int): The ID of the group to retrieve.
            members (List): The member list.

        Returns:
            Dict: Response from the API containing the group information.
        """
        body = {
            "members": members
        }
        group = self.http_request(method='PATCH', url_suffix="{}/{}".format(ENDPOINTS['GROUP_ENDPOINT'], group_id),
                                  json_data=body, response_type='json')
        return group


""" HELPER FUNCTIONS """


def validate_urgency_score(urgency_score: str, score_name: str) -> Optional[int]:
    """
    Validates the urgency score to ensure it falls within the valid range of 0 to 100.

    Args:
        urgency_score (str): The urgency score to validate.
        score_name (str): The name of the urgency score.

    Raises:
        ValueError: If the urgency score is outside the valid range.
    """
    score = arg_to_number(urgency_score, arg_name=score_name)
    if not MIN_URGENCY_SCORE <= score <= MAX_URGENCY_SCORE:  # type: ignore
        raise ValueError(f"Please provide a valid {score_name} between 0 and 100.")
    return score


def validate_configuration_parameters(params: dict[str, Any]):
    """
    Validates the configuration parameters provided.

    Args:
        params (Dict[str, Any]): A dictionary containing the configuration parameters.

    Raises:
        ValueError: Raised when required parameters are missing or have invalid values.
    """
    fetch_time = params.get('first_fetch')
    max_fetch = params.get('max_fetch')
    urgency_score = params.get('urgency_score')
    urgency_score_low_threshold = params.get('urgency_score_low_threshold', '30').strip()
    urgency_score_medium_threshold = params.get('urgency_score_medium_threshold', '50').strip()
    urgency_score_high_threshold = params.get('urgency_score_high_threshold', '80').strip()

    # Validate empty values
    if not fetch_time:
        raise ValueError(ERRORS['REQUIRED_ARGUMENT'].format('First Fetch Time'))
    if not max_fetch:
        raise ValueError(ERRORS['REQUIRED_ARGUMENT'].format('Max Fetch'))
    # validate max_fetch
    max_fetch = arg_to_number(max_fetch, arg_name='Max Fetch', required=True)
    if not 1 <= max_fetch <= 200:  # type: ignore
        raise ValueError(ERRORS['INVALID_MAX_FETCH'].format(max_fetch))
    # validate first_fetch parameter
    arg_to_datetime(fetch_time, arg_name='first_fetch', required=True)

    # validate urgency score
    if urgency_score:
        validate_urgency_score(urgency_score, 'urgency_score')  # type: ignore

    uslt = validate_urgency_score(urgency_score_low_threshold, 'urgency_score_low_threshold')  # type: ignore

    usmt = validate_urgency_score(urgency_score_medium_threshold, 'urgency_score_medium_threshold')  # type: ignore

    usht = validate_urgency_score(urgency_score_high_threshold, 'urgency_score_high_threshold')  # type: ignore

    # validating urgency score threshold
    if not (uslt < usmt < usht):  # type: ignore
        raise ValueError(ERRORS['INVALID_URGENCY_SCORE_THRESHOLD'])


def validate_positive_integer_arg(value: Optional[Any], arg_name: str, required: bool = False) -> bool:
    """
    Validates whether the provided argument value is a valid positive integer.

    Args:
        value (int): The value to validate.
        arg_name (str): The name of the argument.
        required (bool): Flag indicating if the argument is required (default: False).

    Returns:
        bool: True if the value is a valid positive integer.

    Raises:
        ValueError: If the value is not a valid positive integer.
    """
    if required and not value:
        raise ValueError(ERRORS['REQUIRED_ARGUMENT'].format(arg_name))
    if value is not None and (not str(value).isdigit() or int(value) <= 0):
        raise ValueError(ERRORS['INVALID_INTEGER_VALUE'].format(arg_name))

    return True


def validate_entity_list_command_args(args: dict):
    """
    Validate the arguments for the entity_list command.

    Args:
        args (Dict): The arguments passed to the entity_list command.

    Raises:
        ValueError: If any of the arguments are invalid.

    Returns:
        None
    """
    entity_type = args.get('entity_type', '').lower()
    state = args.get('state', '').lower()
    page = args.get('page', '1')
    page_size = args.get('page_size', '50')
    # Validate entity_type value
    if entity_type and entity_type not in VALID_ENTITY_TYPE:
        raise ValueError(ERRORS['INVALID_COMMAND_ARG_VALUE'].format('entity_type', ', '.join(VALID_ENTITY_TYPE)))

    # Validate state value
    if state and state not in VALID_ENTITY_STATE:
        raise ValueError(ERRORS['INVALID_COMMAND_ARG_VALUE'].format('state', ', '.join(VALID_ENTITY_STATE)))

    validate_positive_integer_arg(page, arg_name='page')
    validate_positive_integer_arg(page_size, arg_name='page_size')
    if not 1 <= int(page_size) <= ENTITY_AND_DETECTION_MAX_PAGE_SIZE:
        raise ValueError(ERRORS['INVALID_PAGE_SIZE'])


def validate_list_entity_detections_args(args: dict[Any, Any]):
    """
    Validate the arguments for listing entity detections.

    Args:
         args (dict[Any, Any]): The arguments dictionary.

    Raises:
        ValueError: If the entity ID is not provided.
        ValueError: If the detection category is invalid.
        ValueError: If the page size is invalid.
    """
    entity_id = args.get('entity_id')
    entity_type = args.get('entity_type', '').lower()
    detection_category = args.get('detection_category')
    page = args.get('page', '1')
    page_size = args.get('page_size', '50')

    validate_positive_integer_arg(entity_id, arg_name='entity_id', required=True)

    if not entity_type:
        raise ValueError(ERRORS['REQUIRED_ARGUMENT'].format('entity_type'))
    if entity_type not in VALID_ENTITY_TYPE:
        raise ValueError(ERRORS['INVALID_COMMAND_ARG_VALUE'].format('entity_type', ', '.join(VALID_ENTITY_TYPE)))

    if detection_category and detection_category not in DETECTION_CATEGORY_TO_ARG.keys():
        raise ValueError(ERRORS['INVALID_COMMAND_ARG_VALUE'].format('detection_category',
                                                                    ', '.join(DETECTION_CATEGORY_TO_ARG.keys())))

    validate_positive_integer_arg(value=page, arg_name='page')
    validate_positive_integer_arg(value=page_size, arg_name='page_size')
    if not 1 <= int(page_size) <= ENTITY_AND_DETECTION_MAX_PAGE_SIZE:
        raise ValueError(ERRORS['INVALID_PAGE_SIZE'])


def validate_detection_describe_args(args: dict[Any, Any]):
    """
    Validate the arguments for detection describe.

    Args:
         args (dict[Any, Any]): The arguments dictionary.

    Raises:
        ValueError: If the detection IDs are not provided.
        ValueError: If the page size is invalid.
    """
    detection_ids = args.get('detection_ids', '')
    page = args.get('page', '1')
    page_size = args.get('page_size', '50')

    detection_ids = argToList(detection_ids, transform=arg_to_number)
    found_valid_detection_ids = False
    for detection_id in detection_ids:
        if isinstance(detection_id, int):
            if detection_id < 1:
                raise ValueError(ERRORS['INVALID_INTEGER_VALUE'].format('detection_ids'))
            found_valid_detection_ids = True
    if not found_valid_detection_ids:
        raise ValueError(ERRORS['REQUIRED_ARGUMENT'].format('detection_ids'))

    validate_positive_integer_arg(value=page, arg_name='page')
    validate_positive_integer_arg(value=page_size, arg_name='page_size')
    if not 1 <= int(page_size) <= ENTITY_AND_DETECTION_MAX_PAGE_SIZE:
        raise ValueError(ERRORS['INVALID_PAGE_SIZE'])


def validate_entity_note_list_command_args(args: dict[Any, Any]):
    """
    Validates the arguments provided for the entity list add command.

    Args:
        args (dict[Any, Any]): The arguments dictionary.

    Raises:
        ValueError: If any of the arguments are invalid.
    """
    entity_type = args.get('entity_type', '').lower()
    entity_id = args.get('entity_id')
    # Validate entity_id value
    validate_positive_integer_arg(entity_id, arg_name='entity_id', required=True)
    # Validate entity_type value
    if not entity_type:
        raise ValueError(ERRORS['REQUIRED_ARGUMENT'].format('entity_type'))
    if entity_type and entity_type not in VALID_ENTITY_TYPE:
        raise ValueError(ERRORS['INVALID_COMMAND_ARG_VALUE'].format('entity_type', ', '.join(VALID_ENTITY_TYPE)))


def validate_entity_note_add_command_args(args: dict[Any, Any]):
    """
    Validates the arguments provided for the entity note add command.

    Args:
        args (dict[Any, Any]): The arguments dictionary.

    Raises:
        ValueError: If any of the arguments are invalid.
    """
    entity_type = args.get('entity_type', '').lower()
    note = args.get('note')
    entity_id = args.get('entity_id')
    # Validate entity_id value
    validate_positive_integer_arg(entity_id, arg_name='entity_id', required=True)
    # Validate entity_type value
    if not entity_type:
        raise ValueError(ERRORS['REQUIRED_ARGUMENT'].format('entity_type'))
    if entity_type and entity_type not in VALID_ENTITY_TYPE:
        raise ValueError(ERRORS['INVALID_COMMAND_ARG_VALUE'].format('entity_type', ', '.join(VALID_ENTITY_TYPE)))
    # Validate note value
    if not note:
        raise ValueError(ERRORS['REQUIRED_ARGUMENT'].format('note'))


def validate_entity_note_update_command_args(args: dict[Any, Any]):
    """
    Validates the arguments provided for the entity note update command.

    Args:
        args (dict[Any, Any]): The arguments dictionary.

    Raises:
        ValueError: If any of the arguments are invalid.
    """
    entity_type = args.get('entity_type', '').lower()
    note = args.get('note')
    entity_id = args.get('entity_id')
    note_id = args.get('note_id')
    # Validate entity_id value
    validate_positive_integer_arg(entity_id, arg_name='entity_id', required=True)
    # Validate note_id value
    validate_positive_integer_arg(note_id, arg_name='note_id', required=True)
    if not entity_type:
        raise ValueError(ERRORS['REQUIRED_ARGUMENT'].format('entity_type'))
    if entity_type and entity_type not in VALID_ENTITY_TYPE:
        raise ValueError(ERRORS['INVALID_COMMAND_ARG_VALUE'].format('entity_type', ', '.join(VALID_ENTITY_TYPE)))
    # Validate note value
    if not note:
        raise ValueError(ERRORS['REQUIRED_ARGUMENT'].format('note'))


def validate_entity_note_remove_command_args(args: dict[Any, Any]):
    """
    Validates the arguments provided for the entity note update command.

    Args:
        args (dict[Any, Any]): The arguments dictionary.

    Raises:
        ValueError: If any of the arguments are invalid.
    """
    entity_type = args.get('entity_type', '').lower()
    entity_id = args.get('entity_id')
    note_id = args.get('note_id')
    # Validate entity_id value
    validate_positive_integer_arg(entity_id, arg_name='entity_id', required=True)
    # Validate note_id value
    validate_positive_integer_arg(note_id, arg_name='note_id', required=True)
    # Validate entity_type value
    if not entity_type:
        raise ValueError(ERRORS['REQUIRED_ARGUMENT'].format('entity_type'))
    if entity_type and entity_type.lower() not in VALID_ENTITY_TYPE:
        raise ValueError(ERRORS['INVALID_COMMAND_ARG_VALUE'].format('entity_type', ', '.join(VALID_ENTITY_TYPE)))


def validate_entity_tag_add_command_args(args: dict[Any, Any]):
    """
    Validates the arguments provided for the entity tag add command.

    Args:
        args (dict[Any, Any]): The arguments dictionary.

    Raises:
        ValueError: If any of the arguments are invalid.
    """
    validate_entity_tag_list_command_args(args)
    tags = argToList(args.get('tags', ''))
    # Validate Tags value
    if not [tag.strip() for tag in tags if isinstance(tag, str) and tag.strip()]:
        raise ValueError(ERRORS['REQUIRED_ARGUMENT'].format('tags'))


def validate_entity_tag_list_command_args(args: dict[Any, Any]):
    """
    Validates the arguments provided for the entity tag list command.

    Args:
        args (dict[Any, Any]): The arguments dictionary.

    Raises:
        ValueError: If any of the arguments are invalid.
    """
    entity_type = args.get('entity_type', '').lower()
    entity_id = args.get('entity_id')
    # Validate entity_id value
    validate_positive_integer_arg(entity_id, arg_name='entity_id', required=True)
    # Validate entity_type value
    if not entity_type:
        raise ValueError(ERRORS['REQUIRED_ARGUMENT'].format('entity_type'))
    if entity_type and entity_type not in VALID_ENTITY_TYPE:
        raise ValueError(ERRORS['INVALID_COMMAND_ARG_VALUE'].format('entity_type', ', '.join(VALID_ENTITY_TYPE)))


def validate_detections_mark_and_unmark_args(detection_ids: List):
    """
    Validate the arguments for mark and unmark detections as fixed.

    Args:
        detection_ids (List[int]): The list of detection IDs.

    Raises:
        ValueError: If the detection IDs are empty or contain invalid values.
    """
    # Validate detection_ids
    if not detection_ids:
        raise ValueError(ERRORS['REQUIRED_ARGUMENT'].format('detection_ids'))
    all(validate_positive_integer_arg(i, arg_name='detection_ids') for i in detection_ids)


def validate_assignment_list_command_args(args: dict):
    """
    Validate the arguments provided for the assignment list command.

    Args:
        args (Dict): A dictionary containing the arguments for the assignment list command.

    Raises:
        ValueError: If the provided entity_type is not one of the valid types.
        ValueError: If entity_ids are provided without an entity_type and vice-versa.
        ValueError: If page or page_size values are not positive integers.
    """
    entity_ids = args.get('entity_ids')
    entity_type = args.get('entity_type')
    page = args.get('page', '1')
    page_size = args.get('page_size', '50')
    # Validate entity type
    if entity_type and entity_type.lower() not in VALID_ENTITY_TYPE:
        raise ValueError(ERRORS['INVALID_COMMAND_ARG_VALUE'].format('entity_type', ', '.join(VALID_ENTITY_TYPE)))
    # Validate entity ids without entity_type and vice-versa
    if (entity_ids and not entity_type) or (entity_type and not entity_ids):
        raise ValueError(ERRORS['ENTITY_IDS_WITHOUT_TYPE'])
    # Validate pagination
    validate_positive_integer_arg(value=page, arg_name='page')
    validate_positive_integer_arg(value=page_size, arg_name='page_size')


def validate_entity_assignment_add_command_args(args: dict):
    """
    Validate the arguments provided for adding an entity assignment.

    Args:
        args (Dict): A dictionary containing the arguments for adding an entity assignment.

    Raises:
        ValueError: If the provided entity_id or user_id is not a positive integer.
        ValueError: If the entity_type is missing or not one of the valid types.
    """
    entity_id = args.get('entity_id')
    entity_type = args.get('entity_type')
    user_id = args.get('user_id')
    # Validate entity_id value
    validate_positive_integer_arg(entity_id, arg_name='entity_id', required=True)
    # Validate note_id value
    validate_positive_integer_arg(user_id, arg_name='user_id', required=True)
    # Validate entity_type value
    if not entity_type:
        raise ValueError(ERRORS['REQUIRED_ARGUMENT'].format('entity_type'))
    if entity_type and entity_type.lower() not in VALID_ENTITY_TYPE:
        raise ValueError(ERRORS['INVALID_COMMAND_ARG_VALUE'].format('entity_type', ', '.join(VALID_ENTITY_TYPE)))


def validate_entity_assignment_update_command_args(args: dict):
    """
    Validate the arguments provided for updating an entity assignment.

    Args:
        args (Dict): A dictionary containing the arguments for updating an entity assignment.

    Raises:
        ValueError: If the provided assignment_id or user_id is not a positive integer.
    """
    assignment_id = args.get('assignment_id')
    user_id = args.get('user_id')
    # Validate assignment_id value
    validate_positive_integer_arg(assignment_id, arg_name='assignment_id', required=True)
    # Validate user_id value
    validate_positive_integer_arg(user_id, arg_name='user_id', required=True)


def validate_entity_assignment_resolve_command_args(args):
    """
    Validate the arguments provided for resolving an entity assignment.

    Args:
        args (Dict): A dictionary containing the arguments for resolving an entity assignment.

    Raises:
        ValueError: If the provided assignment_id is not a positive integer.
        ValueError: If the outcome argument is missing.
        ValueError: If detection_ids are provided without triage_as.
    """
    outcome = args.get('outcome')
    assignment_id = args.get('assignment_id')
    triage_as = args.get('triage_as')
    detection_ids = args.get('detection_ids')
    # Validate assignment_id value
    validate_positive_integer_arg(assignment_id, arg_name='assignment_id', required=True)
    # Validate outcome value
    if not outcome:
        raise ValueError(ERRORS['REQUIRED_ARGUMENT'].format('outcome'))
    if detection_ids and not triage_as:
        raise ValueError(ERRORS['TRIAGE_AS_REQUIRED_WITH_DETECTION_IDS'])


def validate_entity_detections_mark_fix_command_args(args):
    """
    Validate the arguments provided for marking entity detections as fixed.

    Args:
        args (Dict): A dictionary containing the arguments for marking entity detections as fixed.

    Raises:
        ValueError: If the provided entity_id is not a positive integer.
        ValueError: If the entity_type is missing or not one of the valid types.
    """
    entity_id = args.get('entity_id')
    entity_type = args.get('entity_type')
    validate_positive_integer_arg(entity_id, arg_name="entity_id", required=True)

    if not entity_type:
        raise ValueError(ERRORS['REQUIRED_ARGUMENT'].format('entity_type'))
    if entity_type and entity_type.lower() not in VALID_ENTITY_TYPE:
        raise ValueError(ERRORS['INVALID_COMMAND_ARG_VALUE'].format('entity_type', ', '.join(VALID_ENTITY_TYPE)))


def validate_group_list_command_args(args: dict[Any, Any]):
    """
    Validates the arguments provided for the group list command.

    Args:
        args (dict[Any, Any]): The arguments dictionary.

    Raises:
        ValueError: If any of the arguments are invalid.
    """
    group_type = args.get('group_type') or ''
    if group_type and isinstance(group_type, str):
        group_type = group_type.lower()
        # Validate group_type value
        if group_type not in VALID_GROUP_TYPE:
            raise ValueError(ERRORS['INVALID_COMMAND_ARG_VALUE'].format('group_type', ', '.join(VALID_GROUP_TYPE)))

    importance = args.get('importance') or ''
    # Validate importance value
    if importance and isinstance(importance, str) and importance.lower() not in VALID_IMPORTANCE_VALUE:
        raise ValueError(ERRORS['INVALID_COMMAND_ARG_VALUE'].format('importance', ', '.join(VALID_IMPORTANCE_VALUE)))

    # Validate account_names value
    account_names = argToList(args.get('account_names') or '')
    if account_names and group_type != 'account':
        raise ValueError(ERRORS['INVALID_SUPPORT_FOR_ARG'].format('group_type', 'account', 'account_names'))

    # Validate domains value
    domains = argToList(args.get('domains') or '')
    if domains and group_type != 'domain':
        raise ValueError(ERRORS['INVALID_SUPPORT_FOR_ARG'].format('group_type', 'domain', 'domains'))

    # Validate host_ids value
    host_ids = argToList(args.get('host_ids') or '')
    if host_ids and group_type != 'host':
        raise ValueError(ERRORS['INVALID_SUPPORT_FOR_ARG'].format('group_type', 'host', 'host_ids'))
    for host_id in host_ids:
        host_id = arg_to_number(host_id, 'host_ids')
        validate_positive_integer_arg(host_id, arg_name="host_ids")

    # Validate host_names value
    host_names = argToList(args.get('host_names') or '')
    if host_names and group_type != 'host':
        raise ValueError(ERRORS['INVALID_SUPPORT_FOR_ARG'].format('group_type', 'host', 'host_names'))

    # Validate ips value
    ips = argToList(args.get('ips') or '')
    if ips and group_type != 'ip':
        raise ValueError(ERRORS['INVALID_SUPPORT_FOR_ARG'].format('group_type', 'ip', 'ips'))


def validate_group_assign_and_unassign_command_args(args):
    """
    Validate the arguments provided for assigning or unassigning members to/from a group.

    Args:
        args (Dict): A dictionary containing the arguments for the group assign and unassign command.

    Raises:
        ValueError: If the provided group_id is not a positive integer.
        ValueError: If members argument is missing.
    """
    group_id = args.get('group_id')
    members = args.get('members')
    validate_positive_integer_arg(group_id, arg_name="group_id", required=True)

    if not members:
        raise ValueError(ERRORS['REQUIRED_ARGUMENT'].format('members'))


def urgency_score_to_severity(entity_urgency_score: Optional[int], params: dict[str, Any]) -> int:
    """
    Maps the urgency score to severity levels.
    Demisto's severity levels are 4 - Critical, 3 - High, 2 - Medium, 1 - Low

    Args:
        entity_urgency_score(int): The urgency score to be mapped.
        params (Dict[str, Any]): Fetch incidents parameters.

    Returns
        severity(int):The corresponding severity level based on the urgency score.
    """
    try:
        urgency_score_lt = validate_urgency_score(urgency_score=params.get('urgency_score_low_threshold', '30').strip(),
                                                  score_name='urgency_score_lt')
    except ValueError:
        demisto.error(
            'Provided urgency_score_low_threshold is not a valid number. Falling back to default threshold value 30.')
        urgency_score_lt = DEFAULT_URGENCY_SCORE_LOW_THRESHOLD

    try:
        urgency_score_mt = validate_urgency_score(
            urgency_score=params.get('urgency_score_medium_threshold', '50').strip(),
            score_name='urgency_score_mt')
    except ValueError:
        demisto.error(
            'Provided urgency_score_medium_threshold is not a valid number. Falling back to default threshold value 50.')
        urgency_score_mt = DEFAULT_URGENCY_SCORE_MEDIUM_THRESHOLD

    try:
        urgency_score_ht = validate_urgency_score(
            urgency_score=params.get('urgency_score_high_threshold', '80').strip(),
            score_name='urgency_score_ht')
    except ValueError:
        demisto.error(
            'Provided urgency_score_high_threshold is not a valid number. Falling back to default threshold value 80.')
        urgency_score_ht = DEFAULT_URGENCY_SCORE_HIGH_THRESHOLD

    if entity_urgency_score > urgency_score_ht:  # type: ignore
        return SEVERITY['critical']
    elif entity_urgency_score > urgency_score_mt:  # type: ignore
        return SEVERITY['high']
    elif entity_urgency_score > urgency_score_lt:  # type: ignore
        return SEVERITY['medium']
    else:
        return SEVERITY['low']


def trim_spaces_from_args(args: dict) -> dict:
    """
    Trim spaces from values of the args Dict.

    Args:
        args (Dict): Dictionary to trim spaces from.

    Returns:
        Dict: Arguments after trim spaces.
    """
    for key, val in args.items():
        if isinstance(val, str):
            args[key] = val.strip()
        val_list = argToList(val)
        if len(val_list) > 1:
            val_list = [item for item in val_list if item.strip()]
            args[key] = ','.join(val_list)
    return args


def calc_pages(total_count: int, per_page_count: int):
    """
    Calculates the number of pages required to display all the items,
    considering the number of items to be displayed per page

    Args:
        total_count (int): The total number of items.
        per_page_count (int): The count of items per page.

    Returns:
        int: The total number of pages.
    """
    return -(-total_count // per_page_count)


def trim_api_version(url: str) -> str:
    """
    Trim the '/api/v3.3' portion from a URL.

    Args:
        url (str): The URL to trim.

    Returns:
        str: The trimmed URL.
    """
    api_versions = ["/api/v3.3", "/api/v3"]
    for api_version in api_versions:
        if api_version in url:
            trimmed_url = url.replace(api_version, "") + UTM_PIVOT
            return trimmed_url
    return url


def get_mirroring():
    """
    Get the mirroring configuration parameters from the Demisto integration parameters.

    Returns:
        dict: A dictionary containing the mirroring configuration parameters.
    """
    params = demisto.params()
    mirror_direction = params.get('mirror_direction', 'None').strip()
    mirror_tags = params.get('note_tag', '').strip()
    return {
        'mirror_direction': MIRROR_DIRECTION.get(mirror_direction),
        'mirror_tags': mirror_tags,
        'mirror_instance': demisto.integrationInstance()
    }


def reopen_in_xsoar(entries: list, entity_id_type: list):
    """Reopen the XSOAR incident for the given entity.

    Args:
        entries (list): List of entries where the reopening entry will be appended.
        entity_id_type (list): Indicates the entity ID and type.
    """
    demisto.debug(f'Reopening the incident with remote entity ID: {entity_id_type}.')
    entries.append({
        'Type': EntryType.NOTE,
        'Contents': {
            'dbotIncidentReopen': True
        },
        'ContentsFormat': EntryFormat.JSON
    })


def get_user_list_command_hr(users: List):
    """
    Converts a list of users into a human-readable table format.

    Args:
        users (Dict): The list of entities to convert.

    Returns:
        str: The human-readable table in Markdown format.
    """
    hr_dict = []
    # Process detection_set and create detection_ids field
    for user in users:  # type: ignore
        user["user_id"] = user["id"]
        hr_dict.append({
            "User ID": user.get('user_id'),
            "User Name": user.get('username'),
            "Email": user.get('email'),
            "Role": user.get('role'),
            "Last Login Timestamp": user.get('last_login_timestamp'),
        })
    # Prepare human-readable output table
    human_readable = tableToMarkdown("Users Table", hr_dict,
                                     ['User ID', 'User Name', 'Email', 'Role', 'Last Login Timestamp'], removeNull=True)

    return human_readable


def get_entity_list_command_hr(entities: dict, page: int, page_size: int, count: int):
    """
    Converts a list of entities into a human-readable table format.

    Args:
        entities (Dict): The list of entities to convert.
        page (int): The current page number.
        page_size (int): The page size.
        count (int): The total count of entities.

    Returns:
        str: The human-readable table in Markdown format.
    """
    hr_dict = []
    entity_list = copy.deepcopy(entities)
    # Process detection_set and create detection_ids field
    for entity in entity_list:  # type: ignore
        # Trim API version from url
        entity['url'] = trim_api_version(entity.get('url'))
        # Convert ID into clickable URL
        entity['id_url'] = f"[{entity['id']}]({entity['url']})"
        # Map entity importance
        entity['importance'] = ENTITY_IMPORTANCE_LABEL[entity.get('importance')]
        if 'detection_set' in entity:
            entity['detection_ids'] = ', '.join(
                ["[{}]({})".format(detection.split('/')[-1], trim_api_version(detection)) for detection in
                 entity.get('detection_set')])
        hr_dict.append({
            "ID": entity.get('id_url'),
            "Name": entity.get('name'),
            "Entity Type": entity.get('type'),
            "Urgency Score": entity.get('urgency_score'),
            "Entity Importance": entity.get('importance'),
            "Last Modified Timestamp": entity.get('last_modified_timestamp'),
            "Last Detection Timestamp": entity.get('last_detection_timestamp'),
            "Detections IDs": entity.get('detection_ids'),
            "Prioritize": entity.get('is_prioritized'),
            "State": entity.get('state'),
            "Tags": ', '.join(entity.get('tags')) if entity.get('tags') else None,
        })
    # Prepare human-readable output table
    pages = calc_pages(per_page_count=page_size, total_count=count)  # type: ignore
    human_readable = tableToMarkdown(f"Entities Table (Showing Page {page} out of {pages})",
                                     hr_dict,
                                     ['ID', 'Name', 'Entity Type', 'Urgency Score', 'Entity Importance',
                                      'Last Detection Timestamp', 'Last Modified Timestamp', 'Detections IDs',
                                      'Prioritize', 'State', 'Tags'],
                                     removeNull=True)

    return human_readable


def get_entity_get_command_hr(entity: dict):
    """
    Returns the human-readable output for the entity details.

    Args:
        entity (Dict): The entity details dictionary.

    Returns:
        str: The human-readable output.
    """
    hr_dict = []
    entity_res = copy.deepcopy(entity)
    # Trim API version from entity url
    entity_res['url'] = trim_api_version(entity_res.get('url'))  # type: ignore
    entity_res['id'] = f"[{entity_res['id']}]({entity_res['url']})"

    # Process detection_set and create detection_ids field
    if 'detection_set' in entity_res:
        entity_res['detection_ids'] = ', '.join(
            ["[{}]({})".format(detection.split('/')[-1], trim_api_version(detection)) for detection in
             entity_res.get('detection_set')])  # type: ignore
    # Entity importance value to label
    entity_res['importance'] = ENTITY_IMPORTANCE_LABEL[entity_res.get('importance')]  # type: ignore
    hr_dict.append({
        "Name": entity_res.get('name'),
        "Entity Type": entity_res.get('type'),
        "Urgency Score": entity_res.get('urgency_score'),
        "Entity Importance": entity_res.get('importance'),
        "Last Modified Timestamp": entity_res.get('last_modified_timestamp'),
        "Last Detection Timestamp": entity_res.get('last_detection_timestamp'),
        "Detections IDs": entity_res.get('detection_ids'),
        "Prioritize": entity_res.get('is_prioritized'),
        "State": entity_res.get('state'),
        "Tags": ', '.join(entity_res.get('tags')) if entity_res.get('tags') else None,  # type: ignore
    })

    # Prepare human-readable output table
    human_readable = tableToMarkdown(f"Entity detail:\n#### Entity ID: {entity_res.get('id')}", hr_dict,
                                     ['Name', 'Entity Type', 'Urgency Score', 'Entity Importance',
                                      'Last Detection Timestamp', 'Last Modified Timestamp', 'Detections IDs',
                                      'Prioritize', 'State', 'Tags'],
                                     removeNull=True)
    return human_readable


def get_list_entity_detections_command_hr(detections: dict[Any, Any], page: Optional[int], page_size: Optional[int],
                                          count: int):
    """
    Converts the list of detections into a human-readable table format.

    Args:
        detections (Dict): Dictionary containing the list of detections.
        page (int): The current page number.
        page_size (int): The page size.
        count (int): The total count of detections.

    Returns:
        str: Human-readable table representation of the detections.
    """
    hr_dict = []
    detection_list = copy.deepcopy(detections)
    # Process detection_set and create detection_ids field
    for detection in detection_list:  # type: ignore
        # Trim API version from url
        detection['url'] = trim_api_version(detection.get('url'))
        # Convert ID into clickable URL
        detection['id'] = f"[{detection['id']}]({detection['url']})"
        account_url = None
        host_url = None
        if detection.get('src_account'):
            account_url = f"[{detection.get('src_account').get('name')}]" \
                          f"({trim_api_version(detection.get('src_account').get('url'))})"
        if detection.get('src_host'):
            host_url = f"[{detection.get('src_host').get('name')}]" \
                       f"({trim_api_version(detection.get('src_host').get('url'))})"
        summary = detection.get('summary')
        num_events = 0
        # For counting number of events
        if summary and isinstance(summary, dict):
            num_events = int(summary.get('num_events') or 0)

        hr_dict.append({
            'ID': detection.get('id'),
            'Detection Name': detection.get('detection'),
            'Detection Type': detection.get('detection_type'),
            'Category': detection.get('category'),
            'Account Name': account_url,
            'Host Name': host_url,
            'Src IP': detection.get('src_ip'),
            'Threat Score': detection.get('threat'),
            'Certainty Score': detection.get('certainty'),
            'Number Of Events': num_events,
            'State': detection.get('state'),
            'Tags': detection.get('tags'),
            'Last Timestamp': detection.get('last_timestamp')
        })
        pages = calc_pages(per_page_count=page_size, total_count=count)  # type: ignore
    human_readable = tableToMarkdown(f"Detections Table (Showing Page {page} out of {pages})", hr_dict,
                                     ['ID', 'Detection Name', 'Detection Type', 'Category', 'Account Name', 'Host Name',
                                      'Src IP', 'Threat Score', 'Certainty Score', 'Number Of Events', 'State', 'Tags',
                                      'Last Timestamp'],
                                     removeNull=True)

    return human_readable


def get_assignment_list_command_hr(assignments: dict, page: Optional[int], page_size: Optional[int],
                                   count: int):
    """
    Returns the human-readable output for the assignment.

    Args:
        assignments(Dict): The assignment details dictionary.
        page (int): The current page number.
        page_size (int): The page size.
        count (int): The total count of assignments.

    Returns:
        str: The human-readable output.
    """
    hr_dict = []
    for assignment in assignments:
        assignment['assignment_id'] = assignment['id']
        hr_dict.append({
            'Account ID': assignment.get('account_id'),
            'Host ID': assignment.get('host_id'),
            'Assignment ID': assignment.get('id'),
            'Assigned By': assignment.get('assigned_by', {}).get('username', ''),
            'Assigned To': assignment.get('assigned_to', {}).get('username', ''),
            'Date Assigned': assignment.get('date_assigned'),
            'Resolved By': assignment.get('resolved_by', {}).get('username', ''),
            'Date Resolved': assignment.get('date_resolved'),
            'Outcome ID': assignment.get('outcome', {}).get('id', ''),
            'Outcome': assignment.get('outcome', {}).get('title', ''),
        })
    pages = calc_pages(per_page_count=page_size, total_count=count)  # type: ignore
    human_readable = tableToMarkdown(f"Assignments Table (Showing Page {page} out of {pages})", hr_dict,
                                     ['Account ID', 'Host ID', 'Assignment ID', 'Assigned By', 'Assigned To',
                                      'Date Assigned', 'Resolved By', 'Date Resolved', 'Outcome ID', 'Outcome'],
                                     removeNull=True)
    return human_readable, assignments


def entity_assignment_add_command_hr(assignment: dict) -> str:
    """
    Returns the human-readable output for the assignment.

    Args:
        assignment (Dict): The assignment details dictionary.

    Returns:
        str: The human-readable output.
    """
    assigned_by = assignment.get('assigned_by', {})
    assigned_to = assignment.get('assigned_to', {})
    events = assignment.get('events', [{}])
    hr_dict = [{
        "Assignment ID": assignment.get('assignment_id'),
        "Assigned By": assigned_by.get('username') if isinstance(assigned_by, dict) else '',
        "Assigned Date": assignment.get('date_assigned'),
        "Assigned To": assigned_to.get('username') if isinstance(assigned_to, dict) else '',
        "Event Type": events[0].get('event_type') if isinstance(events, list) and len(events) > 0 else '',
    }]

    # Prepare human-readable output table
    human_readable = tableToMarkdown("Assignment detail", hr_dict,
                                     ['Assignment ID', 'Assigned By', 'Assigned Date', 'Assigned To', 'Event Type'],
                                     removeNull=True)
    return human_readable


def get_assignment_outcome_list_command_hr(outcomes: dict, page: Optional[int], page_size: Optional[int],
                                           count: int):
    """
    Returns the human-readable output for the assignment outcome list.

    Args:
        outcomes(Dict): The assignment outcomes list dictionary.
        page (int): The current page number.
        page_size (int): The page size.
        count (int): The total count of outcomes.

    Returns:
        str: The human-readable output.
        dict: Outcomes dictionary
    """
    hr_dict = []
    for outcome in outcomes:
        outcome['outcome_id'] = outcome['id']
        hr_dict.append({
            "Outcome ID": outcome.get('id'),
            "Built IN": outcome.get('builtin'),
            "User Selectable": outcome.get('user_selectable'),
            "Title": outcome.get('title'),
            "Category": outcome.get('category'),
        })
    pages = calc_pages(per_page_count=page_size, total_count=count)  # type: ignore
    # Prepare human-readable output table
    human_readable = tableToMarkdown(f"Assignment Outcomes Table (Showing Page {page} out of {pages})", hr_dict,
                                     ['Outcome ID', 'Title', 'Category', 'Built IN', 'User Selectable'],
                                     removeNull=True)
    return human_readable, outcomes


def get_list_entity_notes_command_hr(notes: dict, entity_id: Optional[int], entity_type: str) -> str:
    """
    Returns the human-readable output for the entity notes.

    Args:
        notes (Dict): The assignment details dictionary.
        entity_id (Optional[int]): Entity ID.
        entity_type (str): Entity Type.

    Returns:
        str: The human-readable output.
    """
    hr_dict = []
    for note in notes:
        note['note_id'] = note['id']
        note.update({'entity_id': entity_id, 'entity_type': entity_type})

        hr_dict.append({
            "Note ID": note.get('id'),
            "Note": note.get('note'),
            "Created By": note.get('created_by'),
            "Created Date": note.get('date_created'),
            "Modified By": note.get('modified_by'),
            "Modified Date": note.get('date_modified'),
        })

    # Prepare human-readable output table
    human_readable = tableToMarkdown("Entity Notes Table", hr_dict,
                                     ['Note ID', 'Note', 'Created By', 'Created Date', 'Modified By', 'Modified Date'],
                                     removeNull=True)
    return human_readable


def get_group_list_command_hr(groups: List):
    """
    Converts a list of groups into a human-readable table format.

    Args:
        groups (Dict): The list of groups to convert.

    Returns:
        str: The human-readable table in Markdown format.
    """
    hr_dict = []
    # Process members data from group and make HR for groups
    for group in groups:  # type: ignore
        group["group_id"] = group["id"]
        members: List = group.get('members')
        members_hr = None
        if members and isinstance(members, list):
            # If the members are simple list of strings, then join them with comma.
            if isinstance(members[0], str):
                members_hr = ', '.join([re.escape(str(member)) for member in members])
            # If the members are list of dictionaries, then extract important field from that and join it with comma.
            elif isinstance(members[0], dict):
                members_list = []
                for member in members:
                    if member.get('uid'):
                        members_list.append(re.escape(str(member.get('uid'))))  # type: ignore
                    elif member.get('id'):
                        members_list.append(  # type: ignore
                            "[{}]({})".format(member.get('id'), trim_api_version(member.get('url'))))
                members_hr = ', '.join(members_list)

        hr_dict.append({
            "Group ID": group.get('group_id'),
            "Name": group.get('name'),
            "Group Type": group.get('type'),
            "Description": group.get('description'),
            "Importance": group.get('importance'),
            "Members": members_hr,
            "Last Modified Timestamp": group.get('last_modified'),
        })
    # Prepare human-readable output table
    human_readable = tableToMarkdown("Groups Table", hr_dict,
                                     ['Group ID', 'Name', 'Group Type', 'Description', 'Importance', 'Members',
                                      'Last Modified Timestamp'], removeNull=True)

    return human_readable


def get_group_unassign_and_assign_command_hr(group: dict, changed_members: List, assign_flag: bool = False):
    """
    Converts group into a human-readable table format.

    Args:
        group (Dict): The group to convert.
        changed_members (List): Removed/Added members from the group.
        assign_flag (bool): True for unassigning members, False for assigning members.

    Returns:
        str: The human-readable table in Markdown format.
    """
    hr_dict = []
    group["group_id"] = group["id"]
    members = group.get('members')
    members_hr = None
    if members and isinstance(members, list):
        # If the members are simple list of strings, then join them with comma.
        if isinstance(members[0], str):
            members_hr = ', '.join([re.escape(str(member)) for member in members])
        # If the members are list of dictionaries, then extract important field from that and join it with comma.
        elif isinstance(members[0], dict):
            members_list = []
            for member in members:
                if member.get('uid'):
                    members_list.append(re.escape(str(member.get('uid'))))  # type: ignore
                elif member.get('id'):
                    members_list.append(  # type: ignore
                        "[{}]({})".format(member.get('id'), trim_api_version(member.get('url'))))
            members_hr = ', '.join(members_list)

    hr_dict.append({
        "Group ID": group.get('group_id'),
        "Name": group.get('name'),
        "Group Type": group.get('type'),
        "Description": group.get('description'),
        "Members": members_hr,
        "Last Modified Timestamp": group.get('last_modified'),
    })

    # Prepare human-readable output table
    change_action = "assigned to" if assign_flag else "unassigned from"
    changed_members = [re.escape(member) for member in changed_members]
    human_readable = tableToMarkdown(
        f"Member(s) {', '.join(changed_members)} have been {change_action} the group.\n### Updated group details:",
        hr_dict, ['Group ID', 'Name', 'Group Type', 'Description', 'Members',
                  'Last Modified Timestamp'], removeNull=True)

    return human_readable


""" COMMAND FUNCTIONS """


def fetch_incidents(client: VectraClient, params: dict[str, Any]) -> List:
    """
    Fetches incidents from the Vectra server.

    Args:
        client (VectraClient): Vectra client object.
        params (Dict[str, Any]): Fetch incidents parameters.

    Returns:
        List[Dict[str, Any]]: List of fetched incidents.
    """

    # Fetch parameters from the integration configuration
    first_fetch_time = params.get('first_fetch', FIRST_FETCH).strip()
    max_fetch_ = arg_to_number(params.get('max_fetch', str(MAX_PAGE_SIZE)).strip(), arg_name='Max Fetch', required=True)
    # Ensure max_fetch is not greater than 200
    if max_fetch_ < 1:  # type: ignore
        raise ValueError(ERRORS["INVALID_MAX_FETCH"].format(max_fetch_))
    if max_fetch_ > 200:  # type: ignore
        demisto.debug(f'The max fetch value is {max_fetch_}, which is greater than the maximum allowed value '
                      'of 200. Setting it to 200.')
    max_fetch = min(200, max_fetch_)  # type: ignore
    # Default page is 1
    page = MAX_PAGE
    # Retrieve last run data from the previous execution
    last_run = json.loads(demisto.getLastRun().get('value', '{}'))

    # Retrieve and preprocess entity_type parameter
    entity_type = params.get('entity_type', '')
    if isinstance(entity_type, list):
        entity_type = ','.join(entity_type).lower()
    else:
        entity_type = entity_type.lower()

    # Process is_prioritized parameter
    is_prioritized = params.get('is_prioritized', '')
    if not is_prioritized:
        is_prioritized = None
    else:
        is_prioritized = argToBoolean(is_prioritized.lower())

    # Fetch and process tags parameter
    tags = params.get('tags', '').strip()

    # Fetch detection_category and detection_type parameters
    detection_category = params.get('detection_category', '')
    detection_type = params.get('detection_type', '').strip()

    if not last_run:  # If it's the first time running
        # Create a new last run object with the first fetch time
        new_last_run = {
            'time': arg_to_datetime(first_fetch_time, arg_name='First Fetch Time'
                                    ).strftime(DATE_FORMAT)  # type: ignore
        }
        demisto.debug(f'No last run object found, creating new last run object with value: {json.dumps(new_last_run)}')
    else:
        # Use the last run object from the previous run
        new_last_run = last_run
        demisto.debug('Using the last run object obtained from the previous run.')

    # Retrieve the from_timestamp from the new last run object
    from_timestamp = new_last_run.get('time')

    # Initialize the demisto_incidents list
    demisto_incidents: List = []

    # Retrieve the page number from the last run object or use the default value of 1
    next_url_last_run = last_run.get('next_url')
    if next_url_last_run:
        # Parse the URL
        parsed_url = urlparse(next_url_last_run)
        # Extract the query parameters
        query_params = parse_qs(parsed_url.query)
        page = arg_to_number(query_params.get('page', [''])[0], arg_name='page')  # type: ignore
        max_fetch = arg_to_number(query_params.get('page_size', [''])[0], arg_name='max_fetch')
        entity_type = query_params.get('type', [''])[0]
        is_prioritized = query_params.get('is_prioritized', [''])[0]
        if is_prioritized:
            is_prioritized = argToBoolean(is_prioritized)
        from_timestamp = query_params.get('last_modified_timestamp_gte', [''])[0]
        tags = query_params.get('tags', [''])[0]

    try:
        # Fetch the entities list from the server using the provided parameters
        response = client.list_entities_request(page=page, page_size=max_fetch, entity_type=entity_type,  # type: ignore
                                                is_prioritized=is_prioritized,
                                                last_modified_timestamp=from_timestamp,  # type: ignore
                                                tags=tags, ordering='last_modified_timestamp')
    except DemistoException as e:
        # If the status code is 404 and the message is invalid page number, then return the empty list of incidents.
        if str(e.res) == '<Response [404]>' and (
                e.res.status_code == 404 and ERRORS['INVALID_PAGE_RESPONSE'] in str(e.message).lower()):
            demisto.debug(f'Returning 0 incidents in fetch incidents due to the end of page: {str(e.message)}')
            return demisto_incidents
        raise e

    # Retrieve the next page URL for pagination
    next_url = response.get('next')
    # Get the entities from the response
    entities = response.get('results')

    # Retrieve the already fetched IDs from the last run
    already_fetched = last_run.get('already_fetched', [])

    # Extract the IDs to check from the current response
    ids_to_check = [f"{item['id']}-{item['type']}" for item in response['results']]

    # Check if entities exist and not all IDs to check are already fetched
    if entities and not all(id_to_check in already_fetched for id_to_check in ids_to_check):
        # Iterate over each entity in the entities list
        for entity in entities:
            # Retrieve entity details
            detection_set = entity.get('detection_set', [])
            entity_id = entity.get('id')
            entity_name = entity.get('name')
            entity_type = entity.get('type')
            last_modified_timestamp = entity.get('last_modified_timestamp')
            entity_urgency_score = entity.get('urgency_score')
            entity_checkpoint = f"{entity_id}-{entity_type}"

            # Check if the entity has detections
            if len(detection_set) != 0:
                detections_ids = ','.join([url.split("/")[-1] for url in detection_set])
                # Fetch detections data using detections API call
                detections_data = client.list_detections_request(detection_type=detection_type,
                                                                 detection_category=detection_category,
                                                                 ids=detections_ids)
                detections = detections_data.get('results', [])
                # Add detection details to the entity
                entity.update({'detection_details': detections})

            # Fetch entity assignment
            if entity_type == 'account':
                response = client.list_assignments_request(account_ids=entity_id)
            elif entity_type == 'host':
                response = client.list_assignments_request(host_ids=entity_id)
            assignment_details = response.get('results', [])
            assignment_details = assignment_details[0] if len(assignment_details) > 0 else assignment_details
            entity.update({'assignment_details': assignment_details})
            # Add configuration filter
            entity.update({'filter_tags': tags})
            entity['url'] = f"{entity.get('url') or ''}{UTM_PIVOT}"

            # Create an incident if the entity is not already fetched
            if entity_checkpoint not in already_fetched:
                # Updating mirroring fields
                mirroring_fields = get_mirroring()
                mirroring_fields.update({'mirror_id': str(entity_id) + '-' + entity_type})
                entity.update(mirroring_fields)

                incident_name = f'Vectra XDR Entity {entity_name}:{entity_id}'
                # Calculate severity based on urgency score using the urgency_score_to_severity function.
                severity = urgency_score_to_severity(entity_urgency_score, params)  # type: ignore
                entity["urgency_score_based_severity"] = severity
                demisto_incidents.append({
                    'name': incident_name,
                    'occurred': last_modified_timestamp,
                    'rawJSON': json.dumps(entity),
                    'severity': severity
                })
                already_fetched.append(entity_checkpoint)

        # Update the last run object with the latest timestamp and page information if incidents were found
        if len(entities) == max_fetch and next_url:
            new_last_run.update({
                'next_url': next_url,
                'already_fetched': already_fetched
            })
        else:
            new_last_run.update({
                'time': entities[-1].get('last_modified_timestamp'),
                'next_url': None,
                'already_fetched': already_fetched
            })
    else:
        # If no incidents were found, update the last run object with the current time and reset the page to 1
        now = datetime.now().strftime(DATE_FORMAT)
        new_last_run.update({'page': 1, 'time': now})
    # Save the new last run object
    demisto.setLastRun({'value': json.dumps(new_last_run)})

    return demisto_incidents


def vectra_user_list_command(client: VectraClient, args: dict[str, Any]):
    """
    Retrieves a list of users from the Vectra API.

    Args:
        client (VectraClient): The Vectra API client.
        args (Dict[str, Any]): Function arguments.

    Returns:
        CommandResults: The command results containing the entities.
    """
    last_login_timestamp = arg_to_datetime(args.get('last_login_timestamp'), arg_name='last_login_timestamp')
    if last_login_timestamp:
        last_login_timestamp = last_login_timestamp.strftime(DATE_FORMAT)  # type: ignore
    username = args.get('username', '')
    role = args.get('role', '')
    # Call Vectra API to retrieve users
    response = client.list_users_request(username=username, role=role, last_login_timestamp=last_login_timestamp)
    count = response.get('count')
    if count == 0:
        return CommandResults(outputs={}, readable_output="##### Got the empty list of users.", raw_response=response)
    users = response.get('results')

    # Prepare context data
    human_readable = get_user_list_command_hr(users)  # type: ignore
    context = [createContext(user) for user in remove_empty_elements(users)]  # type: ignore

    return CommandResults(outputs_prefix='Vectra.User', outputs=context,
                          readable_output=human_readable, raw_response=users, outputs_key_field=['user_id'])


def vectra_entity_list_command(client: VectraClient, args: dict[str, Any]):
    """
    Retrieves a list of entities from the Vectra API.

    Args:
        client (VectraClient): The Vectra API client.
        args (Dict[str, Any]): Function arguments.

    Returns:
        CommandResults: The command results containing the entities.

    Raises:
        ValueError: If an invalid entity_type or state value is provided.
    """
    # Validate command args
    validate_entity_list_command_args(args)

    # Get function arguments
    entity_type = args.get('entity_type', '').lower()
    last_detection_timestamp = arg_to_datetime(args.get('last_detection_timestamp'),
                                               arg_name='last_detection_timestamp')
    last_modified_timestamp = arg_to_datetime(args.get('last_modified_timestamp'),
                                              arg_name='last_modified_timestamp')
    if last_detection_timestamp:
        last_detection_timestamp = last_detection_timestamp.strftime(DATE_FORMAT)  # type: ignore
    if last_modified_timestamp:
        last_modified_timestamp = last_modified_timestamp.strftime(DATE_FORMAT)  # type: ignore
    ordering = args.get('ordering', '')
    page = arg_to_number(args.get('page', '1'), arg_name='page')
    page_size = arg_to_number(args.get('page_size', '50'), arg_name='page_size')
    prioritized = args.get('prioritized', '')
    if prioritized:
        prioritized = argToBoolean(prioritized)
    state = args.get('state', '')
    tags = args.get('tags', '')

    # Call Vectra API to retrieve entities
    response = client.list_entities_request(entity_type=entity_type,
                                            last_detection_timestamp=last_detection_timestamp,
                                            last_modified_timestamp=last_modified_timestamp,
                                            ordering=ordering, page=page, page_size=page_size,  # type: ignore
                                            is_prioritized=prioritized,
                                            state=state, tags=tags)
    count = response.get('count')
    if count == 0:
        return CommandResults(outputs={},
                              readable_output="##### Couldn't find any matching entities for provided filters.",
                              raw_response=response)
    entities = response.get('results')

    # Prepare context data
    human_readable = get_entity_list_command_hr(entities, page, page_size, count)  # type: ignore
    context = [createContext(entity) for entity in remove_empty_elements(entities)]  # type: ignore

    return CommandResults(outputs_prefix='Vectra.Entity', outputs=context,
                          readable_output=human_readable, raw_response=entities, outputs_key_field=['id', 'type'])


def vectra_entity_describe_command(client: VectraClient, args: dict[str, Any]):
    """
    Describes an entity from the Vectra API.

    Args:
        client (VectraClient): The Vectra API client.
        args (Dict[str, Any]): Function arguments.

    Returns:
        CommandResults: The command results containing the entity.

    Raises:
        ValueError: If an invalid entity_type is provided.
    """
    # Get function arguments
    entity_id = arg_to_number(args.get('entity_id'), arg_name="entity_id")
    entity_type = args.get('entity_type', '').lower()

    # Validate entity_id
    validate_positive_integer_arg(entity_id, arg_name='entity_id', required=True)
    # Validate entity_type value
    if not entity_type:
        raise ValueError(ERRORS['REQUIRED_ARGUMENT'].format('entity_type'))
    if entity_type not in VALID_ENTITY_TYPE:
        raise ValueError(ERRORS['INVALID_COMMAND_ARG_VALUE'].format('entity_type', ', '.join(VALID_ENTITY_TYPE)))

    # Call Vectra API to retrieve entity
    entity = client.get_entity_request(entity_id=entity_id, entity_type=entity_type)  # type: ignore

    human_readable = get_entity_get_command_hr(entity)

    return CommandResults(outputs_prefix='Vectra.Entity', outputs=createContext(remove_empty_elements(entity)),
                          readable_output=human_readable, raw_response=entity, outputs_key_field=['id', 'type'])


def vectra_entity_detection_list_command(client: VectraClient, args: dict[str, Any]):
    """
    Retrieves a list of entity detections from the Vectra API.

    Args:
        client (VectraClient): The Vectra API client.
        args (Dict[str, Any]): Function arguments.

    Returns:
        CommandResults: The command results containing the entity detections.

    Raises:
        ValueError: If an invalid entity_type or state value is provided.
    """
    # Validation for args
    validate_list_entity_detections_args(args)

    # Get function arguments
    entity_id = arg_to_number(args.get('entity_id'), arg_name="entity_id")
    entity_type = args.get('entity_type', '').lower()
    detection_category = args.get('detection_category')
    detection_type = args.get('detection_type')
    detection_name = args.get('detection_name')
    state = args.get('state', 'active')
    tags = args.get('tags')
    last_timestamp = arg_to_datetime(args.get('last_timestamp'), arg_name='last_timestamp')
    if last_timestamp:
        last_timestamp = last_timestamp.strftime(DATE_FORMAT)  # type: ignore
    page = arg_to_number(args.get('page', '1'), arg_name="page")
    page_size = arg_to_number(args.get('page_size', '50'), arg_name="page_size")
    if detection_category:
        detection_category = DETECTION_CATEGORY_TO_ARG[detection_category]

    entity = client.get_entity_request(entity_id=entity_id, entity_type=entity_type)
    detection_set = entity.get('detection_set', [])
    detections_ids = ','.join([url.split("/")[-1] for url in detection_set]) if detection_set else ''
    if len(detections_ids) == 0:
        return CommandResults(outputs={}, readable_output="##### Couldn't find any matching detections for "
                                                          "provided entity ID and type.", raw_response={})
    # Call Vectra API to retrieve entities
    response = client.list_detections_request(ids=detections_ids, page=page, page_size=page_size,
                                              detection_category=detection_category,
                                              detection_type=detection_type, detection_name=detection_name,
                                              last_timestamp=last_timestamp, state=state, tags=tags)
    count = response.get('count', 0)
    if count == 0:
        return CommandResults(outputs={},
                              readable_output="##### Couldn't find any matching entity detections for "
                                              "provided filters.", raw_response=response)
    detections = response.get('results', {})
    # Remove empty elements from the response
    # Prepare HR
    hr = get_list_entity_detections_command_hr(detections, page, page_size, count)
    # Create context
    context = [createContext(remove_empty_elements(detection)) for detection in detections]  # type: ignore

    return CommandResults(outputs_prefix='Vectra.Entity.Detections', outputs=context,
                          readable_output=hr, raw_response=response, outputs_key_field='id')


def vectra_detection_describe_command(client: VectraClient, args: dict[str, Any]):
    """
    Describes a list of detections for provided detection IDs from the Vectra API.

    Args:
        client (VectraClient): The Vectra API client.
        args (Dict[str, Any]): Function arguments.

    Returns:
        CommandResults: The command results containing the detections.

    Raises:
        ValueError: If an invalid detection_ids or page value is provided.
    """
    # Validation for args
    validate_detection_describe_args(args)

    # Get function arguments
    detection_ids = argToList(args.get('detection_ids'), transform=arg_to_number)
    detection_ids = [detection_id for detection_id in detection_ids if isinstance(detection_id, int)]
    page = arg_to_number(args.get('page', '1'), arg_name="page")
    page_size = arg_to_number(args.get('page_size', '50'), arg_name="page_size")
    # Call Vectra API to retrieve entities
    response = client.list_detections_request(ids=','.join([str(detection_id) for detection_id in detection_ids]),
                                              state='', page=page, page_size=page_size)
    count = response.get('count', 0)
    if count == 0:
        return CommandResults(outputs={},
                              readable_output="##### Couldn't find any matching detections for "
                                              "provided detection ID(s).", raw_response=response)
    detections = response.get('results', {})
    # Prepare HR
    hr = get_list_entity_detections_command_hr(detections, page, page_size, count)
    # Create context
    context = [createContext(remove_empty_elements(detection)) for detection in detections]  # type: ignore

    return CommandResults(outputs_prefix='Vectra.Entity.Detections', outputs=context,
                          readable_output=hr, raw_response=response, outputs_key_field='id')


def vectra_entity_note_list_command(client: VectraClient, args: dict[str, Any]):
    """
    List entity notes.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict[str, Any]): The command arguments provided by the user.

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    validate_entity_note_list_command_args(args)
    # Get function arguments
    entity_id = arg_to_number(args.get('entity_id'), arg_name="entity_id", required=True)
    entity_type = args.get('entity_type', '').lower()

    # Call Vectra API to add entity note
    notes = client.list_entity_note_request(entity_id=entity_id, entity_type=entity_type)  # type: ignore
    notes = remove_empty_elements(notes)
    if notes:
        human_readable = get_list_entity_notes_command_hr(notes, entity_id, entity_type)

        context = [createContext(note) for note in notes]

        return CommandResults(outputs_prefix='Vectra.Entity.Notes', outputs=context,
                              readable_output=human_readable, raw_response=notes,
                              outputs_key_field=['entity_id', 'entity_type', 'note_id'])
    else:
        return CommandResults(outputs={},
                              readable_output="##### Couldn't find any notes for provided entity.",
                              raw_response=notes)


def vectra_entity_note_add_command(client: VectraClient, args: dict[str, Any]):
    """
    Adds a note to an entity in Vectra API.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict[str, Any]): The command arguments provided by the user.

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    validate_entity_note_add_command_args(args)
    # Get function arguments
    entity_id = arg_to_number(args.get('entity_id'), arg_name="entity_id", required=True)
    entity_type = args.get('entity_type', '').lower()
    note = args.get('note')

    # Call Vectra API to add entity note
    notes = client.add_entity_note_request(entity_id=entity_id, entity_type=entity_type, note=note)  # type: ignore
    if notes:
        notes['note_id'] = notes['id']
        notes.update({'entity_id': entity_id, 'entity_type': entity_type})

    human_readable = "##### The note has been successfully added to the entity."
    human_readable += f"\nReturned Note ID: **{notes['note_id']}**"

    return CommandResults(outputs_prefix='Vectra.Entity.Notes', outputs=createContext(remove_empty_elements(notes)),
                          readable_output=human_readable, raw_response=notes,
                          outputs_key_field=['entity_id', 'entity_type', 'note_id'])


def vectra_entity_note_update_command(client: VectraClient, args: dict[str, Any]):
    """
    Updates a note to an entity in Vectra API.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict[str, Any]): The command arguments provided by the user.

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    validate_entity_note_update_command_args(args)
    # Get function arguments
    entity_id = arg_to_number(args.get('entity_id'), arg_name="entity_id", required=True)
    entity_type = args.get('entity_type', '').lower()
    note = args.get('note')
    note_id = arg_to_number(args.get('note_id'), arg_name="note_id", required=True)

    # Call Vectra API to update entity note
    notes = client.update_entity_note_request(entity_id=entity_id, entity_type=entity_type, note=note,
                                              note_id=note_id)  # type: ignore
    if notes:
        notes['note_id'] = notes['id']
        notes.update({'entity_id': entity_id, 'entity_type': entity_type})

    human_readable = "##### The note has been successfully updated in the entity."

    return CommandResults(outputs_prefix='Vectra.Entity.Notes', outputs=createContext(remove_empty_elements(notes)),
                          readable_output=human_readable, raw_response=notes,
                          outputs_key_field=['entity_id', 'entity_type', 'note_id'])


def vectra_entity_note_remove_command(client: VectraClient, args: dict[str, Any]):
    """
    Updates a note to an entity in Vectra API.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict[str, Any]): The command arguments provided by the user.

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    validate_entity_note_remove_command_args(args)
    # Get function arguments
    entity_id = arg_to_number(args.get('entity_id'), arg_name="entity_id", required=True)
    entity_type = args.get('entity_type', '').lower()
    note_id = arg_to_number(args.get('note_id'), arg_name="note_id", required=True)

    # Call Vectra API to remove note
    response = client.remove_entity_note_request(entity_id=entity_id, entity_type=entity_type,
                                                 note_id=note_id)  # type: ignore
    if response.status_code == 204:
        human_readable = "##### The note has been successfully removed from the entity."
    else:
        human_readable = "Something went wrong."
    return CommandResults(outputs={}, readable_output=human_readable)


def vectra_entity_tag_add_command(client: VectraClient, args: dict[str, Any]):
    """
    Add tags to an entity.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict[str, Any]): The command arguments provided by the user.

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    validate_entity_tag_add_command_args(args)
    # Get function arguments
    entity_id = arg_to_number(args.get('entity_id'), arg_name="entity_id", required=True)
    entity_type = args.get('entity_type', '').lower()
    tags = [tag.strip() for tag in argToList(args.get('tags', '')) if isinstance(tag, str) and tag.strip()]

    # Call Vectra API to get existing entity tags
    existing_tag_res = client.list_entity_tags_request(entity_id=entity_id, entity_type=entity_type)  # type: ignore
    existing_tag_res_status = existing_tag_res.get('status', '')
    if not existing_tag_res_status or not isinstance(existing_tag_res_status,
                                                     str) or existing_tag_res_status.lower() != 'success':
        message = 'Something went wrong.'
        if existing_tag_res.get('message'):
            message += f" Message: {existing_tag_res.get('message')}."
        raise DemistoException(message)
    tags_resp = existing_tag_res.get('tags', [])
    tags = list(dict.fromkeys(tags_resp + tags))

    res = existing_tag_res
    if len(dict.fromkeys(tags_resp)) != len(tags):
        # Call Vectra API to add entity tags
        res = client.update_entity_tags_request(entity_id=entity_id, entity_type=entity_type, tags=tags)  # type: ignore
        res_status = res.get('status', '')
        if not res_status or not isinstance(res_status, str) or res_status.lower() != 'success':
            message = 'Something went wrong.'
            if res.get('message'):
                message += f" Message: {res.get('message')}."
            raise DemistoException(message)

    human_readable = '##### Tags have been successfully added to the entity.'
    tags_resp = res.get('tags', [])
    if tags_resp and isinstance(tags_resp, list):
        tags_resp = [tag.strip() for tag in tags_resp if isinstance(tag, str) and tag.strip()]
        if tags_resp:
            tags_resp = f'**{"**, **".join(tags_resp)}**'
            human_readable += f'\nUpdated list of tags: {tags_resp}'

    res['entity_type'] = entity_type
    res['entity_id'] = entity_id
    del res['status']

    return CommandResults(outputs_prefix='Vectra.Entity.Tags', outputs=createContext(remove_empty_elements(res)),
                          readable_output=human_readable, raw_response=res,
                          outputs_key_field=['tag_id', 'entity_type', 'entity_id'])


def vectra_entity_tag_remove_command(client: VectraClient, args: dict[str, Any]):
    """
    Removes associated tags for the specified entity using Vectra API.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict[str, Any]): The command arguments provided by the user.

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    validate_entity_tag_add_command_args(args)
    # Get function arguments
    entity_id = arg_to_number(args.get('entity_id'), arg_name="entity_id", required=True)
    entity_type = args.get('entity_type', '').lower()
    input_tags = [tag.strip() for tag in argToList(args.get('tags', '')) if isinstance(tag, str) and tag.strip()]

    # Call Vectra API to get existing entity tags
    existing_tag_res = client.list_entity_tags_request(entity_id=entity_id, entity_type=entity_type)  # type: ignore
    existing_tag_res_status = existing_tag_res.get('status', '')
    if not existing_tag_res_status or not isinstance(existing_tag_res_status,
                                                     str) or existing_tag_res_status.lower() != 'success':
        message = 'Something went wrong.'
        if existing_tag_res.get('message'):
            message += f" Message: {existing_tag_res.get('message')}."
        raise DemistoException(message)
    tags_resp = existing_tag_res.get('tags', [])
    # Filtering set of tags from existing tags response with the provide set of input tags
    updated_tags = [tag_resp.strip() for tag_resp in tags_resp if tag_resp.strip() not in input_tags]

    res = existing_tag_res
    # Only update tags if there is any update required with the specified tags
    if len(dict.fromkeys(tags_resp)) != len(updated_tags):
        # Call Vectra API to update entity tags
        res = client.update_entity_tags_request(
            entity_id=entity_id, entity_type=entity_type, tags=updated_tags)  # type: ignore
        res_status = res.get('status', '')
        if not res_status or not isinstance(res_status, str) or res_status.lower() != 'success':
            message = 'Something went wrong.'
            if res.get('message'):
                message += f" Message: {res.get('message')}."
            raise DemistoException(message)

    human_readable = '##### Specified tags have been successfully removed for the entity.'
    tags_resp = res.get('tags', [])
    if tags_resp and isinstance(tags_resp, list):
        tags_resp = [tag.strip() for tag in tags_resp if isinstance(tag, str) and tag.strip()]
        if tags_resp:
            tags_resp = f'**{"**, **".join(tags_resp)}**'
            human_readable += f'\nUpdated list of tags: {tags_resp}'

    res['entity_type'] = entity_type
    res['entity_id'] = entity_id
    del res['status']

    return CommandResults(outputs_prefix='Vectra.Entity.Tags', outputs=createContext(remove_empty_elements(res)),
                          readable_output=human_readable, raw_response=res,
                          outputs_key_field=['tag_id', 'entity_type', 'entity_id'])


def vectra_entity_tag_list_command(client: VectraClient, args: dict[str, Any]):
    """
    List tags for an entity.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict[str, Any]): The command arguments provided by the user.

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    validate_entity_tag_list_command_args(args)
    # Get function arguments
    entity_id = arg_to_number(args.get('entity_id'), arg_name="entity_id", required=True)
    entity_type = args.get('entity_type', '').lower()

    # Call Vectra API to get existing entity tags
    existing_tag_res = client.list_entity_tags_request(entity_id=entity_id, entity_type=entity_type)  # type: ignore
    existing_tag_res_status = existing_tag_res.get('status', '')
    if not existing_tag_res_status or not isinstance(existing_tag_res_status,
                                                     str) or existing_tag_res_status.lower() != 'success':
        message = 'Something went wrong.'
        if existing_tag_res.get('message'):
            message += f" Message: {existing_tag_res.get('message')}."
        raise DemistoException(message)
    tags_resp = existing_tag_res.get('tags', [])

    human_readable = '##### No tags were found for the given entity ID and entity type.'
    if tags_resp and isinstance(tags_resp, list):
        tags_resp = [tag.strip() for tag in tags_resp if isinstance(tag, str) and tag.strip()]
        if tags_resp:
            tags_resp = f'**{"**, **".join(tags_resp)}**'
            human_readable = f'##### List of tags: {tags_resp}'

    existing_tag_res['entity_type'] = entity_type
    existing_tag_res['entity_id'] = entity_id
    del existing_tag_res['status']

    return CommandResults(outputs_prefix='Vectra.Entity.Tags',
                          outputs=createContext(remove_empty_elements(existing_tag_res)),
                          readable_output=human_readable, raw_response=existing_tag_res,
                          outputs_key_field=['tag_id', 'entity_type', 'entity_id'])


def vectra_detections_mark_fixed_command(client: VectraClient, args: dict[str, Any]):
    """
    Mark the provided detection IDs as fixed.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict[str, Any]): The command arguments.

    Raises:
        ValueError: If detection_ids argument is missing or empty.

    Returns:
        CommandResults: The command results.
    """
    # Get function arguments
    detection_ids = args.get('detection_ids')
    # Convert string into list
    detection_ids_list = argToList(detection_ids)
    # Validate detection_ids
    validate_detections_mark_and_unmark_args(detection_ids_list)

    # Call Vectra API to mark detection as fixed
    res = client.mark_or_unmark_detection_fixed_request(detection_ids_list, mark='True')

    if res.get('_meta', {}).get('level') == 'Success' and res.get('_meta').get(  # type: ignore
            'message') == 'Successfully marked detections':
        human_readable = "##### The provided detection IDs have been successfully marked as fixed."
    else:
        raise DemistoException("Something went wrong.")

    return CommandResults(outputs={}, readable_output=human_readable)


def vectra_detections_unmark_fixed_command(client: VectraClient, args: dict[str, Any]):
    """
    Unmark the provided detection IDs as fixed.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict[str, Any]): The command arguments.

    Raises:
        ValueError: If detection_ids argument is missing or empty.

    Returns:
        CommandResults: The command results.
    """
    # Get function arguments
    detection_ids = args.get('detection_ids')
    # Convert string into list
    detection_ids_list = argToList(detection_ids)
    # Validate detection_ids
    validate_detections_mark_and_unmark_args(detection_ids_list)

    # Call Vectra API to unmark detection as fixed
    res = client.mark_or_unmark_detection_fixed_request(detection_ids_list, mark='False')

    if res.get('_meta', {}).get('level') == 'Success' and res.get('_meta').get(  # type: ignore
            'message') == 'Successfully marked detections':
        human_readable = "##### The provided detection IDs have been successfully unmarked as fixed."
    else:
        raise DemistoException("Something went wrong.")

    return CommandResults(outputs={}, readable_output=human_readable)


def vectra_assignment_list_command(client: VectraClient, args: dict[str, Any]):
    """
    List assignments.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict[str, Any]): The command arguments.

    Returns:
        CommandResults: The command results.
    """
    validate_assignment_list_command_args(args)
    # Get function arguments
    entity_ids = args.get('entity_ids')
    entity_type = args.get('entity_type', '').lower()
    resolved = args.get('resolved')
    page = arg_to_number(args.get('page', '1'), arg_name='page')
    page_size = arg_to_number(args.get('page_size', '50'), arg_name='page_size')
    assignees = args.get('assignees')
    resolution = args.get('resolution')
    # Convert argument to value
    if resolved:
        resolved = argToBoolean(resolved)
    created_after = arg_to_datetime(args.get('created_after'), arg_name='created_after')
    if created_after:
        created_after = created_after.strftime(DATE_FORMAT)  # type: ignore
    accounts = None
    hosts = None
    if entity_type == 'account':
        accounts = entity_ids
    elif entity_type == 'host':
        hosts = entity_ids
    # Call Vectra API for assignment list
    response = client.list_assignments_request(account_ids=accounts, host_ids=hosts, resolved=resolved,
                                               assignees=assignees, resolution=resolution,
                                               created_after=created_after, page=page,  # type: ignore
                                               page_size=page_size)  # type: ignore
    response = remove_empty_elements(response)
    count = response.get('count', 0)
    assignments = response.get('results', [])
    if assignments:
        human_readable, assignments = get_assignment_list_command_hr(assignments, page=page, page_size=page_size,
                                                                     count=count)
        context = [createContext(assignment) for assignment in assignments]

        return CommandResults(outputs=context, readable_output=human_readable, raw_response=assignments,
                              outputs_prefix="Vectra.Entity.Assignments", outputs_key_field=['assignment_id'])
    else:
        return CommandResults(outputs={},
                              readable_output="##### Couldn't find any matching assignments for provided filters.",
                              raw_response=response)


def vectra_entity_assignment_add_command(client: VectraClient, args: dict[str, Any]):
    """
    Create an assignment for specified entity id.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict[str, Any]): The command arguments.

    Raises:
        ValueError: If detection_ids argument is missing or empty.

    Returns:
        CommandResults: The command results.
    """
    # Validate command arguments
    validate_entity_assignment_add_command_args(args)
    # Get function arguments
    entity_id = arg_to_number(args.get('entity_id'), arg_name="entity_id")
    entity_type = args.get('entity_type', '').lower()
    user_id = arg_to_number(args.get('user_id'), arg_name="user_id")

    assign_account_id = None
    assign_host_id = None
    if entity_type == 'account':
        assign_account_id = entity_id
    elif entity_type == 'host':
        assign_host_id = entity_id
    # Call Vectra API to create an assignment
    response = client.add_entity_assignment_request(assign_account_id=assign_account_id, assign_host_id=assign_host_id,
                                                    assign_to_user_id=user_id)
    assignment = response.get('assignment', {})
    # Update assignment response
    if assignment:
        assignment['assignment_id'] = assignment['id']
    human_readable = "##### The assignment has been successfully created.\n"
    human_readable += entity_assignment_add_command_hr(assignment)

    return CommandResults(outputs_prefix='Vectra.Entity.Assignments',
                          outputs=createContext(remove_empty_elements(assignment)),
                          readable_output=human_readable, raw_response=assignment, outputs_key_field=['assignment_id'])


def vectra_entity_assignment_update_command(client: VectraClient, args: dict[str, Any]):
    """
    Updates an assignment for specified entity id.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict[str, Any]): The command arguments.

    Raises:
        ValueError: If detection_ids argument is missing or empty.

    Returns:
        CommandResults: The command results.
    """
    # Validate command arguments
    validate_entity_assignment_update_command_args(args)
    # Get function arguments
    assignment_id = arg_to_number(args.get('assignment_id'), arg_name="assignment_id")
    user_id = arg_to_number(args.get('user_id'), arg_name="user_id")

    # Call Vectra API to update an assignment
    response = client.update_entity_assignment_request(assignment_id=assignment_id, assign_to_user_id=user_id)
    updated_assignment = response.get('assignment', {})
    # Update assignment response
    if updated_assignment:
        updated_assignment['assignment_id'] = updated_assignment['id']
    human_readable = "##### The assignment has been successfully updated.\n"
    human_readable += entity_assignment_add_command_hr(updated_assignment)

    return CommandResults(outputs_prefix='Vectra.Entity.Assignments',
                          outputs=createContext(remove_empty_elements(updated_assignment)),
                          readable_output=human_readable,
                          raw_response=updated_assignment, outputs_key_field=['assignment_id'])


def vectra_entity_assignment_resolve_command(client: VectraClient, args: dict[str, Any]):
    """
    Resolve an assignment for specified assignment id.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict[str, Any]): The command arguments.

    Raises:
        ValueError: If detection_ids argument is missing or empty.

    Returns:
        CommandResults: The command results.
    """
    # Validate command arguments
    validate_entity_assignment_resolve_command_args(args)
    # Get function arguments
    assignment_id = arg_to_number(args.get('assignment_id'), arg_name="assignment_id")
    outcome = args.get('outcome')
    note = args.get('note')
    triage_as = args.get('triage_as')
    detection_ids = argToList(args.get('detection_ids'))

    # list outcome assignment
    res = client.list_assignment_outcomes_request()
    outcome_list = res.get('results')
    title_to_id = {item["title"]: item["id"] for item in outcome_list}  # type: ignore

    if outcome in title_to_id:
        outcome_id = title_to_id[outcome]
    else:
        outcome_list = ", ".join([item["title"] for item in outcome_list])  # type: ignore
        raise ValueError(ERRORS['INVALID_OUTCOME'].format(outcome_list))

    # Call Vectra API to resolve an assignment
    response = client.resolve_entity_assignment_request(assignment_id=assignment_id, outcome=outcome_id,
                                                        note=note, triage_as=triage_as,  # type: ignore
                                                        detection_ids=detection_ids)
    assignment = response.get('assignment', {})
    # resolve assignment response
    if assignment:
        assignment['assignment_id'] = assignment['id']
    human_readable = "##### The assignment has been successfully resolved."

    return CommandResults(outputs_prefix='Vectra.Entity.Assignments',
                          outputs=createContext(remove_empty_elements(assignment)),
                          readable_output=human_readable, raw_response=assignment, outputs_key_field=['assignment_id'])


def vectra_assignment_outcome_list_command(client: VectraClient, args: dict[str, Any]):
    """
    List assignment outcomes.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict[str, Any]): The command arguments.

    Returns:
        CommandResults: The command results.
    """
    page = args.get('page', '1')
    page_size = args.get('page_size', '50')
    # Validate page and page_size
    validate_positive_integer_arg(value=page, arg_name='page')
    validate_positive_integer_arg(value=page_size, arg_name='page_size')
    # Get command args
    page = arg_to_number(page, arg_name="page")
    page_size = arg_to_number(page_size, arg_name="page_size")
    # Call Vectra API for assignment outcome list
    response = client.list_assignment_outcomes_request(page=page, page_size=page_size)
    response = remove_empty_elements(response)
    count = response.get('count', 0)
    outcomes = response.get('results', [])
    human_readable, outcomes = get_assignment_outcome_list_command_hr(outcomes=outcomes, page=page,
                                                                      page_size=page_size,
                                                                      count=count)
    context = [createContext(outcome) for outcome in outcomes]

    return CommandResults(outputs=context, readable_output=human_readable, raw_response=outcomes,
                          outputs_prefix="Vectra.Entity.Assignments.Outcomes", outputs_key_field=['id'])


def vectra_detection_pcap_download_command(client: VectraClient, args: dict[str, Any]):
    """
    Download the packet capture (PCAP) file associated with a Vectra detection.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict[str, Any]): A dictionary containing the arguments for downloading the PCAP file.
            - detection_id (str): The ID of the detection associated with the PCAP file.

    Returns:
        fileResult: A fileResult object containing the downloaded PCAP file content.
    """
    detection_id = args.get('detection_id')
    # Validate detection id
    validate_positive_integer_arg(detection_id, arg_name="detection_id", required=True)

    # Call Vectra API to download detection pcap
    response = client.download_detection_pcap_request(detection_id=detection_id)
    content_disposition = response.headers.get('Content-Disposition', '')
    file_name = content_disposition.split(';')[1].replace('filename=', '').replace('"', '')

    return fileResult(filename=file_name, data=response.content)


def vectra_entity_detections_mark_fixed_command(client: VectraClient, args: dict[str, Any]):
    """
    Mark the provided entity detections as fixed.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict[str, Any]): The command arguments.

    Raises:
        ValueError: If detection_ids argument is missing or empty.

    Returns:
        CommandResults: The command results.
    """
    validate_entity_detections_mark_fix_command_args(args)
    # Get function arguments
    entity_id = args.get('entity_id')
    entity_type = args.get('entity_type', '').lower()
    response = client.get_entity_request(entity_id=entity_id, entity_type=entity_type)
    detection_set = response.get('detection_set')
    detection_ids = [url.split("/")[-1] for url in detection_set] if detection_set else ''

    if not detection_ids:
        return CommandResults(
            readable_output=f"There are no detections to mark as fixed for this entity ID:{entity_id}.")

    # Call Vectra API to mark detection as fixed
    res = client.mark_or_unmark_detection_fixed_request(detection_ids=detection_ids, mark='True')  # type: ignore
    if res.get('_meta', {}).get('level') == 'Success' and res.get('_meta').get(  # type: ignore
            'message') == 'Successfully marked detections':
        human_readable = f"##### The detections ({', '.join(detection_ids)}) of the provided entity ID have been " \
                         f"successfully marked as fixed."
    else:
        raise DemistoException("Something went wrong.")

    return CommandResults(readable_output=human_readable)


def vectra_group_list_command(client: VectraClient, args: dict[str, Any]):
    """
    Retrieves a list of groups.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict[str, Any]): The command arguments provided by the user.

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    validate_group_list_command_args(args)

    # Get function arguments
    group_type = args.get('group_type') or ''
    if group_type:
        group_type = group_type.lower()
    importance = args.get('importance') or ''
    if importance:
        importance = importance.lower()
    account_names = argToList(args.get('account_names') or '')
    domains = argToList(args.get('domains') or '')
    host_ids = argToList(args.get('host_ids') or '')
    host_names = argToList(args.get('host_names') or '')
    ips = argToList(args.get('ips') or '')
    description = args.get('description') or ''
    last_modified_timestamp = arg_to_datetime(args.get('last_modified_timestamp'), arg_name='last_modified_timestamp')
    last_modified_by = args.get('last_modified_by') or ''
    group_name = args.get('group_name') or ''

    # Call Vectra API to get groups
    response = client.list_group_request(group_type=group_type, account_names=account_names, domains=domains,
                                         host_ids=host_ids, host_names=host_names, importance=importance, ips=ips,
                                         description=description, last_modified_timestamp=last_modified_timestamp,
                                         last_modified_by=last_modified_by, group_name=group_name)  # type: ignore
    count = response.get('count')
    if count == 0:
        return CommandResults(outputs={},
                              readable_output="##### Couldn't find any matching groups for provided filters.",
                              raw_response=response)
    groups = response.get('results')

    # Prepare context data
    human_readable = get_group_list_command_hr(groups)  # type: ignore
    context = [createContext(group) for group in remove_empty_elements(groups)]  # type: ignore

    return CommandResults(outputs_prefix='Vectra.Group', outputs=context, readable_output=human_readable,
                          raw_response=groups, outputs_key_field=['group_id'])


def vectra_group_unassign_command(client: VectraClient, args: dict[str, Any]):
    """
    Unassign members in Group.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict[str, Any]): The command arguments.

    Returns:
        CommandResults: The command results.
    """
    validate_group_assign_and_unassign_command_args(args)
    group_id = args.get('group_id')
    members = args.get('members')

    # Call to get group details
    group = client.get_group_request(group_id=group_id)
    group_type = group.get('type')
    updated_members = group_members = group.get('members')
    members_list = argToList(members)
    removed_members = []

    if group_type.lower() == "ip" or group_type.lower() == "domain":  # type: ignore
        for member in members_list:
            if member in group_members:  # type: ignore
                removed_members.append(member)
                updated_members.remove(member)  # type: ignore
    elif group_type.lower() == "account":  # type: ignore
        uids = [i.get('uid') for i in group_members]  # type: ignore
        for member in members_list:
            if member in uids:
                removed_members.append(member)
                uids.remove(member)
        updated_members = uids
    elif group_type.lower() == "host":  # type: ignore
        ids = [str(i.get('id')) for i in group_members]  # type: ignore
        for member in members_list:
            if member in ids:
                removed_members.append(member)
                ids.remove(member)
        updated_members = ids
    if not removed_members:
        members_list = [re.escape(member) for member in members_list]
        return CommandResults(readable_output=f"##### Member(s) {', '.join(members_list)} do not exist in the group.")
    # Call Vectra API to unassign members in group
    res = client.update_group_members_request(group_id=group_id, members=updated_members)
    updated_group = remove_empty_elements(res)

    human_readable = get_group_unassign_and_assign_command_hr(group=updated_group, changed_members=removed_members,
                                                              assign_flag=False)

    return CommandResults(outputs_prefix='Vectra.Group', outputs=createContext(updated_group),
                          readable_output=human_readable,
                          raw_response=updated_group, outputs_key_field=['group_id'])


def vectra_group_assign_command(client: VectraClient, args: dict[str, Any]):
    """
    Assign members in Group.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict[str, Any]): The command arguments.

    Returns:
        CommandResults: The command results.
    """
    validate_group_assign_and_unassign_command_args(args)
    group_id = args.get('group_id')
    members = args.get('members')

    # Call to get group details
    group = client.get_group_request(group_id=group_id)
    group_type = group.get('type')
    updated_members = group_members = group.get('members')
    members_list = argToList(members)
    added_members = []

    if group_type.lower() == "ip" or group_type.lower() == "domain":  # type: ignore
        for member in members_list:
            if member not in group_members:  # type: ignore
                added_members.append(member)
                updated_members.append(member)  # type: ignore
    elif group_type.lower() == "account":  # type: ignore
        uids = [i.get('uid') for i in group_members]  # type: ignore
        for member in members_list:
            if member not in uids:
                added_members.append(member)
                uids.append(member)
        updated_members = uids
    elif group_type.lower() == "host":  # type: ignore
        ids = [str(i.get('id')) for i in group_members]  # type: ignore
        for member in members_list:
            if member not in ids:
                added_members.append(member)
                ids.append(member)
        updated_members = ids
    if not added_members:
        members_list = [re.escape(member) for member in members_list]
        return CommandResults(readable_output=f"##### Member(s) {', '.join(members_list)} are already in the group.")
    # Call Vectra API to assign members in group
    res = client.update_group_members_request(group_id=group_id, members=updated_members)
    updated_group = remove_empty_elements(res)

    human_readable = get_group_unassign_and_assign_command_hr(group=updated_group, changed_members=added_members,
                                                              assign_flag=True)

    return CommandResults(outputs_prefix='Vectra.Group', outputs=createContext(updated_group),
                          readable_output=human_readable,
                          raw_response=updated_group, outputs_key_field=['group_id'])


def test_module(client: VectraClient) -> str:
    """
    Tests the connection to the Vectra server.

    Args:
        client (VectraClient): An instance of the VectraClient class.

    Returns:
        str: A message indicating the success of the test.
    """
    params = demisto.params()
    if params.get('isFetch'):
        validate_configuration_parameters(params)
    client.list_entities_request(page_size=1)
    return "ok"


def get_modified_remote_data_command(client: VectraClient, args: dict) -> GetModifiedRemoteDataResponse:
    """
    Get modified remote data from the Vectra platform and prepare it for mirroring in XSOAR.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict): A dictionary containing the arguments for retrieving modified remote data.

    Returns:
        GetModifiedRemoteDataResponse: List of incidents IDs which are modified since the last update.
    """
    command_args = GetModifiedRemoteDataArgs(args)
    command_last_run_date = dateparser.parse(
        command_args.last_update, settings={'TIMEZONE': 'UTC'}).strftime(DATE_FORMAT)  # type: ignore
    modified_entities_ids = []

    demisto.debug(f'Last update date of get-modified-remote-data command is {command_last_run_date}.')
    next_url = None
    page = 1
    page_size = 500
    while True:
        if next_url:
            # Parse the URL
            parsed_url = urlparse(next_url)
            # Extract the query parameters
            query_params = parse_qs(parsed_url.query)
            page = arg_to_number(query_params.get('page', [''])[0], arg_name='page')  # type: ignore
            page_size = arg_to_number(query_params.get('page_size', [''])[0], arg_name='page_size')  # type: ignore[assignment]
            command_last_run_date = query_params.get('last_modified_timestamp_gte', [''])[0]

        try:
            response = client.list_entities_request(last_modified_timestamp=command_last_run_date,  # type: ignore
                                                    page=page, page_size=page_size, state='')
        except DemistoException as e:
            # If the status code is 404 and the message is invalid page number, then return the empty list of incidents.
            if str(e.res) == '<Response [404]>' and (
                    e.res.status_code == 404 and ERRORS['INVALID_PAGE_RESPONSE'] in str(e.message)):
                demisto.debug(f'Got the 404 error in get-modified-remote-data command: {str(e.message)}')
                break
            raise e
        entities = response.get('results', [])
        next_url = response.get('next_url')
        if len(entities) == 0:
            break
        # Extra ID and type of the entities
        modified_entities_ids.extend([str(entity.get('id')) + '-' + entity.get('type') for entity in entities])
        # If there is no data on the next page
        if not next_url:
            break
        # Mirroring limit
        if len(modified_entities_ids) > MAX_MIRRORING_LIMIT:
            demisto.debug("Max mirroring limit reached.")
            break
    # Filter out None values if there are any.
    modified_entities_ids: List[str] = list(filter(None, modified_entities_ids))  # type: ignore
    demisto.debug(f'Performing get-modified-remote-data command. Numbers Entity IDs to update in XSOAR:'
                  f' {len(modified_entities_ids)}')
    demisto.debug(f'Performing get-modified-remote-data command. Entity IDs to update in XSOAR:'
                  f' {modified_entities_ids}')

    # Filter out any duplicate incident IDs.
    updated_incident_ids = list(set(modified_entities_ids))

    # At max 5,000 incidents should be updated.
    updated_incident_ids = updated_incident_ids[:5000]

    return GetModifiedRemoteDataResponse(modified_incident_ids=updated_incident_ids)


def get_remote_data_command(client: VectraClient, args: dict) -> GetRemoteDataResponse:
    """
    Get remote data for a specific entity from the Vectra platform and prepare it for mirroring in XSOAR.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict): A dictionary containing the arguments for retrieving remote data.
            - id (str): The ID of the entity to retrieve.
            - lastUpdate (str): The timestamp of the last update received for this entity.

    Returns:
        GetRemoteDataResponse: An object containing the remote incident data and any new entries to return to XSOAR.
    """
    new_entries_to_return: List[dict] = []

    dbot_mirror_id: str = args.get('id')  # type: ignore
    demisto.debug(f'dbot_mirror_id:{dbot_mirror_id}')
    entity_id_type = dbot_mirror_id.split('-')
    vectra_entity_id = entity_id_type[0] if entity_id_type else ""
    vectra_entity_type = entity_id_type[1] if entity_id_type else ""
    demisto.debug(f'vectra_entity_id:{vectra_entity_type}')
    demisto.debug(f'Getting update for remote {vectra_entity_id}.')

    command_last_run_dt = arg_to_datetime(args.get('lastUpdate'), arg_name="lastUpdate", required=True)
    command_last_run_timestamp = command_last_run_dt.strftime(DATE_FORMAT)  # type: ignore
    demisto.debug(f'The time when the last time get-remote-data command is called for current incident is '
                  f'{command_last_run_timestamp}.')

    # Retrieve the latest entity data from the Vectra platform.
    remote_incident_data = client.get_entity_request(entity_id=int(vectra_entity_id), entity_type=vectra_entity_type)
    if not remote_incident_data:
        return 'Incident was not found.'  # type: ignore
    # Get detection set.
    detection_set = remote_incident_data.get('detection_set', [])

    entity_urgency_score = remote_incident_data.get('urgency_score')
    params = demisto.params()

    # Calculate severity based on urgency score using the urgency_score_to_severity function.
    severity = urgency_score_to_severity(entity_urgency_score, params)  # type: ignore

    remote_incident_data["urgency_score_based_severity"] = severity

    # Collect the detections if the detection set is not empty.
    if len(detection_set) != 0:
        detections_ids = ','.join([url.split("/")[-1] for url in detection_set])
        detections_data = client.list_detections_request(detection_type=params.get('detection_type'),
                                                         detection_category=params.get('detection_category'),
                                                         ids=detections_ids)
        detections = detections_data.get('results', [])
    else:
        detections = []
    response = {}
    # Add detection details to the entity.
    remote_incident_data.update({'detection_details': detections})

    if vectra_entity_type == "account":
        response = client.list_assignments_request(account_ids=vectra_entity_id)
    elif vectra_entity_type == "host":
        response = client.list_assignments_request(host_ids=vectra_entity_id)

    assignment_details = response.get('results', [])
    assignment_details = assignment_details[0] if len(assignment_details) > 0 else {}
    if assignment_details:
        if not assignment_details.get("resolved_by"):
            assignment_details["resolved_by"] = {"username": ""}
            assignment_details["outcome"] = {"title": ""}
            assignment_details["date_resolved"] = ""
    else:
        assignment_details = EMPTY_ASSIGNMENT
    remote_incident_data.update({'assignment_details': assignment_details})

    last_modified_timestamp = arg_to_datetime(remote_incident_data.get('last_modified_timestamp'))

    if command_last_run_dt > last_modified_timestamp:  # type: ignore
        demisto.debug(f'Nothing new in the Vectra entity {entity_id_type}.')
    else:
        demisto.debug(f'The Vectra entity {entity_id_type} is updated.')
        if detections:
            reopen_in_xsoar(new_entries_to_return, entity_id_type)

    notes = remote_incident_data.get('notes')

    if notes:
        for note in notes:
            if "[Mirrored From XSOAR]" in note.get('note'):
                demisto.debug(f"Skipping the note {note.get('id')} as it is mirrored from XSOAR.")
                continue
            note_date_modified = arg_to_datetime(note.get('date_modified'))
            if note_date_modified:
                if note_date_modified <= command_last_run_dt:  # type: ignore
                    demisto.debug(
                        f"Skipping the note {note.get('id')} as it was modified earlier than the command last run "
                        "timestamp.")
                    continue
            else:
                note_date_created = arg_to_datetime(note.get('date_created'), arg_name='date_created', required=True)
                if note_date_created <= command_last_run_dt:  # type: ignore
                    demisto.debug(
                        f"Skipping the note {note.get('id')} as it is older than the command last run timestamp.")
                    continue
            new_entries_to_return.append({
                'Type': EntryType.NOTE,
                'Contents': f'[Mirrored From Vectra]\n'
                            f'Added By: {note.get("created_by")}\n'
                            f'Added At: {note.get("date_created")} UTC\n'
                            f'Note: {note.get("note")}',
                'ContentsFormat': EntryFormat.TEXT,
                'Note': True,
            })
    demisto.debug(f'remote_incident_data:{remote_incident_data}')
    return GetRemoteDataResponse(remote_incident_data, new_entries_to_return)


def update_remote_system_command(client: VectraClient, args: dict) -> str:
    """
    Update a remote system based on changes in the XSOAR incident.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict): A dictionary containing the arguments required for updating the remote system.

    Returns:
        str: The ID of the updated remote entity.
    """
    parsed_args = UpdateRemoteSystemArgs(args)
    # Get remote incident ID
    remote_entity_id = parsed_args.remote_incident_id
    mirror_entity_id = parsed_args.data.get('vectraxdrentityid', '')
    demisto.debug(f'Remote Incident ID: {remote_entity_id}')
    delta = parsed_args.delta
    # Get XSOAR incident id
    xsoar_incident_id = parsed_args.data.get('id', '')
    demisto.debug(f'XSOAR Incident ID: {xsoar_incident_id}')
    new_entries = parsed_args.entries
    xsoar_tags: List = parsed_args.delta.get('tags', [])
    remote_entity_type = parsed_args.data.get('vectraxdrentitytype', '').lower()

    # For notes
    if new_entries:
        for entry in new_entries:
            entry_id = entry.get("id")
            demisto.debug(f'Sending the entry with ID: {entry_id} and Type: {entry.get("type")}')
            # Get note content and user
            entry_content = re.sub(r'([^\n])\n', r'\1\n\n', entry.get('contents', ''))
            if len(entry_content) > MAX_OUTGOING_NOTE_LIMIT:
                demisto.info(
                    f"Skipping outgoing mirroring for entity note with XSOAR Incident ID:{xsoar_incident_id}, "
                    "because the note length exceeds 8000 characters.")
                entry_user = ""
            else:
                entry_user = entry.get('user', 'dbot') or 'dbot'

            note_str = f'[Mirrored From XSOAR] XSOAR Incident ID: {xsoar_incident_id} \n\n' \
                       f'Note: {entry_content} \n\n' \
                       f'Added By: {entry_user}'
            # API request for adding notes
            client.add_entity_note_request(entity_id=mirror_entity_id, entity_type=remote_entity_type, note=note_str)

    # For tags
    res = client.list_entity_tags_request(entity_id=mirror_entity_id, entity_type=remote_entity_type)
    vectra_tags = res.get('tags')
    if xsoar_tags:
        demisto.debug(f'Sending the tags: {xsoar_tags}')
        client.update_entity_tags_request(entity_id=mirror_entity_id, entity_type=remote_entity_type,
                                          tags=xsoar_tags)
    # Check if all tags from XSOAR removed
    elif not xsoar_tags and vectra_tags and 'tags' in delta:
        demisto.debug(f'Sending the tags: {xsoar_tags}')
        client.update_entity_tags_request(entity_id=mirror_entity_id, entity_type=remote_entity_type,
                                          tags=xsoar_tags)
    # For Closing notes
    delta_keys = parsed_args.delta.keys()
    if 'closingUserId' in delta_keys:
        # Check if incident status is Done
        if parsed_args.incident_changed and parsed_args.inc_status == IncidentStatus.DONE:
            close_notes = parsed_args.data.get('closeNotes', '')
            close_reason = parsed_args.data.get('closeReason', '')
            close_user_id = parsed_args.data.get('closingUserId', '')

            if len(close_notes) > MAX_OUTGOING_NOTE_LIMIT:
                demisto.info(
                    f"Skipping outgoing mirroring for closing notes with XSOAR Incident ID {xsoar_incident_id}, "
                    f"because the note length exceeds {MAX_OUTGOING_NOTE_LIMIT} characters.")
            else:
                closing_note = f'[Mirrored From XSOAR] XSOAR Incident ID: {xsoar_incident_id}\n\n' \
                               f'Close Reason: {close_reason}\n\n' \
                               f'Closed By: {close_user_id}\n\n' \
                               f'Close Notes: {close_notes}'
                demisto.debug(f'Closing Comment: {closing_note}')
                client.add_entity_note_request(entity_id=mirror_entity_id, entity_type=remote_entity_type,
                                               note=closing_note)

    return remote_entity_id


def main():
    params = demisto.params()
    remove_nulls_from_dictionary(params)
    # get connectivity parameters
    server_url = params.get('server_url', '').strip()
    client_id = str(dict_safe_get(params, ["credentials", "identifier"])).strip()
    client_secret_key = str(dict_safe_get(params, ["credentials", "password"])).strip()
    verify_certificate = not argToBoolean(params.get('insecure', False))
    proxy = argToBoolean(params.get('proxy', False))

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    commands: dict[str, Callable] = {
        'vectra-user-list': vectra_user_list_command,
        'vectra-entity-list': vectra_entity_list_command,
        'vectra-entity-describe': vectra_entity_describe_command,
        'vectra-entity-detection-list': vectra_entity_detection_list_command,
        'vectra-detection-describe': vectra_detection_describe_command,
        'vectra-entity-note-list': vectra_entity_note_list_command,
        'vectra-entity-note-add': vectra_entity_note_add_command,
        'vectra-entity-note-update': vectra_entity_note_update_command,
        'vectra-entity-note-remove': vectra_entity_note_remove_command,
        'vectra-entity-tag-add': vectra_entity_tag_add_command,
        'vectra-entity-tag-remove': vectra_entity_tag_remove_command,
        'vectra-entity-tag-list': vectra_entity_tag_list_command,
        'vectra-detections-mark-fixed': vectra_detections_mark_fixed_command,
        'vectra-detections-unmark-fixed': vectra_detections_unmark_fixed_command,
        'vectra-assignment-list': vectra_assignment_list_command,
        'vectra-entity-assignment-add': vectra_entity_assignment_add_command,
        'vectra-entity-assignment-update': vectra_entity_assignment_update_command,
        'vectra-entity-assignment-resolve': vectra_entity_assignment_resolve_command,
        'vectra-assignment-outcome-list': vectra_assignment_outcome_list_command,
        'vectra-detection-pcap-download': vectra_detection_pcap_download_command,
        'vectra-entity-detections-mark-fixed': vectra_entity_detections_mark_fixed_command,
        'vectra-group-list': vectra_group_list_command,
        'vectra-group-assign': vectra_group_assign_command,
        'vectra-group-unassign': vectra_group_unassign_command
    }
    try:
        result = None
        # Creates vectra client
        client = VectraClient(
            server_url=server_url, client_id=client_id, client_secret_key=client_secret_key, verify=verify_certificate,
            proxy=proxy
        )
        # Get Command args
        args = demisto.args()
        if command == "test-module":
            result = test_module(client)
        elif command == "fetch-incidents":
            # Fetch incidents
            incidents = fetch_incidents(client, params)
            # Ingest incidents in XSOAR
            demisto.debug(f'{len(incidents)} incidents are created successfully in XSOAR.')
            demisto.incidents(incidents)
        elif command == 'get-modified-remote-data':
            result = get_modified_remote_data_command(client, args)  # type: ignore
        elif command == 'get-remote-data':
            result = get_remote_data_command(client, args)  # type: ignore
        elif command == 'update-remote-system':
            result = update_remote_system_command(client, args)
        elif command in commands:
            # remove nulls from dictionary and trim space from args
            remove_nulls_from_dictionary(trim_spaces_from_args(args))
            result = commands[command](client, args)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

        return_results(result)  # Returns either str, CommandResults and a list of CommandResults

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()

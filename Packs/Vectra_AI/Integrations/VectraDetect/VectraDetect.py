# ## ### #### #####
# Vectra Detect Integration for Cortex XSOAR
#
# Developer Documentation: https://xsoar.pan.dev/docs/welcome
# Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
# Linting: https://xsoar.pan.dev/docs/integrations/linting
# ## ### #### #####

# Python linting disabled example (disable linting on error code E203)
# noqa: E203

# Standard libraries
import json
from typing import Any
from copy import deepcopy

# Specific libraries
import dateparser
import urllib3
from urllib.parse import urlparse, parse_qs

# XSOAR libraries
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *

# Disable insecure warnings
urllib3.disable_warnings()

# ####       #### #
# ## CONSTANTS ## #

TOTAL_RETRIES = 4
STATUS_CODE_TO_RETRY = (429, *(
    status_code for status_code in requests.status_codes._codes if status_code >= 500))  # type: ignore
OK_CODES = (200, 201, 204)
BACKOFF_FACTOR = 7.5  # Sleep for [0s, 15s, 30s, 60s] between retries.
PACK_VERSION = get_pack_version(pack_name='Vectra AI') or '2.0.3'
UTM_PIVOT = f"?pivot=Vectra_AI-XSOAR-{PACK_VERSION}"
DATE_FORMAT: str = '%Y-%m-%dT%H:%M:%S.000Z'
USER_AGENT = f"Vectra_AI-XSOAR-{PACK_VERSION}"
MAX_RESULTS: int = 200
DEFAULT_FIRST_FETCH: str = '7 days'
DEFAULT_FETCH_ENTITY_TYPES: list = ['Hosts', 'Accounts']
DEFAULT_MAX_FETCH: int = 50

ERRORS = {
    'REQUIRED_ARGUMENT': "Please provide valid value of the '{}'. It is required field.",
    'INVALID_INTEGER_VALUE': "'{}' value must be a non-zero and positive integer value.",
    'POSITIVE_VALUE': 'The value of the "{}" must be greater than or equal to 0',
    'INVALID_MAX_FETCH': '"{}" is an invalid value for Max incidents per fetch. The value must be between 1 to 200.',
    'INVALID_COMMAND_ARG_VALUE': ("Invalid '{}' value provided. Please ensure it is one of the values from the "
                                  "following options: {}."),
    'INVALID_SUPPORT_FOR_ARG': 'The argument "{}" must be set to "{}" when providing value for argument "{}".',
}

ENDPOINTS = {
    'ADD_AND_LIST_ACCOUNT_NOTE_ENDPOINT': '/accounts/{}/notes',
    'ADD_AND_LIST_HOST_NOTE_ENDPOINT': '/hosts/{}/notes',
    'ADD_AND_LIST_DETECTION_NOTE_ENDPOINT': '/detections/{}/notes',
    'UPDATE_AND_REMOVE_ACCOUNT_NOTE_ENDPOINT': '/accounts/{}/notes/{}',
    'UPDATE_AND_REMOVE_HOST_NOTE_ENDPOINT': '/hosts/{}/notes/{}',
    'UPDATE_AND_REMOVE_DETECTION_NOTE_ENDPOINT': '/detections/{}/notes/{}',
}

OUTPUT_PREFIXES = {
    'ACCOUNT_NOTES': 'Vectra.Account.Notes',
    'HOST_NOTES': 'Vectra.Host.Notes',
    'DETECTION_NOTES': 'Vectra.Detection.Notes'
}

NOTE_OUTPUT_KEY_FIELD = 'note_id'

API_VERSION_URL = '/api/v2.5'

API_ENDPOINT_ACCOUNTS = '/accounts'
API_ENDPOINT_ASSIGNMENT = '/assignments'
API_ENDPOINT_OUTCOMES = '/assignment_outcomes'
API_ENDPOINT_DETECTIONS = '/detections'
API_ENDPOINT_HOSTS = '/hosts'
API_ENDPOINT_USERS = '/users'
API_ENDPOINT_GROUPS = '/groups'

API_SEARCH_ENDPOINT_ACCOUNTS = '/search/accounts'
API_SEARCH_ENDPOINT_DETECTIONS = '/search/detections'
API_SEARCH_ENDPOINT_HOSTS = '/search/hosts'

API_TAGGING = '/tagging'

UI_ACCOUNTS = '/accounts'
UI_DETECTIONS = '/detections'
UI_HOSTS = '/hosts'

DEFAULT_ORDERING = {
    'accounts': {'ordering': 'last_detection_timestamp'},
    'detections': {'ordering': 'last_timestamp'},
    'hosts': {'ordering': 'last_detection_timestamp'},
}
DEFAULT_STATE = {
    'state': 'active',
    'resolved': 'false'
}

ENTITY_TYPES = ('Accounts', 'Hosts', 'Detections')

OUTCOME_CATEGORIES = {
    'benign_true_positive': 'Benign True Positive',
    'malicious_true_positive': 'Malicious True Positive',
    'false_positive': 'False Positive'
}
ASSIGNMENT_ENTITY_TYPES = ('account', 'host')

BACK_IN_TIME_SEARCH_IN_MINUTES = '0'

VALID_GROUP_TYPE = ['account', 'host', 'ip', 'domain']
VALID_IMPORTANCE_VALUE = ['high', 'medium', 'low', 'never_prioritize']

MAX_MIRRORING_LIMIT = 5000
ENTITY_TYPES_FOR_MIRRORING = ['host', 'account']
EMPTY_ASSIGNMENT = [{"id": "", "date_assigned": "", "date_resolved": "", "assigned_to": {"username": ""},
                     "resolved_by": {"username": ""}, "assigned_by": {"username": ""}, "outcome": {"title": ""}}]
MIRROR_DIRECTION = {
    'Incoming': 'In',
    'Outgoing': 'Out',
    'Incoming And Outgoing': 'Both'
}

# ####     #### #
# ## GLOBALS ## #
global_UI_URL: str | None = None


# ####          #### #
# ## CLIENT CLASS ## #
class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def http_request(self, method, url_suffix, params=None, json_data=None, resp_type='json'):
        """
        Get http response based on url and given parameters.

        :param method: Specify http methods.
        :param url_suffix: Url encoded url suffix.
        :param params: Parameters to submit with the http request.
        :param json_data: Json data to submit with the http request.
        :param resp_type: Response type.
        :return: http response.
        """
        demisto.debug('Requesting Vectra Detect with method: '
                      f'{method}, url_suffix: {url_suffix}, params: {params} and json_data: {json_data}')
        resp = self._http_request(method=method, url_suffix=url_suffix, params=params, json_data=json_data, retries=TOTAL_RETRIES,
                                  status_list_to_retry=STATUS_CODE_TO_RETRY, backoff_factor=BACKOFF_FACTOR,
                                  raise_on_redirect=False, raise_on_status=False, resp_type=resp_type,
                                  ok_codes=OK_CODES)  # type: ignore
        return resp

    def search_detections(self,
                          min_id=None, max_id=None,
                          min_threat=None, max_threat=None,
                          min_certainty=None, max_certainty=None,
                          last_timestamp=None, state: str = None,  # type: ignore
                          search_query: str = None, search_query_only: str = None,  # type: ignore
                          max_results=None,  # type: ignore
                          **kwargs) -> dict[str, Any]:
        """
        Gets Detections using the 'detections' API endpoint

        :return: dict containing all Detections details
        :rtype: ``Dict[str, Any]``
        """

        # Default params
        demisto.debug("Forcing 'page', 'order_field' and 'page_size' query arguments")
        query_params: dict[str, Any] = {
            'page': 1,
            'order_field': 'last_timestamp'
        }
        query_params['page_size'] = sanitize_max_results(max_results)

        params: dict[str, Any] = {}

        if search_query_only:
            # Specific search query used
            query_params['query_string'] = search_query_only
        else:
            # Test min_id / max_id
            validate_min_max('min_id', min_id, 'max_id', max_id)
            if min_id:
                params['min_id'] = min_id
            if max_id:
                params['max_id'] = max_id

            # Test min_threat / max_threat
            validate_min_max('min_threat', min_threat, 'max_threat', max_threat)
            if min_threat:
                params['min_threat'] = min_threat
            if max_threat:
                params['max_threat'] = max_threat

            # Test min_certainty / max_certainty
            validate_min_max('min_certainty', min_certainty, 'max_certainty', max_certainty)
            if min_certainty:
                params['min_certainty'] = min_certainty
            if max_certainty:
                params['max_certainty'] = max_certainty

            # Last timestamp
            if last_timestamp:
                params['last_timestamp'] = last_timestamp

            # State
            if state:
                params['state'] = state
            else:
                params['state'] = DEFAULT_STATE['state']

            # Build search query
            query_params['query_string'] = build_search_query('detection', params)

            # Adding additional search query
            if search_query:
                query_params['query_string'] += f" AND {search_query}"

        demisto.debug(f"Search query : '{query_params['query_string']}'")

        # Execute request
        demisto.debug("Executing API request")
        return self.http_request(
            method='GET',
            params=query_params,
            url_suffix=f'{API_SEARCH_ENDPOINT_DETECTIONS}'
        )

    def list_detections_by_host_id(self, host_id: str, state: str = 'active',
                                   detection_category: str = '', detection_type: str = '') -> dict:
        """
        Get Detections by Host ID.

        :param host_id: Host ID.
        :param state: The state of the detections.
        :param detection_category: Detection Category.
        :param detection_type: Detection Type.

        :return: List of Detections.
        :rtype: ``Dict``
        """
        params = assign_params(detection_category=detection_category, detection_type=detection_type,
                               state=state, host_id=host_id)

        return self.http_request(method='GET', url_suffix=f'{API_ENDPOINT_DETECTIONS}', params=params)

    def search_accounts(self,
                        min_id=None, max_id=None,
                        min_threat=None, max_threat=None,
                        min_certainty=None, max_certainty=None,
                        last_timestamp=None, state: str = None,  # type: ignore
                        search_query: str = None, search_query_only: str = None,  # type: ignore
                        page: int = None, max_results=None,  # type: ignore
                        **kwargs) -> dict[str, Any]:
        """
        Gets Accounts using the 'Search Accounts' API endpoint.

        :return: dict containing all Accounts details
        :rtype: ``Dict[str, Any]``
        """

        # Default params
        demisto.debug("Forcing 'page', 'order_field' and 'page_size' query arguments")
        query_params: dict[str, Any] = {
            'page': page if page else 1,
            'order_field': 'last_detection_timestamp'
        }
        query_params['page_size'] = sanitize_max_results(max_results)

        params: dict[str, Any] = {}

        if search_query_only:
            # Specific search query used
            query_params['query_string'] = search_query_only
        else:
            # Test min_id / max_id
            validate_min_max('min_id', min_id, 'max_id', max_id)
            if min_id:
                params['min_id'] = min_id
            if max_id:
                params['max_id'] = max_id

            # Test min_threat / max_threat
            validate_min_max('min_threat', min_threat, 'max_threat', max_threat)
            if min_threat:
                params['min_threat'] = min_threat
            if max_threat:
                params['max_threat'] = max_threat

            # Test min_certainty / max_certainty
            validate_min_max('min_certainty', min_certainty, 'max_certainty', max_certainty)
            if min_certainty:
                params['min_certainty'] = min_certainty
            if max_certainty:
                params['max_certainty'] = max_certainty

            # Last timestamp
            if last_timestamp:
                params['last_timestamp'] = last_timestamp

            # State
            if state:
                params['state'] = state
            else:
                params['state'] = DEFAULT_STATE['state']

            # Build search query
            query_params['query_string'] = build_search_query('account', params)

            # Adding additional search query
            if search_query:
                query_params['query_string'] += f" AND {search_query}"

        demisto.debug(f"Search query : '{query_params['query_string']}'")

        # Execute request
        demisto.debug("Executing API request")
        return self.http_request(
            method='GET',
            params=query_params,
            url_suffix=f'{API_SEARCH_ENDPOINT_ACCOUNTS}'
        )

    def search_hosts(self,
                     min_id=None, max_id=None,
                     min_threat=None, max_threat=None,
                     min_certainty=None, max_certainty=None,
                     last_timestamp=None, state: str = None,  # type: ignore
                     search_query: str = None, search_query_only: str = None,  # type: ignore
                     page: int = None, max_results=None,  # type: ignore
                     **kwargs) -> dict[str, Any]:
        """
        Gets Hosts using the 'hosts' API endpoint.

        :return: dict containing all Hosts details.
        :rtype: ``Dict[str, Any]``
        """

        # Default params
        demisto.debug("Forcing 'page', 'order_field' and 'page_size' query arguments")
        query_params: dict[str, Any] = {
            'page': page if page else 1,
            'order_field': 'last_detection_timestamp'
        }
        query_params['page_size'] = sanitize_max_results(max_results)

        params: dict[str, Any] = {}

        if search_query_only:
            # Specific search query used
            query_params['query_string'] = search_query_only
        else:
            # Test min_id / max_id
            validate_min_max('min_id', min_id, 'max_id', max_id)
            if min_id:
                params['min_id'] = min_id
            if max_id:
                params['max_id'] = max_id

            # Test min_threat / max_threat
            validate_min_max('min_threat', min_threat, 'max_threat', max_threat)
            if min_threat:
                params['min_threat'] = min_threat
            if max_threat:
                params['max_threat'] = max_threat

            # Test min_certainty / max_certainty
            validate_min_max('min_certainty', min_certainty, 'max_certainty', max_certainty)
            if min_certainty:
                params['min_certainty'] = min_certainty
            if max_certainty:
                params['max_certainty'] = max_certainty

            # Last timestamp
            if last_timestamp:
                params['last_timestamp'] = last_timestamp

            # State
            if state:
                params['state'] = state
            else:
                params['state'] = DEFAULT_STATE['state']

            # Build search query
            query_params['query_string'] = build_search_query('host', params)

            # Adding additional search query
            if search_query:
                query_params['query_string'] += f" AND {search_query}"

        demisto.debug(f"Search query : '{query_params['query_string']}'")

        # Execute request
        return self.http_request(
            method='GET',
            params=query_params,
            url_suffix=f'{API_SEARCH_ENDPOINT_HOSTS}'
        )

    def search_assignments(self,
                           id=None,
                           account_ids=None, host_ids=None,
                           assignee_ids=None,
                           outcome_ids=None,
                           resolved=None) -> dict[str, Any]:
        """
        Gets Assignments using the 'assignment' API endpoint.

        :return: dict containing all Assignments details.
        :rtype: ``Dict[str, Any]``
        """

        # Default params
        # Assignment endpoint doesn't support pagination
        query_params: dict[str, Any] = {}

        url_addon = f'/{id}' if id else ''

        # If id is specified, do not use other params
        if not id:
            if account_ids and host_ids:
                raise VectraException("Cannot use 'account_ids' and 'host_ids' at the same time")

            # Test Account IDs
            account_ids_set = sanitize_str_ids_list_to_set(account_ids)
            if account_ids_set is not None:
                query_params['accounts'] = account_ids_set

            # Test Host IDs
            host_ids_set = sanitize_str_ids_list_to_set(host_ids)
            if host_ids_set is not None:
                query_params['hosts'] = host_ids_set

            # Test Assignee IDs
            assignee_ids_set = sanitize_str_ids_list_to_set(assignee_ids)
            if assignee_ids_set is not None:
                query_params['assignees'] = assignee_ids_set

            # Test Outcome IDs
            outcome_ids_set = sanitize_str_ids_list_to_set(outcome_ids)
            if outcome_ids_set is not None:
                query_params['resolution'] = outcome_ids_set

            # Resolved
            if resolved:
                query_params['resolved'] = resolved
            else:
                query_params['resolved'] = DEFAULT_STATE['resolved']

        # Execute request
        return self.http_request(
            method='GET',
            params=query_params,
            url_suffix=f'{API_ENDPOINT_ASSIGNMENT}{url_addon}'
        )

    def search_outcomes(self,
                        id=None,
                        max_results=None) -> dict[str, Any]:
        """
        Gets Assignment outcomes using the 'assignment_outcomes' API endpoint.

        :return: dict containing all Outcomes details.
        :rtype: ``Dict[str, Any]``
        """
        # Default params
        demisto.debug("Forcing 'page' and 'page_size' query arguments")
        query_params: dict[str, Any] = {
            'page': 1
        }
        query_params['page_size'] = sanitize_max_results(max_results)

        url_addon = f'/{id}' if id else ''

        # Execute request
        return self.http_request(
            method='GET',
            params=query_params,
            url_suffix=f'{API_ENDPOINT_OUTCOMES}{url_addon}'
        )

    def search_users(self,
                     id=None,
                     last_login_datetime=None,
                     role=None,
                     type=None,
                     username=None) -> dict[str, Any]:
        """
        Gets Vectra Users using the 'assignment_outcomes' API endpoint.

        :return: dict containing all User details.
        :rtype: ``Dict[str, Any]``
        """
        # Default params
        # Users endpoint doesn't support pagination
        query_params: dict[str, Any] = {}

        url_addon = f'/{id}' if id else ''

        # If id is specified, do not use other params
        if not id:
            # Test user name
            if username:
                query_params['username'] = username

            # Test user role
            if role:
                query_params['role'] = role

            # Test user type
            if type:
                query_params['account_type'] = type

            # Test last login datetime
            if last_login_datetime and convert_date(last_login_datetime) is not None:
                query_params['last_login_gte'] = last_login_datetime

        # Execute request
        return self.http_request(
            method='GET',
            params=query_params,
            url_suffix=f'{API_ENDPOINT_USERS}{url_addon}'
        )

    def get_pcap_by_detection_id(self, id: str):
        """
        Gets a single detection PCAP file using the detection endpoint

        - params:
            - id: The Detection ID
        - returns:
            PCAP file if available
        """

        # Execute request
        return self.http_request(
            method='GET',
            url_suffix=f'{API_ENDPOINT_DETECTIONS}/{id}/pcap',
            resp_type='response'
        )

    def markasfixed_by_detection_id(self, id: str, fixed: bool):
        """
        Mark/Unmark a single detection as fixed

        - params:
            - id: Vectra Detection ID
            - fixed: Targeted state
        - returns:
            Vectra API call result (unused)
        """

        json_payload = {
            'detectionIdList': [id],
            'mark_as_fixed': "true" if fixed else "false"
        }

        # Execute request
        return self.http_request(
            method='PATCH',
            url_suffix=API_ENDPOINT_DETECTIONS,
            json_data=json_payload
        )

    def add_tags(self, id: str, type: str, tags: list[str]):
        """
        Adds tags from Vectra entity

        - params:
            id: The entity ID
            type: The entity type
            tags: Tags list
        - returns
            Vectra API call result (unused)
        """

        # Must be done in two steps
        # 1 - get current tags
        # 2 - merge list and apply

        # Execute get request
        api_response = self.http_request(
            method='GET',
            url_suffix=f'{API_TAGGING}/{type}/{id}'
        )

        current_tags: list[str] = api_response.get('tags', [])

        json_payload = {
            'tags': list(set(current_tags).union(set(tags)))
        }

        # Execute request
        return self.http_request(
            method='PATCH',
            url_suffix=f'{API_TAGGING}/{type}/{id}',
            json_data=json_payload
        )

    def del_tags(self, id: str, type: str, tags: list[str]):
        """
        Deletes tags from Vectra entity

        - params:
            id: The entity ID
            type: The entity type
            tags: Tags list
        - returns
            Vectra API call result (unused)
        """

        # Must be done in two steps
        # 1 - get current tags
        # 2 - merge list and apply

        # Execute get request
        api_response = self.http_request(
            method='GET',
            url_suffix=f'{API_TAGGING}/{type}/{id}'
        )

        current_tags = api_response.get('tags', [])

        json_payload = {
            'tags': list(set(current_tags).difference(set(tags)))
        }

        # Execute request
        return self.http_request(
            method='PATCH',
            url_suffix=f'{API_TAGGING}/{type}/{id}',
            json_data=json_payload
        )

    def create_outcome(self, category: str, title: str):
        """
        Creates a new Outcome

        - params:
            - category: The Outcome category (one of "BTP,MTP,FP" in human readable format)
            - title: A custom title for this new outcome
        - returns:
            Vectra API call result
        """
        raw_category = convert_outcome_category_text2raw(category)
        if raw_category is None:
            raise ValueError('"category" value is invalid')
        raw_title = title.strip()
        if raw_title == '':
            raise ValueError('"title" cannot be empty')

        json_payload = {
            'title': raw_title,
            'category': raw_category
        }

        # Execute request
        return self.http_request(
            method='POST',
            url_suffix=API_ENDPOINT_OUTCOMES,
            json_data=json_payload
        )

    def update_assignment(self, assignee_id: str, assignment_id: str = None,  # type: ignore
                          account_id: str = None, host_id: str = None):  # type: ignore
        """
        Creates or updates an assignment

        - params:
            - assignee_id: The Vectra User ID who want to assign to
            - assignment_id: The existing assignment ID associated with the targeted Entity, if there is any
            - assignee_id: The Vectra User ID who want to assign to
            - account_id: The Account ID
            - host_id: The Host ID
        - returns:
            Vectra API call result
        """
        # Test Assignee ID
        try:
            validate_argument('min_id', assignee_id)
        except ValueError:
            raise ValueError('"assignee_id" value is invalid')

        json_payload = {
            'assign_to_user_id': assignee_id,
        }

        if assignment_id:  # Reassign an existing assignment
            # Test Assignment ID
            try:
                validate_argument('min_id', assignment_id)
            except ValueError:
                raise ValueError('"assignment_id" value is invalid')

            url_addon = f'/{assignment_id}'

            return self.http_request(
                method='PUT',
                url_suffix=f'{API_ENDPOINT_ASSIGNMENT}{url_addon}',
                json_data=json_payload
            )
        elif account_id:
            # Test Entity ID
            try:
                validate_argument('min_id', account_id)
            except ValueError:
                raise ValueError('"account_id" value is invalid')

            json_payload.update({
                'assign_account_id': account_id
            })

            # Execute request
            return self.http_request(
                method='POST',
                url_suffix=API_ENDPOINT_ASSIGNMENT,
                json_data=json_payload
            )
        elif host_id:
            # Test Entity ID
            try:
                validate_argument('min_id', host_id)
            except ValueError:
                raise ValueError('"host_id" value is invalid')

            json_payload.update({
                'assign_host_id': host_id
            })

            # Execute request
            return self.http_request(
                method='POST',
                url_suffix=API_ENDPOINT_ASSIGNMENT,
                json_data=json_payload
            )
        else:
            raise ValueError('Either "assignment_id" or "account_id" or "host_id" must be specified.')

    def resolve_assignment(self, assignment_id: str, outcome_id: str, note: str = None,  # type: ignore
                           rule_name: str = None, detections_list: str = None):  # type: ignore
        """
        Creates or updates an assignment

        - params:
            - assignee_id: The Vectra User ID who want to assign to
            - assignment_id: The existing assignment ID associated with the targeted Entity, if there is any
            - assignee_id: The Vectra User ID who want to assign to
            - account_id: The Account ID
            - host_id: The Host ID
        - returns:
            Vectra API call result
        """
        # Test assignment ID
        try:
            validate_argument('min_id', assignment_id)
        except ValueError:
            raise ValueError('"assignment_id" value is invalid')

        # Test outcome ID
        try:
            validate_argument('min_id', outcome_id)
        except ValueError:
            raise ValueError('"outcome_id" value is invalid')

        json_payload: dict[str, Any] = {
            'outcome': outcome_id,
            'note': note,
        }

        if rule_name:
            detection_ids_set = sanitize_str_ids_list_to_set(detections_list)
            if detection_ids_set is None:
                raise ValueError('"detections_list" value is invalid')

            json_payload.update({
                'triage_as': rule_name,
                'detection_ids': list(detection_ids_set)
            })

        # Execute request
        return self.http_request(
            method='PUT',
            url_suffix=f'{API_ENDPOINT_ASSIGNMENT}/{assignment_id}/resolve',
            json_data=json_payload
        )

    def delete_assignment(self, assignment_id: str = ''):  # type: ignore
        """
        Delete the assignment.

        - params:
            - assignment_id: The existing assignment ID associated with the targeted Entity.
        - returns:
            Vectra API call result.
        """
        if assignment_id:
            url_addon = f'/{assignment_id}'
            return self.http_request(method='DELETE', url_suffix=f'{API_ENDPOINT_ASSIGNMENT}{url_addon}',
                                     resp_type='response')
        return None

    def markasfixed_by_detection_ids(self, ids_list: list):
        """
        Mark a list of detections as fixed.

        - params:
            - ids_list: Vectra Detection IDs list.
        - returns:
            Vectra API call result.
        """

        json_payload = {
            'detectionIdList': ids_list,
            'mark_as_fixed': 'true'
        }

        # Execute request
        return self.http_request(method='PATCH', url_suffix=API_ENDPOINT_DETECTIONS, json_data=json_payload)

    def list_tags_request(self, entity_id: int = None, entity_type: str = None) -> dict:  # type: ignore
        """
        List tags for the specified entity.

        Args:
            entity_id (int): The ID of the Account/Host/Detection to list tags.
            entity_type (str): The type of the entity.

        Returns:
            Dict: Response from the API containing the tags.
        """
        res = self.http_request(method='GET', url_suffix=f'{API_TAGGING}/{entity_type}/{entity_id}')
        return res

    def add_note_request(self, entity_id: int = None, entity_type: str = None, note: str = None) -> dict:  # type: ignore
        """
        Add a note to an Account, Host or Detection.

        Args:
            entity_id (int): The ID of the Account, Host or Detection to add the note to.
            entity_type (str): The type Account, Host or Detection.
            note (str): The note to add.

        Returns:
            Dict: Response from the API containing the added note.
        """
        data = {'note': note}
        notes = self.http_request(method='POST', json_data=data, url_suffix=ENDPOINTS[
            f'ADD_AND_LIST_{entity_type.upper()}_NOTE_ENDPOINT'].format(entity_id))  # type: ignore
        return notes

    def update_note_request(self, entity_id: int = None, entity_type: str = None, note: str = None,  # type: ignore
                            note_id: int = None) -> dict:  # type: ignore
        """
        Updates the note of an Account, Host or Detection.

        Args:
            entity_id (int): The ID of the Account, Host or Detection to update the note for.
            entity_type (str): The type Account, Host or Detection.
            note (str): The updated note for the Account, Host or Detection.
            note_id (int): The ID of the note to be updated.

        Returns:
            Dict: Response from the API containing the updated note details.
        """
        data = {'note': note}
        notes = self.http_request(
            method='PATCH', json_data=data, url_suffix=ENDPOINTS[
                f'UPDATE_AND_REMOVE_{entity_type.upper()}_NOTE_ENDPOINT'].format(entity_id, note_id))  # type: ignore

        return notes

    def remove_note_request(self, entity_type: str = None, entity_id: int = None,  # type: ignore
                            note_id: str = None) -> requests.Response:  # type: ignore
        """
        Remove a note from an Account, Host or Detection.

        Args:
            entity_id (int): The ID of the Account, Host or Detection to remove the note from .
            entity_type (str): The type Account, Host or Detection.
            note_id (int): The Id of the note to be removed.

        Returns:
            requests.Response: Response from the API containing the added note.
        """
        res = self.http_request(method='DELETE', resp_type='response', url_suffix=ENDPOINTS[
            f'UPDATE_AND_REMOVE_{entity_type.upper()}_NOTE_ENDPOINT'].format(entity_id, note_id))  # type: ignore
        return res

    def list_note_request(self, entity_id: int = None, entity_type: str = None) -> dict:  # type: ignore
        """
        List Account/Host/Detection notes.

        Args:
            entity_id (int): The ID of the Account/Host/Detection to add the note to.
            entity_type (str): The type Account, Host or Detection.

        Returns:
            Dict: Response from the API.
        """
        notes = self.http_request(method='GET', url_suffix=ENDPOINTS[
            f'ADD_AND_LIST_{entity_type.upper()}_NOTE_ENDPOINT'].format(entity_id))  # type: ignore
        return notes

    def get_account_by_account_id(self, account_id: str | None = None):
        """
        Get Account by Account ID.

        - params:
            - account_id: The Account ID
        - returns:
            Vectra API call result.
        """
        return self.http_request(method='GET', url_suffix=f'{API_ENDPOINT_ACCOUNTS}/{account_id}')

    def get_host_by_host_id(self, host_id: str | None = None):
        """
        Get Host by Host ID.

        - params:
            - host_id: The Host ID
        - returns:
            Vectra API call result.
        """
        return self.http_request(method='GET', url_suffix=f'{API_ENDPOINT_HOSTS}/{host_id}')

    def get_group_request(self, group_id: int = None) -> dict:  # type: ignore
        """Get group by ID.

        Args:
            group_id (int): The ID of the group to retrieve.

        Returns:
            Dict: Response from the API containing the group information.
        """
        return self.http_request(method='GET', url_suffix=f"{API_ENDPOINT_GROUPS}/{group_id}")

    def update_group_members_request(self, group_id: int = None, members: list = None) -> dict:  # type: ignore
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
        return self.http_request(method='PATCH', url_suffix=f"{API_ENDPOINT_GROUPS}/{group_id}",
                                 json_data=body)

    def list_assignments_request(self, accounts: str | None = None, hosts: str | None = None,
                                 page_size: int | None = None) -> dict:
        """
        Get Assignments by Accounts and Hosts.

        - params:
            - accounts: The Accounts IDs
            - hosts: The Host IDs
            - page_size: Total number of Assignments
        - returns:
            Vectra API call result.
        """
        query_params = {}
        if page_size:
            query_params = {'page_size': page_size}
        if accounts:
            query_params['accounts'] = accounts  # type: ignore
        if hosts:
            query_params['hosts'] = hosts  # type: ignore
        return self.http_request(method='GET', url_suffix=f'{API_ENDPOINT_ASSIGNMENT}', params=query_params)

    def list_entity_tags_request(self, entity_id: str | None = None, entity_type: str | None = None):
        """
        Get Entity Tags by Entity ID and Entity Type.

        - params:
            - entity_id: The Entity ID
            - entity_type: The Entity Type
        - returns:
            Vectra API call result.
        """
        return self.http_request(method='GET', url_suffix=f'{API_TAGGING}/{entity_type}/{entity_id}')

    def update_entity_tags_request(self, entity_id: str | None = None, entity_type: str | None = None,
                                   tag_list: list | None = None):
        """
        Update Entity Tags by Entity ID and Entity Type.

        - params:
            - entity_id: The Entity ID
            - entity_type: The Entity Type
            - tag_list: The List of Tags
        - returns:
            Vectra API call result.
        """
        tags = {'tags': tag_list}
        return self.http_request(method='PATCH', url_suffix=f'{API_TAGGING}/{entity_type}/{entity_id}', json_data=tags)

    def list_group_request(self, group_type: str = '', account_names: list[str] = [], domains: list[str] = [],
                           host_ids: list[str] = [], host_names: list[str] = [], importance: str = '',
                           ips: list[str] = [], description: str = '', last_modified_timestamp: datetime | None = None,
                           last_modified_by: str = '', group_name: str = ''):
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

        return self.http_request(method='GET', url_suffix=API_ENDPOINT_GROUPS, params=params)


# ####                 #### #
# ##  HELPER FUNCTIONS   ## #
#                           #


def str2bool(value: str | None) -> bool | None:
    """
    Converts a string into a boolean

    - params:
        - value: The string to convert
    - returns:
        True if value matches the 'true' list
        False if value matches the 'false' list
        None instead
    """
    if value is None:
        output = None
    elif value.lower() in ('true', 'yes'):
        output = True
    elif value.lower() in ('false', 'no'):
        output = False
    else:
        output = None

    return output


def sanitize_max_results(max_results=None) -> int:
    """
    Cleans max_results value and ensure it's always lower than the MAX

    - params:
        max_results: The max results number
    - returns:
        The checked/enforced max results value
    """
    if max_results and isinstance(max_results, str):
        max_results = int(max_results)

    if (not max_results) or (max_results > MAX_RESULTS) or (max_results <= 0):
        return MAX_RESULTS
    else:
        return max_results


def scores_to_severity(threat: int | None, certainty: int | None) -> str:
    """
    Converts Vectra scores to a severity String

    - params:
        - threat: The Vectra threat score
        - certainty: The Vectra certainty score
    - returns:
        The severity as text
    """
    severity = 'Unknown'
    if isinstance(threat, int) and isinstance(certainty, int):
        if threat < 50 and certainty < 50:
            severity = 'Low'
        elif threat < 50:  # and certainty >= 50
            severity = 'Medium'
        elif certainty < 50:  # and threat >= 50
            severity = 'High'
        else:  # threat >= 50 and certainty >= 50
            severity = 'Critical'

    return unify_severity(severity)


def severity_string_to_int(severity: str | None) -> int:
    """
    Converts a severity String to XSOAR severity value

    - params:
        - severity: The severity as text
    - returns:
        The XSOAR severity value
    """
    output = 0
    if severity == 'Critical':
        output = 4
    elif severity == 'High':
        output = 3
    elif severity == 'Medium':
        output = 2
    elif severity == 'Low':
        output = 1

    return output


def convert_date(date: str | None) -> str | None:
    """
    Converts a date format to an ISO8601 string

    Converts the Vectra date (YYYY-mm-ddTHH:MM:SSZ) format in a datetime.

    :type date: ``str``
    :param date: a string with the format 'YYYY-mm-DDTHH:MM:SSZ'

    :return: Parsed time in ISO8601 format
    :rtype: ``str``
    """
    if date:
        date_dt = dateparser.parse(str(date))
        if date_dt:
            return date_dt.strftime(DATE_FORMAT)
        else:
            return None
    else:
        return None


def remove_space_from_args(args):
    """Remove space from args."""
    for key in args:
        if isinstance(args[key], str):
            args[key] = args[key].strip()
    return args


def validate_argument(label: str | None, value: Any) -> int:
    """
    Validates a command argument based on its type

    - params:
        - label: The argument label
        - value: The argument value
    - returns:
        The value if OK or raises an Exception if not
    """

    demisto.debug(f"Testing '{label}' argument value")
    if label in ['min_id', 'max_id']:
        try:
            if (value is None) or isinstance(value, float):
                raise ValueError('Cannot be empty or a float')
            if value and isinstance(value, str):
                value = int(value)
            if not isinstance(value, int):
                raise ValueError('Should be an int')
            if int(value) <= 0:
                raise ValueError('Should be > 0')
        except ValueError:
            raise ValueError(f'"{label}" must be an integer greater than 0')
    elif label in ['min_threat', 'min_certainty', 'max_threat', 'max_certainty']:
        try:
            if (value is None) or isinstance(value, float):
                raise ValueError('Cannot be empty or a float')
            if value and isinstance(value, str):
                value = int(value)
            if not isinstance(value, int):
                raise ValueError('Should be an int')
            if int(value) < 0:
                raise ValueError('Should be >= 0')
            if int(value) > 99:
                raise ValueError('Should be < 100')
        except ValueError:
            raise ValueError(f'"{label}" must be an integer between 0 and 99')
    elif label in ['min_privilege_level']:
        try:
            if (value is None) or isinstance(value, float):
                raise ValueError('Cannot be empty or a float')
            if value and isinstance(value, str):
                value = int(value)
            if not isinstance(value, int):
                raise ValueError('Should be an int')
            if int(value) < 1:
                raise ValueError('Should be >= 1')
            if int(value) > 10:
                raise ValueError('Should be <= 10')
        except ValueError:
            raise ValueError(f'"{label}" must be an integer between 1 and 10')
    else:
        raise SystemError('Unknown argument type')
    return value


def validate_min_max(min_label: str = None, min_value: str = None, max_label: str = None, max_value: str = None):  # type: ignore
    """
    Validates min/max values for a specific search attribute and ensure max_value >= min_value

    - params:
        - min_label: The attribute label for the min value
        - min_value: The min value
        - max_label: The attribute label for the max value
        - max_value: The max value
    - returns:
        Return True if OK or raises Exception if not
    """
    if min_value:
        validate_argument(min_label, min_value)

    if max_value:
        validate_argument(max_label, max_value)

    if min_value and max_value and int(min_value) > int(max_value):
        raise ValueError(f'"{max_label}" must be greater than or equal to "{min_label}"')

    return True


def validate_fetch_incident_params(integration_params: dict):
    """
    Validates the integration parameters for fetching incidents, including timestamps, entity types, fetch queries,
    and the maximum number of incidents per fetch. Raises ValueErrors for invalid parameters.

    - params:
        - integration_params: A dictionary containing the integration parameters.

    - raises:
        ValueError: If the integration parameters are invalid.
    """
    demisto.debug('Fetching mode is enabled. Testing settings ...')

    demisto.debug('Testing Fetch first timestamp ...')
    fetch_first_time = integration_params.get('first_fetch', DEFAULT_FIRST_FETCH)
    look_back = integration_params.get('look_back', BACK_IN_TIME_SEARCH_IN_MINUTES)
    demisto.debug(f'Fetch first timestamp : {fetch_first_time}')
    try:
        iso_date_to_vectra_start_time(fetch_first_time, look_back)
    except SystemError as exc:
        raise ValueError('Fetch first timestamp is invalid.') from exc
    demisto.debug('Testing Fetch first timestamp [done]')

    demisto.debug('Testing Fetch entity types ...')
    fetch_entity_types = integration_params.get('fetch_entity_types', DEFAULT_FETCH_ENTITY_TYPES)
    demisto.debug(f'Fetch entity types : {fetch_entity_types}')
    if len(fetch_entity_types) == 0:
        raise ValueError('You must select at least one entity type to fetch.')
    for entity_itt in fetch_entity_types:
        if entity_itt not in ENTITY_TYPES:
            raise ValueError(f'This entity type "{entity_itt}" is invalid.')
    demisto.debug('Testing Fetch entity types [done]')

    accounts_fetch_query = integration_params.get('accounts_fetch_query')
    demisto.debug(f"'Accounts' fetch query : {accounts_fetch_query}")

    hosts_fetch_query = integration_params.get('hosts_fetch_query')
    demisto.debug(f"'Hosts' fetch query : {hosts_fetch_query}")

    detections_fetch_query = integration_params.get('detections_fetch_query')
    demisto.debug(f"'Detections' fetch query : {detections_fetch_query}")

    demisto.debug('Testing Max incidents per fetch ...')
    max_incidents_per_fetch = integration_params.get('max_fetch', DEFAULT_MAX_FETCH)
    demisto.debug(f'Max incidents per fetch (initial value): {max_incidents_per_fetch}')
    if isinstance(max_incidents_per_fetch, str):
        try:
            max_incidents_per_fetch = int(max_incidents_per_fetch)
        except ValueError as exc:
            raise ValueError(ERRORS['INVALID_MAX_FETCH'].format(max_incidents_per_fetch)) from exc
    if max_incidents_per_fetch <= 0:
        raise ValueError(ERRORS['INVALID_MAX_FETCH'].format(max_incidents_per_fetch))

    if (max_incidents_per_fetch // len(fetch_entity_types)) == 0:
        raise ValueError(f"Max incidents per fetch ({max_incidents_per_fetch}) must be >= "
                         f"to the number of entity types you're fetching ({len(fetch_entity_types)})")

    demisto.debug(f'Max incidents per fetch (final value): {max_incidents_per_fetch}')
    demisto.debug('Testing Max incidents per fetch [done]')


def build_search_query_for_detections(entity_id: str, fetch_type: str,
                                      detection_category: str = '', detection_type: str = '') -> str:
    """
    Builds a search query for tags.

    - params:
        - entity_id: The ID of the entity.
        - fetch_type: The type of entity.
        - detection_category: The category of the detection.
        - detection_type: The type of the detection.
    - returns:
        Returns the search query.
    """
    search_query = f'detection.src_linked_{fetch_type}.id:{entity_id}'
    if detection_category:
        search_query += f' AND detection.detection_category:"{detection_category}"'
    if detection_type:
        search_query += f' AND detection.detection_type:"{detection_type}"'
    return search_query


def build_search_query_for_tags(fetch_query: str, fetch_type: str, tags: list[str]) -> str:
    """
    Builds a search query for tags.

    - params:
        - fetch_query: The search query.
        - fetch_type: The type of entity.
        - tags: The list of tags.
    - returns:
        Returns the search query.
    """
    if not tags:
        return fetch_query
    first_tag = tags[0]
    if '*' not in first_tag:
        first_tag = f'"{first_tag}"'
    tag_query = f'({fetch_type}.tags:{first_tag}'
    if len(tags) > 1:
        for tag in tags[1:]:
            if '*' in tag:
                tag_query += f' OR {fetch_type}.tags:{tag}'
            else:
                tag_query += f' OR {fetch_type}.tags:"{tag}"'
    tag_query += ')'
    if fetch_query:
        return f'{fetch_query} AND {tag_query}'
    return tag_query


def sanitize_str_ids_list_to_set(list: str | None) -> set[int] | None:
    """
    Sanitize the given list to ensure all IDs are valid

    - params:
        - list: The list to sanitize
    - returns:
        Returns the sanitized list (only valid IDs)
    """
    output: set[int] = set()
    if list is not None and isinstance(list, str):
        ids_list = [id.strip() for id in list.split(',')]
        for id in ids_list:
            if id != '':
                try:
                    validate_argument('min_id', id)
                except ValueError:
                    raise ValueError(f'ID "{id}" is invalid')
                output.add(int(id))

    if len(output) > 0:
        return output
    else:
        return None


def build_search_query(object_type, params: dict) -> str:
    """
    Builds a Lucene syntax search query depending on the object type to search on (Account, Detection, Host)

    - params:
        - object_type: The object type we're searching (Account, Detection, Host)
        - params: The search params
    - returns:
        The Lucene search query
    """
    query = ''
    attribute = ''
    operator = ''

    for key, value in params.items():
        if key.startswith('min_'):
            operator = ':>='
        elif key.startswith('max_'):
            operator = ':<='

        if key.endswith('_id'):
            attribute = 'id'
        elif key.endswith('_threat'):
            attribute = 'threat'
        elif key.endswith('_certainty'):
            attribute = 'certainty'

        if key in ['state']:
            attribute = key
            operator = ':'
            value = f'"{value}"'

        if key == 'last_timestamp':
            operator = ':>='
            if object_type == 'detection':
                attribute = 'last_timestamp'
            else:
                attribute = 'last_detection_timestamp'

        # Append query
        # No need to add "AND" as implied
        query += f' {object_type}.{attribute}{operator}{value}'

    return query.strip()


def forge_entity_url(type: str, id: str | None) -> str:
    """
    Generate the UI pivot URL

    - params:
        - type: The object type ("account", "detection" or "host")
        - id: The object ID
    - returns:
        The pivot URL using server FQDN
    """
    if type == 'account':
        url_suffix = f'{UI_ACCOUNTS}/'
    elif type == 'detection':
        url_suffix = f'{UI_DETECTIONS}/'
    elif type == 'host':
        url_suffix = f'{UI_HOSTS}/'
    else:
        raise Exception(f"Unknown type : {type}")

    if not id:
        raise Exception("Missing ID")

    return urljoin(urljoin(global_UI_URL, url_suffix), str(id)) + UTM_PIVOT


def common_extract_data(entity: dict[str, Any]) -> dict[str, Any]:
    """
    Extracts common information from Vectra object renaming attributes on the fly.

    - params:
        - host: The Vectra object
    - returns:
        The extracted data
    """
    return {
        'Assignee': entity.get('assigned_to'),
        'AssignedDate': convert_date(entity.get('assigned_date')),
        'CertaintyScore': entity.get('certainty'),
        'ID': entity.get('id'),
        'State': entity.get('state'),
        'Tags': entity.get('tags'),
        'ThreatScore': entity.get('threat'),
    }


def extract_account_data(account: dict[str, Any]) -> dict[str, Any]:
    """
    Extracts useful information from Vectra Account object renaming attributes on the fly.

    - params:
        - host: The Vectra Account object
    - returns:
        The Account extracted data
    """
    return common_extract_data(account) | {  # type: ignore
        'LastDetectionTimestamp': convert_date(account.get('last_detection_timestamp')),
        'PrivilegeLevel': account.get('privilege_level'),
        'PrivilegeCategory': account.get('privilege_category'),
        'Severity': unify_severity(account.get('severity')),
        'Type': account.get('account_type'),
        'URL': forge_entity_url('account', account.get('id')),
        'Username': account.get('name'),
    }


def extract_detection_data(detection: dict[str, Any]) -> dict[str, Any]:
    """
    Extracts useful information from Vectra Detection object renaming attributes on the fly.

    - params:
        - host: The Vectra Detection object
    - returns:
        The Detection extracted data
    """
    # Complex values
    detection_name = detection.get('custom_detection') if detection.get(
        'custom_detection') else detection.get('detection')

    source_account = detection.get('src_account')
    source_account_id = source_account.get('id') if source_account else None

    source_host = detection.get('src_host')
    source_host_id = source_host.get('id') if source_host else None

    summary = detection.get('summary')
    if summary:
        description = summary.get('description')
        dst_ips = summary.get('dst_ips')
        dst_ports = summary.get('dst_ports')
    else:
        description = dst_ips = dst_ports = None

    return common_extract_data(detection) | remove_empty_elements({
        'Category': detection.get('category'),
        'Description': description,
        'DestinationIPs': dst_ips,
        'DestinationPorts': dst_ports,
        'FirstTimestamp': convert_date(detection.get('first_timestamp')),
        'IsTargetingKeyAsset': detection.get('is_targeting_key_asset'),
        'LastTimestamp': convert_date(detection.get('last_timestamp')),
        'Name': detection_name,
        'Severity': scores_to_severity(detection.get('threat'), detection.get('certainty')),
        'SensorLUID': detection.get('sensor'),
        'SensorName': detection.get('sensor_name'),
        'SourceAccountID': source_account_id,
        'SourceHostID': source_host_id,
        'SourceIP': detection.get('src_ip'),
        'TriageRuleID': detection.get('triage_rule_id'),
        'Type': detection.get('detection'),
        'URL': forge_entity_url('detection', detection.get('id')),
    })


def extract_host_data(host: dict[str, Any]) -> dict[str, Any]:
    """
    Extracts useful information from Vectra Host object renaming attributes on the fly.

    - params:
        - host: The Vectra Hosts object
    - returns:
        The Host extracted data
    """
    return common_extract_data(host) | {  # type: ignore
        'HasActiveTraffic': host.get('has_active_traffic'),
        'Hostname': host.get('name'),
        'IPAddress': host.get('ip'),
        'IsKeyAsset': host.get('is_key_asset'),
        'IsTargetingKeyAsset': host.get('is_targeting_key_asset'),
        'LastDetectionTimestamp': convert_date(host.get('last_detection_timestamp')),
        'PrivilegeLevel': host.get('privilege_level'),
        'PrivilegeCategory': host.get('privilege_category'),
        'ProbableOwner': host.get('probable_owner'),
        'SensorLUID': host.get('sensor'),
        'SensorName': host.get('sensor_name'),
        'Severity': unify_severity(host.get('severity')),
        'URL': forge_entity_url('host', host.get('id')),
    }


def extract_assignment_data(assignment: dict[str, Any]) -> dict[str, Any]:
    """
    Extracts useful information from Vectra Assignment object renaming attributes on the fly.

    - params:
        - assignment: The Vectra Assignment object
    - returns:
        The Assignment extracted data
    """
    assigned_by = assignment.get('assigned_by')
    assigned_by_user = assigned_by.get('username') if assigned_by else None
    assigned_to = assignment.get('assigned_to')
    assigned_to_user = assigned_to.get('username') if assigned_to else None

    outcome = assignment.get('outcome')
    outcome_title = outcome.get('title') if outcome else None
    outcome_category = outcome.get('category') if outcome else None

    resolved_by = assignment.get('resolved_by')
    resolved_by_user = resolved_by.get('username') if resolved_by else None

    # assignment['events'][0]['context'] is always present
    triaged_as = assignment['events'][0]['context'].get('triage_as')

    return remove_empty_elements({
        'AccountID': assignment.get('account_id'),
        'AssignedBy': assigned_by_user,
        'AssignedDate': convert_date(assignment.get('date_assigned')),
        'AssignedTo': assigned_to_user,
        'HostID': assignment.get('host_id'),
        'ID': assignment.get('id'),
        'IsResolved': assignment.get('resolved_by') is not None,
        'OutcomeCategory': convert_outcome_category_raw2text(outcome_category),
        'OutcomeTitle': outcome_title,
        'TriagedDetections': assignment.get('triaged_detections'),
        'TriagedAs': triaged_as,
        'ResolvedBy': resolved_by_user,
        'ResolvedDate': convert_date(assignment.get('date_resolved')),
    })


def extract_outcome_data(outcome: dict[str, Any]) -> dict[str, Any]:
    """
    Extracts useful information from Vectra Outcome object renaming attributes on the fly.

    - params:
        - outcome: The Vectra Outcome object
    - returns:
        The Outcome extracted data
    """
    return {
        'Category': convert_outcome_category_raw2text(outcome.get('category')),
        'ID': outcome.get('id'),
        'IsBuiltIn': outcome.get('builtin'),
        'Title': outcome.get('title')
    }


def extract_user_data(user: dict[str, Any]) -> dict[str, Any]:
    """
    Extracts useful information from Vectra User object renaming attributes on the fly.

    - params:
        - user: The Vectra User object
    - returns:
        The User extracted data
    """
    return {
        'Email': user.get('email'),
        'ID': user.get('id'),
        'Role': user.get('role'),
        'Type': user.get('account_type'),
        'Username': user.get('username'),
        'LastLoginDate': convert_date(user.get('last_login'))
    }


def detection_to_incident(detection: dict):
    """
    Creates an incident of a Detection.

    :type detection: ``dict``
    :param detection: Single detection object

    :return: Incident representation of a Detection
    :rtype ``dict``
    """

    extracted_data = extract_detection_data(detection)

    incident_name = f"Vectra Detection ID: {extracted_data.get('ID')} - {extracted_data.get('Name')}"

    vectra_specific = {
        'entity_type': extracted_data.get('Category'),
        'UI_URL': extracted_data.get('URL'),
    }
    detection.update({'_vectra_specific': vectra_specific})

    incident = {
        'name': incident_name,                            # name is required field, must be set
        'occurred': extracted_data.get('LastTimestamp'),  # must be string of a format ISO8601
        'rawJSON': json.dumps(detection),                 # the original event,
                                                          #   this will allow mapping of the event in the mapping stage.
                                                          #   Don't forget to `json.dumps`
        'severity': severity_string_to_int(extracted_data.get('Severity')),
        # 'dbotMirrorId': extracted_data.get('ID')
    }

    incident_last_run = {
        'last_timestamp': dateparser.parse(extracted_data.get('LastTimestamp'),  # type: ignore
                                           settings={'TO_TIMEZONE': 'UTC'}).isoformat(),  # type: ignore
        'id': extracted_data.get('ID')
    }

    return incident, incident_last_run


def host_to_incident(client: Client, host: dict, detection_category: str = '', detection_type: str = ''):
    """
    Creates an incident of a Host.

    :type client: ``Client``
    :param client: The client object used to communicate with the Vectra API.

    :type host: ``dict``
    :param host: Single Host object.

    :type detection_category: ``str``
    :param detection_category: The category of the detection.

    :type detection_type: ``str``
    :param detection_type: The type of the detection.

    :return: Incident representation of a Host.
    :rtype ``dict``
    """

    extracted_data = extract_host_data(host)

    incident_name = f"Vectra Host ID: {extracted_data.get('ID')} - {extracted_data.get('Hostname')}"

    detections = []
    detections_data = client.list_detections_by_host_id(str(host.get('id')), 'active',
                                                        detection_category, detection_type)
    detections = detections_data.get('results', [])
    for detection in detections:
        detection['url'] = forge_entity_url('detection', detection.get('id'))
    demisto.debug(f'Found {len(detections)} detection(s) for the host with the ID: {host.get("id")}.')
    host.update({'detection_details': detections})

    response = client.list_assignments_request(hosts=host.get('id'), page_size=1)
    assignment_details = response.get('results', [])
    assignment_details = assignment_details[0] if len(assignment_details) > 0 else {}
    if assignment_details:
        if not assignment_details.get("resolved_by"):
            assignment_details["resolved_by"] = {"username": ""}
            assignment_details["outcome"] = {"title": ""}
            assignment_details["date_resolved"] = ""
    else:
        assignment_details = EMPTY_ASSIGNMENT
    host.update({'assignment_details': assignment_details})

    vectra_specific = {
        'entity_type': 'host',
        'UI_URL': extracted_data.get('URL'),
    }
    host.update({'_vectra_specific': vectra_specific})

    mirroring_fields = get_mirroring()
    mirroring_fields.update({'mirror_id': str(host.get('id')) + '-' + 'host'})
    host.update(mirroring_fields)
    calculated_severity = severity_string_to_int(scores_to_severity(host.get('threat'), host.get('certainty')))
    host.update({'calculated_severity': calculated_severity})

    incident = {
        'name': incident_name,                                     # name is required field, must be set
        'occurred': extracted_data.get('LastDetectionTimestamp'),  # must be string of a format ISO8601
        'rawJSON': json.dumps(host),                               # the original event,
                                                                   #   this will allow mapping of the event in the mapping stage.
                                                                   #   Don't forget to `json.dumps`
        'severity': host.get('calculated_severity'),
        # 'dbotMirrorId': extracted_data.get('ID')
    }

    incident_last_run = {
        'last_timestamp': dateparser.parse(extracted_data.get('LastDetectionTimestamp'),  # type: ignore
                                           settings={'TO_TIMEZONE': 'UTC'}).isoformat(),  # type: ignore
        'id': extracted_data.get('ID')
    }

    return incident, incident_last_run


def account_to_incident(client: Client, account: dict, detection_category: str = '', detection_type: str = ''):
    """
    Creates an incident of an Account.

    :type client: ``Client``
    :param client: The client object used to communicate with the Vectra API.

    :type host: ``dict``
    :param host: Single Account object

    :type detection_category: ``str``
    :param detection_category: The category of the detection.

    :type detection_type: ``str``
    :param detection_type: The type of the detection.

    :return: Incident representation of a Account
    :rtype ``dict``
    """

    extracted_data = extract_account_data(account)
    account_id: str = extracted_data.get('ID', '')

    incident_name = f"Vectra Account ID: {account_id} - {account.get('display_name')}"

    search_query = build_search_query_for_detections(account_id, 'account', detection_category, detection_type)
    api_response = client.search_detections(state='active', search_query=search_query)
    if (api_response is None) or (api_response.get('count') is None):
        raise VectraException("API issue - Response is empty or invalid")

    detections = []
    if api_response.get('count') == 0:
        demisto.info(f'Found 0 detection(s) for the account with the ID: {account_id}.')
    elif api_response.get('count', 0) > 0:
        demisto.info(f"Found {api_response.get('count')} detection(s) for the account with the ID: {account_id}.")

        if api_response.get('results') is None:
            raise VectraException("API issue - Response is empty or invalid")

        # Due to backward search we need to avoid creating incidents of already ingested events
        detections = api_response.get('results', [])
        for detection in detections:
            detection['url'] = forge_entity_url('detection', detection.get('id'))

    groups_response = client.list_group_request(
        group_type='account', account_names=[account.get('display_name')])  # type: ignore

    account.update({'groups': groups_response.get('results', [])})

    # Add detection details to the entity
    account.update({'detection_details': detections})

    response = client.list_assignments_request(accounts=account.get('id'), page_size=1)
    assignment_details = response.get('results', [])
    assignment_details = assignment_details[0] if len(assignment_details) > 0 else {}
    if assignment_details:
        if not assignment_details.get("resolved_by"):
            assignment_details["resolved_by"] = {"username": ""}
            assignment_details["outcome"] = {"title": ""}
            assignment_details["date_resolved"] = ""
    else:
        assignment_details = EMPTY_ASSIGNMENT
    account.update({'assignment_details': assignment_details})

    vectra_specific = {
        'entity_type': 'account',
        'UI_URL': extracted_data.get('URL'),
    }
    account.update({'_vectra_specific': vectra_specific})

    mirroring_fields = get_mirroring()
    mirroring_fields.update({'mirror_id': str(account.get('id')) + '-' + 'account'})
    account.update(mirroring_fields)
    calculated_severity = severity_string_to_int(scores_to_severity(account.get('threat'), account.get('certainty')))
    account.update({'calculated_severity': calculated_severity})
    incident = {
        'name': incident_name,                                     # name is required field, must be set
        'occurred': extracted_data.get('LastDetectionTimestamp'),  # must be string of a format ISO8601
        'rawJSON': json.dumps(account),                            # the original event,
                                                                   #   this will allow mapping of the event in the mapping stage.
                                                                   #   Don't forget to `json.dumps`
        'severity': account.get('calculated_severity'),
    }

    incident_last_run = {
        'last_timestamp': dateparser.parse(extracted_data.get('LastDetectionTimestamp'),  # type: ignore
                                           settings={'TO_TIMEZONE': 'UTC'}).isoformat(),  # type: ignore
        'id': account_id
    }

    return incident, incident_last_run


def get_last_run_details(integration_params: dict, is_test: bool = False) -> dict:
    """
    Extracts detail from the stored last_run variable or create them if needed

    :type integration_params: ``dict``
    :param integration_params: The integration configuration parameters.

    :type is_test: ``bool``
    :param is_test: A boolean indicating whether the command is being run in test mode.

    :return: Last run content.
    :rtype ``dict``
    """
    # Get the config settings
    fetch_first_time = integration_params.get('first_fetch', DEFAULT_FIRST_FETCH)
    fetch_entity_types = integration_params.get('fetch_entity_types', DEFAULT_FETCH_ENTITY_TYPES)

    # Get the last run value
    last_run = {} if is_test else demisto.getLastRun()
    demisto.debug(f"last run : {last_run}")

    output_last_run: dict = {}
    for entity_type in ENTITY_TYPES:
        if entity_type in fetch_entity_types:
            # This will return a relative TZaware datetime (in UTC)
            last_timestamp = dateparser.parse(fetch_first_time,  # type: ignore
                                              settings={'TO_TIMEZONE': 'UTC'}).isoformat()  # type: ignore
            last_id = 0
            empty_last_run: dict = {
                'last_timestamp': last_timestamp,
                'id': last_id,
                'last_created_events': []
            }
            output_last_run[entity_type] = empty_last_run
            if not last_run.get(entity_type):
                demisto.debug(f"Last run is not set for '{entity_type}'. Using value from config : {fetch_first_time}")
                # This will return a relative TZaware datetime (in UTC)
                demisto.debug(f"New last run for {entity_type}, {output_last_run[entity_type]}")
            else:
                output_last_run[entity_type].update(last_run.get(entity_type, {}))

        elif last_run.get(entity_type):
            demisto.debug(f"'{entity_type} present in last run but no more used, discarding.")

    return output_last_run


def iso_date_to_vectra_start_time(iso_date: str, look_back: str = BACK_IN_TIME_SEARCH_IN_MINUTES):
    """
    Converts an iso date into a Vectra timestamp used in search query.

    - params:
        - iso_date: The ISO date to convert
        - look_back: The look back time in minutes.
    - returns:
        A Vectra date timestamp.
    """
    # This will return a relative TZaware datetime (in UTC)
    date = dateparser.parse(iso_date, settings={'TO_TIMEZONE': 'UTC'})  # type: ignore

    if date:
        # We should return time in YYYY-MM-DDTHHMM format for Vectra Lucene query search ...
        start_datetime = date.strftime(r'%Y-%m-%dT%H%M')
        demisto.debug(f'Start datetime is : {start_datetime}')

        if look_back:
            look_back_int = arg_to_number(look_back, 'look_back', True)
            if look_back_int < 0:  # type: ignore
                raise ValueError(ERRORS['POSITIVE_VALUE'].format('look back'))
            demisto.debug(f'The look back is : {look_back_int} minutes. ')
            if look_back_int != 0:
                # Manipulate the date if we need to search backward
                # Timedelta is imported from CommonServerPython
                date = date - timedelta(minutes=look_back_int)  # type: ignore
                backward_start_datetime = date.strftime('%Y-%m-%dT%H%M')  # type: ignore
                demisto.debug('Manipulated time as backward search. '
                              f'Changed the Start time from : {start_datetime} to : {backward_start_datetime}')
                start_datetime = backward_start_datetime

    else:
        raise SystemError('Invalid ISO date')

    return start_datetime


def unify_severity(severity: str | None) -> str:
    """
    Force severity string to be consistent across endpoints

    - params:
        - severity: The severity string
    - returns:
        The unified severity string (First capitalized letter)
    """
    if severity:
        output = severity.capitalize()
    else:
        output = 'Unknown'

    return output


def convert_outcome_category_raw2text(category: str | None) -> str | None:
    """
    Convert outcome category from raw to human readable text

    - params:
        - category: The raw outcome category string
    - returns:
        The human readable outcome category string
    """
    return OUTCOME_CATEGORIES.get(category) if category else None


def convert_outcome_category_text2raw(category: str) -> str | None:
    """
    Convert outcome category from human readable text to raw

    - params:
        - category: The human readable outcome category string
    - returns:
        The raw outcome category string
    """
    # Inverting Key/Value
    category_text = {v: k for k, v in OUTCOME_CATEGORIES.items()}
    return category_text.get(category) if category else None


def validate_positive_integer_arg(value: Any | None, arg_name: str, required: bool = False) -> bool:
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


def validate_group_list_command_args(args: dict[Any, Any]):
    """
    Validates the arguments provided for the group list command.

    Args:
        args (dict[Any, Any]): The arguments dictionary.

    Raises:
        ValueError: If any of the arguments are invalid.
    """
    group_type = args.get('group_type', '')
    if group_type and isinstance(group_type, str):
        group_type = group_type.lower()
        # Validate group_type value
        if group_type not in VALID_GROUP_TYPE:
            raise ValueError(ERRORS['INVALID_COMMAND_ARG_VALUE'].format('group_type', ', '.join(VALID_GROUP_TYPE)))

    importance = args.get('importance', '')
    # Validate importance value
    if importance and isinstance(importance, str) and importance.lower() not in VALID_IMPORTANCE_VALUE:
        raise ValueError(ERRORS['INVALID_COMMAND_ARG_VALUE'].format('importance', ', '.join(VALID_IMPORTANCE_VALUE)))

    # Validate account_names value
    account_names = argToList(args.get('account_names', ''))
    if account_names and group_type != 'account':
        raise ValueError(ERRORS['INVALID_SUPPORT_FOR_ARG'].format('group_type', 'account', 'account_names'))

    # Validate domains value
    domains = argToList(args.get('domains', ''))
    if domains and group_type != 'domain':
        raise ValueError(ERRORS['INVALID_SUPPORT_FOR_ARG'].format('group_type', 'domain', 'domains'))

    # Validate host_ids value
    host_ids = argToList(args.get('host_ids', ''))
    if host_ids and group_type != 'host':
        raise ValueError(ERRORS['INVALID_SUPPORT_FOR_ARG'].format('group_type', 'host', 'host_ids'))
    for host_id in host_ids:
        host_id = arg_to_number(host_id, 'host_ids')
        validate_positive_integer_arg(host_id, arg_name="host_ids")

    # Validate host_names value
    host_names = argToList(args.get('host_names', ''))
    if host_names and group_type != 'host':
        raise ValueError(ERRORS['INVALID_SUPPORT_FOR_ARG'].format('group_type', 'host', 'host_names'))

    # Validate ips value
    ips = argToList(args.get('ips', ''))
    if ips and group_type != 'ip':
        raise ValueError(ERRORS['INVALID_SUPPORT_FOR_ARG'].format('group_type', 'ip', 'ips'))


def get_group_list_command_hr(groups: list):
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
        group['group_id'] = group['id']
        members: list = group.get('members')
        members_hr = None
        if members and isinstance(members, list):
            # If the members are simple list of strings, then join them with comma.
            if isinstance(members[0], str):
                members_hr = ', '.join([(str(member)) for member in members])
            # If the members are list of dictionaries, then extract important field from that and join it with comma.
            elif isinstance(members[0], dict):
                members_list = []
                for member in members:
                    if member.get('uid'):
                        members_list.append(str(member.get('uid')))  # type: ignore
                    elif member.get('id'):
                        members_list.append(  # type: ignore
                            f'[{member.get("id")}]({forge_entity_url(group.get("type"), member.get("id"))})')
                members_hr = ', '.join(members_list)

        hr_dict.append({
            'Group ID': group.get('group_id'),
            'Name': group.get('name'),
            'Group Type': group.get('type'),
            'Description': group.get('description'),
            'Importance': group.get('importance'),
            'Members': members_hr,
            'Last Modified Timestamp': group.get('last_modified'),
        })
    # Prepare human-readable output table
    human_readable = tableToMarkdown('Groups Table', hr_dict,
                                     ['Group ID', 'Name', 'Group Type', 'Description', 'Importance', 'Members',
                                      'Last Modified Timestamp'], removeNull=True)

    return human_readable


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


def get_group_unassign_and_assign_command_hr(group: dict, changed_members: list, assign_flag: bool = False):
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
            members_hr = ', '.join([(str(member)) for member in members])
        # If the members are list of dictionaries, then extract important field from that and join it with comma.
        elif isinstance(members[0], dict):
            members_list = []
            for member in members:
                if member.get('uid'):
                    members_list.append(str(member.get('uid')))  # type: ignore
                elif member.get('id'):
                    members_list.append(  # type: ignore
                        f"[{member.get('id')}]({forge_entity_url(str(group.get('type')), member.get('id'))})")
            members_hr = ', '.join(members_list)

    hr_dict.append({
        "Group ID": group.get('group_id'),
        "Name": group.get('name'),
        "Group Type": group.get('type'),
        "Description": group.get('description'),
        "Members": members_hr,
        "Last Modified Timestamp": group.get('last_modified'),
    })

    if group.get('type').lower() == 'account' and assign_flag is True:  # type: ignore
        new_changed_members = []
        ignored_members = []
        accounts = [account.get('uid') for account in group.get('members', [])]
        for member in changed_members:
            if member in accounts:
                new_changed_members.append(member)
            else:
                ignored_members.append(member)

        if ignored_members:
            return_warning(f'The following account names were invalid: {", ".join(ignored_members)}',
                           exit=len(ignored_members) == len(changed_members))

        changed_members = new_changed_members

    # Prepare human-readable output table
    change_action = "assigned to" if assign_flag else "unassigned from"
    human_readable = tableToMarkdown(
        f"Member(s) {', '.join(changed_members)} have been {change_action} the group.\n### Updated group details:",
        hr_dict, ['Group ID', 'Name', 'Group Type', 'Description', 'Members',
                  'Last Modified Timestamp'], removeNull=True)

    return human_readable


def validate_note_add_command_args(entity_id: int | None, note: str, entity_type: str):
    """
    Validates the arguments provided for the note add command.

    Args:
        entity_id (int): The ID of the object.
        note (str): The note to add.

    Raises:
        ValueError: If any of the arguments are invalid.
    """

    # Validate id value
    validate_positive_integer_arg(entity_id, arg_name=f'{entity_type}_id', required=True)

    # Validate note value
    if not note:
        raise ValueError(ERRORS['REQUIRED_ARGUMENT'].format('note'))


def validate_note_update_command_args(entity_id: int | None, note_id: int | None, note: str, entity_type: str):
    """
    Validates the arguments provided for the note update command.

    Args:
        entity_id (int): The ID of the object.
        note_id (int): The ID of the note to be updated.
        note (str): The note to update.

    Raises:
        ValueError: If any of the arguments are invalid.
    """

    # Validate entity_id and note_id value
    validate_positive_integer_arg(entity_id, arg_name=f'{entity_type}_id', required=True)
    validate_positive_integer_arg(note_id, arg_name='note_id', required=True)

    # Validate note value
    if not note:
        raise ValueError(ERRORS['REQUIRED_ARGUMENT'].format('note'))


def validate_note_remove_command_args(entity_id: int | None, note_id: int | None, entity_type: str):
    """
    Validates the arguments provided for the note remove command.

    Args:
        entity_id (int): The ID of the object.
        note_id (int): The ID of the note to be removed.
        entity_type (str): The type from Account, Host or Detection.

    Raises:
        ValueError: If any of the arguments are invalid.
    """

    # Validate entity_id value
    validate_positive_integer_arg(entity_id, arg_name=f'{entity_type}_id', required=True)

    # Validate note_id value
    validate_positive_integer_arg(note_id, arg_name='note_id', required=True)

    return True


def get_list_notes_command_hr(notes: dict, entity_id: int | None, entity_type: str) -> str:  # type: ignore
    """
    Returns the human-readable output for the Account, Host or Detection notes.

    Args:
        notes (Dict): The assignment details dictionary.
        entity_id (Optional[int]): Account/Host/Detection ID.
        entity_type (str): Account, Host or Detection.

    Returns:
        str: The human-readable output.
    """
    hr_dict = []
    for note in notes:
        note.update({'note_id': note['id']})
        del note['id']
        note.update({f'{entity_type}_id': entity_id})

        hr_dict.append({
            'Note ID': note.get('note_id'),
            'Note': note.get('note'),
            'Created By': note.get('created_by'),
            'Created Date': note.get('date_created'),
            'Modified By': note.get('modified_by'),
            'Modified Date': note.get('date_modified'),
        })

    # Prepare human-readable output table
    human_readable = tableToMarkdown('Notes Table', hr_dict,
                                     ['Note ID', 'Note', 'Created By', 'Created Date', 'Modified By', 'Modified Date'],
                                     removeNull=True)
    return human_readable


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


def add_notes_to_new_entries(notes: list, command_last_run_dt: datetime | None) -> list:
    """
    Lists notes from vectra that to be added when mirrored on xsoar

    Args:
        notes (list): Notes from vectra platform
        command_last_run_dt (str): last time when command was ran on XSOAR

    Returns:
        list: list of notes to be added in XSOAR
    """
    if not notes:
        return []

    new_entry_notes: list[dict] = []
    for note in notes:
        if '[Mirrored From XSOAR]' in note.get('note'):
            demisto.debug(f"Skipping the note {note.get('id')} as it is mirrored from XSOAR.")
            continue
        note_date_modified = arg_to_datetime(note.get('date_modified'))
        if note_date_modified and note_date_modified <= command_last_run_dt:  # type: ignore
            demisto.debug(
                f"Skipping the note {note.get('id')} as it was modified earlier than the command last run "
                'timestamp.')
            continue
        else:
            note_date_created = arg_to_datetime(note.get('date_created'), arg_name='date_created', required=True)
            if note_date_created <= command_last_run_dt:  # type: ignore
                demisto.debug(
                    f"Skipping the note {note.get('id')} as it is older than the command last run timestamp.")
                continue

        if '\n' in note.get('note'):
            note_info = f"\n{note.get('note')}"
        else:
            note_info = note.get('note')

        new_entry_notes.append({
            'Type': EntryType.NOTE,
            'Contents': f'[Mirrored From Vectra]\n'
                        f'Added By: {note.get("created_by")}\n'
                        f'Added At: {note.get("date_created")} UTC\n'
                        f'Note: {note_info}',
            'ContentsFormat': EntryFormat.MARKDOWN,
            'Note': True,
        })
    return new_entry_notes


class VectraException(Exception):
    """
    Custom Vectra Exception in case of Vectra API issue
    """


# ####               #### #
# ## COMMAND FUNCTIONS ## #
#                         #
def test_module(client: Client, integration_params: dict) -> str:
    """
    Tests API connectivity and authentication.

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    - params:
        - client: The API Client
        - integration_params: All additional integration settings
    - returns:
        'ok' if test passed, anything else if at least one test failed.
    """
    try:
        last_timestamp = None

        if integration_params.get('isFetch'):
            fetch_incidents(client, integration_params, True)
        else:
            # Client class should raise the exceptions, but if the test fails
            # the exception text is printed to the Cortex XSOAR UI.
            client.search_detections(max_results=1, last_timestamp=last_timestamp)
        message = 'ok'

    except ValueError as e:
        message = str(e)
        demisto.debug(message)
    except DemistoException as e:
        if 'Invalid token' in str(e):
            message = 'Authorization Error: make sure API Token is properly set'
            demisto.debug(message)
        elif 'Verify that the server URL parameter is correct' in str(e):
            message = 'Verify that the Vectra Server FQDN or IP is correct and that you have access to the server from your host'
            demisto.debug(message)
        else:
            raise e

    return message


def fetch_incidents(client: Client, integration_params: dict, is_test: bool = False):
    """
    Fetches incidents based on the provided client and integration parameters.

    :param client: The client object used to communicate with the Vectra API.
    :param integration_params: A dictionary containing integration parameters like fetch entity types and queries.
    :param is_test: A boolean indicating whether the command is being run in test mode.

    :return: A tuple containing the new last run details and a list of fetched incidents.
    """
    validate_fetch_incident_params(integration_params)
    fetch_entity_types = integration_params.get('fetch_entity_types', DEFAULT_FETCH_ENTITY_TYPES)
    look_back = integration_params.get('look_back', BACK_IN_TIME_SEARCH_IN_MINUTES)
    tags = argToList(integration_params.get('tags', ''))
    tags = [tag.strip() for tag in tags if tag.strip()]

    detection_category = integration_params.get('detection_category', '')
    detection_type = integration_params.get('detection_type', '').strip()
    api_response: dict = {}

    # Get the last run and the last fetched value
    previous_last_run = get_last_run_details(integration_params, is_test)

    incidents = []
    new_last_run: dict = previous_last_run

    # We split the number of incidents to create into the number of remaining endpoints to call
    remaining_fetch_types: set = fetch_entity_types
    max_fetch = arg_to_number(integration_params.get('max_fetch', DEFAULT_MAX_FETCH))

    if max_fetch > MAX_RESULTS:  # type: ignore
        if is_test:
            raise ValueError(ERRORS['INVALID_MAX_FETCH'].format(max_fetch))
        demisto.debug(f'The value for the Max Fetch parameter is {max_fetch} which is greater than '
                      f'{MAX_RESULTS}, so reducing it to {MAX_RESULTS}.')
        max_fetch = MAX_RESULTS

    max_created_incidents: int = max_fetch // len(remaining_fetch_types)  # type: ignore

    for entity_type in ENTITY_TYPES:
        entity_incidents: list = []
        if entity_type not in fetch_entity_types:
            continue

        last_fetched_timestamp = previous_last_run[entity_type]['last_timestamp']
        last_fetched_id = previous_last_run[entity_type]['id']
        # Forced to use "get" as this field wasn't present in the first version of this integration
        last_created_events = previous_last_run[entity_type].get('last_created_events', [])  # Retro-compat

        demisto.debug(f"{entity_type} - Last fetched incident"
                      f"last_timestamp : {last_fetched_timestamp} / ID : {last_fetched_id}")

        start_time = iso_date_to_vectra_start_time(last_fetched_timestamp, look_back)

        new_last_run[entity_type] = previous_last_run.get(entity_type, {})
        new_last_run[entity_type]['last_created_events'] = last_created_events
        if entity_type == 'Accounts':
            accounts_fetch_query = build_search_query_for_tags(
                integration_params.get('accounts_fetch_query', ''), 'linked_account', tags)
            api_response = client.search_accounts(
                last_timestamp=start_time,
                search_query=accounts_fetch_query,
            )
        elif entity_type == 'Hosts':
            hosts_fetch_query = build_search_query_for_tags(
                integration_params.get('hosts_fetch_query', ''), 'host', tags)
            api_response = client.search_hosts(
                last_timestamp=start_time,
                search_query=hosts_fetch_query,
            )
        elif entity_type == 'Detections':
            api_response = client.search_detections(
                last_timestamp=start_time,
                search_query=integration_params.get('detections_fetch_query'),  # type: ignore
            )

        if (api_response is None) or (api_response.get('count') is None):
            raise VectraException("API issue - Response is empty or invalid")

        if api_response.get('count') == 0:
            demisto.info(f"{entity_type} - No results")
        elif api_response.get('count', 0) > 0:
            demisto.debug(f"{entity_type} - {api_response.get('count')} objects fetched from Vectra")

            if api_response.get('results') is None:
                raise VectraException("API issue - Response is empty or invalid")

            # Due to backward search we need to avoid creating incidents of already ingested events
            api_results = api_response.get('results', [])
            for event in api_results:
                if len(entity_incidents) >= max_created_incidents:
                    demisto.debug(f"{entity_type} - Maximum created incidents has been reached ({max_created_incidents})."
                                  f" Skipping other objects.")
                    break

                incident_last_run = None
                if entity_type == 'Accounts':
                    incident, incident_last_run = account_to_incident(client, event, detection_category, detection_type)
                elif entity_type == 'Hosts':
                    incident, incident_last_run = host_to_incident(client, event, detection_category, detection_type)
                elif entity_type == 'Detections':
                    incident, incident_last_run = detection_to_incident(event)
                else:
                    demisto.debug(f"The {entity_type=} didn't match any condition, can't create an incident, continue.")
                    continue

                # Search this incident in the last_run, if it's in, skip it, if not create it
                # Create incident UID and search for it
                if incident_last_run is not None:
                    incident_uid = f"{entity_type}_{incident_last_run.get('id')}"
                    if incident_uid in last_created_events:
                        demisto.debug(f"{entity_type} - Skipping object "
                                      f"last_timestamp : {incident_last_run.get('last_timestamp')} "
                                      f"/ ID : {incident_last_run.get('id')}")
                        continue

                    demisto.debug(f"{entity_type} - New incident from object "
                                  f"last_timestamp : {incident_last_run.get('last_timestamp')} "
                                  f"/ ID : {incident_last_run.get('id')}")
                    entity_incidents.append(incident)
                    new_last_run[entity_type]['last_timestamp'] = incident_last_run.get('last_timestamp')
                    new_last_run[entity_type]['id'] = incident_last_run.get('id')
                    # We add this event in the list, as that's a new event we need to remember for next run
                    last_created_events.append(incident_uid)

            if len(entity_incidents) > 0:
                demisto.info(f"{entity_type} - {len(entity_incidents)} incident(s) to create")
                incidents += entity_incidents
            else:
                demisto.debug(f"{entity_type} - No new incidents to create, keeping previous last_run data")
                new_last_run[entity_type] = previous_last_run[entity_type]

            # Update remaining list
            remaining_fetch_types.remove(entity_type)
            if len(remaining_fetch_types) > 0:
                max_created_incidents = (max_fetch - len(incidents)) // len(remaining_fetch_types)  # type: ignore

    if is_test:
        demisto.debug(f"Setting last run to : {new_last_run}")
        return previous_last_run, []

    demisto.info(f"{len(incidents)} total incident(s) to create.")

    return new_last_run, incidents


def get_modified_remote_data_command(client: Client) -> GetModifiedRemoteDataResponse:
    """
    Get modified remote data from the Vectra platform and prepare it for mirroring in XSOAR.

    Args:
        client (Client): An instance of the VectraClient class.

    Returns:
        GetModifiedRemoteDataResponse: List of incidents IDs which are modified since the last update.
    """
    args = demisto.args()
    command_args = GetModifiedRemoteDataArgs(args)
    command_last_run_date = dateparser.parse(
        command_args.last_update, settings={'TIMEZONE': 'UTC'}).strftime('%Y-%m-%dT%H%M')  # type: ignore
    modified_entities_ids = []

    demisto.debug(f'Last update date of get-modified-remote-data command is {command_last_run_date}.')

    for entity_type in ENTITY_TYPES_FOR_MIRRORING:
        entity_next_url = None
        page = 1
        page_size = 500
        while True:
            if entity_next_url:
                # Parse the URL
                parsed_url = urlparse(entity_next_url)
                # Extract the query parameters
                query_params = parse_qs(parsed_url.query)
                page = arg_to_number(query_params.get('page', [''])[0], arg_name='page')  # type: ignore
                page_size = arg_to_number(query_params.get('page_size', [''])[
                                          0], arg_name='page_size')  # type: ignore[assignment]
                query_string = query_params.get('query_string', [''])[0]  # type: ignore
            else:
                query_string = '_doc_modified_ts:>=' + command_last_run_date

            if entity_type == 'host':
                response = client.search_hosts(search_query_only=query_string, page=page, max_results=page_size)
            else:
                response = client.search_accounts(search_query_only=query_string, page=page, max_results=page_size)

            entities = response.get('results', [])
            entity_next_url = response.get('next')
            if len(entities) == 0:
                break
            # Extra ID and type of the entities
            modified_entities_ids.extend([str(entity.get('id')) + f'-{entity_type}' for entity in entities])

            # Mirroring limit
            if len(modified_entities_ids) > MAX_MIRRORING_LIMIT / 2:
                demisto.debug(f'Max mirroring limit reached for {entity_type}.')
                break

            # If there is no data on the next page
            if not entity_next_url:
                break

    # Filter out None values if there are any.
    modified_entities_ids: list[str] = list(filter(None, modified_entities_ids))  # type: ignore
    demisto.debug(f'Performing get-modified-remote-data command. Numbers Entity IDs to update in XSOAR:'
                  f' {len(modified_entities_ids)}')
    demisto.debug(f'Performing get-modified-remote-data command. Entity IDs to update in XSOAR:'
                  f' {modified_entities_ids}')

    # Filter out any duplicate incident IDs.
    updated_incident_ids = list(set(modified_entities_ids))

    # At max 5,000 incidents should be updated.
    updated_incident_ids = updated_incident_ids[:5000]

    return GetModifiedRemoteDataResponse(modified_incident_ids=updated_incident_ids)


def get_remote_data_command(client: Client, integration_params: dict = {}) -> GetRemoteDataResponse:
    """
    Get remote data for a specific entity from the Vectra platform and prepare it for mirroring in XSOAR.

    Args:
        client (Client): An instance of the VectraClient class.
        integration_params (Dict): The integration parameters.

    Returns:
        GetRemoteDataResponse: An object containing the remote incident data and any new entries to return to XSOAR.
    """
    detection_category = integration_params.get('detection_category', '')
    detection_type = integration_params.get('detection_type', '').strip()
    new_entries_to_return: list[dict] = []

    args = demisto.args()
    dbot_mirror_id: str = args.get('id')  # type: ignore
    demisto.debug(f'dbot_mirror_id:{dbot_mirror_id}')
    entity_id_type = dbot_mirror_id.split('-')
    vectra_entity_id = entity_id_type[0] if entity_id_type else ''
    vectra_entity_type = entity_id_type[1] if entity_id_type else ''

    demisto.debug(f'vectra_entity_id:{vectra_entity_type}')
    demisto.debug(f'Getting update for remote {vectra_entity_id}.')

    command_last_run_dt = arg_to_datetime(args.get('lastUpdate'), arg_name='lastUpdate', required=True)
    command_last_run_timestamp = command_last_run_dt.strftime(DATE_FORMAT)  # type: ignore

    demisto.debug(f'The time when the last time get-remote-data command is called for current incident is '
                  f'{command_last_run_timestamp}.')

    # Retrieve the latest entity data from the Vectra platform.
    if vectra_entity_type == 'account':
        remote_incident_data = client.get_account_by_account_id(account_id=vectra_entity_id)
        groups_response = client.list_group_request(
            group_type='account', account_names=[remote_incident_data.get('name')])  # type: ignore
        remote_incident_data.update({'groups': groups_response.get('results', [])})
    else:
        remote_incident_data = client.get_host_by_host_id(host_id=vectra_entity_id)

    if not remote_incident_data:
        return 'Incident was not found.'  # type: ignore

    remote_incident_data['_vectra_specific'] = {
        'entity_type': vectra_entity_type,
        'UI_URL': forge_entity_url(vectra_entity_type, remote_incident_data.get('id'))
    }

    updated_severity_score = severity_string_to_int(scores_to_severity(remote_incident_data.get('threat'),
                                                                       remote_incident_data.get('certainty')))

    remote_incident_data.update({'calculated_severity': updated_severity_score})

    # Get detection set.
    detection_set = remote_incident_data.get('detection_set', [])

    # Collect the detections if the detection set is not empty.
    detections = []
    if len(detection_set) != 0:
        if vectra_entity_type == 'account':
            search_query = build_search_query_for_detections(vectra_entity_id, 'account', detection_category, detection_type)
            api_response = client.search_detections(state='active', search_query=search_query)
            if (api_response is None) or (api_response.get('count') is None):
                raise VectraException('API issue - Response is empty or invalid')

            if api_response.get('count') == 0:
                demisto.info(f'Found 0 detection(s) for the account with the ID: {vectra_entity_id}.')
            elif api_response.get('count', 0) > 0:
                demisto.info(f"Found {api_response.get('count')} detection(s) for the account with the ID: {vectra_entity_id}.")

                if api_response.get('results') is None:
                    raise VectraException('API issue - Response is empty or invalid')

                # Due to backward search we need to avoid creating incidents of already ingested events
                detections = api_response.get('results', [])
                for detection in detections:
                    detection['url'] = forge_entity_url('detection', detection.get('id'))
        else:
            detections_data = client.list_detections_by_host_id(vectra_entity_id, 'active',
                                                                detection_category, detection_type)
            detections = detections_data.get('results', [])
            for detection in detections:
                detection['url'] = forge_entity_url('detection', detection.get('id'))
            demisto.debug(f'Found {len(detections)} detection(s) for the host with the ID: {vectra_entity_id}.')

    # Add detection details to the entity.
    remote_incident_data.update({'detection_details': detections})

    assignment_details = remote_incident_data.get('assignment', {})

    if not assignment_details:
        past_assignments = remote_incident_data.get('past_assignments', [{}])
        if past_assignments and isinstance(past_assignments, list):
            assignment_details = past_assignments[0]

    if assignment_details:
        if not assignment_details.get('resolved_by'):
            assignment_details['resolved_by'] = {'username': ''}
            assignment_details['outcome'] = {'title': ''}
            assignment_details['date_resolved'] = ''
    else:
        assignment_details = EMPTY_ASSIGNMENT

    remote_incident_data.update({'assignment_details': assignment_details})

    if detections:
        reopen_in_xsoar(new_entries_to_return, entity_id_type)

    notes = remote_incident_data.get('notes', [])

    new_entry_notes = add_notes_to_new_entries(notes, command_last_run_dt)
    new_entries_to_return.extend(new_entry_notes)

    demisto.debug(f'remote_incident_data:{remote_incident_data}')
    return GetRemoteDataResponse(remote_incident_data, new_entries_to_return)


def update_remote_system_command(client: Client) -> str:
    """
    Update a remote system based on changes in the XSOAR incident.

    Args:
        client (Client): An instance of the VectraClient class.

    Returns:
        str: The ID of the updated remote entity.
    """
    args = demisto.args()
    parsed_args = UpdateRemoteSystemArgs(args)
    # Get remote incident ID
    remote_entity_id = parsed_args.remote_incident_id
    demisto.debug(f'Remote Incident ID: {remote_entity_id}')
    delta = parsed_args.delta or {}
    demisto.debug(f'Delta: {delta}')
    # Get XSOAR incident id
    data = parsed_args.data or {}
    xsoar_incident_id = data.get('id', '')
    demisto.debug(f'XSOAR Incident ID: {xsoar_incident_id}')
    new_entries = parsed_args.entries or []
    xsoar_tags: list = delta.get('tags', [])
    mirror_entity_id = remote_entity_id.split('-')[0]
    remote_entity_type = remote_entity_id.split('-')[1]

    # For notes
    if new_entries:
        for entry in new_entries:
            entry_id = entry.get('id')
            demisto.debug(f'Sending the entry with ID: {entry_id} and Type: {entry.get("type")}')
            # Get note content and user
            entry_content = re.sub(r'([^\n])\n', r'\1\n\n', entry.get('contents', ''))
            entry_user = entry.get('user', 'dbot') or 'dbot'

            note_str = (
                f'[Mirrored From XSOAR] XSOAR Incident ID: {xsoar_incident_id}\n\n'
                f'Note: {entry_content}\n\n'
                f'Added By: {entry_user}'
            )
            # API request for adding notes
            client.add_note_request(entity_id=mirror_entity_id, entity_type=remote_entity_type, note=note_str)

    # For tags
    res = client.list_entity_tags_request(entity_id=mirror_entity_id, entity_type=remote_entity_type)
    vectra_tags = res.get('tags')
    if xsoar_tags or (not xsoar_tags and vectra_tags and 'tags' in delta):
        demisto.debug(f'Sending the tags: {xsoar_tags}')
        client.update_entity_tags_request(entity_id=mirror_entity_id, entity_type=remote_entity_type,
                                          tag_list=xsoar_tags)

    # For closing notes if the XSOAR incident is closed.
    send_close_notes(client, data, xsoar_incident_id, remote_entity_id, remote_entity_type,
                     mirror_entity_id, delta, parsed_args)

    return remote_entity_id


def send_close_notes(client: Client, data: dict, xsoar_incident_id: str, remote_entity_id: str,
                     remote_entity_type: str, mirror_entity_id: int, delta: dict,
                     parsed_args: UpdateRemoteSystemArgs):
    """
    Send close notes to Vectra and also remove the assignment when the XSOAR incident is reopened.

    Args:
        data (dict): A dictionary of data from Vectra.
        xsoar_incident_id (str): The ID of the XSOAR incident.
        delta (dict): A dictionary of changes in the XSOAR incident.
    """
    delta_keys = delta.keys()
    closing_user_id = delta.get('closingUserId')
    if 'closingUserId' in delta_keys and parsed_args.incident_changed:
        # For Closing notes
        if parsed_args.inc_status == IncidentStatus.DONE:
            close_notes = data.get('closeNotes', '')
            close_reason = data.get('closeReason', '')
            close_user_id = data.get('closingUserId', '')

            closing_note = (
                f'[Mirrored From XSOAR] XSOAR Incident ID: {xsoar_incident_id}\n\n'
                f'Close Reason: {close_reason}\n\n'
                f'Closed By: {close_user_id}\n\n'
                f'Close Notes: {close_notes}'
            )
            demisto.debug(f'Closing Comment: {closing_note}')
            client.add_note_request(entity_id=mirror_entity_id, entity_type=remote_entity_type, note=closing_note)
        # Remove assignment in Vectra if incident is reopened.
        elif parsed_args.inc_status == IncidentStatus.ACTIVE and closing_user_id == '':
            api_response = {}
            if 'account' in remote_entity_type:
                api_response = client.list_assignments_request(accounts=mirror_entity_id, page_size=1)  # type: ignore
            elif 'host' in remote_entity_type:
                api_response = client.list_assignments_request(hosts=mirror_entity_id, page_size=1)  # type: ignore

            assignment_details = api_response.get('results', [])
            assignment = assignment_details[0] if assignment_details else {}
            if assignment:
                assignment_id = assignment.get('id', '')
                if not assignment.get("resolved_by"):
                    demisto.debug(f'Removing assignment with the ID: {assignment_id} for the incident having'
                                  f' remote entity ID: {remote_entity_id} as incident in XSOAR is reopened.')
                    client.delete_assignment(assignment_id)


def vectra_search_accounts_command(client: Client, **kwargs) -> CommandResults:
    """
    Returns several Account objects matching the search criteria passed as arguments

    - params:
        - client: Vectra Client
        - kwargs: The different possible search query arguments
    - returns
        CommandResults to be used in War Room
    """
    api_response = client.search_accounts(**kwargs)

    count = api_response.get('count')
    if count is None:
        raise VectraException('API issue - Response is empty or invalid')

    accounts_data = []
    if count == 0:
        readable_output = 'Cannot find any Account.'
    else:
        if api_response.get('results') is None:
            raise VectraException('API issue - Response is empty or invalid')

        api_results = api_response.get('results', [])

        for account in api_results:
            accounts_data.append(extract_account_data(account))

        readable_output_keys = ['ID', 'Username', 'Severity', 'URL']
        readable_output = tableToMarkdown(
            name=f'Accounts table (Showing max {MAX_RESULTS} entries)',
            t=accounts_data,
            headers=readable_output_keys,
            url_keys=['URL'],
            date_fields=['AssignedDate', 'LastDetectionTimestamp']
        )

    command_result = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Vectra.Account',
        outputs_key_field='ID',
        outputs=accounts_data,
        raw_response=api_response
    )

    return command_result


def vectra_search_detections_command(client: Client, **kwargs) -> CommandResults:
    """
    Returns several Detection objects matching the search criteria passed as arguments

    - params:
        - client: Vectra Client
        - kwargs: The different possible search query arguments
    - returns
        CommandResults to be used in War Room
    """
    api_response = client.search_detections(**kwargs)

    count = api_response.get('count')
    if count is None:
        raise VectraException('API issue - Response is empty or invalid')

    detections_data = []
    if count == 0:
        readable_output = 'Cannot find any Detection.'
    else:
        if api_response.get('results') is None:
            raise VectraException('API issue - Response is empty or invalid')

        api_results = api_response.get('results', [])

        # Define which fields we want to exclude from the context output
        # detection_context_excluded_fields = []
        # Context Keys
        # context_keys = []

        for detection in api_results:
            detection_data = extract_detection_data(detection)
            # detection_data = {k: detection_data[k] for k in detection_data if k not in detection_context_excluded_fields}
            detections_data.append(detection_data)

        readable_output_keys = ['ID', 'Name', 'Severity', 'LastTimestamp', 'Category', 'URL']
        readable_output = tableToMarkdown(
            name=f'Detections table (Showing max {MAX_RESULTS} entries)',
            t=detections_data,
            headers=readable_output_keys,
            url_keys=['URL'],
            date_fields=['AssignedDate', 'FirstTimestamp', 'LastTimestamp'],
        )

    command_result = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Vectra.Detection',
        outputs_key_field='ID',
        outputs=detections_data,
        raw_response=api_response
    )

    return command_result


def vectra_search_hosts_command(client: Client, **kwargs) -> CommandResults:
    """
    Returns several Host objects matching the search criteria passed as arguments

    - params:
        - client: Vectra Client
        - kwargs: The different possible search query arguments
    - returns
        CommandResults to be used in War Room
    """
    api_response = client.search_hosts(**kwargs)

    count = api_response.get('count')
    if count is None:
        raise VectraException('API issue - Response is empty or invalid')

    hosts_data = []
    if count == 0:
        readable_output = 'Cannot find any Host.'
    else:
        if api_response.get('results') is None:
            raise VectraException('API issue - Response is empty or invalid')

        api_results = api_response.get('results', [])

        for host in api_results:
            hosts_data.append(extract_host_data(host))

        readable_output_keys = ['ID', 'Hostname', 'Severity', 'LastDetectionTimestamp', 'URL']
        readable_output = tableToMarkdown(
            name=f'Hosts table (Showing max {MAX_RESULTS} entries)',
            t=hosts_data,
            headers=readable_output_keys,
            url_keys=['URL'],
            date_fields=['AssignedDate', 'LastDetectionTimestamp'],
        )

    command_result = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Vectra.Host',
        outputs_key_field='ID',
        outputs=hosts_data,
        raw_response=api_response
    )

    return command_result


def vectra_search_assignments_command(client: Client, **kwargs) -> CommandResults:
    """
    Returns several Assignment objects matching the search criteria passed as arguments

    - params:
        - client: Vectra Client
        - kwargs: The different possible search query arguments
    - returns
        CommandResults to be used in War Room
    """
    api_response = client.search_assignments(**kwargs)

    count = api_response.get('count')
    if count is None:
        raise VectraException('API issue - Response is empty or invalid')

    assignments_data = []
    if count == 0:
        readable_output = 'Cannot find any Assignments.'
    else:
        if api_response.get('results') is None:
            raise VectraException('API issue - Response is empty or invalid')

        api_results = api_response.get('results', [])

        for assignment in api_results:
            assignments_data.append(extract_assignment_data(assignment))

        readable_output_keys = ['ID', 'IsResolved', 'AssignedTo', 'AccountID', 'HostID']
        readable_output = tableToMarkdown(
            name=f'Assignments table (Showing max {MAX_RESULTS} entries)',
            t=assignments_data,
            headers=readable_output_keys,
            date_fields=['AssignedDate', 'ResolvedDate']
        )

    command_result = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Vectra.Assignment',
        outputs_key_field='ID',
        outputs=assignments_data,
        raw_response=api_response
    )

    return command_result


def vectra_search_outcomes_command(client: Client, **kwargs) -> CommandResults:
    """
    Returns several Assignment outcome objects matching the search criteria passed as arguments

    - params:
        - client: Vectra Client
        - kwargs: The different possible search query arguments
    - returns
        CommandResults to be used in War Room
    """
    api_response = client.search_outcomes(**kwargs)

    count = api_response.get('count')
    if count is None:
        raise VectraException('API issue - Response is empty or invalid')

    outcomes_data = []
    if count == 0:
        readable_output = 'Cannot find any Outcomes.'
    else:
        if api_response.get('results') is None:
            raise VectraException('API issue - Response is empty or invalid')

        api_results = api_response.get('results', [])

        for outcome in api_results:
            outcomes_data.append(extract_outcome_data(outcome))

        readable_output_keys = ['ID', 'Title', 'Category', 'IsBuiltIn']
        readable_output = tableToMarkdown(
            name=f'Outcomes table (Showing max {MAX_RESULTS} entries)',
            t=outcomes_data,
            headers=readable_output_keys
        )

    command_result = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Vectra.Outcome',
        outputs_key_field='ID',
        outputs=outcomes_data,
        raw_response=api_response
    )

    return command_result


def vectra_search_users_command(client: Client, **kwargs) -> CommandResults:
    """
    Returns several Vectra Users objects matching the search criteria passed as arguments

    - params:
        - client: Vectra Client
        - kwargs: The different possible search query arguments
    - returns
        CommandResults to be used in War Room
    """
    api_response = client.search_users(**kwargs)

    count = api_response.get('count')
    if count is None:
        raise VectraException('API issue - Response is empty or invalid')

    users_data = []
    if count == 0:
        readable_output = 'Cannot find any Vectra Users.'
    else:
        if api_response.get('results') is None:
            raise VectraException('API issue - Response is empty or invalid')

        api_results = api_response.get('results', [])

        for assignment in api_results:
            users_data.append(extract_user_data(assignment))

        readable_output_keys = ['ID', 'Role', 'Type', 'Username', 'LastLoginDate']
        readable_output = tableToMarkdown(
            name=f'Vectra Users table (Showing max {MAX_RESULTS} entries)',
            t=users_data,
            headers=readable_output_keys,
            date_fields=['LastLoginDate']
        )

    command_result = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Vectra.User',
        outputs_key_field='ID',
        outputs=users_data,
        raw_response=api_response
    )

    return command_result


def vectra_get_account_by_id_command(client: Client, id: str) -> CommandResults:
    """
    Gets Account details using its ID

    - params:
        - client: Vectra Client
        - id: The Account ID
    - returns
        CommandResults to be used in War Room
    """
    # Check args
    if not id:
        raise VectraException('"id" not specified')

    search_query: str = f"account.id:{id}"

    api_response = client.search_accounts(search_query_only=search_query)

    count = api_response.get('count')
    if count is None:
        raise VectraException('API issue - Response is empty or invalid')
    if count > 1:
        raise VectraException('Multiple Accounts found')

    account_data = None
    if count == 0:
        readable_output = f'Cannot find Account with ID "{id}".'
    else:
        if api_response.get('results') is None:
            raise VectraException('API issue - Response is empty or invalid')

        api_results = api_response.get('results', [])
        account_data = extract_account_data(api_results[0])

        readable_output = tableToMarkdown(
            name=f'Account ID {id} details table',
            t=account_data,
            url_keys=['URL'],
            date_fields=['LastDetectionTimestamp']
        )

    command_result = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Vectra.Account',
        outputs_key_field='ID',
        outputs=account_data,
        raw_response=api_response
    )

    return command_result


def vectra_get_detection_by_id_command(client: Client, id: str) -> CommandResults:
    """
    Gets Detection details using its ID

    - params:
        - client: Vectra Client
        - id: The Detection ID
    - returns
        CommandResults to be used in War Room
    """
    # Check args
    if not id:
        raise VectraException('"id" not specified')

    search_query: str = f"detection.id:{id}"

    api_response = client.search_detections(search_query_only=search_query)

    count = api_response.get('count')
    if count is None:
        raise VectraException('API issue - Response is empty or invalid')
    if count > 1:
        raise VectraException('Multiple Detections found')

    detection_data = None
    if count == 0:
        readable_output = f'Cannot find Detection with ID "{id}".'
    else:
        if api_response.get('results') is None:
            raise VectraException('API issue - Response is empty or invalid')

        api_results = api_response.get('results', [])
        detection_data = extract_detection_data(api_results[0])

        readable_output = tableToMarkdown(
            name=f"Detection ID '{id}' details table",
            t=detection_data,
            url_keys=['URL'],
            date_fields=['FirstTimestamp', 'LastTimestamp'],
        )

    command_result = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Vectra.Detection',
        outputs_key_field='ID',
        outputs=detection_data,
        raw_response=api_response
    )

    return command_result


def vectra_get_host_by_id_command(client: Client, id: str) -> CommandResults:
    """
    Gets Host details using its ID

    - params:
        - client: Vectra Client
        - id: The Host ID
    - returns
        CommandResults to be used in War Room
    """
    # Check args
    if not id:
        raise VectraException('"id" not specified')

    search_query: str = f"host.id:{id}"

    api_response = client.search_hosts(search_query_only=search_query)

    count = api_response.get('count')
    if count is None:
        raise VectraException('API issue - Response is empty or invalid')
    if count > 1:
        raise VectraException('Multiple Hosts found')

    host_data = None
    if count == 0:
        readable_output = f'Cannot find Host with ID "{id}".'
    else:
        if api_response.get('results') is None:
            raise VectraException('API issue - Response is empty or invalid')

        api_results = api_response.get('results', [])
        host_data = extract_host_data(api_results[0])

        readable_output = tableToMarkdown(
            name=f'Host ID {id} details table',
            t=host_data,
            url_keys=['URL'],
            date_fields=['LastDetectionTimestamp'],
        )

    command_result = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Vectra.Host',
        outputs_key_field='ID',
        outputs=host_data,
        raw_response=api_response
    )

    return command_result


def get_detection_pcap_file_command(client: Client, id: str):
    """
    Downloads a PCAP fileassociated to a detection

    - params:
        - client: Vectra Client
        - id: The Detection ID
    - returns:
        A commandResult to use in the War Room
    """
    if not id:
        raise VectraException('"id" not specified')

    api_response = client.get_pcap_by_detection_id(id=id)

    # 404 API error will be raised by the Client class
    filename = f'detection-{id}.pcap'
    file_content = api_response.content
    pcap_file = fileResult(filename, file_content)

    return pcap_file


def mark_detection_as_fixed_command(client: Client, id: str, fixed: str) -> CommandResults:
    """
    Toggles a detection status as : fixed / Not fixed

    - params:
        - client: Vectra Client
        - id: The Detection ID
        - fixed: The Detection future state
    """

    if (id is None) or (id == ''):
        raise VectraException('"id" not specified')
    fixed_as_bool = str2bool(fixed)
    if fixed_as_bool is None:
        raise VectraException('"fixed" not specified')

    api_response = client.markasfixed_by_detection_id(id=id, fixed=fixed_as_bool)

    # 404 API error will be raised by the Client class
    command_result = CommandResults(
        readable_output=f'Detection "{id}" successfully {"marked" if fixed_as_bool else "unmarked"} as fixed.',
        raw_response=api_response
    )

    return command_result


def vectra_get_assignment_by_id_command(client: Client, id: str) -> CommandResults:
    """
    GetsAssignment details using its ID

    - params:
        - client: Vectra Client
        - id: The Assignment ID
    - returns
        CommandResults to be used in War Room
    """
    # Check args
    if not id:
        raise VectraException('"id" not specified')

    api_response = client.search_assignments(id=id)

    assignment_data = None
    # Assignment doesn't follow classic describe behavior
    obtained_assignment = api_response.get('assignment')
    if obtained_assignment is None:
        readable_output = f'Cannot find Assignment with ID "{id}".'
    else:
        assignment_data = extract_assignment_data(obtained_assignment)

        readable_output = tableToMarkdown(
            name=f'Assignment ID {id} details table',
            t=assignment_data,
            date_fields=['AssignedDate', 'ResolvedDate']
        )

    command_result = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Vectra.Assignment',
        outputs_key_field='ID',
        outputs=assignment_data,
        raw_response=api_response
    )

    return command_result


def vectra_assignment_assign_command(client: Client, assignee_id: str = None,  # type: ignore
                                     account_id: str = None, host_id: str = None,  # type: ignore
                                     assignment_id: str = None) -> CommandResults:  # type: ignore
    """
    Assign or reassign an Account/Host

    - params:
        - client: Vectra Client
        - assignee_id: The Vectra User ID who want to assign to
        - account_id: The Account ID
        - host_id: The Host ID
        - assignment_id: The existing assignment ID associated with the targeted Entity, if there is any
    - returns
        CommandResults to be used in War Room
    """
    # Check args
    if not assignee_id:
        raise VectraException('"assignee_id" not specified')
    if ((assignment_id is None) and (account_id is None) and (
            host_id is None)) or (account_id and host_id) or (assignment_id and (account_id or host_id)):
        raise VectraException('You must specify one of "assignment_id", "account_id" or "host_id"')
    if assignment_id is None:
        api_response = client.update_assignment(assignee_id=assignee_id, account_id=account_id, host_id=host_id)
    else:
        api_response = client.update_assignment(assignee_id=assignee_id, assignment_id=assignment_id)

    # 40x API error will be raised by the Client class
    obtained_assignment = api_response.get('assignment')
    assignment_data = extract_assignment_data(obtained_assignment)

    readable_output = tableToMarkdown(
        name='Assignment details table',
        t=assignment_data
    )

    command_result = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Vectra.Assignment',
        outputs_key_field='ID',
        outputs=assignment_data,
        raw_response=api_response
    )

    return command_result


def vectra_assignment_resolve_command(client: Client, assignment_id: str = None, outcome_id: str = None,  # type: ignore
                                      note: str = None, detections_filter: str = None,  # type: ignore
                                      filter_rule_name: str = None, detections_list: str = None):  # type: ignore
    """
    Resolve an existing assignment

    - params:
        - client: Vectra Client
        - assignment_id: Assignment ID
        - outcome_id: The Outcome ID
        - detections_filter: Filter mode to use ('None' or 'Filter Rule') [Default: None]
        - filter_rule_name: Filter rule name (when detections_filter equals 'Filter Rule')
        - detections_list: List of the Detections to filter
    - returns
        CommandResults to be used in War Room
    """
    # Check args
    if not assignment_id:
        raise VectraException('"assignment_id" not specified')
    if not outcome_id:
        raise VectraException('"outcome_id" not specified')

    if detections_filter == 'Filter Rule':
        if not filter_rule_name:
            raise VectraException('"filter_rule_name" not specified')
        if not detections_list:
            raise VectraException('"detections_list" not specified')
        api_response = client.resolve_assignment(assignment_id=assignment_id, outcome_id=outcome_id, note=note,
                                                 rule_name=filter_rule_name, detections_list=detections_list)
    else:
        api_response = client.resolve_assignment(assignment_id=assignment_id, outcome_id=outcome_id, note=note)

    # 40x API error will be raised by the Client class
    obtained_assignment = api_response.get('assignment')
    assignment_data = extract_assignment_data(obtained_assignment)

    readable_output = tableToMarkdown(
        name='Assignment details table',
        t=assignment_data
    )

    command_result = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Vectra.Assignment',
        outputs_key_field='ID',
        outputs=assignment_data,
        raw_response=api_response
    )

    return command_result


def vectra_get_outcome_by_id_command(client: Client, id: str) -> CommandResults:
    """
    Gets Outcome details using its ID

    - params:
        - client: Vectra Client
        - id: The Outcome ID
    - returns
        CommandResults to be used in War Room
    """
    # Check args
    if not id:
        raise VectraException('"id" not specified')

    api_response = client.search_outcomes(id=id)

    outcome_data = None
    obtained_id = api_response.get('id')
    if obtained_id is None:
        readable_output = f'Cannot find Outcome with ID "{id}".'
    else:
        outcome_data = extract_outcome_data(api_response)

        readable_output = tableToMarkdown(
            name=f'Outcome ID {id} details table',
            t=outcome_data
        )

    command_result = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Vectra.Outcome',
        outputs_key_field='ID',
        outputs=outcome_data,
        raw_response=api_response
    )

    return command_result


def vectra_outcome_create_command(client: Client, category: str, title: str) -> CommandResults:
    """
    Creates a new Outcome

    - params:
        - client: Vectra Client
        - category: The Outcome category (one of "BTP,MTP,FP")
        - title: A custom title for this new outcome
    - returns
        CommandResults to be used in War Room
    """
    # Check args
    if not category:
        raise VectraException('"category" not specified')
    if not title:
        raise VectraException('"title" not specified')

    api_response = client.create_outcome(category=category, title=title)

    # 40x API error will be raised by the Client class
    outcome_data = extract_outcome_data(api_response)

    readable_output = tableToMarkdown(
        name='Newly created Outcome details table',
        t=outcome_data
    )

    command_result = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Vectra.Outcome',
        outputs_key_field='ID',
        outputs=outcome_data,
        raw_response=api_response
    )

    return command_result


def vectra_get_user_by_id_command(client: Client, id: str) -> CommandResults:
    """
    Gets Vectra User details using its ID

    - params:
        - client: Vectra Client
        - id: The User ID
    - returns
        CommandResults to be used in War Room
    """
    # Check args
    if not id:
        raise VectraException('"id" not specified')

    api_response = client.search_users(id=id)

    user_data = None
    obtained_id = api_response.get('id')
    if obtained_id is None:
        readable_output = f'Cannot find Vectra User with ID "{id}".'
    else:
        user_data = extract_user_data(api_response)

        readable_output = tableToMarkdown(
            name=f'Vectra User ID {id} details table',
            t=user_data,
            date_fields=['LastLoginDate']
        )

    command_result = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Vectra.User',
        outputs_key_field='ID',
        outputs=user_data,
        raw_response=api_response
    )

    return command_result


def add_tags_command(client: Client, type: str, id: str, tags: str) -> CommandResults:
    """
    Adds several tags to an account/host/detection

    - params:
        - client: Vectra Client
        - type: The object to work with ("account", "host" or "detection")
        - id: The id ID the account/host/detection
        - tags: The tags list (comma separated)
    """

    if not type:
        raise VectraException('"type" not specified')
    if not id:
        raise VectraException('"id" not specified')
    if not tags:
        raise VectraException('"tags" not specified')

    api_response = client.add_tags(id=id, type=type, tags=tags.split(','))

    # 404 API error will be raised by the Client class
    command_result = CommandResults(
        readable_output=f'Tags "{tags}" successfully added.',
        raw_response=api_response
    )

    return command_result


def del_tags_command(client: Client, type: str, id: str, tags: str) -> CommandResults:
    """
    Removes several tags from an account/host/detection

    - params:
        - client: Vectra Client
        - type: The object to work with ("account", "host" or "detection")
        - id: The ID of the account/host/detection
        - tags: The tags list (comma separated)
    """

    if not type:
        raise VectraException('"type" not specified')
    if not id:
        raise VectraException('"id" not specified')
    if not tags:
        raise VectraException('"tags" not specified')

    api_response = client.del_tags(id=id, type=type, tags=tags.split(','))

    # 404 API error will be raised by the Client class
    command_result = CommandResults(
        readable_output=f'Tags "{tags}" successfully deleted.',
        raw_response=api_response
    )

    return command_result


def tag_list_command(client: Client, entity_type: str, args: dict) -> CommandResults:
    """
    List all tags of specific Account, Host or Detection.

    Args:
        client : An instance of the Client class.
        entity_type: The type Account, Host or Detection
        args: dictionary of arguments.
    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    entity_id = arg_to_number(args.get('id'), arg_name='id', required=True)

    validate_positive_integer_arg(entity_id, arg_name='id', required=True)

    existing_tag_res = client.list_tags_request(entity_id=entity_id, entity_type=entity_type)  # type: ignore
    raw_res = deepcopy(existing_tag_res)
    existing_tag_res_status = existing_tag_res.get('status', '')
    if not existing_tag_res_status or not isinstance(existing_tag_res_status,
                                                     str) or existing_tag_res_status.lower() != 'success':
        message = 'Something went wrong.'
        if existing_tag_res.get('message'):
            message += f' Message: {existing_tag_res.get("message")}.'
        raise VectraException(message)
    tags_resp = existing_tag_res.get('tags', [])

    human_readable = f'##### No tags were found for the given {entity_type} ID.'
    if tags_resp and isinstance(tags_resp, list):
        tags_resp = [tag.strip() for tag in tags_resp if isinstance(tag, str) and tag.strip()]
        if tags_resp:
            tags_resp = f'**{"**, **".join(tags_resp)}**'
            human_readable = f'##### List of tags: {tags_resp}'

    existing_tag_res['ID'] = entity_id
    existing_tag_res['Tags'] = existing_tag_res['tags']
    del existing_tag_res['status']
    del existing_tag_res['tags']
    del existing_tag_res['tag_id']
    return CommandResults(outputs_prefix=f'Vectra.{entity_type.capitalize()}',
                          outputs=createContext(remove_empty_elements(existing_tag_res)),
                          readable_output=human_readable, raw_response=raw_res,
                          outputs_key_field='ID')


def note_add_command(client: Client, entity_type: str, args: dict) -> CommandResults:
    """
    Adds a note to an account/host/detection in Vectra API.

    Args:
        client : An instance of the Client class.
        entity_type (str): The type of the object (account, host or detection).

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    entity_id = arg_to_number(args.get(f'{entity_type}_id'), arg_name=f'{entity_type}_id', required=True)

    note = args.get('note')

    validate_note_add_command_args(entity_id=entity_id, note=note, entity_type=entity_type)  # type: ignore
    # Call Vectra API to add note
    notes = client.add_note_request(entity_id=entity_id, entity_type=entity_type, note=note)  # type: ignore

    notes_raw_response = deepcopy(notes)
    output_prefix = OUTPUT_PREFIXES[f'{entity_type.upper()}_NOTES']
    if notes:
        notes['note_id'] = notes.get('id')
        del notes['id']
        notes.update({f'{entity_type}_id': entity_id})

    human_readable = f'##### The note has been successfully added to the {entity_type}.'
    human_readable += f'\nReturned Note ID: **{notes["note_id"]}**'

    return CommandResults(outputs_prefix=output_prefix,
                          outputs=createContext(remove_empty_elements(notes)),
                          readable_output=human_readable,
                          raw_response=notes_raw_response,
                          outputs_key_field=NOTE_OUTPUT_KEY_FIELD)


def note_update_command(client: Client, entity_type: str, args: dict) -> CommandResults:
    """
    Updates a note to an Account/Host/Detection in Vectra API.

    Args:
        client: An instance of the Client class.
        entity_type (str): The type of the object (account, host or detection).

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    entity_id = arg_to_number(args.get(f'{entity_type}_id'), arg_name=f'{entity_type}_id', required=True)
    note_id = arg_to_number(args.get('note_id'), arg_name='note_id', required=True)
    note = args.get('note')

    validate_note_update_command_args(entity_id=entity_id, note_id=note_id, note=note, entity_type=entity_type)  # type: ignore

    # Call Vectra API to update note
    notes = client.update_note_request(entity_id=entity_id, entity_type=entity_type,  # type: ignore
                                       note=note, note_id=note_id)  # type: ignore
    notes_raw_response = deepcopy(notes)
    output_prefix = OUTPUT_PREFIXES[f'{entity_type.upper()}_NOTES']
    if notes:
        notes['note_id'] = notes['id']
        del notes['id']
        notes.update({f'{entity_type}_id': entity_id})

    human_readable = f'##### The note has been successfully updated in the {entity_type}.'

    return CommandResults(outputs_prefix=output_prefix,
                          outputs=createContext(remove_empty_elements(notes)),
                          readable_output=human_readable,
                          raw_response=notes_raw_response,
                          outputs_key_field=NOTE_OUTPUT_KEY_FIELD)


def note_remove_command(client: Client, entity_type: str, args: dict) -> CommandResults:
    """
    Removes a note from an Account/Host/Detection in Vectra API.

    Args:
        client (VectraClient): An instance of the VectraClient class.

    Returns:
        CommandResults: The command results containing the outputs, readable output.
    """
    entity_id = arg_to_number(args.get(f'{entity_type}_id'), arg_name=f'{entity_type}_id', required=True)
    note_id = arg_to_number(args.get('note_id'), arg_name='note_id', required=True)

    validate_note_remove_command_args(entity_id=entity_id, note_id=note_id, entity_type=entity_type)

    # Call Vectra API to remove note
    response = client.remove_note_request(entity_id=entity_id, entity_type=entity_type, note_id=note_id)  # type: ignore

    if response.status_code == 204:
        human_readable = f'##### The note has been successfully removed from the {entity_type}.'
    else:
        human_readable = f'Something went wrong. API Response: {response.text}'

    return CommandResults(readable_output=human_readable, raw_response=response.text)


def note_list_command(client: Client, entity_type: str, args: dict) -> CommandResults:  # type: ignore
    """
    List notes of specific Account, Host or Detection.

    Args:
        client: An instance of the Client class.
        entity_type: The type Account, Host or Detection
    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    entity_id = arg_to_number(args.get(f'{entity_type}_id'), arg_name=f'{entity_type}_id', required=True)

    validate_positive_integer_arg(entity_id, arg_name=f'{entity_type}_id', required=True)

    notes = client.list_note_request(entity_id=entity_id, entity_type=entity_type)  # type: ignore
    notes_raw_response = deepcopy(notes)
    notes = remove_empty_elements(notes)
    if notes:
        human_readable = get_list_notes_command_hr(notes, entity_id, entity_type)  # type: ignore

        context = [createContext(note) for note in notes]

        output_prefix = OUTPUT_PREFIXES[f'{entity_type.upper()}_NOTES']  # type: ignore

        return CommandResults(outputs_prefix=output_prefix, outputs=context, readable_output=human_readable,
                              raw_response=notes_raw_response, outputs_key_field=NOTE_OUTPUT_KEY_FIELD)
    return CommandResults(outputs={}, raw_response=notes_raw_response,
                          readable_output=f"Couldn't find any notes for provided {entity_type}.")


def markall_detections_asfixed_command(client: Client, type: str, account_id: str = None,  # type: ignore
                                       host_id: str = None) -> CommandResults:  # type: ignore
    """
    Marks all active detections of an account/host as fixed.

    - param:
        - client: Vectra Client
        - type: The object to work with ("account" or "host")

    - return:
        CommandResults to be used in War Room.
    """
    if type == 'account':
        validate_positive_integer_arg(account_id, 'account_id', True)
        entity_data = client.get_account_by_account_id(account_id=str(account_id))
    else:
        validate_positive_integer_arg(host_id, 'host_id', True)
        entity_data = client.get_host_by_host_id(host_id=str(host_id))

    detections_ids = [str(detection.get('detection_id')) for detection in entity_data.get('detection_summaries')
                      if detection.get('state') == 'active']

    if detections_ids:
        api_response = client.markasfixed_by_detection_ids(ids_list=detections_ids)

        # 404 API error will be raised by the Client class
        command_result = CommandResults(
            readable_output=f'The active detections of the provided {type} have been successfully marked as fixed.',
            raw_response=api_response
        )
    else:
        command_result = CommandResults(
            readable_output='There are no active detections present.',
            raw_response={}
        )

    return command_result


def vectra_group_list_command(client: Client, args: dict[str, Any]):
    """
    Retrieves a list of groups.

    Args:
        client (Client): An instance of the Client class.
        args (Dict[str, Any]): The command arguments provided by the user.

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    validate_group_list_command_args(args)

    # Get function arguments
    group_type = args.get('group_type', '')
    if group_type:
        group_type = group_type.lower()
    importance = args.get('importance', '')
    if importance:
        importance = importance.lower()
    account_names = argToList(args.get('account_names', ''))
    domains = argToList(args.get('domains', ''))
    host_ids = argToList(args.get('host_ids', ''))
    host_names = argToList(args.get('host_names', ''))
    ips = argToList(args.get('ips', ''))
    description = args.get('description', '')
    last_modified_timestamp = arg_to_datetime(args.get('last_modified_timestamp'), arg_name='last_modified_timestamp')
    last_modified_by = args.get('last_modified_by', '')
    group_name = args.get('group_name', '')

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
                          raw_response=groups, outputs_key_field='group_id')


def vectra_group_unassign_command(client: Client, args: dict[str, Any]):
    """
    Unassign members in Group.

    Args:
        client (Client): An instance of the Client class.
        args (Dict[str, Any]): The command arguments.

    Returns:
        CommandResults: The command results.
    """
    validate_group_assign_and_unassign_command_args(args)
    group_id = args.get('group_id')
    members = args.get('members')

    # Call to get group details
    group = client.get_group_request(group_id=group_id)  # type: ignore
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
        return CommandResults(readable_output=f"##### Member(s) {', '.join(members_list)} do not exist in the group.")
    # Call Vectra API to unassign members in group
    res = client.update_group_members_request(group_id=group_id, members=updated_members)  # type: ignore
    updated_group = remove_empty_elements(res)

    human_readable = get_group_unassign_and_assign_command_hr(group=updated_group, changed_members=removed_members,
                                                              assign_flag=False)

    return CommandResults(outputs_prefix='Vectra.Group', outputs=createContext(updated_group),
                          readable_output=human_readable, raw_response=updated_group, outputs_key_field='group_id')


def vectra_group_assign_command(client: Client, args: dict[str, Any]):
    """
    Assign members in Group.

    Args:
        client (Client): An instance of the Client class.
        args (Dict[str, Any]): The command arguments.

    Returns:
        CommandResults: The command results.
    """
    validate_group_assign_and_unassign_command_args(args)
    group_id = args.get('group_id')
    members = args.get('members')

    # Call to get group details
    group = client.get_group_request(group_id=group_id)  # type: ignore
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
        return CommandResults(readable_output=f"##### Member(s) {', '.join(members_list)} are already in the group.")
    # Call Vectra API to assign members in group
    res = client.update_group_members_request(group_id=group_id, members=updated_members)  # type: ignore
    updated_group = remove_empty_elements(res)

    human_readable = get_group_unassign_and_assign_command_hr(group=updated_group, changed_members=added_members,
                                                              assign_flag=True)

    return CommandResults(outputs_prefix='Vectra.Group', outputs=createContext(updated_group),
                          readable_output=human_readable, raw_response=updated_group, outputs_key_field='group_id')


# ####           #### #
# ## MAIN FUNCTION ## #


def main() -> None:  # pragma: no cover
    # Set some settings as global (to use them inside some functions)
    global global_UI_URL

    integration_params = remove_space_from_args(demisto.params())
    remove_nulls_from_dictionary(integration_params)
    command = demisto.command()
    kwargs = remove_space_from_args(demisto.args())
    remove_nulls_from_dictionary(kwargs)

    server_fqdn: str | None = integration_params.get('server_fqdn')
    if not server_fqdn:  # Should be impossible thx to UI required settings control
        raise DemistoException("Missing integration setting : 'Server FQDN'")

    credentials: dict | None = integration_params.get('credentials')
    if not credentials:
        raise DemistoException("Missing integration setting : 'Credentials' or 'API token'")

    api_token: str | None = credentials.get('password')
    if (api_token is None) or (api_token == ''):
        raise DemistoException("Missing integration setting : 'Credentials password' or 'API token'")

    # Setting default settings for fetch mode
    if integration_params.get('isFetch'):
        if integration_params.get('first_fetch') == '':
            integration_params['first_fetch'] = DEFAULT_FIRST_FETCH
            demisto.debug(f"First fetch timestamp not set, setting to default '{DEFAULT_FIRST_FETCH}'")
        if integration_params.get('fetch_entity_types') == []:
            integration_params['fetch_entity_types'] = DEFAULT_FETCH_ENTITY_TYPES
            demisto.debug(f"Fetch entity types not set, setting to default '{DEFAULT_FETCH_ENTITY_TYPES}'")
        if integration_params.get('max_fetch') == '':
            integration_params['max_fetch'] = DEFAULT_MAX_FETCH
            demisto.debug(f"Max incidents per fetch not set, setting to default '{DEFAULT_MAX_FETCH}'")

    verify_certificate: bool = not integration_params.get('insecure', False)
    use_proxy: bool = integration_params.get('use_proxy', False)

    global_UI_URL = urljoin('https://', server_fqdn)
    api_base_url = urljoin('https://', urljoin(server_fqdn, API_VERSION_URL))

    demisto.info(f'Command being called is {command}')
    try:
        headers: dict = {"User-Agent": USER_AGENT,
                         "Authorization": f"token {api_token}"}

        # As the Client class inherits from BaseClient, SSL verification and system proxy are handled out of the box by it
        # Passing ``verify_certificate`` and ``proxy``to the Client constructor
        client = Client(
            proxy=use_proxy,
            verify=verify_certificate,
            headers=headers,
            base_url=api_base_url
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            results = test_module(client, integration_params)
            return_results(results)

        elif command == 'fetch-incidents':
            # Get new incidents to create if any from Vectra API
            next_run, incidents = fetch_incidents(client, integration_params)

            # Add incidents in the SOAR platform
            demisto.incidents(incidents)

            if next_run:
                demisto.info(f"Setting last run to : {next_run}")
                demisto.setLastRun(next_run)
            demisto.info("fetch-incidents action done.")

        elif command == 'get-modified-remote-data':
            return_results(get_modified_remote_data_command(client))  # type: ignore
        elif command == 'get-remote-data':
            return_results(get_remote_data_command(client, integration_params))  # type: ignore
        elif command == 'update-remote-system':
            return_results(update_remote_system_command(client))

        elif command == 'vectra-search-accounts':
            return_results(vectra_search_accounts_command(client, **kwargs))
        elif command == 'vectra-search-hosts':
            return_results(vectra_search_hosts_command(client, **kwargs))
        elif command == 'vectra-search-detections':
            return_results(vectra_search_detections_command(client, **kwargs))

        elif command == 'vectra-search-assignments':
            return_results(vectra_search_assignments_command(client, **kwargs))
        elif command == 'vectra-search-outcomes':
            return_results(vectra_search_outcomes_command(client, **kwargs))
        elif command == 'vectra-search-users':
            return_results(vectra_search_users_command(client, **kwargs))

        # ## Accounts centric commands
        elif command == 'vectra-account-describe':
            return_results(vectra_get_account_by_id_command(client, **kwargs))
        elif command == 'vectra-account-add-tags':
            return_results(add_tags_command(client, type="account", **kwargs))
        elif command == 'vectra-account-del-tags':
            return_results(del_tags_command(client, type="account", **kwargs))
        elif command == 'vectra-account-tag-list':
            return_results(tag_list_command(client, entity_type="account", args=kwargs))
        elif command == 'vectra-account-note-add':
            return_results(note_add_command(client, entity_type="account", args=kwargs))
        elif command == 'vectra-account-note-update':
            return_results(note_update_command(client, entity_type="account", args=kwargs))
        elif command == 'vectra-account-note-remove':
            return_results(note_remove_command(client, entity_type="account", args=kwargs))
        elif command == 'vectra-account-note-list':
            return_results(note_list_command(client, entity_type="account", args=kwargs))
        elif command == 'vectra-account-markall-detections-asfixed':
            return_results(markall_detections_asfixed_command(client, type='account', **kwargs))

        # ## Hosts centric commands
        elif command == 'vectra-host-describe':
            return_results(vectra_get_host_by_id_command(client, **kwargs))
        elif command == 'vectra-host-add-tags':
            return_results(add_tags_command(client, type="host", **kwargs))
        elif command == 'vectra-host-del-tags':
            return_results(del_tags_command(client, type="host", **kwargs))
        elif command == 'vectra-host-tag-list':
            return_results(tag_list_command(client, entity_type="host", args=kwargs))
        elif command == 'vectra-host-note-add':
            return_results(note_add_command(client, entity_type="host", args=kwargs))
        elif command == 'vectra-host-note-update':
            return_results(note_update_command(client, entity_type="host", args=kwargs))
        elif command == 'vectra-host-note-remove':
            return_results(note_remove_command(client, entity_type="host", args=kwargs))
        elif command == 'vectra-host-note-list':
            return_results(note_list_command(client, entity_type="host", args=kwargs))
        elif command == 'vectra-host-markall-detections-asfixed':
            return_results(markall_detections_asfixed_command(client, type='host', **kwargs))

        # ## Detections centric commands
        elif command == 'vectra-detection-describe':
            return_results(vectra_get_detection_by_id_command(client, **kwargs))
        elif command == 'vectra-detection-get-pcap':
            return_results(get_detection_pcap_file_command(client, **kwargs))
        elif command == 'vectra-detection-markasfixed':
            return_results(mark_detection_as_fixed_command(client, **kwargs))
        elif command == 'vectra-detection-add-tags':
            return_results(add_tags_command(client, type="detection", **kwargs))
        elif command == 'vectra-detection-del-tags':
            return_results(del_tags_command(client, type="detection", **kwargs))
        elif command == 'vectra-detection-tag-list':
            return_results(tag_list_command(client, entity_type="detection", args=kwargs))
        elif command == 'vectra-detection-note-add':
            return_results(note_add_command(client, entity_type="detection", args=kwargs))
        elif command == 'vectra-detection-note-update':
            return_results(note_update_command(client, entity_type="detection", args=kwargs))
        elif command == 'vectra-detection-note-remove':
            return_results(note_remove_command(client, entity_type="detection", args=kwargs))
        elif command == 'vectra-detection-note-list':
            return_results(note_list_command(client, entity_type="detection", args=kwargs))

        # ## Assignments / Assignment outcomes commands
        elif command == 'vectra-assignment-describe':
            return_results(vectra_get_assignment_by_id_command(client, **kwargs))
        elif command == 'vectra-assignment-assign':
            return_results(vectra_assignment_assign_command(client, **kwargs))
        elif command == 'vectra-assignment-resolve':
            return_results(vectra_assignment_resolve_command(client, **kwargs))
        elif command == 'vectra-outcome-describe':
            return_results(vectra_get_outcome_by_id_command(client, **kwargs))
        elif command == 'vectra-outcome-create':
            return_results(vectra_outcome_create_command(client, **kwargs))
        elif command == 'vectra-user-describe':
            return_results(vectra_get_user_by_id_command(client, **kwargs))

        # ## Groups / Groups outcomes commands
        elif command == 'vectra-group-list':
            return_results(vectra_group_list_command(client, kwargs))
        elif command == 'vectra-group-assign':
            return_results(vectra_group_assign_command(client, kwargs))
        elif command == 'vectra-group-unassign':
            return_results(vectra_group_unassign_command(client, kwargs))

        else:
            raise NotImplementedError

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


# ####         #### #
# ## ENTRY POINT ## #
if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()

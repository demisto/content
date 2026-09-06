import copy
import urllib3
from collections.abc import Callable
from datetime import datetime
from requests.models import Response
from typing import Any

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
STATUS_LIST_TO_RETRY = (429, *(status_code for status_code in requests.status_codes._codes if status_code >= 500))  # type: ignore
OK_CODES = (200, 201, 204, 401)
MAX_RETRIES = 4
BACKOFF_FACTOR = 7.5
FIRST_FETCH = "1 hour"
MAX_FETCH = 200
PACK_VERSION = get_pack_version() or "1.0.0"
USER_AGENT = f"Vectra-RUX-XSOAR-{PACK_VERSION}"
UTM_PIVOT = f"?pivot=Vectra-RUX-XSOAR-{PACK_VERSION}"
DEFAULT_ONLY_PRIORITIZED_DETECTIONS = False
DEFAULT_ENTITY_TYPES = "Host,Account"
VALID_ENTITY_TYPES = ("Host", "Account")
VALID_DETECTION_STATUS = ("open", "acknowledged", "escalated", "paused", "closed", "expired")
DEFAULT_FETCH_DETECTION_STATUS = ("open", "acknowledged", "escalated", "paused")
VALID_CLOSE_REASON = ("benign", "remediated")
MIRROR_DIRECTION = {
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}
MAX_PAGE = 1
MAX_PAGE_SIZE = 50
ENTITY_AND_DETECTION_MAX_PAGE_SIZE = 5000
MAX_URGENCY_SCORE = 100
MIN_URGENCY_SCORE = 0
VALID_ENTITY_TYPE = ["account", "host"]
VALID_GROUP_TYPE = ["account", "host", "ip", "domain"]
VALID_IMPORTANCE_VALUE = ["high", "medium", "low", "never_prioritize"]
VALID_ENTITY_STATE = ["active", "inactive"]
VALID_BOOL_VALUES = ("y", "yes", "t", "true", "on", "1", "n", "no", "f", "false", "off", "0")
MAX_MIRRORING_LIMIT = 5000
MAX_OUTGOING_NOTE_LIMIT = 8000

DETECTION_CATEGORY_TO_ARG = {
    "Command & Control": "command",
    "Botnet": "botnet",
    "Reconnaissance": "reconnaissance",
    "Lateral Movement": "lateral",
    "Exfiltration": "exfiltration",
    "Info": "info",
}
ENTITY_IMPORTANCE = {"low": 0, "medium": 1, "high": 2}
ENTITY_IMPORTANCE_LABEL = {0: "Low", 1: "Medium", 2: "High"}
SEVERITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}
MIRROR_DIRECTION = {"Incoming": "In", "Outgoing": "Out", "Incoming And Outgoing": "Both"}
TAGS_REGEX = re.compile(r"^[\w:._ -]+$", re.U)
DEFAULT_DETECTION_CLOSE_REASON = "Remediated"
DEFAULT_DETECTION_STATUS_FOR_REOPEN = "Escalated"
DEFAULT_ONLY_ESCALATED_DETECTIONS = False
USER_ROLE_MAPPING = {
    "Admin": "admins",
    "Auditor": "auditor",
    "Global Analyst": "global_analyst",
    "Read-Only": "read_only",
    "Restricted Admin": "restricted_admins",
    "Security Analyst": "security_analyst",
    "Setting Admin": "setting_admins",
    "Super Admin": "super_admins",
}

ENDPOINTS = {
    "AUTH_ENDPOINT": "/oauth2/token",
    "EVENTS_DETECTIONS_ENDPOINT": "/api/v3.5/events/detections",
    "DETECTION_ENDPOINT": "/api/v3.5/detections",
    "ENTITY_ENDPOINT": "/api/v3.5/entities",
    "ENTITY_ENDPOINT_v34": "/api/v3.4/entities",
    "CLOSE_DETECTIONS_ENDPOINT": "/api/v3.5/detections/close",
    "ADD_NOTE_ENDPOINT": "/api/v3.5/detections/{}/notes",
    "LIST_TAGS_ENDPOINT": "/api/v3.5/tagging/detection/{}",
    "OPEN_DETECTIONS_ENDPOINT": "/api/v3.5/detections/open",
    "USER_ENDPOINT": "/api/v3.5/users",
    "GROUP_ENDPOINT": "/api/v3.5/groups",
    "ADD_AND_LIST_ENTITY_NOTE_ENDPOINT": "/api/v3.5/entities/{}/notes",
    "UPDATE_AND_REMOVE_ENTITY_NOTE_ENDPOINT": "/api/v3.5/entities/{}/notes/{}",
    "ENTITY_TAG_ENDPOINT": "/api/v3.5/tagging/entity/{}",
    "ASSIGNMENT_ENDPOINT": "/api/v3.5/assignments",
    "UPDATE_ASSIGNMENT_ENDPOINT": "/api/v3.5/assignments/{}",
    "RESOLVE_ASSIGNMENT_ENDPOINT": "/api/v3.5/assignments/{}/resolve",
    "ASSIGNMENT_OUTCOME_ENDPOINT": "/api/v3.5/assignment_outcomes/",
    "DOWNLOAD_DETECTION_PCAP": "/api/v3.5/detections/{}/pcap",
    "DETECTION_CLOSE_ENDPOINT": "/api/v3.5/detections/close",
    "DETECTION_OPEN_ENDPOINT": "/api/v3.5/detections/open",
    "DETECTION_TAG_ENDPOINT": "/api/v3.5/tagging/detection/{}",
    "ADD_AND_LIST_DETECTION_NOTE_ENDPOINT": "/api/v3.5/detections/{}/notes",
    "UPDATE_AND_REMOVE_DETECTION_NOTE_ENDPOINT": "/api/v3.5/detections/{}/notes/{}",
    "INVESTIGATION_ENDPOINT": "/api/v3.5/investigations",
}

ERRORS = {
    "INVALID_OBJECT": "Failed to parse {} object from response: {}",
    "INVALID_URGENCY_SCORE_THRESHOLD": "Invalid urgency score thresholds for severity mapping. Please ensure that the "
    "urgency score thresholds follow the correct order: "
    "urgency_score_low_threshold < urgency_score_medium_threshold < "
    "urgency_score_high_threshold.",
    "INVALID_COMMAND_ARG_VALUE": "Invalid '{}' value provided. Please ensure it is one of the values from the "
    "following options: {}.",
    "REQUIRED_ARGUMENT": "Please provide valid value of the '{}'. It is required field.",
    "INVALID_INTEGER_VALUE": "Invalid '{}' value. '{}' must be a non-zero and positive integer value.",
    "INVALID_NUMBER": '"{}" is not a valid number',
    "INVALID_PAGE_RESPONSE": "page contains no results",
    "INVALID_MAX_FETCH": "Invalid Max Fetch: {}. Max Fetch must be a positive integer ranging from 1 to 200.",
    "INVALID_PAGE_SIZE": "Invalid 'page size' provided. Please ensure that the page size value is between 1 and 5000.",
    "TRIAGE_AS_REQUIRED_WITH_DETECTION_IDS": "'triage_as' argument must be provided when using the 'detection_ids' argument. ",
    "INVALID_OUTCOME": "Invalid outcome value. Valid outcome values are: {}",
    "INVALID_SUPPORT_FOR_ARG": 'The argument "{}" must be set to "{}" when providing value for argument "{}".',
    "ENTITY_IDS_WITHOUT_TYPE": "When using the 'entity_ids' argument, 'entity_type' is required, and vice versa.",
    "INVALID_ARG_VALUE": "Invalid '{}' value provided. Please ensure it is one of the values from the following options: {}.",
    "INVALID_TIME_RANGE": "Invalid time range: '{}' ({}) must be earlier than '{}' ({}).",
}


""" CLIENT CLASS """


class VectraEventsDetectionsClient(BaseClient):
    """
    Client class to interact with the Vectra Events Detections API.
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

    def http_request(
        self,
        method: str,
        url_suffix: str = "",
        params: dict[str, Any] = None,
        data: dict[str, Any] = None,
        json_data: dict[str, Any] = None,
        response_type: str = "response",
        **kwargs,
    ):
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
        headers = {"User-Agent": USER_AGENT, "Authorization": f"Bearer {self._token}"}
        demisto.debug(f"Making API request at {method} {url_suffix} with params: {params} and body: {data or json_data}")
        # Make the HTTP request using the _http_request method, passing the necessary parameters.
        res = self._http_request(
            method=method,
            url_suffix=url_suffix,
            headers=headers,
            data=data,
            json_data=json_data,
            params=params,
            retries=MAX_RETRIES,
            status_list_to_retry=STATUS_LIST_TO_RETRY,
            ok_codes=OK_CODES,
            backoff_factor=BACKOFF_FACTOR,
            resp_type="response",
            raise_on_status=True,
            **kwargs,
        )
        # If the response status code indicates an authentication issue (e.g., 401),
        # generate a new access token using the refresh token and retry the request.
        if res.status_code in [401]:
            demisto.debug("Handling status code 401 by generating a new token using the refresh token.")
            self._token = self._generate_access_token_using_refresh_token()
            return self.http_request(
                method=method,
                url_suffix=url_suffix,
                params=params,
                response_type=response_type,
                data=data,
                json_data=json_data,
                **kwargs,
            )
        try:
            result = None
            if response_type == "json":
                result = res.json()
            if response_type == "content":
                result = res.content()
            if response_type == "response":
                result = res
            if response_type == "text":
                result = res.text
        except ValueError as exception:
            raise DemistoException(
                f"Failed to parse {response_type} object from response: {res.content}",  # type: ignore[str-bytes-safe]
                exception,
                res,
            )
        # If the success response is received, then return it.
        if res.status_code in (200, 201, 204):
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

        payload = "grant_type=client_credentials"
        auth = requests.auth.HTTPBasicAuth(self.client_id, self.client_secret_key)
        headers = {"User-Agent": USER_AGENT, "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        response = self._http_request(
            method="POST",
            url_suffix=ENDPOINTS["AUTH_ENDPOINT"],
            headers=headers,
            data=payload,
            auth=auth,
            retries=MAX_RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            status_list_to_retry=STATUS_LIST_TO_RETRY,
            raise_on_status=True,
        )

        access_token = response.get("access_token")
        refresh_token = response.get("refresh_token")
        set_integration_context({"access_token": access_token, "refresh_token": refresh_token})
        return access_token

    def _generate_access_token_using_refresh_token(self) -> str:  # type: ignore
        """
        Generates a new access token using the refresh token.

        Returns:
            str: The access token.
        """
        context = get_integration_context()
        refresh_token = context.get("refresh_token")
        demisto.info("Generating new access token using refresh token.")

        payload = f"grant_type=refresh_token&refresh_token={refresh_token}"
        headers = {"User-Agent": USER_AGENT, "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        response = self._http_request(
            method="POST",
            url_suffix=ENDPOINTS["AUTH_ENDPOINT"],
            headers=headers,
            data=payload,
            ok_codes=OK_CODES,
            retries=MAX_RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            raise_on_status=True,
            resp_type="response",
        )
        if response.status_code in [401]:
            return self._generate_tokens()
        elif response.status_code in [200, 201]:
            access_token = response.json().get("access_token")
            # set new access token
            set_integration_context({"access_token": access_token, "refresh_token": refresh_token})
            return access_token
        return ""

    def list_events_detections_request(
        self,
        params: dict[str, Any] = None,
    ) -> dict:
        """
        List events detections.

        Args:
            params (dict[str, Any]): Fetch parameters.

        Returns:
            Dict: Response from the API containing the list of events detections.
        """
        events = self.http_request(
            method="GET", url_suffix=ENDPOINTS["EVENTS_DETECTIONS_ENDPOINT"], params=params, response_type="json"
        )
        return events

    def close_detections_by_ids_request(self, ids_list: list[str], reason: str) -> dict:
        """
        Close detections by providing IDs of detections and close reason.

        Args:
            ids_list (list[str]): List of detection IDs.
            reason (str): Close reason.
        """
        data = {"detectionIdList": ids_list, "reason": reason}
        return self.http_request(
            method="PATCH",
            url_suffix=ENDPOINTS["CLOSE_DETECTIONS_ENDPOINT"],
            json_data=data,
            response_type="json",
        )

    def update_detection_status_request(self, ids_list: list[str], status: str) -> dict:
        """
        Update detection status.

        Args:
            ids_list (list[str]): List of detection IDs to update.
            status (str): New status.
        """
        data = {"detectionIdList": ids_list, "investigation_status": status}
        return self.http_request(
            method="PATCH",
            url_suffix=f"{ENDPOINTS['DETECTION_ENDPOINT']}",
            json_data=data,
            response_type="json",
        )

    def update_detection_external_id_request(self, ids_list: list[str], external_reference_id: str) -> dict:
        """
        Update detection external reference ID.

        Args:
            ids_list (list[str]): List of detection IDs to update.
            external_reference_id (str): New external reference ID.
        """
        data = {"detectionIdList": ids_list, "external_reference_id": external_reference_id}
        return self.http_request(
            method="PATCH",
            url_suffix=f"{ENDPOINTS['DETECTION_ENDPOINT']}",
            json_data=data,
            response_type="json",
        )

    def update_entity_external_id_request(
        self,
        entity_id: int,
        entity_type: str,
        external_reference_id: str,
    ) -> dict:
        """
        Update entity external reference ID.

        Args:
            entity_id (int): Entity ID to update.
            entity_type (str): Entity type.
            external_reference_id (str): New external reference ID.
        """
        params = {"type": entity_type}
        data = {"external_reference_id": external_reference_id}
        return self.http_request(
            method="PATCH",
            url_suffix=f"{ENDPOINTS['ENTITY_ENDPOINT']}/{entity_id}",
            params=params,
            json_data=data,
            response_type="json",
        )

    def investigation_query_send(self, query, version) -> dict:
        """
        Send investigation query.

        Args:
            query (str): Investigation query.
            version (str): Investigation version.
        """
        data = {"query": query, "version": version}
        remove_nulls_from_dictionary(data)
        return self.http_request(
            method="POST",
            url_suffix=f"{ENDPOINTS['INVESTIGATION_ENDPOINT']}",
            json_data=data,
            response_type="json",
        )

    def investigation_result_get(self, request_id: str, page: str, page_size: str) -> dict:
        """
        Get investigation result.

        Args:
            request_id (str): Request ID.
            page (str): Page number.
            page_size (str): Page size.
        """
        params = assign_params(page=page, page_size=page_size)
        return self.http_request(
            method="GET",
            url_suffix=f"{ENDPOINTS['INVESTIGATION_ENDPOINT']}/{request_id}",
            params=params,
            response_type="json",
        )

    def update_entity_unresolved_priority_status_request(
        self,
        entity_id: str,
        entity_type: str,
        unresolved_priority: str,
    ) -> dict:
        """
        Update entity unresolved priority status.

        Args:
            entity_id (str): Entity ID to update.
            entity_type (str): Entity type.
            unresolved_priority (str): Unresolved priority.
        """
        params = {"type": entity_type}
        data = {"unresolved_priority": unresolved_priority}
        return self.http_request(
            method="PATCH",
            url_suffix=f"{ENDPOINTS['ENTITY_ENDPOINT']}/{entity_id}",
            params=params,
            json_data=data,
            response_type="json",
        )

    def add_note_to_detection_request(self, detection_id: int, note: str) -> dict:
        """
        Add note to detection.

        Args:
            detection_id (int): Detection ID to add note to.
            note (str): Note to add.
        """
        body = {"note": note}
        return self.http_request(
            method="POST",
            url_suffix=ENDPOINTS["ADD_NOTE_ENDPOINT"].format(detection_id),
            json_data=body,
            response_type="json",
        )

    def list_detection_tags_request(self, detection_id: int) -> dict:
        """
        List detection tags.

        Args:
            detection_id (int): Detection ID to list tags for.
        """
        params = {"type": "detection"}
        return self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["LIST_TAGS_ENDPOINT"].format(detection_id),
            params=params,
            response_type="json",
        )

    def update_detection_tags_request(self, detection_id: int, tags: list) -> dict:
        """
        Update detection tags.

        Args:
            detection_id (int): Detection ID to update tags for.
            tags (list): List of tags to update.
        """
        body = {"tags": tags}
        params = {"type": "detection"}
        return self.http_request(
            method="PATCH",
            url_suffix=ENDPOINTS["LIST_TAGS_ENDPOINT"].format(detection_id),
            params=params,
            json_data=body,
            response_type="json",
        )

    def open_detections_by_ids_request(self, ids_list: list) -> dict:
        """
        Open detections by providing IDs of detections.

        Args:
            ids_list (list[str]): List of detection IDs.
        """
        data = {"detectionIdList": ids_list}
        return self.http_request(
            method="PATCH",
            url_suffix=ENDPOINTS["OPEN_DETECTIONS_ENDPOINT"],
            json_data=data,
            response_type="json",
        )

    def list_detections_standalone_request(
        self,
        params: dict,
    ) -> dict:
        """
        List detections.

        Args:
            params (dict): Parameters to filter detections.

        Returns:
            Dict: Response from the API containing the list of detections.
        """
        detections = self.http_request(
            method="GET", url_suffix=ENDPOINTS["DETECTION_ENDPOINT"], params=params, response_type="json"
        )
        return detections

    def list_users_request(self, email: str | None, role: str | None, last_login_timestamp: datetime | None) -> dict:
        """
        List users.

        Args:
            email (str | None): The optional email to filter with (default: None).
            role (str | None): The optional user role to filter with (default: None).
            last_login_timestamp (datetime | None): Filter users after the specified last login timestamp (default: None).

        Returns:
            Dict: Response from the API containing the users.
        """
        params = assign_params(email=email, role=role, last_login_gte=last_login_timestamp)
        return self.http_request(method="GET", url_suffix=ENDPOINTS["USER_ENDPOINT"], params=params, response_type="json")

    def list_entities_request(
        self,
        page: int = MAX_PAGE,
        page_size: int = MAX_PAGE_SIZE,
        is_prioritized: bool = None,
        entity_type: str = None,
        last_modified_timestamp: datetime | None = None,
        last_detection_timestamp: datetime | None = None,
        tags: str = None,
        ordering: str = None,
        state: str = "active",
        name: str = None,
    ) -> dict:
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
            name (str): Filter entities by name (default: None).

        Returns:
            Dict: Response from the API containing the list of entities.
        """
        params = assign_params(
            page=page,
            page_size=page_size,
            is_prioritized=is_prioritized,
            type=entity_type,
            last_modified_timestamp_gte=last_modified_timestamp,
            last_detection_timestamp_gte=last_detection_timestamp,
            tags=tags,
            state=state,
            ordering=ordering,
            name=name,
        )
        entities = self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["ENTITY_ENDPOINT_v34"],
            params=params,
            response_type="json",
        )
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
        entity = self.http_request(
            method="GET",
            url_suffix="{}/{}".format(ENDPOINTS["ENTITY_ENDPOINT_v34"], entity_id),
            params=params,
            response_type="json",
        )
        return entity

    def list_detections_request(
        self,
        detection_category: str = None,
        detection_type: str = None,
        entity_id: int = None,
        entity_type: str = None,
        page: int = None,
        page_size: int = None,
        last_timestamp: datetime | None = None,
        tags: str = None,
        state: str = "active",
        detection_name: str = None,
        ids: str = None,
    ) -> dict:
        """
        List detections.

        Args:
            detection_category (str, optional): Filter by detection category.
            detection_type (str, optional): Filter by detection type.
            entity_id (int, optional): Filter by entity ID.
            entity_type (str, optional): Filter by entity type.
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
        params = assign_params(
            detection_category=detection_category,
            detection_type=detection_type,
            entity_id=entity_id,
            type=entity_type,
            page=page,
            page_size=page_size,
            last_timestamp_gte=last_timestamp,
            tags=tags,
            state=state,
            detection=detection_name,
            id=ids,
        )
        detections = self.http_request(
            method="GET", url_suffix=ENDPOINTS["DETECTION_ENDPOINT"], params=params, response_type="json"
        )
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
        notes = self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["ADD_AND_LIST_ENTITY_NOTE_ENDPOINT"].format(entity_id),
            params=params,
            response_type="json",
        )
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
        data = {"note": note}
        notes = self.http_request(
            method="POST",
            url_suffix=ENDPOINTS["ADD_AND_LIST_ENTITY_NOTE_ENDPOINT"].format(entity_id),
            params=params,
            json_data=data,
            response_type="json",
        )
        return notes

    def update_entity_note_request(
        self, entity_id: int = None, entity_type: str = None, note: str = None, note_id: int = None
    ) -> dict:
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
        data = {"note": note}
        notes = self.http_request(
            method="PATCH",
            url_suffix=ENDPOINTS["UPDATE_AND_REMOVE_ENTITY_NOTE_ENDPOINT"].format(entity_id, note_id),
            params=params,
            json_data=data,
            response_type="json",
        )
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
        res = self.http_request(
            method="DELETE",
            url_suffix=ENDPOINTS["UPDATE_AND_REMOVE_ENTITY_NOTE_ENDPOINT"].format(entity_id, note_id),
            params=params,
            response_type="response",
        )
        return res

    def update_entity_tags_request(self, entity_id: int = None, entity_type: str = None, tags: list = None) -> dict:
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
        data = {"tags": tags}
        res = self.http_request(
            method="PATCH",
            url_suffix=ENDPOINTS["ENTITY_TAG_ENDPOINT"].format(entity_id),
            params=params,
            json_data=data,
            response_type="json",
        )
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
        res = self.http_request(
            method="GET", url_suffix=ENDPOINTS["ENTITY_TAG_ENDPOINT"].format(entity_id), params=params, response_type="json"
        )
        return res

    def list_assignments_request(
        self,
        account_ids: str = None,
        host_ids: str = None,
        resolution: str = None,
        resolved: bool = None,
        created_after: str = None,
        assignees: str = None,
        page: int = None,
        page_size: int = None,
    ) -> dict:
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
        params = assign_params(
            accounts=account_ids,
            hosts=host_ids,
            resolution=resolution,
            resolved=resolved,
            created_after=created_after,
            assignees=assignees,
            page=page,
            page_size=page_size,
        )
        res = self.http_request(method="GET", url_suffix=ENDPOINTS["ASSIGNMENT_ENDPOINT"], params=params, response_type="json")
        return res

    def add_entity_assignment_request(
        self,
        assign_to_user_id: int | None = None,
        assign_host_id: int | None = None,
        assign_account_id: int | None = None,
    ) -> dict:
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
        body = assign_params(
            assign_to_user_id=assign_to_user_id, assign_host_id=assign_host_id, assign_account_id=assign_account_id
        )
        res = self.http_request(method="POST", url_suffix=ENDPOINTS["ASSIGNMENT_ENDPOINT"], json_data=body, response_type="json")
        return res

    def update_entity_assignment_request(self, assign_to_user_id: int | None = None, assignment_id: int | None = None) -> dict:
        """
        Send a request to update an existing entity assignment.

        Args:
            assign_to_user_id (int, optional): The ID of the user to whom the entity will be reassigned.
                Defaults to None.
            assignment_id (int, optional): The ID of the assignment to be updated.
                Defaults to None.

        Returns:
            dict: Response from the API.
        """
        body = assign_params(assign_to_user_id=assign_to_user_id)
        res = self.http_request(
            method="PUT",
            url_suffix=ENDPOINTS["UPDATE_ASSIGNMENT_ENDPOINT"].format(assignment_id),
            json_data=body,
            response_type="json",
        )
        return res

    def download_detection_pcap_request(self, detection_id: str = None) -> Response:
        """
        Send a request to download the packet capture (PCAP) associated with a Vectra detection.

        Args:
            detection_id (str, optional): The ID of the detection for which the PCAP should be downloaded.

        Returns:
            Response: Response from the API.
        """
        res = self.http_request(
            method="GET", url_suffix=ENDPOINTS["DOWNLOAD_DETECTION_PCAP"].format(detection_id), response_type="response"
        )
        return res

    def list_group_request(
        self,
        group_type: str,
        account_names: list[str],
        domains: list[str],
        host_ids: list[str],
        host_names: list[str],
        importance: str,
        ips: list[str],
        description: str,
        last_modified_timestamp: datetime | None,
        last_modified_by: str,
        group_name: str,
    ) -> dict:
        """
        List groups as per the specified parameters.

        Args:
            group_type (str): Filter by group type.
            account_names (list[str]): Filter groups associated with accounts.
            domains (list[str]): Filter groups associated with domains.
            host_ids (list[str]): Filter groups associated with hosts.
            host_names (list[str]): Filter groups associated with hosts.
            importance (str): User defined group importance.
            ips (list[str]): Filter groups associated with ips.
            description (list[str]): Filter by group description.
            last_modified_timestamp (datetime | None):
                Filters for all groups modified on or after the given timestamp (GTE).
            last_modified_by (str): Filters groups by the user id who made the most recent modification.
            group_name (str): Filters by group name.

        Returns:
            Dict: Response from the API containing the tags.
        """
        params = assign_params(
            type=group_type,
            account_names=",".join(account_names),
            domains=",".join(domains),
            host_ids=",".join(host_ids),
            host_names=",".join(host_names),
            importance=importance,
            ips=",".join(ips),
            description=description,
            name=group_name,
            last_modified_timestamp=last_modified_timestamp,
            last_modified_by=last_modified_by,
        )
        res = self.http_request(method="GET", url_suffix=ENDPOINTS["GROUP_ENDPOINT"], params=params, response_type="json")
        return res

    def get_group_request(self, group_id: int = None) -> dict:
        """Get group by ID.

        Args:
            group_id (int): The ID of the group to retrieve.

        Returns:
            Dict: Response from the API containing the group information.
        """
        group = self.http_request(
            method="GET", url_suffix="{}/{}".format(ENDPOINTS["GROUP_ENDPOINT"], group_id), response_type="json"
        )
        return group

    def update_group_members_request(self, group_id: int = None, members: list = None) -> dict:
        """Update members in group.

        Args:
            group_id (int): The ID of the group to retrieve.
            members (List): The member list.

        Returns:
            Dict: Response from the API containing the group information.
        """
        body = {"members": members}
        group = self.http_request(
            method="PATCH", url_suffix="{}/{}".format(ENDPOINTS["GROUP_ENDPOINT"], group_id), json_data=body, response_type="json"
        )
        return group

    def close_detections_request(self, detection_ids: list[str], reason: str) -> dict:
        """
        Close detections with a specific reason.

        Args:
            detection_ids (List[str]): List of detection IDs to close.
            reason (str): The close reason (benign or remediated).

        Returns:
            Dict: Response from the API.

        Raises:
            ValueError: If detection_ids is empty or reason is invalid.
        """
        data = {"detectionIdList": detection_ids, "reason": reason}
        res = self.http_request(
            method="PATCH", url_suffix=ENDPOINTS["DETECTION_CLOSE_ENDPOINT"], json_data=data, response_type="json"
        )
        return res

    def open_detections_request(self, detection_ids: list[str]) -> dict:
        """
        Open detections with provided detection IDs.

        Args:
            detection_ids (List[str]): List of detection IDs to open.

        Returns:
            Dict: Response from the API.
        """
        data = {"detectionIdList": detection_ids}
        res = self.http_request(
            method="PATCH", url_suffix=ENDPOINTS["DETECTION_OPEN_ENDPOINT"], json_data=data, response_type="json"
        )
        return res

    def list_detection_note_request(self, detection_id: int) -> dict:
        """
        List detection notes.

        Args:
            detection_id (int): The ID of the detection to get the notes for.

        Returns:
            Dict: Response from the API.
        """
        notes = self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["ADD_AND_LIST_DETECTION_NOTE_ENDPOINT"].format(detection_id),
            response_type="json",
        )
        return notes

    def add_detection_note_request(self, detection_id: int = None, note: str = None) -> dict:
        """
        Add a note to a detection.

        Args:
            detection_id (int): The ID of the detection to add the note to.
            note (str): The note to add.

        Returns:
            Dict: Response from the API containing the added note.
        """
        data = {"note": note}
        notes = self.http_request(
            method="POST",
            url_suffix=ENDPOINTS["ADD_AND_LIST_DETECTION_NOTE_ENDPOINT"].format(detection_id),
            json_data=data,
            response_type="json",
        )
        return notes

    def update_detection_note_request(self, detection_id: int = None, note: str = None, note_id: int = None) -> dict:
        """
        Updates the note of a detection.

        Args:
            detection_id (int): The ID of the detection to update the note for.
            note (str): The updated note for the detection.
            note_id (int): The ID of the note to be updated.

        Returns:
            Dict: Response from the API containing the updated note details.
        """
        data = {"note": note}
        notes = self.http_request(
            method="PATCH",
            url_suffix=ENDPOINTS["UPDATE_AND_REMOVE_DETECTION_NOTE_ENDPOINT"].format(detection_id, note_id),
            json_data=data,
            response_type="json",
        )
        return notes

    def remove_detection_note_request(self, detection_id: int = None, note_id: int = None):
        """
        Removes a note from a detection.

        Args:
            detection_id (int): The ID of the detection to remove the note from.
            note_id (int): The ID of the note to be removed.

        Returns:
            Dict: Response from the API confirming the removal of the note.
        """
        res = self.http_request(
            method="DELETE",
            url_suffix=ENDPOINTS["UPDATE_AND_REMOVE_DETECTION_NOTE_ENDPOINT"].format(detection_id, note_id),
            response_type="response",
        )
        return res


""" HELPER FUNCTIONS """


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
        val_list = argToList(val, transform=lambda x: x.strip())
        args[key] = ",".join(val_list)
    return args


def check_empty(x: Any) -> bool:
    """
    Check if input is empty (None, empty dict, empty list, or empty string).

    :param x: Input to check.
    :type x: Any
    :return: True if x is empty, False otherwise.
    :rtype: bool
    """
    return x is None or x == {} or x == [] or x == ""


def remove_empty_elements_for_fetch(d: Any) -> Any:
    """
    Recursively remove empty lists, empty dicts, or None elements from a dictionary or list.
    :param d: Input dictionary or list.
    :return: Dictionary or list with all empty lists, and empty dictionaries removed.
    """
    if not isinstance(d, dict | list):
        return d
    elif isinstance(d, list):
        return [v for v in (remove_empty_elements_for_fetch(v) for v in d) if not check_empty(v)]
    return {k: v for k, v in ((k, remove_empty_elements_for_fetch(v)) for k, v in d.items()) if not check_empty(v)}


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
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format(arg_name))
    if value is not None and (not str(value).isdigit() or int(value) <= 0):
        raise ValueError(ERRORS["INVALID_INTEGER_VALUE"].format(arg_name, value))

    return True


def validate_urgency_score(urgency_score: str, score_name: str) -> int | None:
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
    entity_type = args.get("entity_type", "").lower()
    state = args.get("state", "").lower()
    page = args.get("page", "1")
    page_size = args.get("page_size", "50")
    # Validate entity_type value
    if entity_type and entity_type not in VALID_ENTITY_TYPE:
        raise ValueError(ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)))

    # Validate state value
    if state and state not in VALID_ENTITY_STATE:
        raise ValueError(ERRORS["INVALID_COMMAND_ARG_VALUE"].format("state", ", ".join(VALID_ENTITY_STATE)))

    validate_positive_integer_arg(page, arg_name="page")
    validate_positive_integer_arg(page_size, arg_name="page_size")
    if not 1 <= int(page_size) <= ENTITY_AND_DETECTION_MAX_PAGE_SIZE:
        raise ValueError(ERRORS["INVALID_PAGE_SIZE"])


def validate_list_entity_detections_args(args: dict[str, Any]):
    """
    Validate the arguments for listing entity detections.

    Args:
         args (dict[Any, Any]): The arguments dictionary.

    Raises:
        ValueError: If the entity ID is not provided.
        ValueError: If the detection category is invalid.
        ValueError: If the page size is invalid.
    """
    entity_id = args.get("entity_id")
    entity_type = args.get("entity_type", "").lower()
    detection_category = args.get("detection_category")
    page = args.get("page", "1")
    page_size = args.get("page_size", "50")

    validate_positive_integer_arg(entity_id, arg_name="entity_id", required=True)

    if not entity_type:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("entity_type"))
    if entity_type not in VALID_ENTITY_TYPE:
        raise ValueError(ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)))

    if detection_category and detection_category not in DETECTION_CATEGORY_TO_ARG:
        raise ValueError(
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("detection_category", ", ".join(DETECTION_CATEGORY_TO_ARG.keys()))
        )

    validate_positive_integer_arg(value=page, arg_name="page")
    validate_positive_integer_arg(value=page_size, arg_name="page_size")
    if not 1 <= int(page_size) <= ENTITY_AND_DETECTION_MAX_PAGE_SIZE:
        raise ValueError(ERRORS["INVALID_PAGE_SIZE"])


def validate_detection_describe_args(args: dict[str, Any]):
    """
    Validate the arguments for detection describe.

    Args:
         args (dict[Any, Any]): The arguments dictionary.

    Raises:
        ValueError: If the detection IDs are not provided.
        ValueError: If the page size is invalid.
    """
    detection_ids = args.get("detection_ids", "")
    page = args.get("page", "1")
    page_size = args.get("page_size", "50")

    detection_ids = argToList(detection_ids, transform=arg_to_number)
    found_valid_detection_ids = False
    for detection_id in detection_ids:
        if isinstance(detection_id, int):
            if detection_id < 1:
                raise ValueError(ERRORS["INVALID_INTEGER_VALUE"].format("detection_ids", detection_id))
            found_valid_detection_ids = True
    if not found_valid_detection_ids:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("detection_ids"))

    validate_positive_integer_arg(value=page, arg_name="page")
    validate_positive_integer_arg(value=page_size, arg_name="page_size")
    if not 1 <= int(page_size) <= ENTITY_AND_DETECTION_MAX_PAGE_SIZE:
        raise ValueError(ERRORS["INVALID_PAGE_SIZE"])


def validate_entity_note_list_command_args(args: dict[str, Any]):
    """
    Validates the arguments provided for the entity list add command.

    Args:
        args (dict[Any, Any]): The arguments dictionary.

    Raises:
        ValueError: If any of the arguments are invalid.
    """
    entity_type = args.get("entity_type", "").lower()
    entity_id = args.get("entity_id")
    # Validate entity_id value
    validate_positive_integer_arg(entity_id, arg_name="entity_id", required=True)
    # Validate entity_type value
    if not entity_type:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("entity_type"))
    if entity_type and entity_type not in VALID_ENTITY_TYPE:
        raise ValueError(ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)))


def validate_entity_note_add_command_args(args: dict[str, Any]):
    """
    Validates the arguments provided for the entity note add command.

    Args:
        args (dict[Any, Any]): The arguments dictionary.

    Raises:
        ValueError: If any of the arguments are invalid.
    """
    entity_type = args.get("entity_type", "").lower()
    note = args.get("note")
    entity_id = args.get("entity_id")
    # Validate entity_id value
    validate_positive_integer_arg(entity_id, arg_name="entity_id", required=True)
    # Validate entity_type value
    if not entity_type:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("entity_type"))
    if entity_type and entity_type not in VALID_ENTITY_TYPE:
        raise ValueError(ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)))
    # Validate note value
    if not note:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("note"))


def validate_entity_note_update_command_args(args: dict[str, Any]):
    """
    Validates the arguments provided for the entity note update command.

    Args:
        args (dict[Any, Any]): The arguments dictionary.

    Raises:
        ValueError: If any of the arguments are invalid.
    """
    entity_type = args.get("entity_type", "").lower()
    note = args.get("note")
    entity_id = args.get("entity_id")
    note_id = args.get("note_id")
    # Validate entity_id value
    validate_positive_integer_arg(entity_id, arg_name="entity_id", required=True)
    # Validate note_id value
    validate_positive_integer_arg(note_id, arg_name="note_id", required=True)
    if not entity_type:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("entity_type"))
    if entity_type and entity_type not in VALID_ENTITY_TYPE:
        raise ValueError(ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)))
    # Validate note value
    if not note:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("note"))


def validate_entity_note_remove_command_args(args: dict[str, Any]):
    """
    Validates the arguments provided for the entity note update command.

    Args:
        args (dict[Any, Any]): The arguments dictionary.

    Raises:
        ValueError: If any of the arguments are invalid.
    """
    entity_type = args.get("entity_type", "").lower()
    entity_id = args.get("entity_id")
    note_id = args.get("note_id")
    # Validate entity_id value
    validate_positive_integer_arg(entity_id, arg_name="entity_id", required=True)
    # Validate note_id value
    validate_positive_integer_arg(note_id, arg_name="note_id", required=True)
    # Validate entity_type value
    if not entity_type:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("entity_type"))
    if entity_type and entity_type.lower() not in VALID_ENTITY_TYPE:
        raise ValueError(ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)))


def validate_entity_tag_add_command_args(args: dict[str, Any]):
    """
    Validates the arguments provided for the entity tag add command.

    Args:
        args (dict[Any, Any]): The arguments dictionary.

    Raises:
        ValueError: If any of the arguments are invalid.
    """
    validate_entity_tag_list_command_args(args)
    tags = argToList(args.get("tags", ""))
    # Validate Tags value
    if not [tag.strip() for tag in tags if isinstance(tag, str) and tag.strip()]:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("tags"))


def validate_entity_tag_list_command_args(args: dict[str, Any]):
    """
    Validates the arguments provided for the entity tag list command.

    Args:
        args (dict[Any, Any]): The arguments dictionary.

    Raises:
        ValueError: If any of the arguments are invalid.
    """
    entity_type = args.get("entity_type", "").lower()
    entity_id = args.get("entity_id")
    # Validate entity_id value
    validate_positive_integer_arg(entity_id, arg_name="entity_id", required=True)
    # Validate entity_type value
    if not entity_type:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("entity_type"))
    if entity_type and entity_type not in VALID_ENTITY_TYPE:
        raise ValueError(ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)))


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
    entity_ids = args.get("entity_ids")
    entity_type = args.get("entity_type")
    page = args.get("page", "1")
    page_size = args.get("page_size", "50")
    # Validate entity type
    if entity_type and entity_type.lower() not in VALID_ENTITY_TYPE:
        raise ValueError(ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)))
    # Validate entity ids without entity_type and vice-versa
    if (entity_ids and not entity_type) or (entity_type and not entity_ids):
        raise ValueError(ERRORS["ENTITY_IDS_WITHOUT_TYPE"])
    # Validate pagination
    validate_positive_integer_arg(value=page, arg_name="page")
    validate_positive_integer_arg(value=page_size, arg_name="page_size")


def validate_entity_assignment_add_command_args(args: dict):
    """
    Validate the arguments provided for adding an entity assignment.

    Args:
        args (Dict): A dictionary containing the arguments for adding an entity assignment.

    Raises:
        ValueError: If the provided entity_id or user_id is not a positive integer.
        ValueError: If the entity_type is missing or not one of the valid types.
    """
    entity_id = args.get("entity_id")
    entity_type = args.get("entity_type")
    user_id = args.get("user_id")
    # Validate entity_id value
    validate_positive_integer_arg(entity_id, arg_name="entity_id", required=True)
    # Validate note_id value
    validate_positive_integer_arg(user_id, arg_name="user_id", required=True)
    # Validate entity_type value
    if not entity_type:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("entity_type"))
    if entity_type and entity_type.lower() not in VALID_ENTITY_TYPE:
        raise ValueError(ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)))


def validate_entity_assignment_update_command_args(args: dict):
    """
    Validate the arguments provided for updating an entity assignment.

    Args:
        args (Dict): A dictionary containing the arguments for updating an entity assignment.

    Raises:
        ValueError: If the provided assignment_id or user_id is not a positive integer.
    """
    assignment_id = args.get("assignment_id")
    user_id = args.get("user_id")
    # Validate assignment_id value
    validate_positive_integer_arg(assignment_id, arg_name="assignment_id", required=True)
    # Validate user_id value
    validate_positive_integer_arg(user_id, arg_name="user_id", required=True)


def validate_group_list_command_args(args: dict[str, Any]):
    """
    Validates the arguments provided for the group list command.

    Args:
        args (dict[Any, Any]): The arguments dictionary.

    Raises:
        ValueError: If any of the arguments are invalid.
    """
    group_type = args.get("group_type") or ""
    if group_type and isinstance(group_type, str):
        group_type = group_type.lower()
        # Validate group_type value
        if group_type not in VALID_GROUP_TYPE:
            raise ValueError(ERRORS["INVALID_COMMAND_ARG_VALUE"].format("group_type", ", ".join(VALID_GROUP_TYPE)))

    importance = args.get("importance") or ""
    # Validate importance value
    if importance and isinstance(importance, str) and importance.lower() not in VALID_IMPORTANCE_VALUE:
        raise ValueError(ERRORS["INVALID_COMMAND_ARG_VALUE"].format("importance", ", ".join(VALID_IMPORTANCE_VALUE)))

    # Validate account_names value
    account_names = argToList(args.get("account_names") or "")
    if account_names and group_type != "account":
        raise ValueError(ERRORS["INVALID_SUPPORT_FOR_ARG"].format("group_type", "account", "account_names"))

    # Validate domains value
    domains = argToList(args.get("domains") or "")
    if domains and group_type != "domain":
        raise ValueError(ERRORS["INVALID_SUPPORT_FOR_ARG"].format("group_type", "domain", "domains"))

    # Validate host_ids value
    host_ids = argToList(args.get("host_ids") or "")
    if host_ids and group_type != "host":
        raise ValueError(ERRORS["INVALID_SUPPORT_FOR_ARG"].format("group_type", "host", "host_ids"))
    for host_id in host_ids:
        host_id = arg_to_number(host_id, "host_ids")
        validate_positive_integer_arg(host_id, arg_name="host_ids")

    # Validate host_names value
    host_names = argToList(args.get("host_names") or "")
    if host_names and group_type != "host":
        raise ValueError(ERRORS["INVALID_SUPPORT_FOR_ARG"].format("group_type", "host", "host_names"))

    # Validate ips value
    ips = argToList(args.get("ips") or "")
    if ips and group_type != "ip":
        raise ValueError(ERRORS["INVALID_SUPPORT_FOR_ARG"].format("group_type", "ip", "ips"))


def validate_group_assign_and_unassign_command_args(args):
    """
    Validate the arguments provided for assigning or unassigning members to/from a group.

    Args:
        args (Dict): A dictionary containing the arguments for the group assign and unassign command.

    Raises:
        ValueError: If the provided group_id is not a positive integer.
        ValueError: If members argument is missing.
    """
    group_id = args.get("group_id")
    members = args.get("members")
    validate_positive_integer_arg(group_id, arg_name="group_id", required=True)

    if not members:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("members"))


def validate_entity_detections_mark_asclosed_command_args(args):
    """
    Validate the arguments for marking entity detections as closed.

    Args:
        args (Dict): The command arguments.

    Raises:
        ValueError: If entity_id, entity_type, or close_reason are invalid.
    """
    entity_id = args.get("entity_id")
    entity_type = args.get("entity_type", "").lower()
    close_reason = args.get("close_reason", "").lower()

    validate_positive_integer_arg(entity_id, arg_name="entity_id", required=True)

    if not entity_type:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("entity_type"))
    if entity_type not in VALID_ENTITY_TYPE:
        raise ValueError(ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)))

    if not close_reason:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("close_reason"))
    if close_reason not in VALID_CLOSE_REASON:
        raise ValueError(ERRORS["INVALID_COMMAND_ARG_VALUE"].format("close_reason", ", ".join(VALID_CLOSE_REASON)))


def validate_detection_tag_add_command_args(args):
    """
    Validates the arguments provided for the detection tag add command.

    Args:
        args (dict): The arguments dictionary.

    Raises:
        ValueError: If any of the arguments are invalid.
    """
    detection_id = args.get("detection_id")
    tags = argToList(args.get("tags", ""))
    # Validate detection_id value
    validate_positive_integer_arg(detection_id, arg_name="detection_id", required=True)
    # Validate Tags value
    if not [tag.strip() for tag in tags if isinstance(tag, str) and tag.strip()]:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("tags"))


def validate_detection_note_list_command_args(args: dict[Any, Any]):
    """
    Validates the arguments provided for the detection note list command.

    Args:
        args (dict[Any, Any]): The arguments dictionary.

    Raises:
        ValueError: If any of the arguments are invalid.
    """
    detection_id = args.get("detection_id")
    # Validate detection_id value
    validate_positive_integer_arg(detection_id, arg_name="detection_id", required=True)


def validate_detection_note_add_command_args(args: dict[Any, Any]):
    """
    Validates the arguments provided for the detection note add command.

    Args:
        args (dict[Any, Any]): The arguments dictionary.

    Raises:
        ValueError: If any of the arguments are invalid.
    """
    note = args.get("note")
    detection_id = args.get("detection_id")
    # Validate detection_id value
    validate_positive_integer_arg(detection_id, arg_name="detection_id", required=True)

    if not note:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("note"))


def validate_detection_note_update_command_args(args: dict[Any, Any]):
    """
    Validates the arguments provided for the detection note update command.

    Args:
        args (dict[Any, Any]): The arguments dictionary.

    Raises:
        ValueError: If any of the arguments are invalid.
    """
    note = args.get("note")
    detection_id = args.get("detection_id")
    note_id = args.get("note_id")
    # Validate detection_id value
    validate_positive_integer_arg(detection_id, arg_name="detection_id", required=True)
    # Validate note_id value
    validate_positive_integer_arg(note_id, arg_name="note_id", required=True)
    # Validate note value
    if not note:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("note"))


def validate_detection_note_remove_command_args(args: dict[Any, Any]):
    """
    Validates the arguments provided for the detection note remove command.

    Args:
        args (dict[Any, Any]): The arguments dictionary.

    Raises:
        ValueError: If any of the arguments are invalid.
    """
    detection_id = args.get("detection_id")
    note_id = args.get("note_id")
    # Validate detection_id value
    validate_positive_integer_arg(detection_id, arg_name="detection_id", required=True)
    # Validate note_id value
    validate_positive_integer_arg(note_id, arg_name="note_id", required=True)


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
    Trim the '/api/v3.x' portion from a URL.

    Args:
        url (str): The URL to trim.

    Returns:
        str: The trimmed URL.
    """
    api_versions = ["/api/v3.5", "/api/v3.4", "/api/v3.3", "/api/v3"]
    for api_version in api_versions:
        if api_version in url:
            trimmed_url = url.replace(api_version, "") + UTM_PIVOT
            return trimmed_url
    return url + UTM_PIVOT


def get_user_list_command_hr(users: list):
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
        hr_dict.append(
            {
                "User ID": user.get("user_id"),
                "User Name": user.get("name"),
                "Email": user.get("email"),
                "Role": user.get("role"),
                "Last Login Timestamp": user.get("last_login_timestamp"),
            }
        )
    # Prepare human-readable output table
    human_readable = tableToMarkdown(
        "Users Table", hr_dict, ["User ID", "User Name", "Email", "Role", "Last Login Timestamp"], removeNull=True
    )

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
        entity["url"] = trim_api_version(entity.get("url"))
        # Convert ID into clickable URL
        entity["id_url"] = f"[{entity['id']}]({entity['url']})"
        # Map entity importance
        entity["importance"] = ENTITY_IMPORTANCE_LABEL[entity.get("importance")]
        if "detection_set" in entity:
            entity["detection_ids"] = ", ".join(
                [
                    "[{}]({})".format(detection.split("/")[-1], trim_api_version(detection))
                    for detection in entity.get("detection_set")
                ]
            )
        hr_dict.append(
            {
                "ID": entity.get("id_url"),
                "Name": entity.get("name"),
                "Entity Type": entity.get("type"),
                "Urgency Score": entity.get("urgency_score"),
                "Entity Importance": entity.get("importance"),
                "Last Modified Timestamp": entity.get("last_modified_timestamp"),
                "Last Detection Timestamp": entity.get("last_detection_timestamp"),
                "Detections IDs": entity.get("detection_ids"),
                "Prioritize": entity.get("is_prioritized"),
                "State": entity.get("state"),
                "Tags": ", ".join(entity.get("tags")) if entity.get("tags") else None,
            }
        )
    # Prepare human-readable output table
    pages = calc_pages(per_page_count=page_size, total_count=count)  # type: ignore
    human_readable = tableToMarkdown(
        f"Entities Table (Showing Page {page} out of {pages})",
        hr_dict,
        [
            "ID",
            "Name",
            "Entity Type",
            "Urgency Score",
            "Entity Importance",
            "Last Detection Timestamp",
            "Last Modified Timestamp",
            "Detections IDs",
            "Prioritize",
            "State",
            "Tags",
        ],
        removeNull=True,
    )

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
    entity_res["url"] = trim_api_version(entity_res.get("url"))  # type: ignore
    entity_res["id"] = f"[{entity_res['id']}]({entity_res['url']})"

    # Process detection_set and create detection_ids field
    if "detection_set" in entity_res:
        entity_res["detection_ids"] = ", ".join(
            [
                "[{}]({})".format(detection.split("/")[-1], trim_api_version(detection))
                for detection in entity_res.get("detection_set", [])
            ]
        )  # type: ignore
    # Entity importance value to label
    entity_res["importance"] = ENTITY_IMPORTANCE_LABEL[entity_res.get("importance")]  # type: ignore
    hr_dict.append(
        {
            "Name": entity_res.get("name"),
            "Entity Type": entity_res.get("type"),
            "Urgency Score": entity_res.get("urgency_score"),
            "Entity Importance": entity_res.get("importance"),
            "Last Modified Timestamp": entity_res.get("last_modified_timestamp"),
            "Last Detection Timestamp": entity_res.get("last_detection_timestamp"),
            "Detections IDs": entity_res.get("detection_ids"),
            "Prioritize": entity_res.get("is_prioritized"),
            "State": entity_res.get("state"),
            "Tags": ", ".join(entity_res.get("tags")) if entity_res.get("tags") else None,  # type: ignore
        }
    )

    # Prepare human-readable output table
    human_readable = tableToMarkdown(
        f"Entity detail:\n#### Entity ID: {entity_res.get('id')}",
        hr_dict,
        [
            "Name",
            "Entity Type",
            "Urgency Score",
            "Entity Importance",
            "Last Detection Timestamp",
            "Last Modified Timestamp",
            "Detections IDs",
            "Prioritize",
            "State",
            "Tags",
        ],
        removeNull=True,
    )
    return human_readable


def get_list_entity_detections_command_hr(detections: dict[Any, Any], page: int | None, page_size: int | None, count: int):
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
        detection["url"] = trim_api_version(detection.get("url"))
        # Convert ID into clickable URL
        detection["id"] = f"[{detection['id']}]({detection['url']})"
        account_url = None
        host_url = None
        if detection.get("src_account"):
            account_url = (
                f"[{detection.get('src_account').get('name')}]({trim_api_version(detection.get('src_account').get('url'))})"
            )
        if detection.get("src_host"):
            host_url = f"[{detection.get('src_host').get('name')}]({trim_api_version(detection.get('src_host').get('url'))})"
        summary = detection.get("summary")
        num_events = 0
        # For counting number of events
        if summary and isinstance(summary, dict):
            num_events = int(summary.get("num_events") or 0)

        hr_dict.append(
            {
                "ID": detection.get("id"),
                "Detection Name": detection.get("detection"),
                "Detection Type": detection.get("detection_type"),
                "Category": detection.get("detection_category"),
                "Account Name": account_url,
                "Host Name": host_url,
                "Src IP": detection.get("src_ip"),
                "Threat Score": detection.get("threat"),
                "Certainty Score": detection.get("certainty"),
                "Number Of Events": num_events,
                "State": detection.get("state"),
                "Tags": detection.get("tags"),
                "Last Timestamp": detection.get("last_timestamp"),
            }
        )
        pages = calc_pages(per_page_count=page_size, total_count=count)  # type: ignore
    human_readable = tableToMarkdown(
        f"Detections Table (Showing Page {page} out of {pages})",
        hr_dict,
        [
            "ID",
            "Detection Name",
            "Detection Type",
            "Category",
            "Account Name",
            "Host Name",
            "Src IP",
            "Threat Score",
            "Certainty Score",
            "Number Of Events",
            "State",
            "Tags",
            "Last Timestamp",
        ],
        removeNull=True,
    )

    return human_readable


def get_assignment_list_command_hr(assignments: dict, page: int | None, page_size: int | None, count: int):
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
        assignment["assignment_id"] = assignment["id"]
        hr_dict.append(
            {
                "Account ID": assignment.get("account_id"),
                "Host ID": assignment.get("host_id"),
                "Assignment ID": assignment.get("id"),
                "Assigned By": assignment.get("assigned_by", {}).get("username", ""),
                "Assigned To": assignment.get("assigned_to", {}).get("username", ""),
                "Date Assigned": assignment.get("date_assigned"),
                "Resolved By": assignment.get("resolved_by", {}).get("username", ""),
                "Date Resolved": assignment.get("date_resolved"),
                "Outcome ID": assignment.get("outcome", {}).get("id", ""),
                "Outcome": assignment.get("outcome", {}).get("title", ""),
            }
        )
    pages = calc_pages(per_page_count=page_size, total_count=count)  # type: ignore
    human_readable = tableToMarkdown(
        f"Assignments Table (Showing Page {page} out of {pages})",
        hr_dict,
        [
            "Account ID",
            "Host ID",
            "Assignment ID",
            "Assigned By",
            "Assigned To",
            "Date Assigned",
            "Resolved By",
            "Date Resolved",
            "Outcome ID",
            "Outcome",
        ],
        removeNull=True,
    )
    return human_readable, assignments


def entity_assignment_add_command_hr(assignment: dict) -> str:
    """
    Returns the human-readable output for the assignment.

    Args:
        assignment (Dict): The assignment details dictionary.

    Returns:
        str: The human-readable output.
    """
    assigned_by = assignment.get("assigned_by", {})
    assigned_to = assignment.get("assigned_to", {})
    events = assignment.get("events", [{}])
    hr_dict = [
        {
            "Assignment ID": assignment.get("assignment_id"),
            "Assigned By": assigned_by.get("username") if isinstance(assigned_by, dict) else "",
            "Assigned Date": assignment.get("date_assigned"),
            "Assigned To": assigned_to.get("username") if isinstance(assigned_to, dict) else "",
            "Event Type": events[0].get("event_type") if isinstance(events, list) and len(events) > 0 else "",
        }
    ]

    # Prepare human-readable output table
    human_readable = tableToMarkdown(
        "Assignment detail",
        hr_dict,
        ["Assignment ID", "Assigned By", "Assigned Date", "Assigned To", "Event Type"],
        removeNull=True,
    )
    return human_readable


def get_list_entity_notes_command_hr(notes: dict, entity_id: int | None, entity_type: str) -> str:
    """
    Returns the human-readable output for the entity notes.

    Args:
        notes (Dict): The assignment details dictionary.
        entity_id (int | None): Entity ID.
        entity_type (str): Entity Type.

    Returns:
        str: The human-readable output.
    """
    hr_dict = []
    for note in notes:
        note["note_id"] = note["id"]
        note.update({"entity_id": entity_id, "entity_type": entity_type})

        hr_dict.append(
            {
                "Note ID": note.get("id"),
                "Note": note.get("note"),
                "Created By": note.get("created_by"),
                "Created Date": note.get("date_created"),
                "Modified By": note.get("modified_by"),
                "Modified Date": note.get("date_modified"),
            }
        )

    # Prepare human-readable output table
    human_readable = tableToMarkdown(
        "Entity Notes Table",
        hr_dict,
        ["Note ID", "Note", "Created By", "Created Date", "Modified By", "Modified Date"],
        removeNull=True,
    )
    return human_readable


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
        group["group_id"] = group["id"]
        members: list = group.get("members")
        members_hr = None
        if members and isinstance(members, list):
            # If the members are simple list of strings, then join them with comma.
            if isinstance(members[0], str):
                members_hr = ", ".join([re.escape(str(member)) for member in members])
            # If the members are list of dictionaries, then extract important field from that and join it with comma.
            elif isinstance(members[0], dict):
                members_list = []
                for member in members:
                    if member.get("uid"):
                        members_list.append(re.escape(str(member.get("uid"))))  # type: ignore
                    elif member.get("id"):
                        members_list.append(  # type: ignore
                            "[{}]({})".format(member.get("id"), trim_api_version(member.get("url")))
                        )
                members_hr = ", ".join(members_list)

        hr_dict.append(
            {
                "Group ID": group.get("group_id"),
                "Name": group.get("name"),
                "Group Type": group.get("type"),
                "Description": group.get("description"),
                "Importance": group.get("importance"),
                "Members": members_hr,
                "Last Modified Timestamp": group.get("last_modified"),
            }
        )
    # Prepare human-readable output table
    human_readable = tableToMarkdown(
        "Groups Table",
        hr_dict,
        ["Group ID", "Name", "Group Type", "Description", "Importance", "Members", "Last Modified Timestamp"],
        removeNull=True,
    )

    return human_readable


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
    members = group.get("members")
    members_hr = None
    if members and isinstance(members, list):
        # If the members are simple list of strings, then join them with comma.
        if isinstance(members[0], str):
            members_hr = ", ".join([re.escape(str(member)) for member in members])
        # If the members are list of dictionaries, then extract important field from that and join it with comma.
        elif isinstance(members[0], dict):
            members_list = []
            for member in members:
                if member.get("uid"):
                    members_list.append(re.escape(str(member.get("uid"))))  # type: ignore
                elif member.get("id"):
                    members_list.append(  # type: ignore
                        "[{}]({})".format(member.get("id"), trim_api_version(member.get("url")))
                    )
            members_hr = ", ".join(members_list)

    hr_dict.append(
        {
            "Group ID": group.get("group_id"),
            "Name": group.get("name"),
            "Group Type": group.get("type"),
            "Description": group.get("description"),
            "Members": members_hr,
            "Last Modified Timestamp": group.get("last_modified"),
        }
    )

    # Prepare human-readable output table
    change_action = "assigned to" if assign_flag else "unassigned from"
    changed_members = [re.escape(member) for member in changed_members]
    human_readable = tableToMarkdown(
        f"Member(s) {', '.join(changed_members)} have been {change_action} the group.\n### Updated group details:",
        hr_dict,
        ["Group ID", "Name", "Group Type", "Description", "Members", "Last Modified Timestamp"],
        removeNull=True,
    )

    return human_readable


def get_list_detection_notes_command_hr(notes: dict, detection_id: int | None) -> str:
    """
    Returns the human-readable output for the detection notes.

    Args:
        notes (Dict): list of detection notes.
        detection_id (int | None): Detection ID.

    Returns:
        str: The human-readable output.
    """
    hr_dict = []
    for note in notes:
        note["note_id"] = note["id"]
        note.update({"detection_id": detection_id})

        hr_dict.append(
            {
                "Note ID": note.get("id"),
                "Note": note.get("note"),
                "Created By": note.get("created_by"),
                "Created Date": note.get("date_created"),
                "Modified By": note.get("modified_by"),
                "Modified Date": note.get("date_modified"),
            }
        )

    # Prepare human-readable output table
    human_readable = tableToMarkdown(
        "Detection Notes Table",
        hr_dict,
        ["Note ID", "Note", "Created By", "Created Date", "Modified By", "Modified Date"],
        removeNull=True,
    )
    return human_readable


def merge_values(value1, value2):
    """
    Merge two values based on their types.
    - Strings, Numbers: dict2 value takes priority
    - Lists of dicts: dict2 value takes priority
    - Lists of other types: combine and remove duplicates (preserves order)
    - Dicts: recursively merge
    - Other types: dict2 takes priority
    """
    if isinstance(value1, dict) and isinstance(value2, dict):
        return update_dict_with_new_dict_values(value1, value2)

    # Both are lists
    if isinstance(value1, list) and isinstance(value2, list):
        # Check if list contains dicts
        if all(isinstance(item, dict) for item in value1 + value2):
            return value2

        # Mixed or other types - append and remove duplicates
        merged = []
        seen = []
        for item in value1 + value2:
            if item not in seen:
                merged.append(item)
                seen.append(item)
        return merged

    # Different types or simple values - dict2 takes priority
    return value2


def update_dict_with_new_dict_values(dict1: dict, dict2: dict) -> dict:
    """
    Recursively merge dict1 with dict2, handling different value types intelligently.
    - For strings: dict2 value replaces dict1 (if both valid)
    - For lists of strings: combine and remove duplicates
    - For dicts: recursively merge
    - For lists of dicts: dict2 value replaces dict1 (if both valid)
    - dict2 takes priority when both have valid values
    - Valid values: non-empty strings, non-empty lists, non-empty dicts
    - Preserves all valid data from both dictionaries

    Args:
        dict1 (dict): The base dictionary.
        dict2 (dict): The dictionary containing new values (priority).

    Returns:
        dict: A new merged dictionary with combined values.
    """
    result = dict1.copy()

    for key, value2 in dict2.items() if dict2 else {}:
        if check_empty(value2):
            continue

        if key in result:
            value1 = result[key]
            if not check_empty(value1):
                result[key] = merge_values(value1, value2)
            else:
                result[key] = value2
        else:
            result[key] = value2

    return result


def validate_time_range(
    after_time: datetime | None, before_time: datetime | None, after_arg_name: str, before_arg_name: str
) -> None:
    """
    Validate that the 'after' timestamp is earlier than the 'before' timestamp.

    Args:
        after_time (datetime | None): The 'after' timestamp.
        before_time (datetime | None): The 'before' timestamp.
        after_arg_name (str): The name of the 'after' argument for error messages.
        before_arg_name (str): The name of the 'before' argument for error messages.

    Raises:
        ValueError: If after_time is not earlier than before_time.
    """
    if after_time and before_time and after_time >= before_time:
        raise ValueError(
            ERRORS["INVALID_TIME_RANGE"].format(
                after_arg_name,
                after_time.strftime(DATE_FORMAT),
                before_arg_name,
                before_time.strftime(DATE_FORMAT),
            )
        )


def validate_list_detections_args(args: dict[Any, Any]) -> dict[str, Any]:
    """
    Validate the arguments for listing entity detections.

    Args:
         args (dict[Any, Any]): The arguments dictionary.

    Raises:
        ValueError: arg is invalid.
    return:
        params: return the dict values of params.
    """
    created_after_dt = arg_to_datetime(args.get("created_after"), arg_name="created_after")
    created_before_dt = arg_to_datetime(args.get("created_before"), arg_name="created_before")

    # Validate that created_after is earlier than created_before
    validate_time_range(created_after_dt, created_before_dt, "created_after", "created_before")

    created_after = created_after_dt.strftime(DATE_FORMAT) if created_after_dt else None  # type: ignore
    created_before = created_before_dt.strftime(DATE_FORMAT) if created_before_dt else None  # type: ignore

    last_detected_after_dt = arg_to_datetime(args.get("last_detected_after"), arg_name="last_detected_after")
    last_detected_before_dt = arg_to_datetime(args.get("last_detected_before"), arg_name="last_detected_before")

    # Validate that updated_after is earlier than updated_before
    validate_time_range(last_detected_after_dt, last_detected_before_dt, "last_detected_after", "last_detected_before")

    last_detected_after = last_detected_after_dt.strftime(DATE_FORMAT) if last_detected_after_dt else None  # type: ignore
    last_detected_before = last_detected_before_dt.strftime(DATE_FORMAT) if last_detected_before_dt else None  # type: ignore

    description = args.get("description")
    detection_name = args.get("detection_name")
    detection_type = args.get("detection_type")
    detection_category = args.get("detection_category")
    include_info_category_detections = args.get("include_info_category_detections", "true")
    close_reason = args.get("close_reason")
    detection_state = args.get("detection_state")
    tags = argToList(args.get("tags"))
    is_triaged = args.get("is_triaged", "false")
    page = args.get("page", MAX_PAGE)
    page_size = args.get("page_size", MAX_PAGE_SIZE)
    entity_type = args.get("entity_type")

    if include_info_category_detections:
        if include_info_category_detections.lower() not in VALID_BOOL_VALUES:
            raise ValueError(ERRORS["INVALID_ARG_VALUE"].format("include_info_category_detections", ", ".join(VALID_BOOL_VALUES)))
        else:
            include_info_category_detections = argToBoolean(args.get("include_info_category_detections", "true"))

    if is_triaged:
        if is_triaged.lower() not in VALID_BOOL_VALUES:
            raise ValueError(ERRORS["INVALID_ARG_VALUE"].format("is_triaged", ", ".join(VALID_BOOL_VALUES)))
        else:
            is_triaged = argToBoolean(args.get("is_triaged", "false"))

    if entity_type and entity_type.capitalize() not in VALID_ENTITY_TYPES:
        raise ValueError(ERRORS["INVALID_ARG_VALUE"].format("entity_type", (", ".join(VALID_ENTITY_TYPES)).lower()))

    if close_reason and close_reason not in VALID_CLOSE_REASON:
        raise ValueError(ERRORS["INVALID_COMMAND_ARG_VALUE"].format("close_reason", ", ".join(VALID_CLOSE_REASON)))

    validate_positive_integer_arg(value=page, arg_name="page")
    validate_positive_integer_arg(value=page_size, arg_name="page_size")
    if not 1 <= int(page_size) <= ENTITY_AND_DETECTION_MAX_PAGE_SIZE:
        raise ValueError(ERRORS["INVALID_PAGE_SIZE"])

    params = assign_params(
        created_timestamp_gte=created_after,
        created_timestamp_lte=created_before,
        last_timestamp_gte=last_detected_after,
        last_timestamp_lte=last_detected_before,
        description=description,
        detection=detection_name,
        detection_type=detection_type,
        detection_category=detection_category,
        include_info_category=include_info_category_detections,
        reason=close_reason,
        state=detection_state,
        tags=",".join(tags),
        type=entity_type,
        is_triaged=is_triaged,
        page=page,
        page_size=page_size,
    )

    return params


def investigation_result_get_command_hr(result: dict):
    """
    Returns the human-readable output for the investigation results details.

    Args:
        entity (Dict): The entity details dictionary.

    Returns:
        str: The human-readable output.
    """
    hr_dict = []

    meta_data = result.get("meta", {}) or {}

    hr_dict.append(
        {
            "Query Status": meta_data.get("query_status", ""),
            "Page Number": meta_data.get("page", ""),
            "Page size": meta_data.get("page_size", ""),
            "Total Rows": meta_data.get("num_rows_available", ""),
            "File Size (bytes)": meta_data.get("estimated_file_size_bytes", ""),
            "Columns": meta_data.get("columns", ""),
        }
    )

    # Prepare human-readable output table
    human_readable = tableToMarkdown(
        f"Investigation Result for Request ID: {result.get('request_id')}",
        hr_dict,
        [
            "Query Status",
            "Page Number",
            "Page size",
            "Total Rows",
            "File Size (bytes)",
            "Columns",
        ],
        removeNull=True,
        json_transform_mapping={"Columns": JsonTransformer()},
    )
    return human_readable


""" COMMAND FUNCTIONS """


def vectra_user_list_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    Retrieves a list of users from the Vectra API.

    Args:
        client (VectraEventsDetectionsClient): The Vectra API client.
        args (Dict[str, Any]): Function arguments.

    Returns:
        CommandResults: The command results containing the entities.
    """
    last_login_timestamp = arg_to_datetime(args.get("last_login_timestamp"), arg_name="last_login_timestamp")
    if last_login_timestamp:
        last_login_timestamp = last_login_timestamp.strftime(DATE_FORMAT)  # type: ignore
    email = args.get("email", "")
    role = args.get("role", "")

    if role and role in USER_ROLE_MAPPING:
        role = USER_ROLE_MAPPING.get(role)
    # Call Vectra API to retrieve users
    response = client.list_users_request(email=email, role=role, last_login_timestamp=last_login_timestamp)
    count = response.get("count")
    if count == 0:
        return CommandResults(outputs={}, readable_output="##### Got the empty list of users.", raw_response=response)
    users = response.get("results")

    # Prepare context data
    human_readable = get_user_list_command_hr(users)  # type: ignore
    context = [createContext(user) for user in remove_empty_elements(users)]  # type: ignore

    return CommandResults(
        outputs_prefix="Vectra.User",
        outputs=context,
        readable_output=human_readable,
        raw_response=users,
        outputs_key_field=["user_id"],
    )


def vectra_entity_list_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    Retrieves a list of entities from the Vectra API.

    Args:
        client (VectraEventsDetectionsClient): The Vectra API client.
        args (Dict[str, Any]): Function arguments.

    Returns:
        CommandResults: The command results containing the entities.

    Raises:
        ValueError: If an invalid entity_type or state value is provided.
    """
    # Validate command args
    validate_entity_list_command_args(args)

    # Get function arguments
    entity_type = args.get("entity_type", "").lower()
    last_detection_timestamp = arg_to_datetime(args.get("last_detection_timestamp"), arg_name="last_detection_timestamp")
    last_modified_timestamp = arg_to_datetime(args.get("last_modified_timestamp"), arg_name="last_modified_timestamp")
    if last_detection_timestamp:
        last_detection_timestamp = last_detection_timestamp.strftime(DATE_FORMAT)  # type: ignore
    if last_modified_timestamp:
        last_modified_timestamp = last_modified_timestamp.strftime(DATE_FORMAT)  # type: ignore
    ordering = args.get("ordering", "")
    page = arg_to_number(args.get("page", "1"), arg_name="page")
    page_size = arg_to_number(args.get("page_size", "50"), arg_name="page_size")
    prioritized = args.get("prioritized", "")
    if prioritized:
        prioritized = argToBoolean(prioritized)
    state = args.get("state", "")
    tags = args.get("tags", "")
    name = args.get("name", "")

    # Call Vectra API to retrieve entities
    response = client.list_entities_request(
        entity_type=entity_type,
        last_detection_timestamp=last_detection_timestamp,
        last_modified_timestamp=last_modified_timestamp,
        ordering=ordering,
        page=page,  # type: ignore
        page_size=page_size,  # type: ignore
        is_prioritized=prioritized,
        state=state,
        tags=tags,
        name=name,
    )
    count = response.get("count")
    if count == 0:
        return CommandResults(
            outputs={}, readable_output="##### Couldn't find any matching entities for provided filters.", raw_response=response
        )
    entities = response.get("results")

    # Prepare context data
    human_readable = get_entity_list_command_hr(entities, page, page_size, count)  # type: ignore
    context = [createContext(entity) for entity in remove_empty_elements(entities)]  # type: ignore

    return CommandResults(
        outputs_prefix="Vectra.Entity",
        outputs=context,
        readable_output=human_readable,
        raw_response=entities,
        outputs_key_field=["id", "type"],
    )


def vectra_entity_describe_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    Describes an entity from the Vectra API.

    Args:
        client (VectraEventsDetectionsClient): The Vectra API client.
        args (Dict[str, Any]): Function arguments.

    Returns:
        CommandResults: The command results containing the entity.

    Raises:
        ValueError: If an invalid entity_type is provided.
    """
    # Get function arguments
    entity_id = arg_to_number(args.get("entity_id"), arg_name="entity_id")
    entity_type = args.get("entity_type", "").lower()

    # Validate entity_id
    validate_positive_integer_arg(entity_id, arg_name="entity_id", required=True)
    # Validate entity_type value
    if not entity_type:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("entity_type"))
    if entity_type not in VALID_ENTITY_TYPE:
        raise ValueError(ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)))

    # Call Vectra API to retrieve entity
    entity = client.get_entity_request(entity_id=entity_id, entity_type=entity_type)  # type: ignore

    human_readable = get_entity_get_command_hr(entity)

    return CommandResults(
        outputs_prefix="Vectra.Entity",
        outputs=createContext(remove_empty_elements(entity)),
        readable_output=human_readable,
        raw_response=entity,
        outputs_key_field=["id", "type"],
    )


def vectra_entity_detection_list_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    Retrieves a list of entity detections from the Vectra API.

    Args:
        client (VectraEventsDetectionsClient): The Vectra API client.
        args (Dict[str, Any]): Function arguments.

    Returns:
        CommandResults: The command results containing the entity detections.

    Raises:
        ValueError: If an invalid entity_type or state value is provided.
    """
    # Validation for args
    validate_list_entity_detections_args(args)

    # Get function arguments
    entity_id = arg_to_number(args.get("entity_id"), arg_name="entity_id")
    entity_type = args.get("entity_type", "").lower()
    detection_category = args.get("detection_category")
    detection_type = args.get("detection_type")
    detection_name = args.get("detection_name")
    state = args.get("state", "active")
    tags = args.get("tags")
    last_timestamp = arg_to_datetime(args.get("last_timestamp"), arg_name="last_timestamp")
    if last_timestamp:
        last_timestamp = last_timestamp.strftime(DATE_FORMAT)  # type: ignore
    page = arg_to_number(args.get("page", "1"), arg_name="page")
    page_size = arg_to_number(args.get("page_size", "50"), arg_name="page_size")
    if detection_category:
        detection_category = DETECTION_CATEGORY_TO_ARG[detection_category]

    entity = client.get_entity_request(entity_id=entity_id, entity_type=entity_type)
    detection_set = entity.get("detection_set", [])
    detections_ids = ",".join([url.split("/")[-1] for url in detection_set]) if detection_set else ""
    if len(detections_ids) == 0:
        return CommandResults(
            outputs={},
            readable_output="##### Couldn't find any matching detections for provided entity ID and type.",
            raw_response={},
        )
    # Used entity_id and entity_type to list detections
    response = client.list_detections_request(
        page=page,
        page_size=page_size,
        detection_category=detection_category,
        detection_type=detection_type,
        detection_name=detection_name,
        last_timestamp=last_timestamp,
        state=state,
        tags=tags,
        entity_id=entity_id,
        entity_type=entity_type,
    )
    count = response.get("count", 0)
    if count == 0:
        return CommandResults(
            outputs={},
            readable_output="##### Couldn't find any matching entity detections for provided filters.",
            raw_response=response,
        )
    detections = response.get("results", {})
    # Remove empty elements from the response
    # Prepare HR
    hr = get_list_entity_detections_command_hr(detections, page, page_size, count)
    # Create context
    context = [createContext(remove_empty_elements(detection)) for detection in detections]  # type: ignore

    return CommandResults(
        outputs_prefix="Vectra.Entity.Detections",
        outputs=context,
        readable_output=hr,
        raw_response=response,
        outputs_key_field="id",
    )


def vectra_detection_describe_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    Describes a list of detections for provided detection IDs from the Vectra API.

    Args:
        client (VectraEventsDetectionsClient): The Vectra API client.
        args (Dict[str, Any]): Function arguments.

    Returns:
        CommandResults: The command results containing the detections.

    Raises:
        ValueError: If an invalid detection_ids or page value is provided.
    """
    # Validation for args
    validate_detection_describe_args(args)

    # Get function arguments
    detection_ids = argToList(args.get("detection_ids"), transform=arg_to_number)
    detection_ids = [detection_id for detection_id in detection_ids if isinstance(detection_id, int)]
    page = arg_to_number(args.get("page", "1"), arg_name="page")
    page_size = arg_to_number(args.get("page_size", "50"), arg_name="page_size")
    # Call Vectra API to retrieve entities
    response = client.list_detections_request(
        ids=",".join([str(detection_id) for detection_id in detection_ids]), state="", page=page, page_size=page_size
    )
    count = response.get("count", 0)
    if count == 0:
        return CommandResults(
            outputs={},
            readable_output="##### Couldn't find any matching detections for provided detection ID(s).",
            raw_response=response,
        )
    detections = response.get("results", {})
    # Prepare HR
    hr = get_list_entity_detections_command_hr(detections, page, page_size, count)
    # Create context
    context = [createContext(remove_empty_elements(detection)) for detection in detections]  # type: ignore

    return CommandResults(
        outputs_prefix="Vectra.Entity.Detections",
        outputs=context,
        readable_output=hr,
        raw_response=response,
        outputs_key_field="id",
    )


def vectra_entity_note_list_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    List entity notes.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): The command arguments provided by the user.

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    validate_entity_note_list_command_args(args)
    # Get function arguments
    entity_id = arg_to_number(args.get("entity_id"), arg_name="entity_id", required=True)
    entity_type = args.get("entity_type", "").lower()

    # Call Vectra API to add entity note
    notes = client.list_entity_note_request(entity_id=entity_id, entity_type=entity_type)  # type: ignore
    notes = remove_empty_elements(notes)
    if notes:
        human_readable = get_list_entity_notes_command_hr(notes, entity_id, entity_type)

        context = [createContext(note) for note in notes]

        return CommandResults(
            outputs_prefix="Vectra.Entity.Notes",
            outputs=context,
            readable_output=human_readable,
            raw_response=notes,
            outputs_key_field=["entity_id", "entity_type", "note_id"],
        )
    else:
        return CommandResults(
            outputs={}, readable_output="##### Couldn't find any notes for provided entity.", raw_response=notes
        )


def vectra_entity_note_add_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    Adds a note to an entity in Vectra API.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): The command arguments provided by the user.

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    validate_entity_note_add_command_args(args)
    # Get function arguments
    entity_id = arg_to_number(args.get("entity_id"), arg_name="entity_id", required=True)
    entity_type = args.get("entity_type", "").lower()
    note = args.get("note")

    # Call Vectra API to add entity note
    notes = client.add_entity_note_request(entity_id=entity_id, entity_type=entity_type, note=note)  # type: ignore
    if notes:
        notes["note_id"] = notes["id"]
        notes.update({"entity_id": entity_id, "entity_type": entity_type})

    human_readable = "##### The note has been successfully added to the entity."
    human_readable += f"\nReturned Note ID: **{notes['note_id']}**"

    return CommandResults(
        outputs_prefix="Vectra.Entity.Notes",
        outputs=createContext(remove_empty_elements(notes)),
        readable_output=human_readable,
        raw_response=notes,
        outputs_key_field=["entity_id", "entity_type", "note_id"],
    )


def vectra_entity_note_update_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    Updates a note to an entity in Vectra API.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): The command arguments provided by the user.

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    validate_entity_note_update_command_args(args)
    # Get function arguments
    entity_id = arg_to_number(args.get("entity_id"), arg_name="entity_id", required=True)
    entity_type = args.get("entity_type", "").lower()
    note = args.get("note")
    note_id = arg_to_number(args.get("note_id"), arg_name="note_id", required=True)

    # Call Vectra API to update entity note
    notes = client.update_entity_note_request(
        entity_id=entity_id,  # type: ignore
        entity_type=entity_type,  # type: ignore
        note=note,  # type: ignore
        note_id=note_id,  # type: ignore
    )
    if notes:
        notes["note_id"] = notes["id"]
        notes.update({"entity_id": entity_id, "entity_type": entity_type})

    human_readable = "##### The note has been successfully updated in the entity."

    return CommandResults(
        outputs_prefix="Vectra.Entity.Notes",
        outputs=createContext(remove_empty_elements(notes)),
        readable_output=human_readable,
        raw_response=notes,
        outputs_key_field=["entity_id", "entity_type", "note_id"],
    )


def vectra_entity_note_remove_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    Updates a note to an entity in Vectra API.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): The command arguments provided by the user.

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    validate_entity_note_remove_command_args(args)
    # Get function arguments
    entity_id = arg_to_number(args.get("entity_id"), arg_name="entity_id", required=True)
    entity_type = args.get("entity_type", "").lower()
    note_id = arg_to_number(args.get("note_id"), arg_name="note_id", required=True)

    # Call Vectra API to remove note
    response = client.remove_entity_note_request(
        entity_id=entity_id,  # type: ignore
        entity_type=entity_type,  # type: ignore
        note_id=note_id,  # type: ignore
    )
    if response.status_code == 204:
        human_readable = "##### The note has been successfully removed from the entity."
    else:
        human_readable = "Something went wrong."
    return CommandResults(outputs={}, readable_output=human_readable)


def vectra_entity_tag_add_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    Add tags to an entity.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): The command arguments provided by the user.

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    validate_entity_tag_add_command_args(args)
    # Get function arguments
    entity_id = arg_to_number(args.get("entity_id"), arg_name="entity_id", required=True)
    entity_type = args.get("entity_type", "").lower()
    tags = [tag.strip() for tag in argToList(args.get("tags", "")) if isinstance(tag, str) and tag.strip()]

    # Call Vectra API to get existing entity tags
    existing_tag_res = client.list_entity_tags_request(entity_id=entity_id, entity_type=entity_type)  # type: ignore
    existing_tag_res_status = existing_tag_res.get("status", "")
    if (
        not existing_tag_res_status
        or not isinstance(existing_tag_res_status, str)
        or existing_tag_res_status.lower() != "success"
    ):
        message = "Something went wrong."
        if existing_tag_res.get("message"):
            message += f" Message: {existing_tag_res.get('message')}."
        raise DemistoException(message)
    tags_resp = existing_tag_res.get("tags", [])
    tags = list(dict.fromkeys(tags_resp + tags))

    res = existing_tag_res
    if len(dict.fromkeys(tags_resp)) != len(tags):
        # Call Vectra API to add entity tags
        res = client.update_entity_tags_request(entity_id=entity_id, entity_type=entity_type, tags=tags)  # type: ignore
        res_status = res.get("status", "")
        if not res_status or not isinstance(res_status, str) or res_status.lower() != "success":
            message = "Something went wrong."
            if res.get("message"):
                message += f" Message: {res.get('message')}."
            raise DemistoException(message)

    human_readable = "##### Tags have been successfully added to the entity."
    tags_resp = res.get("tags", [])
    if tags_resp and isinstance(tags_resp, list):
        tags_resp = [tag.strip() for tag in tags_resp if isinstance(tag, str) and tag.strip()]
        if tags_resp:
            tags_resp = f"**{'**, **'.join(tags_resp)}**"
            human_readable += f"\nUpdated list of tags: {tags_resp}"

    res["entity_type"] = entity_type
    res["entity_id"] = entity_id
    del res["status"]

    return CommandResults(
        outputs_prefix="Vectra.Entity.Tags",
        outputs=createContext(remove_empty_elements(res)),
        readable_output=human_readable,
        raw_response=res,
        outputs_key_field=["tag_id", "entity_type", "entity_id"],
    )


def vectra_entity_tag_remove_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    Removes associated tags for the specified entity using Vectra API.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): The command arguments provided by the user.

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    validate_entity_tag_add_command_args(args)
    # Get function arguments
    entity_id = arg_to_number(args.get("entity_id"), arg_name="entity_id", required=True)
    entity_type = args.get("entity_type", "").lower()
    input_tags = [tag.strip() for tag in argToList(args.get("tags", "")) if isinstance(tag, str) and tag.strip()]

    # Call Vectra API to get existing entity tags
    existing_tag_res = client.list_entity_tags_request(entity_id=entity_id, entity_type=entity_type)  # type: ignore
    existing_tag_res_status = existing_tag_res.get("status", "")
    if (
        not existing_tag_res_status
        or not isinstance(existing_tag_res_status, str)
        or existing_tag_res_status.lower() != "success"
    ):
        message = "Something went wrong."
        if existing_tag_res.get("message"):
            message += f" Message: {existing_tag_res.get('message')}."
        raise DemistoException(message)
    tags_resp = existing_tag_res.get("tags", [])
    # Filtering set of tags from existing tags response with the provide set of input tags
    updated_tags = [tag_resp.strip() for tag_resp in tags_resp if tag_resp.strip() not in input_tags]

    res = existing_tag_res
    # Only update tags if there is any update required with the specified tags
    if len(dict.fromkeys(tags_resp)) != len(updated_tags):
        # Call Vectra API to update entity tags
        res = client.update_entity_tags_request(entity_id=entity_id, entity_type=entity_type, tags=updated_tags)  # type: ignore
        res_status = res.get("status", "")
        if not res_status or not isinstance(res_status, str) or res_status.lower() != "success":
            message = "Something went wrong."
            if res.get("message"):
                message += f" Message: {res.get('message')}."
            raise DemistoException(message)

    human_readable = "##### Specified tags have been successfully removed for the entity."
    tags_resp = res.get("tags", [])
    if tags_resp and isinstance(tags_resp, list):
        tags_resp = [tag.strip() for tag in tags_resp if isinstance(tag, str) and tag.strip()]
        if tags_resp:
            tags_resp = f"**{'**, **'.join(tags_resp)}**"
            human_readable += f"\nUpdated list of tags: {tags_resp}"

    res["entity_type"] = entity_type
    res["entity_id"] = entity_id
    del res["status"]

    return CommandResults(
        outputs_prefix="Vectra.Entity.Tags",
        outputs=createContext(remove_empty_elements(res)),
        readable_output=human_readable,
        raw_response=res,
        outputs_key_field=["tag_id", "entity_type", "entity_id"],
    )


def vectra_entity_tag_list_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    List tags for an entity.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): The command arguments provided by the user.

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    validate_entity_tag_list_command_args(args)
    # Get function arguments
    entity_id = arg_to_number(args.get("entity_id"), arg_name="entity_id", required=True)
    entity_type = args.get("entity_type", "").lower()

    # Call Vectra API to get existing entity tags
    existing_tag_res = client.list_entity_tags_request(entity_id=entity_id, entity_type=entity_type)  # type: ignore
    existing_tag_res_status = existing_tag_res.get("status", "")
    if (
        not existing_tag_res_status
        or not isinstance(existing_tag_res_status, str)
        or existing_tag_res_status.lower() != "success"
    ):
        message = "Something went wrong."
        if existing_tag_res.get("message"):
            message += f" Message: {existing_tag_res.get('message')}."
        raise DemistoException(message)
    tags_resp = existing_tag_res.get("tags", [])

    human_readable = "##### No tags were found for the given entity ID and entity type."
    if tags_resp and isinstance(tags_resp, list):
        tags_resp = [tag.strip() for tag in tags_resp if isinstance(tag, str) and tag.strip()]
        if tags_resp:
            tags_resp = f"**{'**, **'.join(tags_resp)}**"
            human_readable = f"##### List of tags: {tags_resp}"

    existing_tag_res["entity_type"] = entity_type
    existing_tag_res["entity_id"] = entity_id
    del existing_tag_res["status"]

    return CommandResults(
        outputs_prefix="Vectra.Entity.Tags",
        outputs=createContext(remove_empty_elements(existing_tag_res)),
        readable_output=human_readable,
        raw_response=existing_tag_res,
        outputs_key_field=["tag_id", "entity_type", "entity_id"],
    )


def vectra_assignment_list_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    List assignments.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): The command arguments.

    Returns:
        CommandResults: The command results.
    """
    validate_assignment_list_command_args(args)
    # Get function arguments
    entity_ids = args.get("entity_ids")
    entity_type = args.get("entity_type", "").lower()
    resolved = args.get("resolved")
    page = arg_to_number(args.get("page", "1"), arg_name="page")
    page_size = arg_to_number(args.get("page_size", "50"), arg_name="page_size")
    assignees = args.get("assignees")
    resolution = args.get("resolution")
    # Convert argument to value
    if resolved:
        resolved = argToBoolean(resolved)
    created_after = arg_to_datetime(args.get("created_after"), arg_name="created_after")
    if created_after:
        created_after = created_after.strftime(DATE_FORMAT)  # type: ignore
    accounts = None
    hosts = None
    if entity_type == "account":
        accounts = entity_ids
    elif entity_type == "host":
        hosts = entity_ids
    # Call Vectra API for assignment list
    response = client.list_assignments_request(
        account_ids=accounts,
        host_ids=hosts,
        resolved=resolved,
        assignees=assignees,
        resolution=resolution,
        created_after=created_after,  # type: ignore
        page=page,  # type: ignore
        page_size=page_size,
    )  # type: ignore
    response = remove_empty_elements(response)
    count = response.get("count", 0)
    assignments = response.get("results", [])
    if assignments:
        human_readable, assignments = get_assignment_list_command_hr(assignments, page=page, page_size=page_size, count=count)
        context = [createContext(assignment) for assignment in assignments]

        return CommandResults(
            outputs=context,
            readable_output=human_readable,
            raw_response=assignments,
            outputs_prefix="Vectra.Entity.Assignments",
            outputs_key_field=["assignment_id"],
        )
    else:
        return CommandResults(
            outputs={},
            readable_output="##### Couldn't find any matching assignments for provided filters.",
            raw_response=response,
        )


def vectra_entity_assignment_add_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    Create an assignment for specified entity id.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): The command arguments.

    Raises:
        ValueError: If detection_ids argument is missing or empty.

    Returns:
        CommandResults: The command results.
    """
    # Validate command arguments
    validate_entity_assignment_add_command_args(args)
    # Get function arguments
    entity_id = arg_to_number(args.get("entity_id"), arg_name="entity_id")
    entity_type = args.get("entity_type", "").lower()
    user_id = arg_to_number(args.get("user_id"), arg_name="user_id")

    assign_account_id = None
    assign_host_id = None
    if entity_type == "account":
        assign_account_id = entity_id
    elif entity_type == "host":
        assign_host_id = entity_id
    # Call Vectra API to create an assignment
    response = client.add_entity_assignment_request(
        assign_account_id=assign_account_id, assign_host_id=assign_host_id, assign_to_user_id=user_id
    )
    assignment = response.get("assignment", {})
    # Update assignment response
    if assignment:
        assignment["assignment_id"] = assignment["id"]
    human_readable = "##### The assignment has been successfully created.\n"
    human_readable += entity_assignment_add_command_hr(assignment)

    return CommandResults(
        outputs_prefix="Vectra.Entity.Assignments",
        outputs=createContext(remove_empty_elements(assignment)),
        readable_output=human_readable,
        raw_response=assignment,
        outputs_key_field=["assignment_id"],
    )


def vectra_entity_assignment_update_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    Updates an assignment for specified entity id.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): The command arguments.

    Raises:
        ValueError: If detection_ids argument is missing or empty.

    Returns:
        CommandResults: The command results.
    """
    # Validate command arguments
    validate_entity_assignment_update_command_args(args)
    # Get function arguments
    assignment_id = arg_to_number(args.get("assignment_id"), arg_name="assignment_id")
    user_id = arg_to_number(args.get("user_id"), arg_name="user_id")

    # Call Vectra API to update an assignment
    response = client.update_entity_assignment_request(assignment_id=assignment_id, assign_to_user_id=user_id)
    updated_assignment = response.get("assignment", {})
    # Update assignment response
    if updated_assignment:
        updated_assignment["assignment_id"] = updated_assignment["id"]
    human_readable = "##### The assignment has been successfully updated.\n"
    human_readable += entity_assignment_add_command_hr(updated_assignment)

    return CommandResults(
        outputs_prefix="Vectra.Entity.Assignments",
        outputs=createContext(remove_empty_elements(updated_assignment)),
        readable_output=human_readable,
        raw_response=updated_assignment,
        outputs_key_field=["assignment_id"],
    )


def vectra_detection_pcap_download_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    Download the packet capture (PCAP) file associated with a Vectra detection.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): A dictionary containing the arguments for downloading the PCAP file.
            - detection_id (str): The ID of the detection associated with the PCAP file.

    Returns:
        fileResult: A fileResult object containing the downloaded PCAP file content.
    """
    detection_id = args.get("detection_id")
    # Validate detection id
    validate_positive_integer_arg(detection_id, arg_name="detection_id", required=True)

    # Call Vectra API to download detection pcap
    response = client.download_detection_pcap_request(detection_id=detection_id)
    content_disposition = response.headers.get("Content-Disposition", "")
    file_name = content_disposition.split(";")[1].replace("filename=", "").replace('"', "")

    return fileResult(filename=file_name, data=response.content)


def vectra_group_list_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    Retrieves a list of groups.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): The command arguments provided by the user.

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    validate_group_list_command_args(args)

    # Get function arguments
    group_type = args.get("group_type") or ""
    if group_type:
        group_type = group_type.lower()
    importance = args.get("importance") or ""
    if importance:
        importance = importance.lower()
    account_names = argToList(args.get("account_names") or "")
    domains = argToList(args.get("domains") or "")
    host_ids = argToList(args.get("host_ids") or "")
    host_names = argToList(args.get("host_names") or "")
    ips = argToList(args.get("ips") or "")
    description = args.get("description") or ""
    last_modified_timestamp = arg_to_datetime(args.get("last_modified_timestamp"), arg_name="last_modified_timestamp")
    last_modified_by = args.get("last_modified_by") or ""
    group_name = args.get("group_name") or ""

    # Call Vectra API to get groups
    response = client.list_group_request(
        group_type=group_type,
        account_names=account_names,
        domains=domains,
        host_ids=host_ids,
        host_names=host_names,
        importance=importance,
        ips=ips,
        description=description,
        last_modified_timestamp=last_modified_timestamp,
        last_modified_by=last_modified_by,
        group_name=group_name,
    )  # type: ignore
    count = response.get("count")
    if count == 0:
        return CommandResults(
            outputs={}, readable_output="##### Couldn't find any matching groups for provided filters.", raw_response=response
        )
    groups = response.get("results")

    # Prepare context data
    human_readable = get_group_list_command_hr(groups)  # type: ignore
    context = [createContext(group) for group in remove_empty_elements(groups)]  # type: ignore

    return CommandResults(
        outputs_prefix="Vectra.Group",
        outputs=context,
        readable_output=human_readable,
        raw_response=groups,
        outputs_key_field=["group_id"],
    )


def vectra_group_unassign_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    Unassign members in Group.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): The command arguments.

    Returns:
        CommandResults: The command results.
    """
    validate_group_assign_and_unassign_command_args(args)
    group_id = args.get("group_id")
    members = args.get("members")

    # Call to get group details
    group = client.get_group_request(group_id=group_id)
    group_type = group.get("type")
    updated_members = group_members = group.get("members")
    members_list = argToList(members)
    removed_members = []

    if group_type.lower() == "ip" or group_type.lower() == "domain":  # type: ignore
        for member in members_list:
            if member in group_members:  # type: ignore
                removed_members.append(member)
                updated_members.remove(member)  # type: ignore
    elif group_type.lower() == "account":  # type: ignore
        uids = [i.get("uid") for i in group_members]  # type: ignore
        for member in members_list:
            if member in uids:
                removed_members.append(member)
                uids.remove(member)
        updated_members = uids
    elif group_type.lower() == "host":  # type: ignore
        ids = [str(i.get("id")) for i in group_members]  # type: ignore
        for member in members_list:
            if member in ids:
                removed_members.append(member)
                ids.remove(member)
        updated_members = ids
    if not removed_members:
        members_list = [re.escape(member) for member in members_list]
        hr_string = f"##### Member(s) {', '.join(members_list)} do not exist in the group."
        return CommandResults(readable_output=hr_string)
    # Call Vectra API to unassign members in group
    res = client.update_group_members_request(group_id=group_id, members=updated_members)
    updated_group = remove_empty_elements(res)

    human_readable = get_group_unassign_and_assign_command_hr(
        group=updated_group, changed_members=removed_members, assign_flag=False
    )

    return CommandResults(
        outputs_prefix="Vectra.Group",
        outputs=createContext(updated_group),
        readable_output=human_readable,
        raw_response=updated_group,
        outputs_key_field=["group_id"],
    )


def vectra_group_assign_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    Assign members in Group.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): The command arguments.

    Returns:
        CommandResults: The command results.
    """
    validate_group_assign_and_unassign_command_args(args)
    group_id = args.get("group_id")
    members = args.get("members")

    # Call to get group details
    group = client.get_group_request(group_id=group_id)
    group_type = group.get("type")
    updated_members = group_members = group.get("members")
    members_list = argToList(members)
    added_members = []

    if group_type.lower() == "ip" or group_type.lower() == "domain":  # type: ignore
        for member in members_list:
            if member not in group_members:  # type: ignore
                added_members.append(member)
                updated_members.append(member)  # type: ignore
    elif group_type.lower() == "account":  # type: ignore
        uids = [i.get("uid") for i in group_members]  # type: ignore
        for member in members_list:
            if member not in uids:
                added_members.append(member)
                uids.append(member)
        updated_members = uids
    elif group_type.lower() == "host":  # type: ignore
        ids = [str(i.get("id")) for i in group_members]  # type: ignore
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

    human_readable = get_group_unassign_and_assign_command_hr(
        group=updated_group, changed_members=added_members, assign_flag=True
    )

    return CommandResults(
        outputs_prefix="Vectra.Group",
        outputs=createContext(updated_group),
        readable_output=human_readable,
        raw_response=updated_group,
        outputs_key_field=["group_id"],
    )


def vectra_entity_detections_mark_asclosed_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    Mark the provided entity detections as closed.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): The command arguments.

    Raises:
        ValueError: If entity_id, entity_type, or close_reason arguments are missing or invalid.

    Returns:
        CommandResults: The command results.
    """
    validate_entity_detections_mark_asclosed_command_args(args)
    # Get function arguments
    entity_id = args.get("entity_id")
    entity_type = args.get("entity_type", "").lower()
    close_reason = args.get("close_reason", "").lower()

    # Get entity details to retrieve detection IDs
    response = client.get_entity_request(entity_id=entity_id, entity_type=entity_type)
    detection_set = response.get("detection_set")
    detection_ids = [url.split("/")[-1] for url in detection_set] if detection_set else []

    hr_string = f"There are no active detections to mark as closed for this entity ID: {entity_id}."
    if not detection_ids:
        return CommandResults(readable_output=hr_string)

    # Call Vectra API to close detections
    res = client.close_detections_request(detection_ids=detection_ids, reason=close_reason)
    res_message = res.get("_meta", {}).get("message", "")
    if res.get("_meta", {}).get("level").lower() == "success" and "successfully closed detections" in res_message.lower():
        client.update_detection_status_request(ids_list=detection_ids, status="closed")
        human_readable = (
            f"##### The detections ({', '.join(detection_ids)}) of the provided entity ID have been"
            f" successfully closed as {close_reason}."
        )
    else:
        message = "Something went wrong."
        if res_message:
            message += f" Message: {res_message}."
        raise DemistoException(message)

    return CommandResults(readable_output=human_readable)


def vectra_detections_mark_asopen_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    Open detection with provided detection IDs.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): The command arguments.

    Raises:
        ValueError: If detection_ids argument is missing or empty.

    Returns:
        CommandResults: The command results.
    """
    # Get function arguments
    detection_ids = args.get("detection_ids")
    # Convert string into list
    detection_ids_list = argToList(detection_ids)

    # Validate detection_ids
    if not detection_ids_list:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("detection_ids"))
    all(validate_positive_integer_arg(detection_id, arg_name="detection_ids") for detection_id in detection_ids_list)

    # Call Vectra API to open detections
    res = client.open_detections_request(detection_ids_list)

    res_message = res.get("_meta", {}).get("message", "")
    if res.get("_meta", {}).get("level", "").lower() == "success" and "successfully re-opened detections" in res_message.lower():
        client.update_detection_status_request(ids_list=detection_ids_list, status="open")
        human_readable = "##### The provided detection IDs have been successfully re-opened."
    else:
        message = "Something went wrong."
        if res_message:
            message += f" Message: {res_message}."
        raise DemistoException(message)

    return CommandResults(readable_output=human_readable)


def vectra_detection_tag_list_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    List tags for a detection.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): The command arguments provided by the user.

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    detection_id = args.get("detection_id")
    # Validate detection_id value
    validate_positive_integer_arg(detection_id, arg_name="detection_id", required=True)

    # Get function arguments
    detection_id = arg_to_number(detection_id)

    # Call Vectra API to get existing detection tags
    existing_tag_res = client.list_detection_tags_request(detection_id=detection_id)  # type: ignore
    existing_tag_res_status = existing_tag_res.get("status", "")
    if (
        not existing_tag_res_status
        or not isinstance(existing_tag_res_status, str)
        or existing_tag_res_status.lower() != "success"
    ):
        message = "Something went wrong."
        if existing_tag_res.get("message"):
            message += f" Message: {existing_tag_res.get('message')}."
        raise DemistoException(message)

    tags_resp = existing_tag_res.get("tags", [])

    human_readable = "##### No tags were found for the given detection ID."

    if tags_resp and isinstance(tags_resp, list):
        tags_resp = [tag.strip() for tag in tags_resp if isinstance(tag, str) and tag.strip()]
        if tags_resp:
            tags_resp_formatted = f"**{', '.join(tags_resp)}**"
            human_readable = f"##### List of tags: {tags_resp_formatted}"

    existing_tag_res["detection_id"] = detection_id
    del existing_tag_res["status"]

    return CommandResults(
        outputs_prefix="Vectra.Detection.Tags",
        outputs=createContext(remove_empty_elements(existing_tag_res)),
        readable_output=human_readable,
        raw_response=existing_tag_res,
        outputs_key_field=["tag_id", "detection_id"],
    )


def vectra_detection_tag_add_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    Add tags to a detection.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): The command arguments provided by the user.

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    validate_detection_tag_add_command_args(args)
    # Get function arguments
    detection_id = arg_to_number(args.get("detection_id"), arg_name="detection_id", required=True)
    tags = [tag.strip() for tag in argToList(args.get("tags", "")) if isinstance(tag, str) and tag.strip()]

    existing_tag_res = client.list_detection_tags_request(detection_id=detection_id)  # type: ignore
    existing_tag_res_status = existing_tag_res.get("status", "")
    if (
        not existing_tag_res_status
        or not isinstance(existing_tag_res_status, str)
        or existing_tag_res_status.lower() != "success"
    ):
        message = "Something went wrong."
        if existing_tag_res.get("message"):
            message += f" Message: {existing_tag_res.get('message')}."
        raise DemistoException(message)

    tags_resp = existing_tag_res.get("tags", [])
    tags = list(dict.fromkeys(tags_resp + tags))

    res = existing_tag_res
    if len(dict.fromkeys(tags_resp)) != len(tags):
        # Call Vectra API to add detection tags
        res = client.update_detection_tags_request(detection_id=detection_id, tags=tags)  # type: ignore
        res_status = res.get("status", "")
        if not res_status or not isinstance(res_status, str) or res_status.lower() != "success":
            message = "Something went wrong."
            if res.get("message"):
                message += f" Message: {res.get('message')}."
            raise DemistoException(message)

    human_readable = "##### Tags have been successfully added to the detection."
    tags_resp = res.get("tags", [])
    if tags_resp and isinstance(tags_resp, list):
        tags_resp = [tag.strip() for tag in tags_resp if isinstance(tag, str) and tag.strip()]
        if tags_resp:
            tags_resp = f"**{'**, **'.join(tags_resp)}**"
            human_readable += f"\nUpdated list of tags: {tags_resp}"

    res["detection_id"] = detection_id
    del res["status"]

    return CommandResults(
        outputs_prefix="Vectra.Detection.Tags",
        outputs=createContext(remove_empty_elements(res)),
        readable_output=human_readable,
        raw_response=res,
        outputs_key_field=["tag_id", "detection_id"],
    )


def vectra_detection_tag_remove_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    Removes associated tags for the specified detection using Vectra API.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): The command arguments provided by the user.

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    validate_detection_tag_add_command_args(args)
    # Get function arguments
    detection_id = arg_to_number(args.get("detection_id"), arg_name="detection_id", required=True)
    input_tags = [tag.strip() for tag in argToList(args.get("tags", "")) if isinstance(tag, str) and tag.strip()]

    # Call Vectra API to get existing detection tags
    existing_tag_res = client.list_detection_tags_request(detection_id=detection_id)  # type: ignore
    existing_tag_res_status = existing_tag_res.get("status", "")
    if (
        not existing_tag_res_status
        or not isinstance(existing_tag_res_status, str)
        or existing_tag_res_status.lower() != "success"
    ):
        message = "Something went wrong."
        if existing_tag_res.get("message"):
            message += f" Message: {existing_tag_res.get('message')}."
        raise DemistoException(message)
    tags_resp = existing_tag_res.get("tags", [])
    # Filtering set of tags from existing tags response with the provide set of input tags
    updated_tags = [tag.strip() for tag in tags_resp if tag.strip() not in input_tags]

    res = existing_tag_res
    # Only update tags if there is any update required with the specified tags
    if len(dict.fromkeys(tags_resp)) != len(updated_tags):
        # Call Vectra API to update detection tags
        res = client.update_detection_tags_request(detection_id=detection_id, tags=updated_tags)  # type: ignore
        res_status = res.get("status", "")
        if not res_status or not isinstance(res_status, str) or res_status.lower() != "success":
            message = "Something went wrong."
            if res.get("message"):
                message += f" Message: {res.get('message')}."
            raise DemistoException(message)

    human_readable = "##### Specified tags have been successfully removed for the detection."
    tags_resp = res.get("tags", [])
    if tags_resp and isinstance(tags_resp, list):
        tags_resp = [tag.strip() for tag in tags_resp if isinstance(tag, str) and tag.strip()]
        if tags_resp:
            tags_resp = f"**{'**, **'.join(tags_resp)}**"
            human_readable += f"\nUpdated list of tags: {tags_resp}"

    res["detection_id"] = detection_id
    del res["status"]

    return CommandResults(
        outputs_prefix="Vectra.Detection.Tags",
        outputs=createContext(remove_empty_elements(res)),
        readable_output=human_readable,
        raw_response=res,
        outputs_key_field=["tag_id", "detection_id"],
    )


def vectra_detection_note_list_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    List detection notes.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict[str, Any]): The command arguments provided by the user.

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    validate_detection_note_list_command_args(args)
    # Get function arguments
    detection_id = arg_to_number(args.get("detection_id"), arg_name="detection_id", required=True)

    # Call Vectra API to list detection notes
    notes = client.list_detection_note_request(detection_id=detection_id)  # type: ignore
    notes = remove_empty_elements(notes)
    if notes:
        human_readable = get_list_detection_notes_command_hr(notes, detection_id)

        context = [createContext(note) for note in notes]

        return CommandResults(
            outputs_prefix="Vectra.Detection.Notes",
            outputs=context,
            readable_output=human_readable,
            raw_response=notes,
            outputs_key_field=["detection_id", "note_id"],
        )
    else:
        return CommandResults(
            outputs={}, readable_output="##### Couldn't find any notes for provided detection.", raw_response=notes
        )


def vectra_detection_note_add_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    Adds a note to a detection in Vectra API.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict[str, Any]): The command arguments provided by the user.

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    validate_detection_note_add_command_args(args)
    # Get function arguments
    detection_id = arg_to_number(args.get("detection_id"), arg_name="detection_id", required=True)
    note = args.get("note")

    # Call Vectra API to add detection note
    notes = client.add_detection_note_request(detection_id=detection_id, note=note)  # type: ignore
    if notes:
        notes["note_id"] = notes["id"]
        notes.update({"detection_id": detection_id})

    human_readable = "##### The note has been successfully added to the detection."
    human_readable += f"\nReturned Note ID: **{notes['note_id']}**"

    return CommandResults(
        outputs_prefix="Vectra.Detection.Notes",
        outputs=createContext(remove_empty_elements(notes)),
        readable_output=human_readable,
        raw_response=notes,
        outputs_key_field=["detection_id", "note_id"],
    )


def vectra_detection_note_update_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    Updates a note to a detection in Vectra API.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict[str, Any]): The command arguments provided by the user.

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    validate_detection_note_update_command_args(args)
    # Get function arguments
    detection_id = arg_to_number(args.get("detection_id"), arg_name="detection_id", required=True)
    note = args.get("note")
    note_id = arg_to_number(args.get("note_id"), arg_name="note_id", required=True)

    # Call Vectra API to update detection note
    notes = client.update_detection_note_request(
        detection_id=detection_id,  # type: ignore
        note=note,  # type: ignore
        note_id=note_id,  # type: ignore
    )
    if notes:
        notes["note_id"] = notes["id"]
        notes.update({"detection_id": detection_id})

    human_readable = "##### The note has been successfully updated in the detection."

    return CommandResults(
        outputs_prefix="Vectra.Detection.Notes",
        outputs=createContext(remove_empty_elements(notes)),
        readable_output=human_readable,
        raw_response=notes,
        outputs_key_field=["detection_id", "note_id"],
    )


def vectra_detection_note_remove_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
    """
    Removes a note from a detection

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict[str, Any]): The command arguments provided by the user.

    Returns:
        CommandResults: The command results containing the outputs, readable output, raw response, and outputs key field.
    """
    validate_detection_note_remove_command_args(args)
    # Get function arguments
    detection_id = arg_to_number(args.get("detection_id"), arg_name="detection_id", required=True)
    note_id = arg_to_number(args.get("note_id"), arg_name="note_id", required=True)

    # Call Vectra API to remove note
    response = client.remove_detection_note_request(
        detection_id=detection_id,  # type: ignore
        note_id=note_id,  # type: ignore
    )
    if response.status_code == 204:
        human_readable = "##### The note has been successfully removed from the detection."
    else:
        human_readable = "Something went wrong."
    return CommandResults(outputs={}, readable_output=human_readable)


def validate_fetch_params(params: dict[str, Any], last_run: dict[str, Any], is_test: bool = False) -> dict[str, Any]:
    """
    Validates the fetch parameters.

    Args:
        params (dict[str, Any]): Fetch parameters.
        last_run (dict[str, Any]): Last run object.
        is_test (bool): Indicates whether to test the module.
    Returns:
        dict[str, Any]: Validated fetch parameters.
    """
    first_fetch = params.get("first_fetch", FIRST_FETCH).strip()
    first_fetch_time = arg_to_datetime(first_fetch, arg_name="First Fetch Time").strftime(DATE_FORMAT)  # type: ignore
    max_fetch_ = arg_to_number(params.get("max_fetch", MAX_FETCH), arg_name="Max Fetch")
    entity_types = argToList(params.get("entity_types", DEFAULT_ENTITY_TYPES), transform=lambda x: x.strip())
    only_prioritized_detections = argToBoolean(params.get("only_prioritized_detections", DEFAULT_ONLY_PRIORITIZED_DETECTIONS))
    only_escalated_detections = argToBoolean(params.get("only_escalated_detections", DEFAULT_ONLY_ESCALATED_DETECTIONS))

    if max_fetch_ < 1:  # type: ignore
        raise ValueError(ERRORS["INVALID_MAX_FETCH"].format(max_fetch_))
    if max_fetch_ > MAX_FETCH:  # type: ignore
        if is_test:
            raise ValueError(ERRORS["INVALID_MAX_FETCH"].format(max_fetch_))
        else:
            demisto.debug(
                f"The max fetch value is {max_fetch_}, "
                "which is greater than the maximum allowed value of "
                f"{MAX_FETCH}. Setting it to {MAX_FETCH}."
            )
    max_fetch = min(MAX_FETCH, max_fetch_)  # type: ignore

    valid_entity_types = []
    for entity_type in entity_types:
        if entity_type not in VALID_ENTITY_TYPES and is_test:
            raise ValueError(ERRORS["INVALID_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPES)))
        elif entity_type in VALID_ENTITY_TYPES:
            valid_entity_types.append(entity_type.lower())
        else:
            demisto.debug(f"The entity type: {entity_type} is not valid. Skipping it.")

    if not valid_entity_types:
        valid_entity_types = argToList(DEFAULT_ENTITY_TYPES.lower())

    if only_escalated_detections and not only_prioritized_detections:
        detection_statuses = ["escalated"]
    else:
        detection_statuses = list(DEFAULT_FETCH_DETECTION_STATUS)

    if only_prioritized_detections and not only_escalated_detections:
        unresolved_priority_status = True
    else:
        unresolved_priority_status = ""  # type: ignore

    event_timestamp_gte = last_run.get("event_timestamp", first_fetch_time)
    _from = last_run.get("from", "")
    valid_entity_types.sort()
    detection_statuses.sort()

    params = assign_params(
        type=",".join(valid_entity_types),
        investigation_status=",".join(detection_statuses),
        unresolved_priority=unresolved_priority_status,
        limit=max_fetch,
        ordering="id",
        event_timestamp_gte=event_timestamp_gte,
        include_info_category=True,
        size="detailed",
        include_triaged=False,
    )

    prev_entity_types = last_run.get("selected_types", "")
    prev_detection_statuses = last_run.get("selected_statuses", "")
    prev_unresolved_priority = last_run.get("unresolved_priority", "")

    if (
        prev_entity_types == params.get("type", "")
        and prev_detection_statuses == params.get("investigation_status", "")
        and prev_unresolved_priority == params.get("unresolved_priority", "")
    ):
        params["from"] = _from
    else:
        demisto.debug("Change detected in filter configuration parameters. Resetting 'from' API parameter.")

    remove_nulls_from_dictionary(params)

    return params


def map_severity(urgency_score: int) -> float:
    """
    Maps the severity to the incident severity.

    Args:
        urgency_score (int): The urgency score to map.

    Returns:
        float: The incident severity.
    """
    if urgency_score > 80:
        return 4
    elif urgency_score > 50:
        return 3
    elif urgency_score > 30:
        return 2
    elif urgency_score > 0:
        return 1
    else:
        return 0.5


def get_mirroring() -> dict:
    """
    Get the mirroring configuration parameters from the Demisto integration parameters.

    :return: A dictionary containing the mirroring configuration parameters.
    :rtype: dict
    """
    params = demisto.params()
    mirror_direction = params.get("mirror_direction", "None").strip()
    mirror_tags = params.get("note_tag", "").strip()
    return {
        "mirror_direction": MIRROR_DIRECTION.get(mirror_direction),
        "mirror_instance": demisto.integrationInstance(),
        "mirror_tags": mirror_tags,
    }


def get_valid_and_dropped_tags(tags: list[str]) -> tuple[list[str], list[str]]:
    """
    Return (valid_tags, dropped_tags) using TAG_REGEX.fullmatch().

    Note: does not strip/mutate inputs. If you want trimming, do it before calling.
    """
    valid: list[str] = []
    invalid: list[str] = []
    for t in tags:
        if TAGS_REGEX.fullmatch(t):
            valid.append(t)
        else:
            invalid.append(t)
    if invalid:
        demisto.debug(f"Dropping invalid tags which contains invalid characters: {invalid}")
    demisto.debug(f"Provided Valid tags(s): {valid}")
    return valid, invalid


def multiline_logs_for_list(array: list, prefix: str = ""):
    """
    Logs a list of items with a prefix, batched into 50 items per log message.

    :type array: list
    :param array: List of items to be logged.

    :type prefix: str
    :param prefix: String to be prefixed to the log message.
    """
    for b in batch(array, batch_size=200):
        demisto.debug(f"{prefix}{b}")


def vectra_entity_unresolved_priority_reset_command(client: VectraEventsDetectionsClient, args: dict[str, Any]) -> CommandResults:
    """
    Updates the priority of an unresolved entity as false.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): Command arguments.
    Returns:
        CommandResults: A CommandResults object containing the updated entity.
    """
    entity_id = args.get("entity_id")
    entity_type = args.get("entity_type")

    validate_positive_integer_arg(entity_id, arg_name="entity_id", required=True)

    if not entity_type:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("entity_type"))

    if entity_type and entity_type.lower() not in VALID_ENTITY_TYPE:
        raise ValueError(ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)))

    result = client.update_entity_unresolved_priority_status_request(
        entity_id=str(entity_id),
        entity_type=entity_type.lower(),
        unresolved_priority="False",
    )

    output_context = {"id": entity_id, "type": entity_type, "unresolved_priority": False}

    human_readable = "##### The unresolved priority of the provided entity has been successfully changed as 'false'."

    return CommandResults(
        outputs_prefix="Vectra.Entity",
        outputs_key_field=["id", "type"],
        outputs=output_context,
        readable_output=human_readable,
        raw_response=result,
    )


def vectra_detection_investigation_status_update_command(
    client: VectraEventsDetectionsClient, args: dict[str, Any]
) -> CommandResults:
    """
    Update the investigation status of the detection by detection IDs.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): Command arguments.
    Returns:
        CommandResults: A CommandResults object containing the updated detection.
    """
    detection_ids = argToList(args.get("detection_ids"), transform=lambda x: x.strip())
    investigation_status = args.get("investigation_status")

    if not detection_ids:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("detection_ids"))
    valid_detection_ids = []
    invalid_detection_ids = []
    for detection_id in detection_ids:
        if detection_id is not None and (not detection_id.isdigit() or int(detection_id) <= 0):
            invalid_detection_ids.append(detection_id)
        elif detection_id:
            valid_detection_ids.append(detection_id)

    if not valid_detection_ids:
        raise DemistoException(ERRORS["INVALID_INTEGER_VALUE"].format("detection_ids", ",".join(invalid_detection_ids)))

    if invalid_detection_ids:
        return_warning(
            message=ERRORS["INVALID_INTEGER_VALUE"].format("detection_ids", ",".join(invalid_detection_ids)),
            exit=(not valid_detection_ids),
        )

    if not investigation_status:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("investigation_status"))

    if investigation_status and investigation_status.lower() not in [status.lower() for status in VALID_DETECTION_STATUS]:
        raise ValueError(
            ERRORS["INVALID_ARG_VALUE"].format(
                "investigation_status", ", ".join([status.lower() for status in VALID_DETECTION_STATUS])
            )
        )

    result = client.update_detection_status_request(
        ids_list=valid_detection_ids,
        status=investigation_status,
    )

    output_context = [{"id": detection_id, "investigation_status": investigation_status} for detection_id in valid_detection_ids]

    human_readable = (
        f"##### The investigation status for provided Detection ID(s) {valid_detection_ids} "
        f"have been updated as {investigation_status}."
    )

    return CommandResults(
        outputs_prefix="Vectra.Detection",
        outputs_key_field="id",
        outputs=output_context,
        readable_output=human_readable,
        raw_response=result,
    )


def vectra_detection_external_id_update_command(client: VectraEventsDetectionsClient, args: dict[str, Any]) -> CommandResults:
    """
    Update the external reference ID for the detection by detection ID(s).

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): Command arguments.
    Returns:
        CommandResults: A CommandResults object containing the updated detection.
    """
    detection_ids = argToList(args.get("detection_ids"), transform=lambda x: x.strip())
    external_reference_id = args.get("external_reference_id")

    if not detection_ids:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("detection_ids"))
    valid_detection_ids = []
    invalid_detection_ids = []
    for detection_id in detection_ids:
        if detection_id is not None and (not detection_id.isdigit() or int(detection_id) <= 0):
            invalid_detection_ids.append(detection_id)
        elif detection_id:
            valid_detection_ids.append(detection_id)

    if not valid_detection_ids:
        raise DemistoException(ERRORS["INVALID_INTEGER_VALUE"].format("detection_ids", ",".join(invalid_detection_ids)))

    if invalid_detection_ids:
        return_warning(
            message=ERRORS["INVALID_INTEGER_VALUE"].format("detection_ids", ",".join(invalid_detection_ids)),
            exit=(not valid_detection_ids),
        )

    if not external_reference_id:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("external_reference_id"))

    result = client.update_detection_external_id_request(
        ids_list=valid_detection_ids,
        external_reference_id=external_reference_id,
    )

    output_context = [
        {"id": detection_id, "external_reference_id": external_reference_id} for detection_id in valid_detection_ids
    ]

    human_readable = (
        f"##### The external reference ID for provided Detection ID(s) {valid_detection_ids} "
        f"have been updated as {external_reference_id}."
    )

    return CommandResults(
        outputs_prefix="Vectra.Detection",
        outputs_key_field="id",
        outputs=output_context,
        readable_output=human_readable,
        raw_response=result,
    )


def vectra_entity_external_id_update_command(client: VectraEventsDetectionsClient, args: dict[str, Any]) -> CommandResults:
    """
    Updates the external reference ID for the provided entity.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): Command arguments.

    Returns:
        CommandResults: A CommandResults object containing the updated entity.
    """
    entity_id = args.get("entity_id")
    entity_type = args.get("entity_type")
    external_reference_id = args.get("external_reference_id")

    validate_positive_integer_arg(entity_id, arg_name="entity_id", required=True)

    if not entity_type:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("entity_type"))

    if entity_type and entity_type.lower() not in VALID_ENTITY_TYPE:
        raise ValueError(ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)))

    if not external_reference_id:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("external_reference_id"))

    result = client.update_entity_external_id_request(
        entity_id=int(entity_id),  # type: ignore
        entity_type=entity_type,
        external_reference_id=external_reference_id,
    )

    output_context = {
        "id": entity_id,
        "type": entity_type,
        "external_reference_id": external_reference_id,
    }

    human_readable = f"##### The external reference ID for provided Entity have been updated as {external_reference_id}."

    return CommandResults(
        outputs_prefix="Vectra.Entity",
        outputs_key_field=["id", "type"],
        outputs=output_context,
        readable_output=human_readable,
        raw_response=result,
    )


def vectra_investigation_query_send_command(client: VectraEventsDetectionsClient, args: dict[str, Any]) -> CommandResults:
    """
    Submit an investigation query.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): Command arguments.

    Returns:
        CommandResults: A CommandResults object containing the updated entity.
    """
    query = args.get("query")
    version = args.get("version")

    if not query:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("query"))

    result = client.investigation_query_send(
        query=query,
        version=version,
    )
    remove_nulls_from_dictionary(result)

    human_readable = (
        "##### The Vectra investigation has started. You can view the result by executing the below command:\n\n"
        f"!vectra-investigation-result-get id={result.get('request_id')}"
    )

    return CommandResults(
        outputs_prefix="Vectra.Investigation",
        outputs_key_field="request_id",
        outputs=result,
        readable_output=human_readable,
        raw_response=result,
    )


def vectra_investigation_result_get_command(client: VectraEventsDetectionsClient, args: dict[str, Any]) -> CommandResults:
    """
    Retrieve the results of a previously submitted investigation using the request ID.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict[str, Any]): Command arguments.

    Returns:
        CommandResults: A CommandResults object containing the investigation results.
    """
    request_id = args.get("id")
    page = arg_to_number(args.get("page", MAX_PAGE))
    page_size = arg_to_number(args.get("page_size", MAX_PAGE_SIZE))
    validate_positive_integer_arg(page, arg_name="page")
    validate_positive_integer_arg(page_size, arg_name="page_size")

    if not request_id:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("id"))

    result = client.investigation_result_get(
        request_id=request_id,
        page=page,  # type: ignore
        page_size=page_size,  # type: ignore
    )
    remove_nulls_from_dictionary(result)

    human_readable = investigation_result_get_command_hr(result)
    human_readable += tableToMarkdown("Investigation Results Data:", result.get("data", []))

    return CommandResults(
        outputs_prefix="Vectra.Investigation",
        outputs_key_field="request_id",
        outputs=result,
        readable_output=human_readable,
        raw_response=result,
    )


def test_module(client: VectraEventsDetectionsClient, params: dict[str, Any]) -> str:
    """
    Tests the connection to the Vectra server.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        params (Dict[str, Any]): Test module parameters.
    Returns:
        str: A message indicating the success of the test.
    """
    if argToBoolean(params.get("isFetch", False)):
        fetch_incidents(client, params, last_run={}, is_test=True)
    else:
        client.list_events_detections_request(params=assign_params(limit=1))
    return "ok"


def fetch_incidents(
    client: VectraEventsDetectionsClient,
    params: dict[str, Any],
    last_run: dict[str, Any],
    is_test: bool = False,
) -> tuple[list, dict]:
    """
    Fetches incidents from the Vectra Events Detections API.

    Args:
        client (VectraEventsDetectionsClient): Vectra client object.
        params (dict[str, Any]): Fetch incidents parameters.
        last_run (dict[str, Any]): Last run object.
        is_test (bool): Indicates whether to test the connection to the Vectra server.

    Returns:
        tuple[list, dict]: List of fetched incidents and the last run object.
    """

    fetch_params = validate_fetch_params(params, last_run, is_test)
    demisto_incidents: list = []
    new_last_run = last_run
    latest_timestamp = last_run.get("event_timestamp", "")

    only_prioritized_detections = argToBoolean(params.get("only_prioritized_detections", DEFAULT_ONLY_PRIORITIZED_DETECTIONS))
    only_escalated_detections = argToBoolean(params.get("only_escalated_detections", DEFAULT_ONLY_ESCALATED_DETECTIONS))

    try:
        response = client.list_events_detections_request(params=fetch_params)
    except DemistoException as e:
        demisto.debug(f"Error fetching events detections: {str(e)}")
        raise e

    if is_test:
        return [], {}

    # Retrieve the already fetched IDs from the last run
    already_fetched = new_last_run.get("was_fetched", [])
    events = remove_empty_elements_for_fetch(response.get("events", []))

    # Process events and create incidents
    if events:
        for event in events:
            # Extract detection ID
            detection_id = event.get("detection_id")
            # Check if the detection is already fetched
            if detection_id in already_fetched:
                demisto.debug(f"Skipping event {detection_id} as it is already fetched")
                continue

            if (
                only_prioritized_detections
                and only_escalated_detections
                and not event.get("unresolved_priority", "")
                and event.get("investigation_status", "").lower() != "escalated"
            ):
                demisto.debug(f"Skipping event {detection_id} as it is not escalated and not event prioritized")
                continue

            detection_href = event.get("detection_href", "")
            if detection_href:
                event["detection_href"] = trim_api_version(detection_href)
            entity_url = event.get("url", "")
            if entity_url:
                event["url"] = trim_api_version(entity_url)

            if event.get("dst_host") and event.get("dst_host", {}).get("url"):
                event["dst_host"]["url"] = trim_api_version(event.get("dst_host", {}).get("url"))
            if event.get("dst_account") and event.get("dst_account", {}).get("url"):
                event["dst_account"]["url"] = trim_api_version(event.get("dst_account", {}).get("url"))

            detection_timestamp = event.get("detail", {}).get("first_timestamp", "")
            occurred_time = detection_timestamp if detection_timestamp else event.get("event_timestamp")
            if occurred_time and occurred_time[-1].lower() != "z":
                occurred_time = occurred_time + "Z"

            # Updating mirroring fields
            mirroring_fields = get_mirroring()
            mirroring_fields.update({"mirror_id": detection_id})
            event.update(mirroring_fields)

            # Create incident name
            detection_type = event.get("detection_type", "")
            entity_name = event.get("entity_name", "")
            category = event.get("category", "").title()

            incident_name = "Vectra RUX:"
            incident_name += f" {category}" if category else ""
            incident_name += " -" if detection_type else ""
            incident_name += f" {detection_type}" if detection_type else ""
            incident_name += " -" if entity_name else ""
            incident_name += f" {entity_name}" if entity_name else ""

            source = event.get("src_account", {})
            if source:
                urgency_score = source.get("urgency_score", 0)
            else:
                urgency_score = event.get("src_host", {}).get("urgency_score", 0)

            demisto_incidents.append(
                {
                    "name": incident_name,
                    "occurred": occurred_time,
                    "rawJSON": json.dumps(event),
                    "severity": map_severity(urgency_score),
                }
            )
            already_fetched.append(detection_id)
            latest_timestamp = event.get("event_timestamp")

        new_last_run["event_timestamp"] = latest_timestamp
        new_last_run["from"] = response.get("next_checkpoint")
        new_last_run["was_fetched"] = already_fetched
        new_last_run["selected_types"] = fetch_params.get("type", "")
        new_last_run["selected_statuses"] = fetch_params.get("investigation_status", "")
        new_last_run["unresolved_priority"] = fetch_params.get("unresolved_priority", "")

        demisto.debug(f"Fetch params of this interval: {fetch_params}")
        demisto.debug(f"New last run: {new_last_run}")
        multiline_logs_for_list(already_fetched, "Ingested Detections: ")

    return demisto_incidents, new_last_run


def vectra_detections_mark_asclosed_command(client: VectraEventsDetectionsClient, args: dict[str, Any]) -> CommandResults:
    """
    Mark the detections as closed by providing IDs of detections and close reason in the argument.

    Args:
        client (VectraEventsDetectionsClient): Vectra events detections client object.
        args (dict[str, Any]): Command arguments. Close reason must be one of the following: benign, remediated.

    Raises:
        ValueError: If detection_ids or close_reason arguments are missing or invalid.

    Returns:
        CommandResults: The command results.
    """

    detection_ids = argToList(args.get("detection_ids"), transform=lambda x: x.strip())
    close_reason = args.get("close_reason", "").lower()

    # Validate detection ids
    if not detection_ids:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("detection_ids"))
    for detection_id in detection_ids:
        if (not detection_id.isdigit()) or int(detection_id) <= 0:
            raise ValueError(ERRORS["INVALID_INTEGER_VALUE"].format("detection_ids", detection_id))

    # Validate close reason
    if not close_reason:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("close_reason"))
    if close_reason not in VALID_CLOSE_REASON:
        raise ValueError(ERRORS["INVALID_ARG_VALUE"].format("close_reason", ", ".join(VALID_CLOSE_REASON)))

    api_response = client.close_detections_by_ids_request(ids_list=detection_ids, reason=close_reason)
    if api_response.get("_meta", {}).get("level", "").lower() == "success":
        client.update_detection_status_request(ids_list=detection_ids, status="closed")
        readable_output = f"##### The provided detection IDs have been successfully closed as {close_reason}."
    else:
        res_message = api_response.get("_meta", {}).get("message", "")
        message = "Something went wrong."
        if res_message:
            message += f" Message: {res_message}."
        raise DemistoException(message)

    command_result = CommandResults(readable_output=readable_output, raw_response=api_response)

    return command_result


def vectra_detection_list_command(client: VectraEventsDetectionsClient, args: dict[str, Any]):
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
    params = validate_list_detections_args(args)

    # list detections
    response = client.list_detections_standalone_request(params=params)

    count = response.get("count", 0)
    if count == 0:
        return CommandResults(
            outputs={},
            readable_output="##### Couldn't find any detections for provided filters.",
            raw_response=response,
        )
    detections = response.get("results", [])
    # Remove empty elements from the response
    # Prepare HR
    hr = get_list_entity_detections_command_hr(
        detections=detections,
        page=int(params.get("page")),  # type: ignore
        page_size=int(params.get("page_size")),  # type: ignore
        count=count,
    )

    return CommandResults(
        outputs_prefix="Vectra.Detection",
        outputs=remove_empty_elements(detections),
        readable_output=hr,
        raw_response=response,
        outputs_key_field="id",
    )


def get_modified_remote_data_command(client: VectraEventsDetectionsClient, args: dict) -> GetModifiedRemoteDataResponse:
    """
    Get modified remote data from the Vectra platform and prepare it for mirroring in XSOAR.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict): A dictionary containing the arguments for retrieving modified remote data.

    Returns:
        GetModifiedRemoteDataResponse: List of incidents IDs which are modified since the last update.
    """
    command_args = GetModifiedRemoteDataArgs(args)
    command_last_run_date = dateparser.parse(
        command_args.last_update,  # type: ignore
        settings={"TIMEZONE": "UTC"},  # type: ignore
    ).strftime(DATE_FORMAT)
    modified_entities_ids = []

    demisto.debug(f"Last update date of get-modified-remote-data command is {command_last_run_date}.")
    next_event_timestamp = None
    next_checkpoint = None
    page_size = 1000

    while True:
        if next_event_timestamp:
            command_last_run_date = next_event_timestamp

        params = assign_params(
            limit=page_size,
            event_timestamp_gte=command_last_run_date,
            include_info_category=True,
            size="detailed",
            ordering="id",
        )
        if next_checkpoint:
            params["from"] = next_checkpoint

        try:
            response = client.list_events_detections_request(params=params)
        except DemistoException as e:
            demisto.debug(f"Got the error in get-modified-remote-data command: {str(e)}")
            raise e

        events_detections = response.get("events", [])
        if not events_detections:
            break

        # Extract detection IDs and remove duplicates
        modified_entities_ids.extend([str(event.get("detection_id")) for event in events_detections])

        # If there is no data on the next page
        if response.get("remaining_count") == 0:
            break
        # Mirroring limit
        if len(modified_entities_ids) > MAX_MIRRORING_LIMIT:
            demisto.debug("Max mirroring limit reached.")
            break

        next_event_timestamp = events_detections[-1].get("event_timestamp")
        next_checkpoint = response.get("next_checkpoint")

    # Filter out None values if there are any.
    modified_entities_ids: list[str] = list(filter(None, modified_entities_ids))  # type: ignore
    demisto.debug(
        f"Performing get-modified-remote-data command. Numbers Detections IDs to update in XSOAR: {len(modified_entities_ids)}"
    )
    demisto.debug(f"Performing get-modified-remote-data command. Detections IDs to update in XSOAR: {modified_entities_ids}")

    # Filter out any duplicate incident IDs.
    updated_incident_ids = list(set(modified_entities_ids))

    # At max 5,000 incidents should be updated.
    updated_incident_ids = updated_incident_ids[:5000]

    return GetModifiedRemoteDataResponse(modified_incident_ids=updated_incident_ids)


def get_remote_data_command(client: VectraEventsDetectionsClient, args: dict) -> GetRemoteDataResponse:
    """
    Get remote data for a specific detection from the Vectra platform and prepare it for mirroring in XSOAR.

    Args:
        client (VectraEventsDetectionsClient): An instance of the VectraEventsDetectionsClient class.
        args (Dict): A dictionary containing the arguments for retrieving remote data.
            - id (str): The ID of the detection to retrieve.
            - lastUpdate (str): The timestamp of the last update received for this detection.

    Returns:
        GetRemoteDataResponse: An object containing the remote incident data and any new entries to return to XSOAR.
    """
    dbot_mirror_id: str = args.get("id")  # type: ignore
    demisto.debug(f"dbot_mirror_id:{dbot_mirror_id}")
    demisto.debug(f"vectra_detection_id:{dbot_mirror_id}")

    command_last_run_dt = arg_to_datetime(args.get("lastUpdate"), arg_name="lastUpdate", required=True)
    command_last_run_timestamp = command_last_run_dt.strftime(DATE_FORMAT)  # type: ignore
    demisto.debug(
        f"The time when the last time get-remote-data command is called for current incident is {command_last_run_timestamp}."
    )

    # Retrieve the latest entity data from the Vectra platform.
    params_for_new_append_change_type = assign_params(
        detection_id=dbot_mirror_id,
        ordering="-id",
        limit=1,
        include_info_category=True,
        include_triaged=True,
        size="detailed",
        change_type="new,append",
    )
    response_for_new_append_change_type = client.list_events_detections_request(params=params_for_new_append_change_type)

    params_for_other_change_type = assign_params(
        detection_id=dbot_mirror_id,
        ordering="-id",
        limit=1,
        include_info_category=True,
        include_triaged=True,
        size="detailed",
        change_type="adjust,triage,investigation_status",
    )
    response_for_other_change_type = client.list_events_detections_request(params=params_for_other_change_type)

    event_for_new_append_chage_type = response_for_new_append_change_type.get("events", [])
    event_for_other_chage_type = response_for_other_change_type.get("events", [])

    if event_for_new_append_chage_type:
        event_for_new_append_chage_type = event_for_new_append_chage_type[0]
        remove_empty_elements_for_fetch(event_for_new_append_chage_type)
    if event_for_other_chage_type:
        event_for_other_chage_type = event_for_other_chage_type[0]
        remove_empty_elements_for_fetch(event_for_other_chage_type)

    remote_incident_data: dict = {}
    if event_for_new_append_chage_type and event_for_other_chage_type:
        if arg_to_datetime(event_for_new_append_chage_type.get("event_timestamp")) > arg_to_datetime(  # type: ignore
            event_for_other_chage_type.get("event_timestamp")
        ):
            remote_incident_data = event_for_new_append_chage_type
        else:
            remote_incident_data = update_dict_with_new_dict_values(event_for_new_append_chage_type, event_for_other_chage_type)
    elif event_for_new_append_chage_type and not event_for_other_chage_type:
        remote_incident_data = event_for_new_append_chage_type
    elif not event_for_new_append_chage_type and event_for_other_chage_type:
        remote_incident_data = event_for_other_chage_type

    remove_nulls_from_dictionary(remote_incident_data)
    if not remote_incident_data:
        return "Incident was not found."  # type: ignore

    detection_href = remote_incident_data.get("detection_href", "")
    if detection_href:
        remote_incident_data["detection_href"] = trim_api_version(detection_href)
    entity_url = remote_incident_data.get("url", "")
    if entity_url:
        remote_incident_data["url"] = trim_api_version(entity_url)

    if remote_incident_data.get("dst_host") and remote_incident_data.get("dst_host", {}).get("url"):
        remote_incident_data["dst_host"]["url"] = trim_api_version(remote_incident_data.get("dst_host", {}).get("url"))
    if remote_incident_data.get("dst_account") and remote_incident_data.get("dst_account", {}).get("url"):
        remote_incident_data["dst_account"]["url"] = trim_api_version(remote_incident_data.get("dst_account", {}).get("url"))

    detection_timestamp = demisto.get(remote_incident_data, "detail.first_timestamp", "")
    if detection_timestamp and detection_timestamp[-1].lower() != "z":
        remote_incident_data["detail"]["first_timestamp"] = detection_timestamp + "Z"

    event_timestamp = arg_to_datetime(remote_incident_data.get("event_timestamp"))
    if command_last_run_dt > event_timestamp:  # type: ignore
        demisto.debug(f"Nothing new in the Vectra detection {dbot_mirror_id}.")
    else:
        demisto.debug(f"The Vectra detection {dbot_mirror_id} is updated.")

    new_entries_to_return: list[dict] = []
    notes = remote_incident_data.get("notes")

    if notes:
        for note in notes:
            if "[Mirrored From XSOAR]" in note.get("note"):
                demisto.debug(f"Skipping the note {note.get('id')} as it is mirrored from XSOAR.")
                continue
            note_date_modified = arg_to_datetime(note.get("date_modified"))
            if note_date_modified:
                if note_date_modified <= command_last_run_dt:  # type: ignore
                    demisto.debug(
                        f"Skipping the note {note.get('id')} as it was modified earlier than the command last run timestamp."
                    )
                    continue
            else:
                note_date_created = arg_to_datetime(note.get("date_created"), arg_name="date_created", required=True)
                if note_date_created <= command_last_run_dt:  # type: ignore
                    demisto.debug(f"Skipping the note {note.get('id')} as it is older than the command last run timestamp.")
                    continue
            new_entries_to_return.append(
                {
                    "Type": EntryType.NOTE,
                    "Contents": f"[Mirrored From Vectra]\n"
                    f"Added By: {note.get('created_by')}\n"
                    f"Added At: {note.get('date_created')} UTC\n"
                    f"Note: {note.get('note')}",
                    "ContentsFormat": EntryFormat.TEXT,
                    "Note": True,
                }
            )

    demisto.debug(f"remote_incident_data:{remote_incident_data} and new_entries_to_return:{new_entries_to_return}")
    return GetRemoteDataResponse(remote_incident_data, new_entries_to_return)


def update_remote_system_command(client: VectraEventsDetectionsClient, args: dict, params: dict) -> str:
    """
    Update a remote system based on changes in the XSOAR incident.

    Args:
        client (VectraClient): An instance of the VectraClient class.
        args (Dict): A dictionary containing the arguments required for updating the remote system.
        params (Dict): A dictionary containing the parameters required for updating the remote system.

    Returns:
        str: The ID of the updated remote entity.
    """
    parsed_args = UpdateRemoteSystemArgs(args)
    # Get remote incident ID
    remote_incident_id = parsed_args.remote_incident_id
    mirror_detection_id = parsed_args.data.get("vectraruxdetectionid", "")
    demisto.debug(f"Remote Incident ID: {remote_incident_id}")

    detection_status = parsed_args.data.get("vectraruxinvestigationstatus", "")
    priority_status = parsed_args.data.get("vectraruxentityprioritystatus", "")
    unresolved_priority = parsed_args.data.get("vectraruxentityunresolvedprioritystatus", "")
    entity_id = parsed_args.data.get("vectraruxentityid", "")
    entity_type = parsed_args.data.get("vectraruxentitytype", "")
    external_reference_id = parsed_args.data.get("vectraruxexternalreferenceid")

    # Get XSOAR incident id
    xsoar_incident_id = parsed_args.data.get("id", "")
    demisto.debug(f"XSOAR Incident ID: {xsoar_incident_id}")

    # For status and unresolved_priority
    if detection_status:
        client.update_detection_status_request(ids_list=[mirror_detection_id], status=detection_status)
        demisto.debug(f"Updated detection investigation status for detection {mirror_detection_id} to {detection_status}")
    if priority_status == "Not Prioritized" and not unresolved_priority:
        client.update_entity_unresolved_priority_status_request(
            entity_id=entity_id,
            entity_type=entity_type.lower(),
            unresolved_priority="False",
        )
        demisto.debug(f"Updated entity {entity_id} priority status to Not Prioritized")
    if external_reference_id:
        client.update_detection_external_id_request(ids_list=[mirror_detection_id], external_reference_id=external_reference_id)
        demisto.debug(f"Updated detection {mirror_detection_id} external reference id to {external_reference_id}")

    delta = parsed_args.delta
    new_entries = parsed_args.entries
    xsoar_tags: list = delta.get("tags") or []

    # For notes
    if new_entries:
        for entry in new_entries:
            entry_id = entry.get("id")
            demisto.debug(f"Sending the entry with ID: {entry_id} and Type: {entry.get('type')}")
            # Get note content and user
            entry_content = re.sub(r"([^\n])\n", r"\1\n\n", entry.get("contents", ""))
            if len(entry_content) > MAX_OUTGOING_NOTE_LIMIT:
                demisto.info(
                    f"Skipping outgoing mirroring for entity note with XSOAR Incident ID:{xsoar_incident_id}, "
                    "because the note length exceeds 8000 characters."
                )
                entry_user = ""
            else:
                entry_user = entry.get("user", "dbot") or "dbot"

            note_str = (
                f"[Mirrored From XSOAR] XSOAR Incident ID: {xsoar_incident_id} \n\n"
                f"Note: {entry_content} \n\n"
                f"Added By: {entry_user}"
            )
            # API request for adding notes
            client.add_note_to_detection_request(detection_id=mirror_detection_id, note=note_str)

    # For tags
    res = client.list_detection_tags_request(detection_id=mirror_detection_id)
    vectra_tags = res.get("tags") or []
    if xsoar_tags:
        xsoar_tags = get_valid_and_dropped_tags(xsoar_tags)[0]
        demisto.debug(f"Sending the tags: {xsoar_tags}")
        client.update_detection_tags_request(detection_id=mirror_detection_id, tags=xsoar_tags)
    # Check if all tags from XSOAR removed
    elif not xsoar_tags and vectra_tags and "tags" in delta:
        demisto.debug(f"Sending the tags: {xsoar_tags}")
        client.update_detection_tags_request(detection_id=mirror_detection_id, tags=xsoar_tags)

    incident_reopened = False
    # Check if incident is reopened
    if delta and delta.get("closingUserId") == "" and delta.get("runStatus") == "":
        demisto.debug(f"Incident {xsoar_incident_id} is reopened.")
        incident_reopened = True

    detection_status_to_set = params.get("detection_status_for_reopen", DEFAULT_DETECTION_STATUS_FOR_REOPEN).lower()
    if incident_reopened and argToBoolean(params.get("open_detection_on_incident_reopen", False)):
        client.open_detections_by_ids_request(ids_list=[mirror_detection_id])
        client.update_detection_status_request(ids_list=[mirror_detection_id], status=detection_status_to_set)

    # For Closing notes
    delta_keys = delta.keys()
    if "closingUserId" in delta_keys and parsed_args.incident_changed and parsed_args.inc_status == IncidentStatus.DONE:
        # Check if incident status is Done
        close_notes = parsed_args.data.get("closeNotes", "")
        close_reason = parsed_args.data.get("closeReason", "")
        close_user_id = parsed_args.data.get("closingUserId", "")

        # close detection
        detection_close_reason = params.get("close_reason_of_detection", DEFAULT_DETECTION_CLOSE_REASON).lower()
        if argToBoolean(params.get("close_detection_on_incident_closure", False)):
            client.update_detection_status_request(ids_list=[mirror_detection_id], status="closed")
            client.close_detections_by_ids_request(ids_list=[mirror_detection_id], reason=detection_close_reason)

        if len(close_notes) > MAX_OUTGOING_NOTE_LIMIT:
            demisto.info(
                f"Skipping outgoing mirroring for closing notes with XSOAR Incident ID {xsoar_incident_id}, "
                f"because the note length exceeds {MAX_OUTGOING_NOTE_LIMIT} characters."
            )
        else:
            closing_note = (
                f"[Mirrored From XSOAR] XSOAR Incident ID: {xsoar_incident_id}\n\n"
                f"Close Reason: {close_reason}\n\n"
                f"Closed By: {close_user_id}\n\n"
                f"Close Notes: {close_notes}"
            )
            demisto.debug(f"Closing Comment: {closing_note}")
            client.add_note_to_detection_request(detection_id=mirror_detection_id, note=closing_note)

    return remote_incident_id


def main():
    params = demisto.params()
    remove_nulls_from_dictionary(params)
    # get connectivity parameters
    server_url = params.get("server_url", "").strip()
    client_id = str(dict_safe_get(params, ["credentials", "identifier"])).strip()
    client_secret_key = str(dict_safe_get(params, ["credentials", "password"])).strip()
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    commands: dict[str, Callable] = {
        "vectra-user-list": vectra_user_list_command,
        "vectra-entity-list": vectra_entity_list_command,
        "vectra-entity-describe": vectra_entity_describe_command,
        "vectra-entity-detection-list": vectra_entity_detection_list_command,
        "vectra-detection-describe": vectra_detection_describe_command,
        "vectra-entity-note-list": vectra_entity_note_list_command,
        "vectra-entity-note-add": vectra_entity_note_add_command,
        "vectra-entity-note-update": vectra_entity_note_update_command,
        "vectra-entity-note-remove": vectra_entity_note_remove_command,
        "vectra-entity-tag-add": vectra_entity_tag_add_command,
        "vectra-entity-tag-remove": vectra_entity_tag_remove_command,
        "vectra-entity-tag-list": vectra_entity_tag_list_command,
        "vectra-assignment-list": vectra_assignment_list_command,
        "vectra-entity-assignment-add": vectra_entity_assignment_add_command,
        "vectra-entity-assignment-update": vectra_entity_assignment_update_command,
        "vectra-detection-pcap-download": vectra_detection_pcap_download_command,
        "vectra-group-list": vectra_group_list_command,
        "vectra-group-assign": vectra_group_assign_command,
        "vectra-group-unassign": vectra_group_unassign_command,
        "vectra-entity-detections-mark-asclosed": vectra_entity_detections_mark_asclosed_command,
        "vectra-detections-mark-asclosed": vectra_detections_mark_asclosed_command,
        "vectra-detections-mark-asopen": vectra_detections_mark_asopen_command,
        "vectra-detection-tag-list": vectra_detection_tag_list_command,
        "vectra-detection-tag-add": vectra_detection_tag_add_command,
        "vectra-detection-tag-remove": vectra_detection_tag_remove_command,
        "vectra-detection-note-list": vectra_detection_note_list_command,
        "vectra-detection-note-add": vectra_detection_note_add_command,
        "vectra-detection-note-update": vectra_detection_note_update_command,
        "vectra-detection-note-remove": vectra_detection_note_remove_command,
        "vectra-entity-unresolved-priority-reset": vectra_entity_unresolved_priority_reset_command,
        "vectra-detection-investigation-status-update": vectra_detection_investigation_status_update_command,
        "vectra-detection-external-id-update": vectra_detection_external_id_update_command,
        "vectra-entity-external-id-update": vectra_entity_external_id_update_command,
        "vectra-detection-list": vectra_detection_list_command,
        "vectra-investigation-query-send": vectra_investigation_query_send_command,
        "vectra-investigation-result-get": vectra_investigation_result_get_command,
    }

    try:
        result = None
        # Creates vectra client
        client = VectraEventsDetectionsClient(
            server_url=server_url,
            client_id=client_id,
            client_secret_key=client_secret_key,
            verify=verify_certificate,
            proxy=proxy,
        )

        args = demisto.args()

        if command == "test-module":
            result = test_module(client, params)
        elif command == "fetch-incidents":
            last_run = demisto.getLastRun()
            incidents, next_run = fetch_incidents(client, params, last_run)
            demisto.setLastRun(next_run)
            demisto.debug(f"{len(incidents)} incidents are created successfully in XSOAR.")
            demisto.incidents(incidents)
        elif command in commands:
            # remove nulls from dictionary and trim space from args
            remove_nulls_from_dictionary(trim_spaces_from_args(args))
            result = commands[command](client, args)
        elif command == "get-modified-remote-data":
            result = get_modified_remote_data_command(client, args)  # type: ignore
        elif command == "get-remote-data":
            result = get_remote_data_command(client, args)  # type: ignore
        elif command == "update-remote-system":
            result = update_remote_system_command(client, args, params)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

        return_results(result)  # Returns either str, CommandResults and a list of CommandResults

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()

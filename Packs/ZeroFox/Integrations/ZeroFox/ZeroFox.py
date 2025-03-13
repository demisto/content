from enum import Enum
import demistomock as demisto
from CommonServerPython import *

""" IMPORTS  """
from dateparser import parse as parse_date
from datetime import datetime
from typing import Any, TypedDict, BinaryIO
from collections.abc import Callable
from requests import Response
from copy import deepcopy
import json

""" GLOBALS / PARAMS  """
FETCH_TIME_DEFAULT = "3 days"
CLOSED_ALERT_STATUS = ["Closed", "Deleted"]
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
MAX_ALERT_IDS_STORED = 300

""" Types """
FetchIncidentsStorage = TypedDict("FetchIncidentsStorage", {
    "last_modified_fetched": str,
    "zf-ids": list[str],
})


""" CLIENT """

ALLOWED_SORT_FIELDS = ["timestamp", "last_modified"]
ALLOWED_ALERT_FILTERS = [
    "last_modified_min_date",
    "escalated_min_date",
    "min_timestamp",
    "max_timestamp"
]


class ZFClient(BaseClient):
    def __init__(
        self, username, token, only_escalated, *args, **kwargs
    ):
        super().__init__(*args, **kwargs)
        self.credentials = {
            "username": username,
            "password": token
        }
        self.only_escalated = only_escalated
        self.auth_token = token

    def raw_api_request(
        self,
        method: str,
        url_suffix: str = "/",
        full_url: str | None = None,
        params: dict[str, str] | None = None,
        data: dict[str, Any] | None = None,
        ok_codes: tuple[int, ...] = None,
        files: dict[str, Any] | None = None,
        prefix: str | None = "1.0",
        empty_response: bool = False,
        **kwargs
    ) -> Response:
        pref_string = f"/{prefix}" if prefix else ""

        headers = self.get_api_request_header()
        return self._http_request(
            method=method,
            url_suffix=urljoin(pref_string, url_suffix),
            full_url=full_url,
            headers=headers,
            params=params,
            json_data=data,
            ok_codes=ok_codes,
            empty_valid_codes=(200, 201),
            return_empty_response=empty_response,
            error_handler=self.handle_zerofox_error,
            files=files,
            resp_type="response",
            **kwargs
        )

    def api_request(
        self,
        method: str,
        url_suffix: str = "/",
        full_url: str | None = None,
        headers_builder_type: str | None = 'api',
        params: dict[str, str] | None = None,
        data: dict[str, Any] | None = None,
        ok_codes: tuple[int, ...] = None,
        files: dict[str, Any] | None = None,
        prefix: str | None = "1.0",
        empty_response: bool = False,
        **kwargs
    ) -> dict[str, Any]:
        """
        :param method: HTTP request type
        :param url_suffix: The suffix of the URL
        :param headers_builder_type: It can be `api` or `cti`. It selects
        the function to build the headers required
        for each case
        :param params: The request's query parameters
        :param data: The request's body parameters
        :param files: The request's files
        :param version: api prefix to consider, default is to use version '1.0'
        :param res_type: Selects the decoder of the response. It can be
        `json` (default), `xml`, `text`, `content`, `response`
        :param empty_response: Indicates if the response data is empty or not
        :param error_handler: Function that receives the response and manage
        the error
        :return: Returns the content of the response received from the API.
        """
        pref_string = f"/{prefix}" if prefix else ""

        headers = {}
        if headers_builder_type is not None:
            if headers_builder_type not in ("api", "cti"):
                raise ValueError(
                    "`headers_builder_type` should be 'api' or 'cti'"
                )
            header_builder = {
                "api": self.get_api_request_header,
                "cti": self.get_cti_request_header
            }.get(headers_builder_type)
            if header_builder is None:
                raise ValueError(
                    "`headers_builder_type` should be 'api' or 'cti'"
                )
            headers = header_builder()

            if files:
                headers.pop("Content-Type", None)

        return self._http_request(
            method=method,
            url_suffix=urljoin(pref_string, url_suffix),
            full_url=full_url,
            headers=headers,
            params=params,
            json_data=data,
            ok_codes=ok_codes,
            empty_valid_codes=(200, 201),
            return_empty_response=empty_response,
            error_handler=self.handle_zerofox_error,
            files=files,
            **kwargs
        )

    def handle_zerofox_error(self, raw_response: Response):
        status_code = raw_response.status_code
        if status_code >= 500:
            raise ZeroFoxInternalException(
                status_code=status_code,
                cause=raw_response.text,
            )
        cause = self._build_exception_cause(raw_response)
        response = raw_response.json()
        if status_code in [401, 403]:
            raise ZeroFoxAuthException(cause=cause)
        raise ZeroFoxInternalException(
            status_code=status_code,
            cause=str(response),
        )

    def _build_exception_cause(self, raw_response: Response) -> str:
        try:
            response = raw_response.json()
            if non_field_errors := response.get("non_field_errors", []):
                return non_field_errors[0]
            return str(response)
        except json.JSONDecodeError:
            return raw_response.text

    def _get_new_access_token(self) -> str:
        url_suffix: str = "/auth/token/"
        response_content = self.api_request(
            "POST",
            url_suffix,
            data=self.credentials,
            headers_builder_type=None,
            prefix=None,
        )
        return response_content.get("access", "")

    def get_cti_authorization_token(self) -> str:
        """
        :return: returns the authorization token for the CTI feed
        """
        token = self._get_new_access_token()
        if not token:
            raise Exception("Unable to retrieve token.")
        return token

    def get_api_request_header(self) -> dict[str, str]:
        token: str = self.auth_token
        return {
            "Authorization": f"Token {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "zf-source": "XSOAR",
        }

    def get_cti_request_header(self) -> dict[str, str]:
        token: str = self.get_cti_authorization_token()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "zf-source": "XSOAR",
        }

    def get_policy_types(self) -> dict[str, Any]:
        """
        :return: HTTP request content.
        """
        url_suffix: str = "/policies/"
        response_content = self.api_request("GET", url_suffix)
        return response_content

    def list_alerts(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Gets the JSON contents of the /alerts/ endpoint
        according to the parameters provided
        :param params: The request's body parameters.
        :return: HTTP request content.
        """
        url_suffix: str = "/alerts/"
        if not params.get("limit"):
            params['limit'] = 100
        if self.only_escalated:
            params['escalated'] = 'true'
        response_content = self.api_request(
            "GET",
            url_suffix,
            params=params
        )
        return response_content.get("alerts", [])

    def get_alerts(self, filter_by: dict[str, Any] = None, sort_by: str = None, **kwargs) -> list[dict[str, Any]]:
        """
        Fetches a list of all alerts obtained from the pages in the /alerts/ endpoint,
          considering ordering and filters.
        :param filter_by: Dictionary of filter parameters for GET alerts call.
        :param sort_by: The field to sort by.
        :param kwargs: Additional parameters to include for GET alerts call.
        """
        RETRIES = 3
        url_suffix: str = "/alerts/"
        try:
            params = {}
            if filter_by:
                params.update({
                    k: v for k, v in filter_by.items()
                    if k in ALLOWED_ALERT_FILTERS
                })
            if sort_direction := kwargs.pop("sort_direction", "asc"):
                params['sort_direction'] = sort_direction
            if sort_by in ALLOWED_SORT_FIELDS:
                params['sort_field'] = sort_by
            if self.only_escalated:
                params['escalated'] = 'true'
            response_content = self.api_request(
                "GET",
                url_suffix,
                retries=RETRIES,
                params=params
            )
            alerts = response_content.get("alerts", [])
            while next_page := response_content.get("next", None):
                response_content = self.api_request(
                    "GET",
                    retries=RETRIES,
                    full_url=next_page
                )
                alerts += (response_content.get("alerts", []))
            return alerts
        except Exception as e:
            raise ZeroFoxGetAlertsException(
                escalated=self.only_escalated,
                cause=e
            )

    def get_alert(self, alert_id: int) -> dict[str, Any]:
        """
        :param alert_id: The ID of the alert.
        :return: HTTP request content.
        """
        try:
            url_suffix: str = f"/alerts/{alert_id}/"
            response_content = self.api_request("GET", url_suffix)
            return response_content.get("alert", {})
        except Exception as e:
            raise ZeroFoxGetAlertException(
                alert_id=alert_id,
                cause=e
            )

    def alert_user_assignment(
        self,
        alert_id: int,
        username: str
    ) -> dict[str, Any]:
        """
        :param alert_id: The ID of the alert.
        :param username: The username we want to assign to the alert.
        :return: HTTP request content.
        """
        url_suffix: str = f"/alerts/{alert_id}/assign/"
        request_body = {"subject": username}
        response_content = self.api_request(
            "POST",
            url_suffix,
            data=request_body,
            empty_response=True,
        )
        return response_content

    class AlertAction(str, Enum):
        OPEN = "open"
        CLOSE = "close"
        REQUEST_TAKEDOWN = "request_takedown"
        CANCEL_TAKEDOWN = "cancel_takedown"

        def __str__(self) -> str:
            return self.value

    def alert_action(self, alert_id: int, action: AlertAction) -> dict[str, Any]:
        """
        :param alert_id: The ID of the alert.
        :param action: action to apply on alert
        :return: HTTP request content.
        """
        try:
            url_suffix: str = f"/alerts/{alert_id}/{action}/"
            response_content = self.api_request(
                "POST",
                url_suffix,
                empty_response=True,
            )
            return response_content
        except Exception as e:
            raise ZeroFoxAlertActionException(
                alert_id=alert_id,
                action=action,
                cause=e
            )

    def close_alert(self, alert_id: int) -> dict[str, Any]:
        """
        :param alert_id: The ID of the alert.
        :return: HTTP request content.
        """
        return self.alert_action(alert_id, self.AlertAction.CLOSE)

    def open_alert(self, alert_id: int) -> dict[str, Any]:
        """
        :param alert_id: The ID of the alert.
        :return: HTTP request content.
        """
        return self.alert_action(alert_id, self.AlertAction.OPEN)

    def alert_request_takedown(self, alert_id: int) -> dict[str, Any]:
        """
        :param alert_id: The ID of the alert.
        :return: HTTP request content.
        """
        return self.alert_action(alert_id, self.AlertAction.REQUEST_TAKEDOWN)

    def alert_cancel_takedown(self, alert_id: int) -> dict[str, Any]:
        """
        :param alert_id: The ID of the alert.
        :return: HTTP request content.
        """
        return self.alert_action(alert_id, self.AlertAction.CANCEL_TAKEDOWN)

    def modify_alert_tags(
        self,
        alert_id: int,
        action: str,
        tags_list: list[str]
    ) -> dict[str, Any]:
        """
        :param alert_id: The ID of the alert.
        :param action: action can be 'added' or 'removed'. It indicates
        what action we want to do i.e add/remove tags/
        :param tags_list: A string representation of the tags,
        separated by a comma ','
        :return: HTTP request content.
        """
        url_suffix: str = "/alerttagchangeset/"
        request_body = {
            "changes": [
                {
                    f"{action}": tags_list,
                    "alert": alert_id,
                },
            ],
        }
        response_content = self.api_request(
            "POST", url_suffix, data=request_body,
        )
        return response_content

    def create_entity(
        self,
        name: str,
        strict_name_matching: bool | None = None,
        tags: list | None = None,
        policy: int | None = None,
        organization: str | None = None,
    ) -> dict[str, Any]:
        """
        :param name: Name of the entity (may be non-unique).
        :param strict_name_matching: Indicating type of string matching for
        comparing name to impersonators.
        :param tags: List of string tags for tagging the entity. Separated
        by a comma ','.
        :param policy: The ID of the policy to assign to the new entity.
        :param organization: Organization name associated with entity.
        :return: HTTP request content.
        """
        url_suffix: str = "/entities/"
        request_body = {
            "name": name,
            "strict_name_matching": strict_name_matching,
            "labels": tags,
            "policy": policy,
            "policy_id": policy,
            "organization": organization,
        }
        request_body = remove_none_dict(request_body)
        response_content = self.api_request(
            "POST", url_suffix, data=request_body,
        )
        return response_content

    def list_entities(self, params: dict[str, Any]) -> dict[str, Any]:
        """
        :param params: The request's body parameters.
        :return: HTTP request content.
        """
        url_suffix: str = "/entities/"
        response_content = self.api_request(
            "GET",
            url_suffix,
            params=params,
        )
        return response_content

    def get_entity_types(self) -> dict[str, Any]:
        """
        :return: HTTP request content.
        """
        url_suffix: str = "/entities/types/"
        response_content = self.api_request("GET", url_suffix)
        return response_content

    def modify_alert_notes(self, alert_id: int, notes: str) -> dict[str, Any]:
        """
        :param alert_id: The ID of the alert.
        :param notes: The notes for the alert.
        :return: HTTP request content.
        """
        try:
            url_suffix: str = f"/alerts/{alert_id}/"
            request_body = {"notes": notes}
            response_content = self.api_request(
                "POST",
                url_suffix,
                data=request_body,
                empty_response=True,
            )
            return response_content
        except Exception as e:
            raise ZeroFoxModifyNotesException(
                alert_id=alert_id,
                cause=e
            )

    def submit_threat(
        self,
        source: str,
        alert_type: str,
        violation: str,
        entity_id: str
    ) -> dict[str, Any]:
        """
        :param source: The source of the threat.
        :param alert_type: The type of the alert.
        :param violation: The violation of the alert.
        :param entity_id: The ID of the entity.
        :return: HTTP request content.
        """
        url_suffix: str = "/threat_submit/"
        request_body = {
            "source": source,
            "alert_type": alert_type,
            "violation": violation,
            "entity_id": entity_id,
        }
        request_body = remove_none_dict(request_body)
        response_content = self.api_request(
            "POST",
            url_suffix,
            data=request_body,
            prefix="2.0",
        )
        return response_content

    def send_alert_attachment(
        self,
        alert_id: int,
        file_name: str,
        file_content: BinaryIO,
        attachment_type: str
    ) -> dict[str, Any]:
        """
        :param alert_id: The ID of the alert.
        :param file_name: The name of the file.
        :param file_content: The content of the file.
        :param attachment_type: The type of the attachment.
        :return: HTTP request content.
        """
        url_suffix = f"/alerts/{alert_id}/attachments/"
        files = {
            "file": (file_name, file_content),
            "attachment_type": (None, attachment_type),
        }
        # request_body = {"attachment_type": attachment_type}

        response_content = self.api_request(
            'POST',
            url_suffix,
            files=files,
        )
        return response_content

    def get_alert_attachments(self, alert_id: int) -> dict[str, Any]:
        """
        :param alert_id: The ID of the alert.
        :return: HTTP request content.
        """
        url_suffix = f"/alerts/{alert_id}/attachments/"
        response_content = self.api_request(
            "GET",
            url_suffix,
        )
        return response_content

    def get_compromised_credentials(self, alert_id: str) -> str:
        """
        :param alert_id: The ID of the alert.
        :return: HTTP request content.
        """
        url_suffix = f"/alerts/{alert_id}/breach_csv/"
        response_content: Response = self.raw_api_request(
            "GET",
            prefix="2.0",
            ok_codes=(200, 404),
            url_suffix=url_suffix,
        )
        if response_content.status_code == 404:
            return ""
        return response_content.text

    def get_cti_c2_domains(self, domain: str) -> dict[str, Any]:
        """
        :param domain: The domain to lookup in c2-domains CTI Feed
        :return: HTTP request content.
        """
        url_suffix = "/c2-domains/"
        params = {"domain": domain}
        response_content = self.api_request(
            "GET",
            url_suffix,
            params=params,
            prefix="cti",
            headers_builder_type="cti",
        )
        return response_content

    def get_cti_phishing(
        self,
        domain: str | None = None,
        ip: str | None = None
    ) -> dict[str, Any]:
        """
        :param domain: The domain to lookup in phishing CTI Feed
        :param ip: The ip to lookup in phishing CTI Feed
        :return: HTTP request content.
        """
        url_suffix = "/phishing/"
        params = remove_none_dict({"domain": domain, "host_ip": ip})
        response_content = self.api_request(
            "GET",
            url_suffix,
            params=params,
            prefix="cti",
            headers_builder_type="cti",
        )
        return response_content

    def get_cti_email_addresses(self, email: str) -> dict[str, Any]:
        """
        :param email: The email to lookup in email-addresses CTI Feed
        :return: HTTP request content.
        """
        url_suffix = "/email-addresses/"
        params = {"email": email}
        response_content = self.api_request(
            "GET",
            url_suffix,
            params=params,
            prefix="cti",
            headers_builder_type="cti",
        )
        return response_content

    def get_cti_compromised_credentials(self, email: str) -> dict[str, Any]:
        """
        :param email: The email to lookup in compromised-credentials CTI Feed
        :return: HTTP request content.
        """
        url_suffix = "/compromised-credentials/"
        params = {"email": email}
        response_content = self.api_request(
            "GET",
            url_suffix,
            params=params,
            prefix="cti",
            headers_builder_type="cti",
        )
        return response_content

    def get_cti_botnet_compromised_credentials(
        self,
        email: str
    ) -> dict[str, Any]:
        """
        :param email: The email to lookup in botnet-compromised-credentials
        CTI Feed
        :return: HTTP request content.
        """
        url_suffix = "/botnet-compromised-credentials/"
        params = {"email": email}
        response_content = self.api_request(
            "GET",
            url_suffix,
            params=params,
            prefix="cti",
            headers_builder_type="cti",
        )
        return response_content

    def get_cti_botnet(self, ip: str) -> dict[str, Any]:
        """
        :param ip: The ip to lookup in botnet CTI Feed
        :return: HTTP request content.
        """
        url_suffix = "/botnet/"
        params = {"ip": ip}
        response_content = self.api_request(
            "GET",
            url_suffix,
            params=params,
            prefix="cti",
            headers_builder_type="cti",
        )
        return response_content

    def get_cti_malware(self, hash_type: str, hash: str) -> dict[str, Any]:
        """
        :param hash_type: The hash type to lookup in malware CTI Feed
        :param hash: The hash to lookup in malware CTI Feed
        :return: HTTP request content.
        """
        url_suffix = "/malware/"
        params = {hash_type: hash}
        response_content = self.api_request(
            "GET",
            url_suffix,
            params=params,
            prefix="cti",
            headers_builder_type="cti",
        )
        return response_content

    def get_cti_exploits(self, since: str) -> dict[str, Any]:
        """
        :param since: since date to query exploits
        :return: HTTP request content.
        """
        url_suffix = "/exploits/"
        params = {"created_after": since}
        response_content = self.api_request(
            "GET",
            url_suffix,
            params=params,
            prefix="cti",
            headers_builder_type="cti",
        )
        return response_content


""" HELPERS """


class ZeroFoxGetAlertsException(Exception):
    def __init__(self, escalated: bool, cause: Exception):
        self.escalated = escalated
        self.cause = cause
        super().__init__(self._generate_msg())

    def _generate_msg(self) -> str:
        escalated = "escalated " if self.escalated else ""
        return f"An error occurred while trying to fetch {escalated}alerts:\
            \n {self.cause}"


class ZeroFoxAlertActionException(Exception):
    def __init__(self, alert_id: int, action: str, cause: Exception):
        self.alert_id = alert_id
        self.action = action
        self.cause = cause
        super().__init__(self._generate_msg())

    def _generate_msg(self) -> str:
        return f"An error occurred while trying to apply action {self.action} on alert {self.alert_id}:\
            \n {self.cause}"


class ZeroFoxInternalException(Exception):
    def __init__(self, status_code: int, cause: str):
        self.status_code = status_code
        self.cause = cause
        super().__init__(self._generate_msg())

    def _generate_msg(self) -> str:
        return f"An error occurred within ZeroFox, please try again later.\
              If the issue persists, contact support.\
              Status Code: {self.status_code}, Response: {self.cause}"


class ZeroFoxAuthException(Exception):
    def __init__(self, cause: str):
        self.cause = cause
        super().__init__(self._generate_msg())

    def _generate_msg(self) -> str:
        return f"An error occurred while trying to authenticate with ZeroFox:\
            \n {self.cause}"


class ZeroFoxGetAlertException(Exception):
    def __init__(self, alert_id: int, cause: Exception):
        self.alert_id = alert_id
        self.cause = cause
        super().__init__(self._generate_msg())

    def _generate_msg(self) -> str:
        return f"An error occurred while trying to fetch alert {self.alert_id}:\
            \n {self.cause}"


class ZeroFoxModifyNotesException(Exception):
    def __init__(self, alert_id: int, cause: Exception):
        self.alert_id = alert_id
        self.cause = cause
        super().__init__(self._generate_msg())

    def _generate_msg(self) -> str:
        return f"An error occurred while trying to modify notes for alert {self.alert_id}:\
            \n {self.cause}"


class AlertToIncident:
    def __init__(self):
        self.integration_instance = demisto.integrationInstance()

    def map(self, alert: dict[str, Any]) -> dict[str, Any]:
        """
        Converts an alert to an incident dictionary object
        :param alert: dictionary representing a zerofox alert
        :return: A dict representing an incident
        """
        alert_id = str(alert.get("id", ""))
        alert["mirror_direction"] = "In"
        alert["mirror_instance"] = self.integration_instance
        incident = {
            "rawJSON": json.dumps(alert),
            "name": f"ZeroFox Alert {alert_id}",
            "dbotMirrorId": alert_id,
            "occurred": alert.get("timestamp", ""),
            "details": f"A ZeroFox Alert with Id {alert.get('id', '')} has been raised.\
            It compromises entity {alert.get('entity', {}).get('name', '')},\
              it was found on {alert.get('network', '')}\
                  and was triggered by rule {alert.get('rule_name', '')}."
        }
        return incident


def parse_dict_values_to_integer(
    params: dict[str, Any],
    keys: list[str]
) -> dict[str, Any]:
    params_copy = deepcopy(params)
    for key in keys:
        value = params_copy.get(key)
        if value is not None:
            try:
                params_copy[key] = int(value)
            except ValueError:
                raise Exception(f"This value for {key} must be an integer.")
    return params_copy


def severity_num_to_string(severity_num: int) -> str:
    """
    transforms severity number to string representation
    :param severity_num: Severity score as Integer
    :return: Returns the String representation of the severity score
    """
    severity_map = {1: "Info", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}
    return severity_map.get(severity_num, "")


def severity_string_to_num(severity_str: str) -> int:
    """
    :param severity_str: Severity score as String
    :return: Returns the Integer representation of the severity score
    """
    severity_map = {"Info": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5}
    return severity_map.get(severity_str, -1)


def get_nested_key(
    obj: dict[str, Any],
    path: list[str],
    default_value: Any | None = None
) -> Any:
    """
    It returns the value of a nested key in a dictionary
    :param obj: The dictionary we want to get the value from
    :param path: The path to the nested key
    :param default_value: The default value to return if the key is not found
    :return: The value of the nested key

    Example:
    obj = {"a": {"b": {"c": 1}}}
    default_value = -1

    get_nested_key(obj, ["a", "b", "c"], default_value) -> 1
    get_nested_key(obj, ["a", "x", "d"], default_value) -> -1
    """
    for key in path[:-1]:
        obj = obj.get(key, {})
        if not isinstance(obj, dict):
            return default_value
    return obj.get(path[-1])


def get_alert_contents(alert: dict[str, Any]) -> dict[str, Any]:
    """
    :param alert: Alert is a dictionary
    :return: A dict representing the alert contents
    """
    return {
        "AlertType": alert.get("alert_type"),
        "OffendingContentURL": alert.get("offending_content_url"),
        "Assignee": alert.get("assignee"),
        "Entity": {
            "ID": get_nested_key(alert, ["entity", "id"]),
            "Name": get_nested_key(alert, ["entity", "name"]),
            "Image": get_nested_key(alert, ["entity", "image"]),
        },
        "EntityID": get_nested_key(alert, ["entity", "id"]),
        "EntityName": get_nested_key(alert, ["entity", "name"]),
        "EntityImage": get_nested_key(alert, ["entity", "image"]),
        "EntityTerm": {
            "ID": get_nested_key(alert, ["entity_term", "id"]),
            "Name": get_nested_key(alert, ["entity_term", "name"]),
            "Deleted": get_nested_key(alert, ["entity_term", "deleted"]),
        },
        "EntityTermID": get_nested_key(alert, ["entity_term", "id"]),
        "EntityTermName": get_nested_key(alert, ["entity_term", "name"]),
        "EntityTermDeleted": get_nested_key(alert, ["entity_term", "deleted"]),
        "ContentCreatedAt": alert.get("content_created_at"),
        "ID": alert.get("id"),
        "ProtectedAccount": alert.get("protected_account"),
        "RiskRating": severity_num_to_string(int(alert.get("severity", ""))),
        "Perpetrator": {
            "Name": get_nested_key(alert, ["perpetrator", "name"]),
            "Url": get_nested_key(alert, ["perpetrator", "url"]),
            "TimeStamp": get_nested_key(alert, ["perpetrator", "timestamp"]),
            "Type": get_nested_key(alert, ["perpetrator", "type"]),
            "ID": get_nested_key(alert, ["perpetrator", "id"]),
            "Network": get_nested_key(alert, ["perpetrator", "network"]),
        },
        "PerpetratorName": get_nested_key(alert, ["perpetrator", "name"]),
        "PerpetratorUrl": get_nested_key(alert, ["perpetrator", "url"]),
        "PerpetratorTimeStamp": get_nested_key(
            alert, ["perpetrator", "timestamp"],
        ),
        "PerpetratorType": get_nested_key(alert, ["perpetrator", "type"]),
        "PerpetratorID": get_nested_key(alert, ["perpetrator", "id"]),
        "PerpetratorNetwork": get_nested_key(
            alert, ["perpetrator", "network"],
        ),
        "RuleGroupID": alert.get("rule_group_id"),
        "Status": alert.get("status"),
        "Timestamp": alert.get("timestamp"),
        "RuleName": alert.get("rule_name"),
        "LastModified": alert.get("last_modified"),
        "ProtectedLocations": alert.get("protected_locations"),
        "DarkwebTerm": alert.get("darkweb_term"),
        "Reviewed": alert.get("reviewed"),
        "Escalated": alert.get("escalated"),
        "Network": alert.get("network"),
        "ProtectedSocialObject": alert.get("protected_social_object"),
        "Notes": alert.get("notes"),
        "RuleID": alert.get("rule_id"),
        "EntityAccount": alert.get("entity_account"),
        "Tags": alert.get("tags"),
    }


def transform_alert_human_readable_values(
    alert: dict[str, Any],
    title_keys: list[str] | None = None
) -> dict[str, Any]:
    """
    It takes an alert and convert the keys indicated in `title_keys` to
    title case

    :param alert: Dictionary representing the alert
    :param title_keys: List of keys to convert to title case
    :return: return a copy of the alert with the keys converted to title case
    """
    title_keys = title_keys or []
    transformed_alert = deepcopy(alert)
    for key in title_keys:
        transformed_alert[key] = transformed_alert.get(key, "").title()
    return transformed_alert


def transform_alerts_human_readable_values(
    alerts: dict[str, Any] | list[dict[str, Any]],
    title_keys: list[str] | None = None
) -> dict[str, Any] | list[dict[str, Any]]:
    """
    It takes an alert or a list of alerts and convert the keys specified in
    `title_keys` to title case

    :param alerts: Alert or list of alerts to transform
    :parma title_keys: List of keys to convert to title case
    :return: a copy of the alert or list of alerts with the corresponding
    transformations
    """
    title_keys = title_keys or []
    if isinstance(alerts, list):
        return [
            transform_alert_human_readable_values(
                alert,
                title_keys=title_keys,
            )
            for alert in alerts
        ]
    elif isinstance(alerts, dict):
        return transform_alert_human_readable_values(
            alerts,
            title_keys=title_keys,
        )
    else:
        raise Exception("alerts must be a list or a dict")


def transform_alert_human_readable_header(header: str) -> str:
    """
    It returns the header name of the alert's key to human readable

    :param header: the key to get the human readable header
    :return: the human readable header name of the key requested
    """
    transformations = {
        "EntityName": "Protected Entity",
        "AlertType": "Content Type",
        "Timestamp": "Alert Date",
        "Network": "Source",
        "RuleName": "Rule",
        "RiskRating": "Risk Rating",
        "OffendingContentURL": "Offending Content",
    }
    return transformations.get(header, header)


def get_human_readable_alerts(
    alerts: dict[str, Any] | list[dict[str, Any]]
) -> str:
    visible_keys = [
        "ID",
        "EntityName",
        "AlertType",
        "Timestamp",
        "Status",
        "OffendingContentURL",
        "Network",
        "RuleName",
        "RiskRating",
        "Notes",
        "Tags",
    ]
    title_keys = ["AlertType", "RuleName", "Network", "EntityName"]
    transformed_alerts = transform_alerts_human_readable_values(
        alerts, title_keys=title_keys
    )
    readable_output: str = tableToMarkdown(
        "ZeroFox Alerts",
        transformed_alerts,
        headers=visible_keys,
        date_fields=["Timestamp"],
        headerTransform=transform_alert_human_readable_header,
        removeNull=True,
    )
    return readable_output


def remove_none_dict(input_dict: dict[Any, Any]) -> dict[Any, Any]:
    """
    removes all none values from a dict
    :param input_dict: any dictionary in the world is OK
    :return: same dictionary but without None values
    """
    return {
        key: value for key, value in input_dict.items()
        if value is not None
    }


def get_entity_contents(entity: dict[str, Any]) -> dict[str, Any]:
    """
    :param entity: Entity is a dictionary
    :return: A dict representation of the contents of entity
    """
    return {
        "ID": entity.get("id"),
        "Name": entity.get("name"),
        "EmailAddress": entity.get("email_address"),
        "Organization": entity.get("organization"),
        "Tags": entity.get("labels"),
        "StrictNameMatching": entity.get("strict_name_matching"),
        "PolicyID": entity.get("policy_id"),
        "Profile": entity.get("profile"),
        "EntityGroupID": get_nested_key(entity, ["entity_group", "id"]),
        "EntityGroupName": get_nested_key(entity, ["entity_group", "name"]),
        "TypeID": get_nested_key(entity, ["type", "id"]),
        "TypeName": get_nested_key(entity, ["type", "name"]),
    }


def get_entity_human_readable_outputs(
    contents: dict[str, Any]
) -> dict[str, Any]:
    """
    returns the convention for the war room
    :param contents: Contents is a dictionary
    :return: A dict representation of the war room contents
    displayed to the user
    """
    return {
        "Name": contents.get("Name"),
        "Type": contents.get("TypeName"),
        "Policy": contents.get("PolicyID"),
        "Email": contents.get("EmailAddress"),
        "Tags": contents.get("Tags"),
        "ID": contents.get("ID"),
    }


def get_c2_domain_content(c2_domain_record: dict[str, Any]) -> dict[str, Any]:
    return {
        "Domain": c2_domain_record.get("domain", ""),
        "LastModified": c2_domain_record.get("created_at", ""),
        "IPs": ", ".join(c2_domain_record.get("ip_addresses", []))
    }


def get_phishing_content(phishing_record: dict[str, Any]) -> dict[str, Any]:
    return {
        "Domain": phishing_record.get("domain", ""),
        "LastModified": phishing_record.get("scanned", ""),
        "IPs": get_nested_key(phishing_record, ["host", "ip"], "")
    }


def get_compromised_domain_content(
    c2_domain_response: dict[str, Any],
    phishing_response: dict[str, Any]
) -> list[dict[str, Any]]:
    """
    It merges the content of c2_domain_response and phishing_response and
    format it to be standardized as compromised domain content

    :param c2_domain_response: The response of the c2-domains CTI Feed
    :param phishing_response: The response of the phishing CTI Feed
    :return: A list of dictionaries representing the compromised domain content
    """
    compromised_domain_content = []

    c2_domains_results = c2_domain_response.get("results", [])
    compromised_domain_content += [
        get_c2_domain_content(record) for record in c2_domains_results
    ]

    phishing_results = phishing_response.get("results", [])
    compromised_domain_content += [
        get_phishing_content(record) for record in phishing_results
    ]

    return compromised_domain_content


def get_email_address_content(
    email_address_record: dict[str, Any]
) -> dict[str, Any]:
    return {
        "Domain": email_address_record.get("domain", ""),
        "Email": email_address_record.get("email", ""),
        "CreatedAt": email_address_record.get("created_at", ""),
    }


def get_credentials_content(
    credentials_record: dict[str, Any]
) -> dict[str, Any]:
    return {
        "Domain": credentials_record.get("domain", ""),
        "Email": credentials_record.get("email", ""),
        "CreatedAt": credentials_record.get("created_at", ""),
    }


def get_botnet_credentials_content(
    botnet_credentials_record: dict[str, Any]
) -> dict[str, Any]:
    return {
        "Domain": botnet_credentials_record.get("domain", ""),
        "Email": botnet_credentials_record.get("email", ""),
        "CreatedAt": botnet_credentials_record.get("created_at", ""),
    }


def get_compromised_email_content(
    email_addressed_response: dict[str, Any],
    credentials_response: dict[str, Any],
    botnet_credentials_response: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    It merges the content of email_addressed_response,
    credentials_response and botnet_credentials_response and
    format it to be standardized as compromised email content

    :param email_addressed_response: The response of the email-addresses
    :param credentials_response: The response of the compromised-credentials
    :param botnet_credentials_response: The response of the
    botnet-compromised-credentials
    :return: A list of dictionaries representing the compromised email content
    """
    compromised_email_content = []

    email_addresses_results = email_addressed_response.get("results", [])
    compromised_email_content += [
        get_email_address_content(record)
        for record in email_addresses_results
    ]

    credentials_results = credentials_response.get("results", [])
    compromised_email_content += [
        get_credentials_content(record)
        for record in credentials_results
    ]

    botnet_credentials_results = botnet_credentials_response.get("results", [])
    compromised_email_content += [
        get_botnet_credentials_content(record)
        for record in botnet_credentials_results
    ]

    return compromised_email_content


def get_botnet_ip_content(botnet_result: dict[str, Any]) -> dict[str, Any]:
    return {
        "CreatedAt": botnet_result.get("acquired_at", ""),
        "IPAddress": botnet_result.get("ip_address", ""),
        "Domain": botnet_result.get("c2_domain", ""),
    }


def get_phishing_ip_content(botnet_result: dict[str, Any]) -> dict[str, Any]:
    return {
        "CreatedAt": botnet_result.get("scanned", ""),
        "IPAddress": get_nested_key(botnet_result, ["host", "ip"]),
        "Domain": botnet_result.get("domain", ""),
    }


def get_malicious_ip_content(
    botnet_response: dict[str, Any],
    phishing_response: dict[str, Any]
) -> list[dict[str, Any]]:
    """
    It merges the content of botnet_response and phishing_response and
    format it to be standardized as malicious ip content

    :param botnet_response: The response of the botnet CTI Feed
    :param phishing_response: The response of the phishing CTI Feed
    :return: A list of dictionaries representing the malicious ip content
    """
    malicious_ip_content = []

    botnet_results = botnet_response.get("results", [])
    malicious_ip_content += [
        get_botnet_ip_content(record)
        for record in botnet_results
    ]

    phishing_results = phishing_response.get("results", [])
    malicious_ip_content += [
        get_phishing_ip_content(record)
        for record in phishing_results
    ]

    return malicious_ip_content


def get_malicious_hash_type_content(
    malicious_hash_result: dict[str, Any],
    hash_type: str
) -> dict[str, str]:
    family_content = malicious_hash_result.get("family", [])
    if not family_content:
        family_content = []
    return {
        "CreatedAt": malicious_hash_result.get("created_at", ""),
        "Family": ", ".join(family_content),
        "MD5": malicious_hash_result.get("md5", ""),
        "SHA1": malicious_hash_result.get("sha1", ""),
        "SHA256": malicious_hash_result.get("sha256", ""),
        "SHA512": malicious_hash_result.get("sha512", ""),
        "FoundHash": hash_type,
    }


def get_malicious_hash_content(
    hash_type: str,
    malicious_hash_response: dict[str, Any]
) -> list[dict[str, Any]]:
    malicious_hash_content = []

    malicious_hash_results = malicious_hash_response.get("results", [])
    malicious_hash_content += [
        get_malicious_hash_type_content(record, hash_type)
        for record in malicious_hash_results
    ]

    return malicious_hash_content


def get_exploit_content(exploit_result: dict[str, Any]) -> dict[str, str]:
    return {
        "CreatedAt": exploit_result.get("created_at", ""),
        "CVECode": exploit_result.get("cve", ""),
        "URLs": ", ".join(exploit_result.get("urls", [])),
    }


def get_exploits_content(
    exploits_response: dict[str, Any]
) -> list[dict[str, Any]]:
    """
    It formats the exploits_response to be standardized as exploits content

    :param exploits_response: The response of the exploits CTI Feed
    :return: A list of dictionaries representing the exploits content
    """
    exploits_content = []

    exploits_results = exploits_response.get("results", [])
    exploits_content += [
        get_exploit_content(record)
        for record in exploits_results
    ]

    return exploits_content


def _build_incidents_given_last_fetch(
    client: ZFClient,
    created_since: datetime,
    is_valid_alert: Callable[[dict[str, Any]], bool],
) -> tuple[list[dict[str, Any]], datetime, list[str]]:

    if client.only_escalated:
        alerts = [
            alert for alert in client.get_alerts(
                filter_by={
                    "escalated_min_date": created_since.strftime(DATE_FORMAT)},
                sort_by="timestamp",
                sort_direction="asc"
            )
            if is_valid_alert(alert)
        ]
    else:
        alerts = [
            alert for alert in client.get_alerts(
                filter_by={
                    "min_timestamp": created_since.strftime(DATE_FORMAT)},
                sort_by="timestamp",
                sort_direction="asc"
            )
            if is_valid_alert(alert)
        ]
    if not alerts:
        return [], created_since, []

    alert_to_incident = AlertToIncident()
    incidents: list[dict[str, Any]] = [
        alert_to_incident.map(alert) for alert in alerts
    ]

    parsed_last_alert_timestamp = __compute_latest_timestamp(
        alerts, "timestamp")
    if parsed_last_alert_timestamp is None:
        raise ValueError(
            "Incorrect timestamp in last alert of fetch-incidents")
    processed_alerts_ids: list[str] = [str(alert.get("id", ""))
                                       for alert in alerts]

    return incidents, parsed_last_alert_timestamp, processed_alerts_ids


def __compute_latest_timestamp(alerts, timestamp_field: str):
    parsed_last_alert_timestamp = datetime.fromtimestamp(0)
    for alert in alerts:
        alert_timestamp_str: str = alert.get(timestamp_field, "")
        alert_timestamp = parse_date(
            alert_timestamp_str,
            date_formats=(DATE_FORMAT,),
        )
        if alert_timestamp is None:
            raise ValueError("Incorrect timestamp in alert of fetch-incidents")
        alert_timestamp = alert_timestamp.replace(tzinfo=None)
        if alert_timestamp > parsed_last_alert_timestamp:
            parsed_last_alert_timestamp = alert_timestamp
    return parsed_last_alert_timestamp


def parse_last_fetched_date(
    last_fetched_str: str | None,
    first_fetch_time: str
) -> datetime:
    # If no last_fetched present, use default value
    if not last_fetched_str:
        last_fetched_str = first_fetch_time
    last_fetched = parse_date(last_fetched_str, date_formats=(DATE_FORMAT,))
    # If last_fetched is invalid, raise ValueError
    if last_fetched is None:
        raise ValueError("last_fetched param is invalid")
    return last_fetched


""" COMMANDS """


def test_module(client: ZFClient) -> str:
    """
    Performs basic get request to get item samples
    """
    client.get_policy_types()
    return "ok"


def fetch_incidents(
    client: ZFClient,
    last_run: FetchIncidentsStorage,
    first_fetch_time: str
) -> tuple[FetchIncidentsStorage, list[dict[str, Any]]]:
    # Last modified fetch date
    last_modified_fetched_str = last_run.get("last_modified_fetched", "")
    last_fetched = parse_last_fetched_date(
        last_modified_fetched_str, first_fetch_time)
    # ZeroFox Alert IDs previously created
    zf_ids: list[str] = list(map(str, last_run.get("zf-ids", [])))

    # Fetch new alerts
    def is_non_registered_alert(alert):
        return str(alert.get("id")) not in zf_ids
    incidents, last_fetched, alert_ids = _build_incidents_given_last_fetch(
        client=client,
        created_since=last_fetched,
        is_valid_alert=is_non_registered_alert,
    )
    next_run: FetchIncidentsStorage = {
        "last_modified_fetched": last_fetched.strftime(DATE_FORMAT),
        "zf-ids": list(zf_ids),
    }
    if not incidents:
        return next_run, []

    ingested_alert_ids = alert_ids + zf_ids
    next_run["zf-ids"] = ingested_alert_ids[:MAX_ALERT_IDS_STORED]

    return next_run, incidents


def get_modified_remote_data_command(
    client: ZFClient,
    args: dict[str, Any]
) -> GetModifiedRemoteDataResponse:
    """
    Gets the modified remote alert IDs.
    Args:
        args:
            lastUpdate: the last time we retrieved modified alerts.

    Returns:
        GetModifiedRemoteDataResponse object, which contains a list of the retrieved alert IDs.
    """
    args = GetModifiedRemoteDataArgs(args)
    last_update = args.last_update

    # Get alerts modified after `last_update`
    try:
        alerts = client.get_alerts(
            filter_by={
                "last_modified_min_date": f"{last_update}"
            },
            sort_by="last_modified",
            sort_direction="asc"
        )
    except Exception as e:
        raise Exception(f"There was an error {e}, skip update")

    demisto.debug(f"Fetched {len(alerts)} alerts that "
                  f" were modified since {last_update}")
    modified_alert_ids = [str(alert.get("id")) for alert in alerts]

    return GetModifiedRemoteDataResponse(
        modified_incident_ids=modified_alert_ids,
    )


def get_remote_data_command(
    client: ZFClient,
    args: dict[str, Any]
) -> GetRemoteDataResponse:
    """
    get-remote-data command: Returns an updated remote alert.
    Args:
        args:
            id: alert id to retrieve.
            lastUpdate: when was the last time we retrieved data.

    Returns:
        GetRemoteDataResponse object, which contain the alert data to update.
    """
    args = GetRemoteDataArgs(args)
    last_update = args.last_update
    alert_id = args.remote_incident_id

    alert: dict[str, Any] = client.get_alert(alert_id)
    logs = sorted(
        filter(lambda log: log['timestamp'] > last_update,
               alert.get("logs", [])
               ),
        key=lambda log: log['timestamp'])
    demisto.debug(f"Alert fetched with id {alert.get('id')}")

    entries = []
    for log in logs:
        if log.get("action", "") == "close":
            demisto.debug(
                f"Incident associated with {alert_id=} is being closed"
            )
            entries.append({
                "Contents": {
                    "dbotIncidentClose": True,
                    "closeReason": "Other",
                    "closeNotes": "Closed in ZeroFox"
                },
            })

    return GetRemoteDataResponse(mirrored_object=alert, entries=entries)


def get_alert_command(
    client: ZFClient,
    args: dict[str, Any]
) -> CommandResults:
    params = parse_dict_values_to_integer(args, ["alert_id"])
    alert_id: int = params.get("alert_id", "")
    alert: dict[str, Any] = client.get_alert(alert_id)
    if not alert or not isinstance(alert, dict):
        raise Exception(f"Alert with ID {alert_id} does not exist")
    output = get_alert_contents(alert)
    readable_output = get_human_readable_alerts(output)
    return CommandResults(
        outputs=output,
        outputs_prefix="ZeroFox.Alert",
        readable_output=readable_output,
        outputs_key_field="ID",
    )


def alert_user_assignment_command(
    client: ZFClient,
    args: dict[str, Any]
) -> CommandResults:
    params = parse_dict_values_to_integer(args, ["alert_id"])
    alert_id: int = params.get("alert_id", "")
    username: str = args.get("username", "")
    client.alert_user_assignment(alert_id, username)
    alert: dict[str, Any] = client.get_alert(alert_id)
    contents = get_alert_contents(alert)

    return CommandResults(
        readable_output="Successful assignment "
                        f"of {username} to alert {alert_id}.",
        outputs=contents,
        outputs_prefix="ZeroFox.Alert",
        outputs_key_field="ID",
    )


def close_alert_command(
    client: ZFClient,
    args: dict[str, Any]
) -> CommandResults:
    params = parse_dict_values_to_integer(args, ["alert_id"])
    alert_id: int = params.get("alert_id", "")
    client.close_alert(alert_id)
    alert: dict[str, Any] = client.get_alert(alert_id)
    contents = get_alert_contents(alert)

    return CommandResults(
        readable_output=f"Successfully closed Alert {alert_id}.",
        outputs=contents,
        outputs_prefix="ZeroFox.Alert",
        outputs_key_field="ID",
    )


def open_alert_command(
    client: ZFClient,
    args: dict[str, Any]
) -> CommandResults:
    params = parse_dict_values_to_integer(args, ["alert_id"])
    alert_id: int = params.get("alert_id", "")
    client.open_alert(alert_id)
    alert: dict[str, Any] = client.get_alert(alert_id)
    contents = get_alert_contents(alert)

    return CommandResults(
        readable_output=f"Successfully opened Alert {alert_id}.",
        outputs=contents,
        outputs_prefix="ZeroFox.Alert",
        outputs_key_field="ID",
    )


def alert_request_takedown_command(
    client: ZFClient,
    args: dict[str, Any]
) -> CommandResults:
    params = parse_dict_values_to_integer(args, ["alert_id"])
    alert_id: int = params.get("alert_id", "")
    client.alert_request_takedown(alert_id)
    alert: dict[str, Any] = client.get_alert(alert_id)
    contents = get_alert_contents(alert)

    return CommandResults(
        readable_output=f"Request to successfully take down Alert {alert_id}.",
        outputs=contents,
        outputs_prefix="ZeroFox.Alert",
        outputs_key_field="ID",
    )


def alert_cancel_takedown_command(
    client: ZFClient,
    args: dict[str, Any]
) -> CommandResults:
    params = parse_dict_values_to_integer(args, ["alert_id"])
    alert_id: int = params.get("alert_id", "")
    client.alert_cancel_takedown(alert_id)
    alert: dict[str, Any] = client.get_alert(alert_id)
    contents = get_alert_contents(alert)

    return CommandResults(
        readable_output=f"Successful cancelled takedown of Alert {alert_id}.",
        outputs=contents,
        outputs_prefix="ZeroFox.Alert",
        outputs_key_field="ID",
    )


def modify_alert_tags_command(
    client: ZFClient,
    args: dict[str, Any]
) -> CommandResults:
    params = parse_dict_values_to_integer(args, ["alert_id"])
    alert_id: int = params.get("alert_id", "")
    action_string: str = args.get("action", "")
    action: str = "added" if action_string == "add" else "removed"
    tags_list_string: str = args.get("tags", "")
    tags_list: list[str] = argToList(tags_list_string, separator=",")
    response_content = client.modify_alert_tags(
        alert_id,
        action,
        tags_list,
    )
    if not response_content.get("changes"):
        raise Exception(f"Alert with ID {alert_id} does not exist")
    alert: dict[str, Any] = client.get_alert(alert_id)
    contents = get_alert_contents(alert)

    return CommandResults(
        readable_output="Successful modification of tags.",
        outputs=contents,
        outputs_prefix="ZeroFox.Alert",
        outputs_key_field="ID",
    )


def create_entity_command(
    client: ZFClient,
    args: dict[str, Any]
) -> CommandResults:
    params = parse_dict_values_to_integer(args, ["policy_id"])
    name = params.get("name", "")
    raw_strict_name_matching = params.get("strict_name_matching", "")
    strict_name_matching = raw_strict_name_matching == "true"
    tags = params.get("tags", "")
    tags: list[str] = argToList(tags, ",")
    policy_id: int = params.get("policy_id", "")
    organization = params.get("organization", "")
    response_content = client.create_entity(
        name, strict_name_matching, tags, policy_id, organization,
    )
    entity_id: int = response_content.get("id", "")

    return CommandResults(
        readable_output=f"Successful creation of entity. ID: {entity_id}.",
        outputs={
            "ID": entity_id,
            "StrictNameMatching": strict_name_matching,
            "Name": name,
            "Tags": tags,
            "PolicyID": policy_id,
            "Organization": organization,
        },
        outputs_prefix="ZeroFox.Entity",
        outputs_key_field="ID",
    )


def list_alerts_command(
    client: ZFClient,
    args: dict[str, Any]
) -> CommandResults:
    params = remove_none_dict(args)
    # handle all integer query params
    params = parse_dict_values_to_integer(params, [
        "entity", "entity_term", "last_modified", "offset", "page_id",
        "rule_id", "limit",
    ])
    # handle severity/risk_rating parameter - special case
    risk_rating_string = str(params.get("risk_rating", ""))
    if risk_rating_string:
        del params["risk_rating"]
        params["severity"] = severity_string_to_num(risk_rating_string)
    # handle limit parameter - special case
    limit: int = params.get("limit", "")
    if limit and (limit < 0 or limit > 100):
        raise Exception("Incorrect limit. Limit should be 0 <= x <= 100.")
    alerts = client.list_alerts(params)
    if not alerts:
        return CommandResults(
            readable_output="No alerts found.",
            outputs=[],
            outputs_prefix="ZeroFox.Alert"
        )
    output: list[dict[str, Any]] = [
        get_alert_contents(alert) for alert in alerts
    ]
    readable_output = get_human_readable_alerts(output)
    return CommandResults(
        outputs=output,
        readable_output=readable_output,
        outputs_prefix="ZeroFox.Alert",
    )


def list_entities_command(
    client: ZFClient,
    args: dict[str, Any]
) -> CommandResults:
    params = remove_none_dict(args)
    # handle all integer query params
    params = parse_dict_values_to_integer(params, [
        "group", "label", "network", "page", "policy", "type",
    ])
    response_content = client.list_entities(params)
    if not response_content:
        return CommandResults(
            readable_output="No entities found.",
            outputs=[],
            outputs_prefix="ZeroFox.Entity",
        )
    elif isinstance(response_content, dict):
        entities: list[dict[str, Any]] = response_content.get("entities", [])
        if not entities:
            return CommandResults(
                readable_output="No entities found.",
                outputs=entities,
                outputs_prefix="ZeroFox.Entity",
            )
        else:
            contents = [get_entity_contents(entity) for entity in entities]
            human_readable = [
                get_entity_human_readable_outputs(content)
                for content in contents
            ]
            headers = ["Name", "Type", "Policy", "Email", "Tags", "ID"]
            return CommandResults(
                readable_output=tableToMarkdown(
                    "ZeroFox Entities",
                    human_readable,
                    headers=headers,
                    removeNull=True,
                ),
                raw_response=response_content,
                outputs=contents,
                outputs_prefix="ZeroFox.Entity",
            )

    return CommandResults(
        readable_output="No entities found.",
        outputs=[],
        outputs_prefix="ZeroFox.Entities",
    )


def get_entity_types_command(
    client: ZFClient,
    args: dict[str, Any]
) -> CommandResults:
    response_content = client.get_entity_types()
    entity_types: list[dict[str, Any]] = response_content.get("results", [])
    human_readable = []
    for entity_type in entity_types:
        type_name: str = entity_type.get("name", "")
        type_id: int = entity_type.get("id", "")
        human_readable.append({"Name": type_name, "ID": type_id})
    headers = ["Name", "ID"]
    return CommandResults(
        outputs=entity_types,
        readable_output=tableToMarkdown(
            "ZeroFox Entity Types",
            human_readable,
            headers=headers,
            removeNull=True,
        ),
        outputs_prefix="ZeroFox.EntityTypes",
    )


def get_policy_types_command(
    client: ZFClient,
    args: dict[str, Any]
) -> CommandResults:
    response_content = client.get_policy_types()
    policy_types: list[dict[str, Any]] = response_content.get("policies", [])
    human_readable = []
    for policy_type in policy_types:
        type_name: str = policy_type.get("name", "")
        type_id: int = policy_type.get("id", "")
        human_readable.append({"Name": type_name, "ID": type_id})
    headers = ["Name", "ID"]

    return CommandResults(
        outputs=policy_types,
        readable_output=tableToMarkdown(
            "ZeroFox Policy Types",
            human_readable,
            headers=headers,
            removeNull=True,
        ),
        outputs_prefix="ZeroFox.PolicyTypes",
        raw_response=response_content,
    )


def modify_alert_notes_command(
    client: ZFClient,
    args: dict[str, Any]
) -> CommandResults:
    params = parse_dict_values_to_integer(args, ["alert_id"])
    alert_id: int = params.get("alert_id", "")
    alert_notes: str = params.get("notes", "")
    action: str = params.get("action", "replace")
    if action == "append":
        alert_pre_change: dict[str, Any] = client.get_alert(alert_id)
        old_notes = alert_pre_change.get("notes", "")
        alert_notes = f"{old_notes}\n{alert_notes}" if old_notes else alert_notes
    client.modify_alert_notes(alert_id, alert_notes)
    alert: dict[str, Any] = client.get_alert(alert_id)
    contents = get_alert_contents(alert)

    return CommandResults(
        readable_output="Successful note modification of alert "
                        f"with ID: {alert_id}",
        outputs=contents,
        outputs_prefix="ZeroFox.Alert",
        outputs_key_field="ID",
    )


def submit_threat_command(
    client: ZFClient,
    args: dict[str, Any]
) -> CommandResults:
    source: str = args.get("source", "")
    alert_type: str = args.get("alert_type", "")
    violation: str = args.get("violation", "")
    entity_id: str = args.get("entity_id", "")
    response_content = client.submit_threat(
        source,
        alert_type,
        violation,
        entity_id,
    )
    alert_id = response_content.get("alert_id")
    if alert_id is None:
        raise Exception("Threat couldn't be created")
    output = f"Successful submission of threat. ID: {alert_id}."
    alert: dict[str, Any] = client.get_alert(alert_id)
    contents = get_alert_contents(alert)

    return CommandResults(
        readable_output=output,
        raw_response=response_content,
        outputs=contents,
        outputs_prefix="ZeroFox.Alert",
        outputs_key_field="ID",
    )


def send_alert_attachment_command(
    client: ZFClient,
    args: dict[str, Any]
) -> CommandResults:
    alert_id: int = args.get("alert_id", "")
    entry_id: str = args.get("entry_id", "")
    attachment_type: str = args.get("attachment_type", "")

    if not alert_id or not entry_id or not attachment_type:
        raise ValueError("alert_id, entry_id and attachment_type are required")

    entry = demisto.getFilePath(entry_id)

    with open(entry["path"], "rb") as file:
        client.send_alert_attachment(
            alert_id, entry["name"], file, attachment_type,
        )

    alert: dict[str, Any] = client.get_alert(alert_id)
    contents = get_alert_contents(alert)

    return CommandResults(
        readable_output="Attachment sent successfully",
        outputs=contents,
        outputs_prefix="ZeroFox.Alert",
        outputs_key_field="ID",
    )


def get_alert_attachments_command(
    client: ZFClient,
    args: dict[str, Any]
) -> CommandResults:
    alert_id: int = args.get("alert_id", "")
    response_content = client.get_alert_attachments(alert_id)
    attachments: list[dict[str, Any]] = response_content.get("attachments", [])
    human_readable = []
    for attachment in attachments:
        attachment_id: int = attachment.get("id", "")
        attachment_name: str = attachment.get("name", "")
        human_readable.append({
            "ID": attachment_id,
            "Name": attachment_name,
        })
    headers = ["ID", "Name"]
    return CommandResults(
        outputs=attachments,
        readable_output=tableToMarkdown(
            "ZeroFox Alert Attachments",
            human_readable,
            headers=headers,
            removeNull=True,
        ),
        outputs_prefix="ZeroFox.AlertAttachments",
    )


def get_compromised_credentials_command(
    client: ZFClient,
    args: dict[str, Any]
) -> CommandResults:
    alert_id = args["alert_id"]
    credentials = client.get_compromised_credentials(alert_id)
    if credentials:
        return fileResult(f"breach_{alert_id}.csv", credentials)
    return CommandResults(
        readable_output=f"No compromised credentials were found for {alert_id=}",
    )


def compromised_domain_command(
    client: ZFClient,
    args: dict[str, Any]
) -> CommandResults:
    domain: str = args.get("domain", "")

    c2_domains_response = client.get_cti_c2_domains(domain)
    phishing_response = client.get_cti_phishing(domain=domain)
    outputs = get_compromised_domain_content(
        c2_domains_response,
        phishing_response,
    )

    if len(outputs) == 0:
        return CommandResults(
            readable_output="No compromised domains were found",
            outputs=outputs,
            outputs_prefix="ZeroFox.CompromisedDomains",
        )
    return CommandResults(
        readable_output=tableToMarkdown("Compromised domain Summary", outputs),
        outputs=outputs,
        outputs_prefix="ZeroFox.CompromisedDomains",
    )


def compromised_email_command(
    client: ZFClient,
    args: dict[str, Any]
) -> CommandResults:
    email: str = args.get("email", "")

    email_addresses_response = client.get_cti_email_addresses(email)
    credentials_response = client.get_cti_compromised_credentials(email)
    botnet_credentials_response = client\
        .get_cti_botnet_compromised_credentials(email)

    outputs = get_compromised_email_content(
        email_addresses_response,
        credentials_response,
        botnet_credentials_response,
    )

    if len(outputs) == 0:
        return CommandResults(
            outputs=outputs,
            readable_output="No compromised emails were found",
            outputs_prefix="ZeroFox.CompromisedEmails",
        )
    return CommandResults(
        outputs=outputs,
        readable_output=tableToMarkdown(
            "Compromised email Summary",
            outputs,
        ),
        outputs_prefix="ZeroFox.CompromisedEmails",
    )


def malicious_ip_command(
    client: ZFClient,
    args: dict[str, Any]
) -> CommandResults:
    ip: str = args.get("ip", "")

    botnet_response = client.get_cti_botnet(ip)
    phishing_response = client.get_cti_phishing(ip=ip)

    outputs = get_malicious_ip_content(
        botnet_response,
        phishing_response,
    )

    if len(outputs) == 0:
        return CommandResults(
            readable_output="No malicious ips were found",
            outputs=outputs,
            outputs_prefix="ZeroFox.MaliciousIPs",
        )
    return CommandResults(
        outputs=outputs,
        readable_output=tableToMarkdown("Malicious ip Summary", outputs),
        outputs_prefix="ZeroFox.MaliciousIPs",
    )


def malicious_hash_command(
    client: ZFClient,
    args: dict[str, Any]
) -> CommandResults:
    hash: str = args.get("hash", "")

    outputs = []
    for hash_type in ["md5", "sha1", "sha256", "sha512"]:
        hash_type_response = client.get_cti_malware(hash_type, hash)
        outputs += get_malicious_hash_content(hash_type, hash_type_response)

    if len(outputs) == 0:
        return CommandResults(
            readable_output="No malicious hashes were found",
            outputs=outputs,
            outputs_prefix="ZeroFox.MaliciousHashes",
        )
    return CommandResults(
        outputs=outputs,
        readable_output=tableToMarkdown("Malicious hash Summary", outputs),
        outputs_prefix="ZeroFox.MaliciousHashes",
    )


def search_exploits_command(
    client: ZFClient,
    args: dict[str, Any]
) -> CommandResults:
    since: str = args.get("since", "")

    exploits_response = client.get_cti_exploits(since)

    outputs = get_exploits_content(exploits_response)

    if len(outputs) == 0:
        return CommandResults(
            outputs=outputs,
            readable_output="No exploits were found",
            outputs_prefix="ZeroFox.Exploits",
        )
    return CommandResults(
        outputs=outputs,
        readable_output=tableToMarkdown("Exploit Search Summary", outputs),
        outputs_prefix="ZeroFox.Exploits",
    )


""" COMMANDS MANAGER / SWITCH PANEL """


def main():
    params = demisto.params()
    USERNAME: str = params.get("credentials", {}).get("identifier")
    PASSWORD: str = params.get("credentials", {}).get("password")
    BASE_URL: str = (
        params["url"][:-1]
        if params["url"].endswith("/")
        else params["url"]
    )
    FETCH_TIME: str = params.get(
        "fetch_time", FETCH_TIME_DEFAULT,
    ).strip()
    USE_SSL: bool = not params.get("insecure", False)
    PROXY: bool = params.get('proxy', False)
    ONLY_ESCALATED: bool = params.get("only_escalated", False)

    commands: dict[str, Callable[[ZFClient, dict[str, Any]], Any]] = {
        "get-modified-remote-data": get_modified_remote_data_command,
        "get-remote-data": get_remote_data_command,

        # ZeroFox Alerts
        "zerofox-get-alert": get_alert_command,
        "zerofox-alert-user-assignment": alert_user_assignment_command,
        "zerofox-close-alert": close_alert_command,
        "zerofox-open-alert": open_alert_command,
        "zerofox-alert-request-takedown": alert_request_takedown_command,
        "zerofox-alert-cancel-takedown": alert_cancel_takedown_command,
        "zerofox-modify-alert-tags": modify_alert_tags_command,
        "zerofox-create-entity": create_entity_command,
        "zerofox-list-alerts": list_alerts_command,
        "zerofox-list-entities": list_entities_command,
        "zerofox-get-entity-types": get_entity_types_command,
        "zerofox-get-policy-types": get_policy_types_command,
        "zerofox-modify-alert-notes": modify_alert_notes_command,
        "zerofox-submit-threat": submit_threat_command,
        "zerofox-send-alert-attachment": send_alert_attachment_command,
        "zerofox-get-alert-attachments": get_alert_attachments_command,
        "zerofox-get-compromised-credentials": get_compromised_credentials_command,

        # ZeroFox CTI Feed
        "zerofox-search-compromised-domain": compromised_domain_command,
        "zerofox-search-compromised-email": compromised_email_command,
        "zerofox-search-malicious-ip": malicious_ip_command,
        "zerofox-search-malicious-hash": malicious_hash_command,
        "zerofox-search-exploits": search_exploits_command,
    }
    try:
        handle_proxy()
        client = ZFClient(
            base_url=BASE_URL,
            ok_codes={200, 201},
            username=USERNAME,
            token=PASSWORD,
            verify=USE_SSL,
            proxy=PROXY,
            only_escalated=ONLY_ESCALATED,
        )

        command = demisto.command()

        if command == 'test-module':
            results = test_module(client)
            return_results(results)
        elif command == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client,
                last_run=demisto.getLastRun(),
                first_fetch_time=FETCH_TIME,
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command in commands:
            command_handler = commands[command]
            results = command_handler(client, demisto.args())
            return_results(results)
        else:
            raise NotImplementedError(f"Command '{command}' not implemented")

    # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {command}:\n {str(e)}")


if __name__ in ["__main__", "builtin", "builtins"]:
    main()

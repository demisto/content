import json
from dataclasses import asdict, dataclass
from typing import Any
from collections.abc import Callable
from urllib.parse import parse_qs, urlparse

import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from requests import Response

""" GLOBALS / PARAMS  """
FETCH_TIME_DEFAULT = "3 days"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
MAX_ALERT_IDS_STORED = 300

# Disable insecure warnings
urllib3.disable_warnings()


@dataclass
class KeyIncidentAttachment:
    content: str
    mime_type: str
    name: str
    created_at: str

    def to_dict(self):
        return asdict(self)


@dataclass
class KeyIncident:
    analysis: str
    created_at: datetime
    updated_at: datetime
    headline: str
    incident_id: str
    risk_level: str
    solution: str
    tags: list[str]
    threat_types: list[str]
    title: str
    url: str
    attachments: list[str]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "KeyIncident":
        return KeyIncident(
            analysis=data.get("analysis", ""),
            created_at=datetime.fromisoformat(
                data.get("created_at", "").replace("Z", "+00:00")),
            updated_at=datetime.fromisoformat(
                data.get("updated_at", "").replace("Z", "+00:00")),
            headline=data.get("headline", ""),
            incident_id=data.get("incident_id", ""),
            risk_level=data.get("risk_level", ""),
            solution=data.get("solution", ""),
            tags=data.get("tags", []),
            threat_types=data.get("threat_types", []),
            title=data.get("title", ""),
            url=data.get("url", ""),
            attachments=[
                _extract_ki_attachment_id(attch.get("url")) for attch in data.get("attachments", [])
            ],
        )

    def to_dict(self):
        new_dict = asdict(self)
        new_dict['created_at'] = self.created_at.isoformat()
        new_dict['updated_at'] = self.updated_at.isoformat()
        return new_dict

@dataclass
class XSOARIncident:
    def __init__(self, name: str, create_time: datetime, rawJSON: str, dbotMirrorId: str):
        self.name = name
        self.create_time = create_time
        self.rawJSON = rawJSON
        self.dbotMirrorId = dbotMirrorId

def map_key_incident_to_xsoar(ki: KeyIncident) -> XSOARIncident:
    ki_as_dict = ki.to_dict()
    return XSOARIncident(
        name=ki.incident_id + " " + ki.headline,
        create_time=ki_as_dict.get("created_at", ""),
        rawJSON=json.dumps(ki_as_dict),
        dbotMirrorId=ki.incident_id
    )

class ZeroFox(BaseClient):
    def __init__(
        self, username, token, *args, **kwargs
    ):
        super().__init__(*args, **kwargs)
        self.credentials = {
            "username": username,
            "password": token
        }
        self.access_token = None

    def _make_rest_call(
        self,
        method: str,
        url_suffix: str = "/",
        cti: bool = True,
        full_url: str | None = None,
        params: dict[str, str] | None = None,
        data: dict[str, Any] | None = None,
        ok_codes: tuple[int, ...] = None,
        empty_response: bool = False,
        **kwargs,
    ) -> dict[str, Any]:
        """
        :param method: HTTP request type
        :param url_suffix: The suffix of the URL
        :param cti: If the request is to cti endpoint
        :param params: The request's query parameters
        :param data: The request's body parameters
        :param empty_response: Indicates if the response data is empty or not
        :param error_handler: Function that receives the response and manage
        the error
        :return: Returns the content of the response received from the API.
        """
        headers = {}
        if cti:
            headers = self.get_cti_request_header()

        return self._http_request(
            method=method,
            url_suffix=url_suffix,
            full_url=full_url,
            headers=headers,
            params=params,
            json_data=data,
            ok_codes=ok_codes,
            return_empty_response=empty_response,
            error_handler=self.handle_zerofox_error,
            **kwargs,
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

    # CTI
    def get_cti_request_header(self) -> dict[str, str]:
        token: str = self.get_cti_authorization_token()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "zf-source": "XSOAR",
        }

    def get_cti_authorization_token(self) -> str:
        """
        :return: returns the authorization token for the CTI feed
        """
        if self.access_token:
            return self.access_token
        token = self._get_new_access_token()
        self.access_token = token
        return token

    def _get_new_access_token(self) -> str:
        url_suffix: str = "/auth/token/"
        response_content = self._make_rest_call(
            "POST",
            url_suffix,
            data=self.credentials,
            cti=False,
        )
        return response_content.get("access", "")

    def _parse_cursor(self, url) -> dict:
        query = parse_qs(urlparse(url).query)
        return query.get("cursor", [None])[0]

    def get_key_incidents(self, start_time, end_time) -> list[KeyIncident]:
        """
        :param start_time: The earliest point in time for which data should be fetched
        :param end_time: The latest point in time for which data should be fetched
        :return: HTTP request content.
        """
        url_suffix = "/cti/key-incidents/"
        headers = self.get_cti_request_header()
        params = remove_none_dict(
            {
                "updated_after": start_time,
                "updated_before": end_time,
                "ordering": "updated",
                "Tags": "Key Incident"
            }
        )
        key_incidents = []
        response = self._http_request(
            "GET",
            url_suffix,
            params=params,
            headers=headers,
        )
        key_incidents += [KeyIncident.from_dict(ki)
                          for ki in response.get("results", [])]

        if next_page := response.get("next"):
            cursor = self._parse_cursor(next_page)
            params.update(cursor=cursor)
            response = self._http_request(
                "GET",
                url_suffix,
                params=params,
                headers=headers,
            )
            key_incidents += [
                KeyIncident.from_dict(ki)
                for ki in response.get("results", [])
            ]
        return key_incidents

    def get_key_incident_attachment(self, attachment_id: str) -> KeyIncidentAttachment:
        """
        :param attachment_id: The ID of the attachment to fetch
        :return: The attachment data
        """
        url_suffix = f"/cti/key-incident-attachments/{attachment_id}/"
        headers = self.get_cti_request_header()
        response = self._http_request(
            "GET",
            url_suffix,
            headers=headers,
        )
        mime_type, content = _parse_file_content(
            response.get("content"))

        return KeyIncidentAttachment(
            content=content,
            mime_type=mime_type,
            name=response["name"],
            created_at=response["created_at"]
        )



""" HELPERS """


def _extract_ki_attachment_id(url) -> str:
    return url.split("/")[-1]


def _parse_file_content(data_uri):
    header_data_match = re.match(r'data:(.*?);base64,(.+)', data_uri)
    if not header_data_match:
        raise ValueError("Invalid data URL format")
    mime_type, data = header_data_match.groups()

    return mime_type, data


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


def remove_none_dict(input_dict: dict[Any, Any]) -> dict[Any, Any]:
    """
    removes all none values from a dict
    :param input_dict: any dictionary in the world is OK
    :return: same dictionary but without None values
    """
    return {key: value for key, value in input_dict.items() if value is not None}


""" COMMAND FUNCTIONS """


def get_key_incidents_command(
    client: ZeroFox,
    args: dict[str, Any]
) -> CommandResults:
    start_time: str = args.get("start_time", "")
    end_time: str = args.get("end_time", "")
    key_incidents = client.get_key_incidents(start_time, end_time)

    if len(key_incidents) == 0:
        return CommandResults(
            readable_output="No Key Incidents were found",
            outputs=key_incidents,
            outputs_prefix="ZeroFox_Key_Incidents.Key_Incidents",
        )
    return CommandResults(
        outputs=key_incidents,
        readable_output=tableToMarkdown("Key Incidents", key_incidents),
        outputs_prefix="ZeroFox_Key_Incidents.Key_Incidents",
    )


def test_conectivity(client: ZeroFox) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises:
     exceptions if something goes wrong.

    Args:
        ZFClient: client to use

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    client.get_cti_authorization_token()
    return "ok"


def main():
    params = demisto.params()
    USERNAME: str = params.get("credentials", {}).get("identifier")
    API_KEY: str = params.get("credentials", {}).get("password")
    BASE_URL: str = params["url"][:-1] if params["url"].endswith("/") else params["url"]
    USE_SSL: bool = not params.get("insecure", False)
    PROXY: bool = params.get("proxy", False)

    commands: dict[str, Callable[[ZeroFox, dict[str, Any]], Any]] = {
        "zerofox-get-key-incidents": get_key_incidents_command,
    }
    try:
        handle_proxy()
        command = demisto.command()

        client = ZeroFox(
            username=USERNAME,
            token=API_KEY,
            base_url=BASE_URL,
            ok_codes={200, 201},
            verify=USE_SSL,
            proxy=PROXY,
        )
        if command == "test-module":
            results = test_conectivity(client)
            return_results(results)
        elif command in commands:
            command_handler = commands[command]
            results = command_handler(client, demisto.args())
            return_results(results)
        raise NotImplementedError(f"Command {command} is not implemented")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
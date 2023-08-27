import copy
import re
from dataclasses import dataclass
from enum import Enum
from functools import partial
from http import HTTPStatus
from typing import Any, Callable

import demistomock as demisto
from CommonServerPython import *
from requests import Response

INTEGRATION_OUTPUT_PREFIX = "Rapid7AppSec"
INTEGRATION_COMMAND_PREFIX = "app-sec"
DEFAULT_OUTPUT_KEY_FIELD = "id"
VULNERABILITY = "vulnerability"
VULNERABILITY_COMMENT = "vulnerability-comment"
ATTACK = "attack"
SCAN = "scan"
SCAN_ACTION = "scan-action"
RESPONSE_TYPE = "response"
CLEAN_HTML_TAGS = re.compile('<.*?>')


class Pagination():
    """
    This class contains the arguments for pagination.
    """

    def __init__(self, limit: str, page: str | None = None, page_size: str | None = None):
        self.page = arg_to_number(page)
        self.page_size = arg_to_number(page_size)
        self.limit = arg_to_number(limit)


@dataclass
class AddToOutput:
    """
    This class will be used to add id to responses without id.
    For example: The scan history is: {scan_history_id: "1234", ...}, we would like to add the scan_id,
    the output will be: {scan_id: "2345", scan_history_id: "1234", ...}
    """
    data_to_add: dict


@dataclass
class PrefixToResponse(AddToOutput):
    """
    This class will be used to create an output with id and data under the prefix.
    For example: The scan platform events response is: [{"time": "...","event": "..."}], we would like to add
    the scan_id to the response and put the response under the Event prefix.
    The output will be: {XsoarArgKey.SCAN: "..." ,"Event": [{"time": "...","event": "..."}]}
    """
    prefix: str
    id_key: str


class RequestAction(str, Enum):
    GET = "GET"
    PUT = "PUT"
    POST = "POST"
    DELETE = "DELETE"


class ReadableOutputs(str, Enum):
    VULNERABILITY = "Vulnerability"
    SCAN = "Scan"
    VULNERABILITY_COMMENT = "Vulnerability Comment"
    UPDATED = "updated"
    DELETED = "deleted"
    SUBMITTED = "submitted"
    ADDED = 'added to vulnerability "{0}"'
    CHANGED = 'changed to "{0}"'


class Headers(list, Enum):
    ATTACK = ["id", "module_id", "type", "class", "description"]
    VULNERABILITY = [
        "id",
        "app_id",
        "root_cause_url",
        "severity",
        "status",
        "first_discovered",
        "last_discovered",
        "newly_discovered",
        "vulnerability_score",
    ]
    VULNERABILITY_COMMENT = [
        'id',
        'vulnerability_id',
        'author_id',
        'content',
        'create_time',
        'update_time',
    ]
    SCAN = [
        'id',
        'app_id',
        'scan_config_id',
        'submitter_id',
        'submit_time',
        'completion_time',
        'status',
        'failure_reason',
        'scan_type',
        'validation_parent_scan_id'
    ]

    SCAN_CONFIG = [
        'id',
        'name',
        'app_id',
        'incremental',
        'attack_template_id',
        'assignment_type',
        'assignment_environment'
    ]


class UrlPrefix(str, Enum):
    VULNERABILITY = "vulnerabilities"
    MODULE = "modules"
    SCAN = "scans"
    SCAN_CONFIG = "scan-configs"
    APP = "apps"
    ATTACK_TEMPLATE = "attack-templates"
    ENGINE_GROUP = "engine-groups"
    ENGINE = "engines"


class OutputPrefix(str, Enum):
    VULNERABILITY = "Vulnerability"
    VULNERABILITY_HISTORY = "VulnerabilityHistory"
    VULNERABILITY_COMMENT = "VulnerabilityComment"
    SCAN = "Scan"
    ENGINE_EVENT = "EngineEvent"
    PLATFORM_EVENT = "PlatformEvent"
    EXECUTION_DETAIL = "ExecutionDetail"
    MODULE = "Module"
    ATTACK = "Attack"
    ATTACK_DOCUMENTATION = "AttackDocumentation"
    SCAN_CONFIG = "ScanConfig"
    APP = "App"
    ATTACK_TEMPLATE = "AttackTemplate"
    ENGINE_GROUP = "EngineGroup"
    ENGINE = "Engine"


class XsoarArgKey(str, Enum):
    VULNERABILITY = "vulnerability_id"
    SCAN = "scan_id"
    COMMENT = "comment_id"
    ATTACK = "attack_id"
    MODULE = "module_id"
    PAGE = "page"
    PAGE_SIZE = "page_size"
    LIMIT = "limit"


class Client(BaseClient):
    """Client class to interact with AppSec API."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        verify: bool,
        proxy: bool,
    ):
        base_url = urljoin(base_url, "/ias/v1/")
        super().__init__(
            base_url=base_url,
            headers={"X-Api-Key": api_key},
            verify=verify,
            proxy=proxy,
        )

    def _http_request(self, *args, **kwargs) -> dict[str, Any]:
        """
        Add error handling to the http request.

        Returns:
            dict[str, Any]: API response from AppSec API.
        """
        kwargs["error_handler"] = partial(self.error_handler, error_message=kwargs.pop('error_message', None))
        return super()._http_request(*args, **kwargs)

    def error_handler(self, res: Response, error_message: str | None):
        """Error handler for Rapid7 AppSec response.

        Args:
            res (Response): Error response.
            error_message (str): Unique error message that related to the request.

        Raises:
            DemistoException: No content.
            DemistoException: Error from AppSec API.
        """
        message = error_message or ''
        if res.status_code == HTTPStatus.NO_CONTENT:
            raise DemistoException(
                f"No content to show. {message}"
            )
        else:
            raise DemistoException(message=f"{res.text} {message}", res=res)

    def update_vulnerability(
        self, vulnerability_id: str, severity: str | None, status: str | None
    ) -> dict[str, Any]:
        """
        Update the severity/ status of the vulnerability.

        Args:
            vulnerability_id (str): The ID of the vulnerability.
            severity (str | None): The severity of the vulnerability.
            status (str | None): The status of the vulnerability.

        Returns:
            dict[str, Any]: API response from AppSec API.
        """
        data = remove_empty_elements(
            {
                "severity": severity,
                "status": status,
            }
        )
        return self._http_request(
            method=RequestAction.PUT,
            url_suffix=f"{UrlPrefix.VULNERABILITY}/{vulnerability_id}",
            json_data=data,
            resp_type=RESPONSE_TYPE,
        )

    def list_vulnerability(
        self,
        index: int | None = None,
        size: int | None = None,
        obj_id: str | None = None,
    ) -> dict[str, Any]:
        """
        List vulnerabilities.

        Args:
            index (int | None): Index for pagination. Defaults to None.
            size (int | None): Size for pagination. Defaults to None.
            obj_id(str | None): Vulnerability ID . Defaults to None.

        Returns:
            dict[str, Any]: API response from AppSec API.
        """
        return self._http_request(
            method=RequestAction.GET,
            url_suffix=generate_api_endpoint(UrlPrefix.VULNERABILITY, obj_id),
            params=remove_empty_elements(
                {
                    "index": index,
                    "size": size,
                }
            ),
        )

    def get_vulnerability_history(self, obj_id: str) -> dict[str, Any]:
        """
        Get vulnerability history.

        Args:
            obj_id (str): The ID of the vulnerability.

        Returns:
            dict[str, Any]: API response from AppSec API.
        """
        return self._http_request(method=RequestAction.GET,
                                  url_suffix=f"{UrlPrefix.VULNERABILITY}/{obj_id}/history")

    def create_vulnerability_comment(
        self, vulnerability_id: str, comment_content: str
    ) -> dict[str, Any]:
        """
        Create a comment to vulnerability.

        Args:
            vulnerability_id (str): The ID of the vulnerability.
            comment_content (str): The content of the comment.

        Returns:
            dict[str, Any]: API response from AppSec API.
        """
        return self._http_request(
            method=RequestAction.POST,
            url_suffix=f"{UrlPrefix.VULNERABILITY}/{vulnerability_id}/comments",
            json_data={"content": comment_content},
            resp_type=RESPONSE_TYPE
        )

    def update_vulnerability_comment(
        self, vulnerability_id: str, comment_id: str, comment_content: str
    ) -> dict[str, Any]:
        """
        Update the severity/ status of the vulnerability.

        Args:
            vulnerability_id (str): The ID of the vulnerability.
            comment_id (str): The ID of the comment.
            comment_content (str): The comment content.

        Returns:
            dict[str, Any]: API response from AppSec API.
        """
        return self._http_request(
            method=RequestAction.PUT,
            url_suffix=f"{UrlPrefix.VULNERABILITY}/{vulnerability_id}/comments/{comment_id}",
            json_data={"content": comment_content},
            resp_type=RESPONSE_TYPE
        )

    def delete_vulnerability_comment(
        self, vulnerability_id: str, comment_id: str
    ) -> dict[str, Any]:
        """
        Delete vulnerability comment.

        Args:
            vulnerability_id (str): The ID of the vulnerability.
            comment_id (str): The ID of the comment.

        Returns:
            dict[str, Any]: API response from AppSec API.
        """
        return self._http_request(
            method=RequestAction.DELETE,
            url_suffix=f"{UrlPrefix.VULNERABILITY}/{vulnerability_id}/comments/{comment_id}",
            resp_type=RESPONSE_TYPE
        )

    def list_vulnerability_comment(self,
                                   vulnerability_id: str,
                                   obj_id: str | None = None) -> dict[str, Any]:
        """
        List vulnerability comments.

        Args:
            vulnerability_id (str): The ID of the vulnerability.
            obj_id(str | None): Vulnerability Comment ID . Defaults to None.

        Returns:
            dict[str, Any]: API response from AppSec API.
        """
        url_suffix = generate_api_endpoint(f"{UrlPrefix.VULNERABILITY}/{vulnerability_id}/comments", obj_id)
        return self._http_request(method=RequestAction.GET,
                                  url_suffix=url_suffix)

    def get_attack(
        self, module_id: str, obj_id: str
    ) -> dict[str, Any]:
        """
        Get attack.

        Args:
            module_id (str): The ID of the attack module.
            attack_id (str): The ID of the attack.

        Returns:
            dict[str, Any]: API response from AppSec API.
        """
        return self._http_request(method=RequestAction.GET,
                                  url_suffix=f"{UrlPrefix.MODULE}/{module_id}/attacks/{obj_id}")

    def get_attack_documentation(
        self, module_id: str, obj_id: str
    ) -> dict[str, Any]:
        """
        Get attack documentation.

        Args:
            module_id (str): The ID of the attack module.
            obj_id (str): The ID of the attack.

        Returns:
            dict[str, Any]: API response from AppSec API.
        """
        return self._http_request(method=RequestAction.GET,
                                  url_suffix=f"{UrlPrefix.MODULE}/{module_id}/attacks/{obj_id}/documentation")

    def list_attack_template(
        self,
        index: int | None = None,
        size: int | None = None,
        obj_id: str | None = None,
    ) -> dict[str, Any]:
        """
        List attack templates.

        Args:
            index (int | None): Index for pagination. Defaults to None.
            size (int | None): Size for pagination. Defaults to None.
            obj_id(str | None): Attack template ID . Defaults to None.

        Returns:
            dict[str, Any]: API response from AppSec API.
        """
        return self._http_request(
            method=RequestAction.GET,
            url_suffix=generate_api_endpoint(UrlPrefix.ATTACK_TEMPLATE, obj_id),
            params=remove_empty_elements(
                {
                    "index": index,
                    "size": size,
                }
            ),
        )

    def submit_scan(
        self, scan_config_id: str, scan_type: str, parent_scan_id: str | None
    ) -> dict[str, Any]:
        """
        Submit a new scan.

        Args:
            scan_config_id (str): The ID of the scan config.
            scan_type (str): The scan type.
            parent_scan_id (str | None): The parent scan id.

        Returns:
            dict[str, Any]: API response from AppSec API.
        """
        data = remove_empty_elements(
            {
                "scan_config": {"id": scan_config_id},
                "scan_type": scan_type,
                "validation": {"parent_scan_id": parent_scan_id},
            }
        )
        return self._http_request(
            method=RequestAction.POST, url_suffix=UrlPrefix.SCAN, json_data=data, resp_type=RESPONSE_TYPE,
        )

    def get_scan_action(self, obj_id: str) -> dict[str, Any]:
        """
        Get scan action.

        Args:
            scan_id (str): The ID of the scan.

        Returns:
            dict[str, Any]: API response from AppSec API.
        """
        return self._http_request(
            method=RequestAction.GET,
            url_suffix=f"{UrlPrefix.SCAN}/{obj_id}/action",
            ok_codes=[HTTPStatus.OK],
            error_message="Please verify the scan status is RUNNING.",
        )

    def submit_scan_action(self, scan_id: str, action: str) -> dict[str, Any]:
        """
        Submit scan action.

        Args:
            scan_id (str): The ID of the scan.
            action (str): The action to submit.

        Returns:
            dict[str, Any]: API response from AppSec API.
        """
        return self._http_request(
            method=RequestAction.PUT,
            url_suffix=f"{UrlPrefix.SCAN}/{scan_id}/action",
            json_data={"action": action},
            resp_type=RESPONSE_TYPE
        )

    def delete_scan(self, scan_id: str) -> dict[str, Any]:
        """
        Delete a scan.

        Args:
            scan_id (str): The ID of the scan.

        Returns:
            dict[str, Any]: API response from AppSec API.
        """
        return self._http_request(
            method=RequestAction.DELETE, url_suffix=f"{UrlPrefix.SCAN}/{scan_id}", resp_type=RESPONSE_TYPE
        )

    def list_scan(
        self,
        index: int | None = None,
        size: int | None = None,
        obj_id: str | None = None
    ) -> dict[str, Any]:
        """
        List scans.

        Args:
            index (int | None): Index for pagination. Defaults to None.
            size (int | None): Size for pagination. Defaults to None.
            obj_id(str | None): Scan ID . Defaults to None.

        Returns:
            dict[str, Any]: API response from AppSec API.
        """
        return self._http_request(
            method=RequestAction.GET,
            url_suffix=generate_api_endpoint(UrlPrefix.SCAN, obj_id),
            params=remove_empty_elements(
                {
                    "index": index,
                    "size": size,
                }
            ),
        )

    def list_scan_engine_event(self, obj_id: str) -> dict[str, Any]:
        """
        List scan engine events.

        Args:
            obj_id (str): The ID of the scan.

        Returns:
            dict[str, Any]: API response from AppSec API.
        """
        return self._http_request(
            method=RequestAction.GET, url_suffix=f"{UrlPrefix.SCAN}/{obj_id}/engine-events"
        )

    def list_scan_platform_event(self, obj_id: str) -> dict[str, Any]:
        """
        List scan platform events.

        Args:
            obj_id (str): The ID of the scan.

        Returns:
            dict[str, Any]: API response from AppSec API.
        """
        return self._http_request(
            method=RequestAction.GET, url_suffix=f"{UrlPrefix.SCAN}/{obj_id}/platform-events"
        )

    def get_scan_execution_details(self, obj_id: str) -> dict[str, Any]:
        """
        Get scan execution details.

        Args:
            obj_id (str): The ID of the scan.

        Returns:
            dict[str, Any]: API response from AppSec API.
        """
        return self._http_request(
            method=RequestAction.GET, url_suffix=f"{UrlPrefix.SCAN}/{obj_id}/execution-details"
        )

    def list_scan_config(
        self,
        index: int | None = None,
        size: int | None = None,
        obj_id: str | None = None
    ) -> dict[str, Any]:
        """
        List scan config.

        Args:
            index (int | None): Index for pagination. Defaults to None.
            size (int | None): Size for pagination. Defaults to None.
            obj_id(str | None): Scan Config ID . Defaults to None.

        Returns:
            dict[str, Any]: API response from AppSec API.
        """
        return self._http_request(
            method=RequestAction.GET,
            url_suffix=generate_api_endpoint(UrlPrefix.SCAN_CONFIG, obj_id),
            params=remove_empty_elements(
                {
                    "index": index,
                    "size": size,
                }
            ),
        )

    def list_app(
        self,
        index: int | None = None,
        size: int | None = None,
        obj_id: str | None = None
    ) -> dict[str, Any]:
        """
        List apps.

        Args:
            index (int | None): Index for pagination. Defaults to None.
            size (int | None): Size for pagination. Defaults to None.
            obj_id(str | None): App ID . Defaults to None.

        Returns:
            dict[str, Any]: API response from AppSec API.
        """
        return self._http_request(
            method=RequestAction.GET,
            url_suffix=generate_api_endpoint(UrlPrefix.APP, obj_id),
            params=remove_empty_elements(
                {
                    "index": index,
                    "size": size,
                }
            ),
        )

    def list_engine_group(
        self,
        index: int | None = None,
        size: int | None = None,
        obj_id: str | None = None
    ) -> dict[str, Any]:
        """
        List engine groups.

        Args:
            index (int | None): Index for pagination. Defaults to None.
            size (int | None): Size for pagination. Defaults to None.
            obj_id(str | None): Engine group ID . Defaults to None.

        Returns:
            dict[str, Any]: API response from AppSec API.
        """
        return self._http_request(
            method=RequestAction.GET,
            url_suffix=generate_api_endpoint(UrlPrefix.ENGINE_GROUP, obj_id),
            params=remove_empty_elements(
                {
                    "index": index,
                    "size": size,
                }
            ),
        )

    def list_engine(
        self,
        index: int | None = None,
        size: int | None = None,
        obj_id: str | None = None
    ) -> dict[str, Any]:
        """
        List engine.

        Args:
            index (int | None): Index for pagination. Defaults to None.
            size (int | None): Size for pagination. Defaults to None.
            obj_id(str | None): Engine ID . Defaults to None.

        Returns:
            dict[str, Any]: API response from AppSec API.
        """
        return self._http_request(
            method=RequestAction.GET,
            url_suffix=generate_api_endpoint(UrlPrefix.ENGINE, obj_id),
            params=remove_empty_elements(
                {
                    "index": index,
                    "size": size,
                }
            ),
        )

    def list_module(
        self,
        obj_id: str | None = None
    ) -> dict[str, Any]:
        """
        List modules.

        Args:
            obj_id(str | None): Module ID . Defaults to None.

        Returns:
            dict[str, Any]: API response from AppSec API.
        """
        return self._http_request(
            method=RequestAction.GET,
            url_suffix=generate_api_endpoint(UrlPrefix.MODULE, obj_id),
        )


@logger
def update_vulnerability_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Update the severity/ status of the vulnerability..

    Args:
        client (Client): Session to AppSec to run API requests.
        args (dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    vulnerability_id = args[XsoarArgKey.VULNERABILITY]

    client.update_vulnerability(
        vulnerability_id=vulnerability_id,
        severity=args.get("severity") and args["severity"].upper(),
        status=args.get("status") and args["status"].upper().replace(" ", "_"),
    )
    return CommandResults(
        readable_output=generate_readable_output_message(
            object_type=ReadableOutputs.VULNERABILITY.value,
            object_id=vulnerability_id,
            action=ReadableOutputs.UPDATED,
        )
    )


@logger
def list_vulnerability_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    List vulnerabilities.

    Args:
        client (Client): Session to AppSec to run API requests.
        args (dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    return list_handler(
        pagination=Pagination(page=args.get(XsoarArgKey.PAGE),
                              page_size=args.get(XsoarArgKey.PAGE_SIZE),
                              limit=args[XsoarArgKey.LIMIT]),
        obj_id=args.get(XsoarArgKey.VULNERABILITY),
        obj_type=OutputPrefix.VULNERABILITY,
        request_command=client.list_vulnerability,
        headers=Headers.VULNERABILITY,
    )


@logger
def list_vulnerability_history_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    List vulnerability history.

    Args:
        client (Client): Session to AppSec to run API requests.
        args (dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    return list_handler(
        obj_id=args[XsoarArgKey.VULNERABILITY],
        request_command=client.get_vulnerability_history,
        obj_type=OutputPrefix.VULNERABILITY_HISTORY,
        add_to_output=AddToOutput(data_to_add={"vulnerability_id": args[XsoarArgKey.VULNERABILITY]}),
    )


@logger
def create_vulnerability_comment_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Create vulnerability comment.

    Args:
        client (Client): Session to AppSec to run API requests.
        args (dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    client.create_vulnerability_comment(
        vulnerability_id=args[XsoarArgKey.VULNERABILITY], comment_content=args["comment_content"]
    )
    return CommandResults(
        readable_output=generate_readable_output_message(
            object_type=ReadableOutputs.VULNERABILITY_COMMENT.value,
            action=ReadableOutputs.ADDED.value.format(args[XsoarArgKey.VULNERABILITY]),
        )
    )


@logger
def update_vulnerability_comment_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Update vulnerability comment.

    Args:
        client (Client): Session to AppSec to run API requests.
        args (dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    client.update_vulnerability_comment(
        vulnerability_id=args[XsoarArgKey.VULNERABILITY],
        comment_id=args[XsoarArgKey.COMMENT],
        comment_content=args["comment_content"],
    )
    return CommandResults(
        readable_output=generate_readable_output_message(
            object_type=ReadableOutputs.VULNERABILITY_COMMENT,
            action=ReadableOutputs.UPDATED,
            object_id=args[XsoarArgKey.COMMENT],
        )
    )


@logger
def delete_vulnerability_comment_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Delete vulnerability comment.

    Args:
        client (Client): Session to AppSec to run API requests.
        args (dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    return delete_handler(
        obj_id=args[XsoarArgKey.VULNERABILITY],
        sub_obj_id=args[XsoarArgKey.COMMENT],
        readable_output=generate_readable_output_message(
            object_type=ReadableOutputs.VULNERABILITY_COMMENT,
            action=ReadableOutputs.DELETED,
            object_id=args[XsoarArgKey.COMMENT],
        ),
        request_command=client.delete_vulnerability_comment,
    )


@logger
def list_vulnerability_comment_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    List vulnerability comments.

    Args:
        client (Client): Session to AppSec to run API requests.
        args (dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    return list_handler(
        obj_id=args.get(XsoarArgKey.COMMENT),
        headers=Headers.VULNERABILITY_COMMENT,
        obj_type=OutputPrefix.VULNERABILITY_COMMENT,
        request_command=partial(client.list_vulnerability_comment, args[XsoarArgKey.VULNERABILITY]),
        add_to_output=AddToOutput(data_to_add={"vulnerability_id": args[XsoarArgKey.VULNERABILITY]}),
    )


@logger
def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication.

    Returning 'ok' indicates that the integration works like it is supposed to.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): Session to AppSec to run API requests.
    """
    try:
        client.list_scan_config(size=1)

    except DemistoException as error:
        if error.res.status_code == HTTPStatus.UNAUTHORIZED:
            return "Authorization Error: invalid API key or secret"

        return error.message

    return "ok"


""" HELPER FUNCTIONS """


@logger
def list_handler(
    obj_id: str | None,
    obj_type: str,
    request_command: Callable,
    add_to_output: AddToOutput | None = None,
    title: str | None = None,
    headers: list | None = None,
    pagination: Pagination | None = None,
    use_flatten_dict: bool = True,
    remove_html_tags: bool = True,
    parser: Callable | None = None,
    readable_parser: Callable | None = None,
) -> CommandResults:
    """
    Handle list requests and responses.

    Args:
        obj_id (str | None): The object ID to get data. In case of None, It will return all objects (with list request).
        obj_type (str): Object type for the readable output.
        request_command (Callable): List request for the relevant object.
        add_to_output (AddToOutput | None, optional): Add to output data. Defaults to None.
        title (str | None, optional): Title for the readable output. Defaults to None.
        headers (list | None, optional): Headers for the readable output. Defaults to None.
        pagination (Pagination | None, optional): Pagination arguments in case the list support pagination.
                                                       Defaults to None.
        use_flatten_dict (bool, optional): Whether to flatten the response. Defaults to True.
        parser (Callable | None, optional): Parser command for the API response. Defaults to None.
        readable_parser (Callable | None, optional): Parser command for readable output only. Defaults to None.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = handle_list_request(pagination=pagination,
                                   obj_id=obj_id,
                                   request_command=request_command)

    raw_response = copy.deepcopy(response)

    parsed_response = parse_list_response(
        data=get_appsec_response(response),
        use_flatten_dict=use_flatten_dict,
        remove_html_tags=remove_html_tags,
        parser_command=parser,
    )

    return create_list_command_results(
        data=parsed_response,
        obj_type=obj_type,
        response=raw_response,
        title=title,
        headers=headers,
        readable_parser=readable_parser,
        edit_outputs_settings=add_to_output
    )


@logger
def get_appsec_response(response: dict[str, Any] | list[dict[str, Any]]) -> dict[str, Any] | list[dict[str, Any]]:
    """
    Get the relevant data from the API response.

    Args:
        response (dict[str, Any] | list[dict[str, Any]]): Response from AppSec http request.

    Returns:
        dict[str, Any] | list[dict[str, Any]]: List of the relevant data.
    """
    if isinstance(response, dict) and (data := response.get("data")) is not None:
        return data
    elif isinstance(response, list):
        return response
    else:
        return [response]


@logger
def create_list_command_results(data: list,
                                obj_type: str,
                                response: dict[str, Any] | list[dict[str, Any]],
                                title: str | None = None,
                                headers: list | None = None,
                                readable_parser: Callable | None = None,
                                edit_outputs_settings: AddToOutput | None = None,
                                ) -> CommandResults:
    """
    Create a CommandResult for list commands.

    Args:
        data (list): Outputs.
        obj_type (str): The object type.
        response (dict[str, Any] | list[dict[str, Any]]): Raw response.
        title (str | None, optional): Title for the readable outputs. Defaults to None.
        headers (list | None, optional): Headers for the readable output. Defaults to None.
        readable_parser (Callable | None, optional): Parser command for readable output only. Defaults to None.
        edit_outputs_settings (ObjectEditor | None, optional): Edit output settings. Defaults to None.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    outputs_key_field = DEFAULT_OUTPUT_KEY_FIELD

    if edit_outputs_settings:
        if isinstance(edit_outputs_settings, PrefixToResponse):
            outputs = [edit_outputs_settings.data_to_add | {edit_outputs_settings.prefix: data}]
            outputs_key_field = edit_outputs_settings.id_key
        else:
            outputs = [edit_outputs_settings.data_to_add | obj for obj in data]

    else:
        outputs = data

    readable_output = create_list_readable_output(
        data=copy.deepcopy(outputs) if not isinstance(edit_outputs_settings, PrefixToResponse) else copy.deepcopy(data),
        obj_type=obj_type,
        title=title,
        headers=headers,
        readable_parser=readable_parser
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix=generate_output_prefix(obj_type),
        outputs_key_field=outputs_key_field,
        outputs=outputs,
        raw_response=response,
    )
    return command_results


@logger
def handle_list_request(request_command: Callable,
                        pagination: Pagination | None = None,
                        obj_id: str | None = None,) -> dict[str, Any] | list[dict[str, Any]]:
    """
    Handle list requests.

    Args:
        pagination (Pagination | None, optional): Pagination arguments. Defaults to None.
        request_command (Callable | None, optional): List request command. Defaults to None.
        obj_id (str | None, optional): The ID of the object to get. Defaults to None.

    Returns:
        dict[str, Any] | list[dict[str, Any]]: API response from AppSec API.
    """
    if obj_id:
        request_command = partial(request_command,
                                  obj_id=obj_id)
    elif pagination:
        request_command = partial(request_command,
                                  index=pagination.page and pagination.page - 1,
                                  size=pagination.page_size or pagination.limit)

    return request_command()


@logger
def parse_list_response(data: list[dict[str, Any]],
                        use_flatten_dict: bool,
                        remove_html_tags: bool,
                        parser_command: Callable | None = None) -> list:
    """
    Parse list outputs response.

    Args:
        data (list[dict[str, Any]]): Data to parse.
        use_flatten_dict (bool): Whether to flatten the output.
        remove_html_tags (bool): Whether to clean html tags from the outputs.
        parser_command (Callable | None, optional): Parser command. Defaults to None.

    Returns:
        list: Parsed output.
    """
    parsed_response = []
    for obj in data:
        obj.pop("links", None)
        if remove_html_tags:
            obj = copy.deepcopy(clean_html_tags(obj))
        parsed_response.append(parser_command(obj) if parser_command else flatten_dict(obj)
                               if use_flatten_dict else obj)

    return parsed_response


@logger
def create_list_readable_output(
        data: list[dict[str, Any]],
        obj_type: str,
        title: str | None = None,
        headers: list[str] | None = None,
        readable_parser: Callable | None = None) -> Any:
    """
    Create a readable output.

    Args:
        data (list[dict[str, Any]]): Data response.
        obj_type (str): Object type.
        title (str | None, optional): Title to the readable output. Defaults to None.
        headers (list[str] | None, optional): Headers of the readable output. Defaults to None.
        readable_parser (Callable | None, optional): Parser command for readable output only. Defaults to None.

    Returns:
        Any: Readable output.
    """
    readable_table = [readable_parser(obj) for obj in data] if readable_parser else data
    title = title or (pascalToSpace(obj_type))
    return tableToMarkdown(
        name=title,
        t=readable_table,
        headers=headers or list(data[0].keys() if len(data) > 0 else []),
        headerTransform=string_to_table_header,
    )


@logger
def generate_output_prefix(
    object_type: str,
) -> str:
    """
    Generate an output prefix.

    Args:
        object_type (str): Object type.

    Returns:
        str: Output prefix.
    """
    return f"{INTEGRATION_OUTPUT_PREFIX}.{object_type}"


@logger
def delete_handler(
    obj_id: str,
    readable_output: str,
    request_command: Callable,
    sub_obj_id: str | None = None,
) -> CommandResults:
    """
    Delete an object.

    Args:
        obj_id (str): Object ID to delete or container ID to delete sub-object from.
        readable_output (str): Readable output message.
        request_command (Callable): Delete request command.
        sub_obj_id (str | None, optional): Sub-object ID to delete. Defaults to None.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    if sub_obj_id:
        request_command(obj_id, sub_obj_id)
    else:
        request_command(obj_id)

    return CommandResults(readable_output=readable_output)


@logger
def flatten_dict(obj: dict | list, separator="_", prefix="") -> dict:
    """
    Flatten a dictionary. For example: {"a": {"b": "c"}, "d": "e"} will flatten to {"a_b": "c", "d": "e"}

    Args:
        obj (dict | list): Dict or list of diction to flatten.
        separator (str, optional): Separator . Defaults to "_".
        prefix (str, optional): Key prefix. Defaults to "".

    Returns:
        dict: Flattened dict.
    """
    return (
        {
            prefix + separator + k if prefix and not str(k).startswith(prefix) else k: v
            for kk, vv in obj.items()
            for k, v in flatten_dict(vv, separator, kk).items()
        }
        if isinstance(obj, dict)
        else {prefix.capitalize(): [flatten_dict(mm) for mm in obj]}
        if isinstance(obj, list)
        else {prefix: clean_html_tags(obj)}
    )


@logger
def generate_readable_output_message(
    object_type: str,
    action: str,
    object_id: str | None = None,
) -> str:
    """
    Generate a simple readable output message.

    Args:
        object_type (str): Object type.
        action (str): The command action.
        object_id (str | None): Object ID. Defaults to None.

    Returns:
        str: Readable output message.
    """
    return (
        f'{object_type} "{object_id}" was successfully {action}.'
        if object_id
        else f"{object_type} was successfully {action}."
    )


@logger
def clean_html_tags(to_clean: dict[str, Any]) -> dict[str, Any]:
    """
    Clean HTML tags from AppSec response.

    Args:
        to_clean (dict[str, Any]): String to clean.

    Returns:
        dict[str, Any]: Cleaned string.
    """
    if isinstance(to_clean, str):
        return re.sub(CLEAN_HTML_TAGS, '', to_clean)
    elif isinstance(to_clean, dict):
        return {key: clean_html_tags(value) for key, value in to_clean.items()}
    elif isinstance(to_clean, list):
        return [clean_html_tags(value) for value in to_clean]
    else:
        return to_clean


@logger
def generate_api_endpoint(url_prefix: str, obj_id: str | None) -> str:
    """
    Generate API endpoint for list request.

    Args:
        url_prefix (str): The API url prefix.
        obj_id (str | None): Object ID to add to the endpoint.

    Returns:
        str: API endpoint for list request.
    """
    return urljoin(url_prefix, obj_id) if obj_id else url_prefix


def main() -> None:
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()
    base_url = params["url"]
    api_key = dict_safe_get(params, ["api_key", "password"])
    insecure: bool = argToBoolean(params["insecure"])
    proxy = argToBoolean(params["proxy"])
    command = demisto.command()
    try:
        client: Client = Client(
            base_url=base_url,
            api_key=api_key,
            verify=insecure,
            proxy=proxy,
        )
        commands: dict[str, Callable] = {
            f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY}-update": update_vulnerability_command,
            f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY}-list": list_vulnerability_command,
            f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY}-history-list": list_vulnerability_history_command,
            f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY_COMMENT}-create": create_vulnerability_comment_command,
            f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY_COMMENT}-update": update_vulnerability_comment_command,
            f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY_COMMENT}-delete": delete_vulnerability_comment_command,
            f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY_COMMENT}-list": list_vulnerability_comment_command,
        }
        if command == "test-module":
            return_results(test_module(client))
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as e:
        return_error(str(e))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()

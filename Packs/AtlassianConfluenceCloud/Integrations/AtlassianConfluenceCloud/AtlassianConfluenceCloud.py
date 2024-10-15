from typing import Final

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import urllib.parse

from collections.abc import Callable
from CommonServerUserPython import *  # noqa

import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
LOGGING_INTEGRATION_NAME = "[Atlassian Confluence Cloud]"
HTTP_ERROR = {
    401: "An error occurred while validating the credentials, please check the username or password.",
    404: "The resource cannot be found.",
    500: "The server encountered an internal error for Atlassian Confluence Cloud "
         "and was unable to complete your request."
}
URL_SUFFIX = {
    "CONTENT_SEARCH": "/wiki/rest/api/content/search",
    "GROUP": "/wiki/rest/api/group",
    "CONTENT": "/wiki/rest/api/content",
    "USER": "/wiki/rest/api/search/user?cql=type=user",
    "SPACE": "/wiki/rest/api/space",
    "PRIVATE_SPACE": "/wiki/rest/api/space/_private",
    "EVENTS": "/wiki/rest/api/audit/",
    "BASE": "/wiki",
    "NEXT_LINK_TEMPLATE": "/rest/api/audit/?end_date={}&next=true&limit={}&start={}&startDate={}"
}

MESSAGES = {
    "REQUIRED_URL_FIELD": "Site Name can not be empty.",
    "NO_RECORDS_FOUND": "No {} were found for the given argument(s).",
    "LIMIT": "{} is an invalid value for limit. Limit must be between 0 and int32.",
    "START": "{} is an invalid value for start. Start must be between 0 and int32.",
    "INVALID_ACCESS_TYPE": "Invalid value for access type. Access type parameter must be one of 'user', 'admin', "
                           "or 'site-admin' ",
    "REQUIRED_ARGUMENT": "Invalid argument value. {} is a required argument.",
    "INVALID_CONTENT_TYPE": "Invalid value for content type. Content type parameter can be 'page' or 'blogpost' ",
    "HR_DELETE_CONTENT": "Content with Id {} is deleted successfully.",
    "INVALID_STATUS": "Invalid value for status. Status must be one of 'current', 'draft' or 'trashed'.",
    "BAD_REQUEST": "Bad request: An error occurred while fetching the data.",
    "REQUIRED_SORT_KEY": "If 'sort_order' is specified, 'sort_key' is required.",
    "INVALID_STATUS_SEARCH": "Invalid value for status. Status must be one of 'current', 'any', 'archived', 'draft' "
                             "or 'trashed'.",
    "INVALID_PERMISSION": "If the 'permission_account_id' or 'permission_group_name' arguments are given, "
                          "the 'permission_operations' argument must also be given.",
    "INVALID_PERMISSIONS_OPERATION": "If the 'permission_operations' argument is given, "
                                     "'permission_account_id' or 'permission_group_name' argument must also be given.",
    "PERMISSION_FORMAT": "Please provide the permission in the valid JSON format. "
                         "Format accepted - 'operation1:targetType1,operation2:targetType2'",
    "ADVANCE_PERMISSION_FORMAT": "Please provide the 'advanced_permissions' in the valid JSON format. ",
    "INVALID_SPACE_STATUS": "Invalid value for status. Status must be one of 'current' or 'archived'.",
    "INVALID_CONTENT_TYPE_UPDATE_CONTENT": "Invalid value for content type. Content type parameter can be 'page', "
                                           "'blogpost', 'comment' or 'attachment'.",
    "INVALID_BODY_REPRESENTATION": "Invalid value for body_representation. Body representation must be one of "
                                   "'editor', 'editor2' or 'storage'.",
    "INVALID_DELETION_TYPE": "Invalid value for deletion_type. Deletion type must be one of 'move to trash', "
                             "'permanent delete' or 'permanent delete draft'.",
    "INVALID_TITLE_LENGTH": "Title cannot be longer than 255 characters.",
    "INVALID_SPACE_NAME_LENGTH": "Space name cannot be longer than 200 characters.",
    "INVALID_SPACE_KEY": "Space Key cannot be longer than 255 characters and should contain alphanumeric characters "
                         "only.",
    "PRIVATE_SPACE_PERMISSION": "Permission can not be granted for a private space."
}
OUTPUT_PREFIX = {
    "GROUP": "ConfluenceCloud.Group",
    "USER": "ConfluenceCloud.User",
    "CONTENT": "ConfluenceCloud.Content",
    "COMMENT": "ConfluenceCloud.Comment",
    "SPACE": "ConfluenceCloud.Space",
    "PAGETOKEN": "ConfluenceCloud.PageToken.Content",
    "EVENT": "ConfluenceCloud.Event"
}
DEFAULT_LIMIT = "50"
DEFAULT_START = "0"
LEGAL_ACCESS_TYPES = ["user", "site-admin", "admin"]
LEGAL_CONTENT_STATUS = ['current', 'trashed', 'draft', 'archived', 'any']
LEGAL_CONTENT_TYPES = ["page", "blogpost"]
LEGAL_CONTENT_TYPE_UPDATE_COMMAND = ["page", "blogpost", "comment", "attachment"]
DEFAULT_EXPANDED_FIELD_CONTENT = "childTypes.all,space,version,history,ancestors,container,body"
DEFAULT_EXPANDED_FIELD_SPACE = "history"
LEGAL_SPACE_STATUS = ['current', 'archived']
LEGAL_BODY_REPRESENTATION = ['editor', 'editor2', 'storage']
LEGAL_DELETION_TYPES = {
    "move to trash": "current",
    "permanent delete": "trashed",
    "permanent delete draft": "draft"
}
VENDOR = "Atlassian"
PRODUCT = "Confluence"
AUDIT_FETCH_PAGE_SIZE = 1000
DEFAULT_GET_EVENTS_LIMIT = "50"
ONE_MINUTE_IN_MILL_SECONDS = 60000
ONE_WEEK_IN_MILL_SECONDS = 604800000
_last_run_cache = None
''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def http_request(self, *args, **kwargs) -> requests.Response:
        """
        Function to make http requests using inbuilt _http_request() method.
        """

        kwargs['ok_codes'] = (200, 201, 204)
        kwargs['error_handler'] = self.exception_handler
        kwargs['resp_type'] = 'response'
        return super()._http_request(*args, **kwargs)

    @staticmethod
    def exception_handler(response: requests.models.Response):
        """
        Handle error in the response and display error message based on status code.

        :type response: ``requests.models.Response``
        :param response: response from API.

        :raises: raise DemistoException based on status code of response.
        """
        err_msg = ""
        if response.status_code in HTTP_ERROR:
            err_msg = HTTP_ERROR[response.status_code]
        elif response.status_code > 500:
            err_msg = HTTP_ERROR[500]
        elif response.status_code not in HTTP_ERROR:
            try:
                # Try to parse json error response
                error_entry = response.json()
                demisto.error(f"{LOGGING_INTEGRATION_NAME} {error_entry}")
                errors = error_entry.get('data', {}).get('errors', [])
                if errors:
                    err_msg = get_error_message(errors)
                elif response.status_code == 400:
                    err_msg = MESSAGES['BAD_REQUEST']
                else:
                    err_msg = error_entry.get('message', '')
            except ValueError:
                err_msg = f'{response.text}'

        raise DemistoException(err_msg)

    def search_events(self, limit: int, start_date: str = None, end_date: str = None, next_link: str = None) -> dict:
        return super()._http_request(
            method='GET',
            url_suffix=URL_SUFFIX['BASE'] + next_link if next_link else URL_SUFFIX['EVENTS'],
            params=None if next_link else {'limit': limit, 'startDate': start_date, 'end_date': end_date}
        )


''' HELPER FUNCTIONS '''


def run_fetch_mechanism(client: Client, fetch_limit: int, next_link: str, start_date: int, end_date: int):
    all_events: List[Dict[str, Any]] = []
    started_new_query = False
    while len(all_events) < fetch_limit and (next_link or not started_new_query):
        page_size = min(AUDIT_FETCH_PAGE_SIZE, fetch_limit - len(all_events))

        started_new_query = started_new_query or not next_link
        response = run_get_events_query(client, next_link, start_date, end_date, page_size)

        events = response['results']
        next_link = response['_links'].get('next', None)
        demisto.debug(f'Fetched {len(events)} events, total_length: {len(all_events)}, next_link: {next_link}')

        all_events.extend(events)
    return all_events, started_new_query, next_link


def run_get_events_query(client: Client, next_link, start_date, end_date, page_size: int) -> dict[str, Any]:
    if not next_link:
        demisto.debug(f'searching events with start date: {start_date}, end date: {end_date} and page size: {page_size}')
        response = client.search_events(limit=page_size, start_date=str(start_date), end_date=str(end_date))
        demisto.debug(f'Found {response["size"]} events between {start_date} and {end_date}')

    else:
        demisto.debug(f'searching events with next_link: {next_link} and page size: {AUDIT_FETCH_PAGE_SIZE}')
        response = client.search_events(limit=page_size, next_link=next_link)
        demisto.debug(f'Found {response["size"]} events in the current page')

    return response


def add_time_to_events(events: list[dict]):
    """
    Adds the _time key to the events.
    Args:
        events: List[Dict] - list of events to add the _time key to.
    Returns:
        list: The events with the _time key.
    """
    for event in events:
        create_time = arg_to_datetime(arg=event.get('creationDate'))
        event['_time'] = create_time.strftime(DATE_FORMAT) if create_time else None


def get_error_message(errors):
    err_msg = ""
    for error in errors:
        if error.get('message').get('key'):
            err_msg += f"{error.get('message').get('key')} \n"
        if error.get('message').get('translation'):
            err_msg += f"{error.get('message').get('translation')} \n"
    return err_msg


def strip_args(args: dict):
    """
    Strips argument dictionary values.

    :type args: dict
    :param args: argument dictionary
    """
    for key, value in args.items():
        if isinstance(value, str):
            args[key] = value.strip()


def validate_url(url: str):
    """
    To Validate url parameter.

    :type url: str
    :param url: url to validate.
    """
    if not url:
        raise ValueError(MESSAGES["REQUIRED_URL_FIELD"])


def remove_empty_elements_for_context(src):
    """
     Recursively remove empty lists, empty dicts, empty string or None elements from a dictionary.

    :type src: ``dict``
    :param src: Input dictionary.

    :return: Dictionary with all empty lists,empty string and empty dictionaries removed.
    :rtype: ``dict``
    """

    def empty(x):
        return x is None or x == '' or x == {} or x == []

    if not isinstance(src, dict | list):
        return src
    elif isinstance(src, list):
        return [v for v in (remove_empty_elements_for_context(v) for v in src) if not empty(v)]
    else:
        return {k: v for k, v in ((k, remove_empty_elements_for_context(v))
                                  for k, v in src.items()) if not empty(v)}


def validated_required_args_for_permission(permission_account_id, permission_group_name, permission_operations):
    """
    Raise value-error when null-values or whitespaces are provided for permission arguments.

    :type permission_account_id: ``str``
    :param permission_account_id: Account ID

    :type permission_group_name: ``str``
    :param permission_group_name: Name of the group

    :type permission_operations: ``str``
    :param permission_operations: Permissions to be granted

    :return: None
    """
    if (permission_account_id or permission_group_name) and not permission_operations:
        raise ValueError(MESSAGES["INVALID_PERMISSION"])

    if permission_operations and (not permission_group_name and not permission_account_id):
        raise ValueError(MESSAGES["INVALID_PERMISSIONS_OPERATION"])


def prepare_permission_object(permission_account_id: str, permission_group_name: str, attr: list) -> dict:
    """
    Prepare permission object from the user provided values

    :type permission_account_id: ``str``
    :param permission_account_id: Account ID of the user to whom permission should be granted.

    :type permission_group_name: ``str``
    :param permission_group_name: Group name to whom permission should be granted.

    :type attr: ``List``
    :param attr: Operation and Target Type specified by user

    :rtype: ``Dict``
    :return: Returns permission object
    """
    permission_object = {
        "subjects": {
            "user": {
                "results": [
                    {
                        "accountId": permission_account_id
                    }
                ]
            },
            "group": {
                "results": [
                    {
                        "name": permission_group_name
                    }
                ]
            }
        },
        "operation": {
            "operation": attr[0],
            "targetType": attr[1]
        },
        "anonymousAccess": False,
        "unlicensedAccess": False
    }
    return permission_object


def validate_permissions(args: dict[str, Any]) -> list:
    """
         Validates the permission argument provided by user and prepare permission object accordingly

        :type args: ``dict``
        :param args: Input dictionary.

        :return: Permission object.
        :rtype: ``List``
    """
    space_permission = []
    permission_account_id = args.get('permission_account_id', '')
    permission_group_name = args.get('permission_group_name', '')
    permission_operations = args.get('permission_operations', '')

    validated_required_args_for_permission(permission_account_id, permission_group_name, permission_operations)

    if permission_operations:
        # create a list of all the permission provided by user
        permissions = [permission.strip() for permission in permission_operations.split(",") if permission.strip()]
        # separate target_type and operation for the single permission
        for permission in permissions:
            if permission:
                attr = [operation.strip() for operation in permission.split(":") if operation.strip()]
                # if target_type or operation is missing then raise ValueError
                if len(attr) != 2:
                    raise ValueError(MESSAGES["PERMISSION_FORMAT"])
                permission_object = prepare_permission_object(permission_account_id, permission_group_name, attr)
                space_permission.append(permission_object)

    return space_permission


def validate_list_command_args(args: dict[str, str]) -> tuple[Optional[int], Optional[int]]:
    """
    Validate arguments for all list commands, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Tuple``
    """

    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    if limit < 0 or limit > 2147483647:  # type:ignore
        raise ValueError(MESSAGES["LIMIT"].format(limit))

    offset = arg_to_number(args.get('offset', DEFAULT_START))
    if offset < 0 or offset > 2147483647:  # type:ignore
        raise ValueError(MESSAGES["START"].format(offset))

    return limit, offset


def validate_list_group_args(args: dict[str, str]):
    """
    Validate arguments for confluence-cloud-group-list command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.
    """

    access_type = args.get("access_type", "").lower()
    if access_type and access_type not in LEGAL_ACCESS_TYPES:
        raise ValueError(MESSAGES["INVALID_ACCESS_TYPE"])

    return access_type


def prepare_group_args(args: dict[str, str]) -> dict[str, str]:
    """
    Prepare params for list group command

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.
    """
    limit, offset = validate_list_command_args(args)
    access_type = validate_list_group_args(args)
    return assign_params(limit=limit, start=offset, accessType=access_type)


def prepare_hr_for_groups(groups: list[dict[str, Any]]) -> str:
    """
       Prepare human-readable for list groups command.

       :type groups: ``List[Dict[str, Any]]``
       :param groups:The group data.

       :rtype: ``str``
       :return: Human readable.
    """
    hr_list = []
    for group in groups:
        hr_record = {
            'ID': group.get('id', ''),
            'Name': group.get('name', '')
        }

        hr_list.append(hr_record)

    return tableToMarkdown('Group(s)', hr_list, ['ID', 'Name'],
                           removeNull=True)


def prepare_content_create_params(args) -> dict[str, Any]:
    """
    Prepare json object for content create command

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Body parameters to send in request
    :rtype: ``Dict[str, Any]``
    """
    body_representation = args.get('body_representation', '')
    params = {
        "title": args['title'],
        "type": args['type'].lower(),
        "space": {
            "key": args.get('space_key', '')
        },
        "status": args.get('status', 'current'),
        "body": {
            body_representation: {
                "value": args.get('body_value', ''),
                "representation": body_representation
            }
        },
        "ancestors": [
            {
                "id": args.get('ancestor_id', '')
            }
        ]
    }

    return remove_empty_elements_for_context(params)


def validate_create_content_args(args: dict[str, str], is_update: bool = False):
    """
    Validate arguments for confluence-cloud-content-create command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

     :type is_update: ``bool``
    :param is_update: Whether command is update content or not.

    :return: None
    :rtype: ``None``
    """

    title = args['title']
    if not title:
        raise ValueError(MESSAGES['REQUIRED_ARGUMENT'].format("title"))
    if len(title) > 255:
        raise ValueError(MESSAGES["INVALID_TITLE_LENGTH"])

    content_type = args['type'].lower()
    if not content_type:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("type"))
    if not is_update and content_type not in LEGAL_CONTENT_TYPES:
        raise ValueError(MESSAGES["INVALID_CONTENT_TYPE"])
    if is_update and content_type not in LEGAL_CONTENT_TYPE_UPDATE_COMMAND:
        raise ValueError(MESSAGES["INVALID_CONTENT_TYPE_UPDATE_CONTENT"])

    space_key = args.get('space_key', '')
    if not is_update and not space_key:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("space_key"))

    body_value = args.get('body_value', '')
    body_representation = args.get('body_representation', '')
    if content_type == "comment":
        if body_value and body_representation:
            if body_representation not in LEGAL_BODY_REPRESENTATION:
                raise ValueError(MESSAGES["INVALID_BODY_REPRESENTATION"])
        else:
            raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("'body_value' and 'body_representation'"))


def prepare_hr_for_content_create(content: dict[str, Any], content_type: str) -> str:
    """
       Prepare human-readable for content create, comment create and content update command.

       :type content: ``Dict[str, Any]``
       :param content:The content data.

       :type content_type: ``str``
       :param content_type: Type of the content.

       :rtype: ``str``
       :return: Human readable.
    """

    hr_record = {
        'ID': content.get('id', ''),
        'Title': f"[{content.get('title', '')}]"
                 f"({content.get('_links', {}).get('base', '')}{content.get('_links', {}).get('webui', '')})",
        'Type': content.get('type', ''),
        'Status': content.get('status', ''),
        'Space Name': content.get('space', {}).get('name', ''),
        'Created By': content.get('history', {}).get('createdBy', {}).get('displayName', ''),
        'Created At': content.get('history', {}).get('createdDate', '')
    }

    return tableToMarkdown(f'{content_type}', hr_record,
                           ['ID', 'Title', 'Type', 'Status', 'Space Name', 'Created By', 'Created At'],
                           removeNull=True)


def prepare_hr_for_content_search(contents: list, url_prefix: str) -> str:
    """
    Prepare human-readable for content search and content list command.

    :type contents: ``list``
    :param contents: List of content.

    :type url_prefix: ``str``
    :param url_prefix: Url prefix the content.

    :rtype: ``str``
    :return: Human readable.
    """
    hr_list = []
    for content in contents:
        hr_record = {
            'ID': content.get('id', ''),
            'Title': f"[{content.get('title', '')}]"
                     f"({url_prefix}{content.get('_links', {}).get('webui', '')})",
            'Type': content.get('type', ''),
            'Status': content.get('status', ''),
            'Space Name': content.get('space', {}).get('name', ''),
            'Created By': content.get('history', {}).get('createdBy', {}).get('displayName', ''),
            'Created At': content.get('history', {}).get('createdDate', ''),
            'Version': content.get('version', {}).get('number', '')
        }

        hr_list.append(hr_record)

    hr = tableToMarkdown('Content(s)', hr_list,
                         ['ID', 'Title', 'Type', 'Status', 'Space Name', 'Created By', 'Created At', 'Version'],
                         removeNull=True)

    return hr


def validate_delete_content_args(args: dict[str, str]):
    """
    Validate arguments for confluence-cloud-content-delete command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: None
    """
    content_id = args["content_id"]
    if not content_id:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("content_id"))

    status = args.get("deletion_type", "").lower()
    if status and status not in LEGAL_DELETION_TYPES.keys():
        raise ValueError(MESSAGES["INVALID_DELETION_TYPE"])


def prepare_comment_create_params(args) -> dict[str, Any]:
    """
    Prepare json object for comment create command

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Body parameters to send in request
    :rtype: ``Dict[str, Any]``
    """
    body_representation = args['body_representation']
    container_type = args.get('container_type', '')
    params = {
        "type": "comment",
        "status": args.get('status', 'current'),
        "container": {
            "id": args['container_id'],
            "type": container_type
        },
        "body": {
            body_representation: {
                "value": args['body_value'],
                "representation": body_representation
            }
        },
        "ancestors": [
            {
                "id": args.get('ancestor_id', '')
            }
        ]
    }
    params = remove_empty_elements_for_context(params)
    params["container"]["type"] = container_type
    return params


def validate_comment_args(args: dict[str, str]):
    """
    Validate arguments for confluence-cloud-comment-create command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: None
    """

    body_value = args['body_value']
    if not body_value:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("Comment body_value"))

    body_representation = args['body_representation']
    if not body_representation:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("body_representation"))
    if body_representation not in LEGAL_BODY_REPRESENTATION:
        raise ValueError(MESSAGES["INVALID_BODY_REPRESENTATION"])

    container_id = args['container_id']
    if not container_id:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("container_id"))


def prepare_hr_for_users(users: list[dict[str, Any]]) -> str:
    """
    Prepare human-readable for list users command.

    :type users: ``List[Dict[str, Any]]``
    :param users: The user data.

    :rtype: ``str``
    :return: Human readable.
    """
    hr_list = []
    for user in users:
        hr_record = {
            'Account ID': user['user'].get('accountId', ''),
            'Name': user['user'].get('displayName', ''),
            'User Type': user['user'].get('type', '')
        }

        hr_list.append(hr_record)

    return tableToMarkdown('User(s)', hr_list, ['Account ID', 'Name', 'User Type'], removeNull=True)


def prepare_expand_argument(expand: str, default_fields: str) -> str:
    """
    The 'expand' command argument specifies which properties should be expanded.
    In this integration, several of the most significant characteristics are extended by default.
    Other attributes that users want to expand can still be provided.

    This method combines the default expand fields with the expand fields specified by the user.

    :type expand: ``str``
    :param expand: The expand argument passed by the user.

    :type default_fields: ``str``
    :param default_fields: The default fields.

    :return: expand argument value to send in request
    :rtype: ``str``
    """
    default_expand_fields = default_fields.split(",")
    custom_expand_fields = set(expand.split(","))
    expand_fields = ""

    for expand_field in custom_expand_fields:
        if expand_field.strip() not in default_expand_fields:
            expand_fields += f',{expand_field.strip()}'

    return default_fields + expand_fields


def validate_query_argument(args: dict[str, str]):
    """
    Validate query argument of content search command

    :param args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: None
    """
    query = args['query']
    if not query:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("query"))


def prepare_search_content_argument(args: dict[str, str]) -> dict[str, Any]:
    """
    Prepare params for confluence-cloud-content-search command.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, Any]``
    """
    limit, offset = validate_list_command_args(args)
    validate_query_argument(args)

    params = {'cql': args['query'],
              'cursor': args.get('next_page_token'),
              'expand': DEFAULT_EXPANDED_FIELD_CONTENT,
              'limit': limit
              }

    expand = args.get('expand', '')
    if expand:
        params['expand'] = prepare_expand_argument(expand, DEFAULT_EXPANDED_FIELD_CONTENT)

    content_status = argToList(args.get('content_status', ''))
    params["cqlcontext"] = json.dumps({"contentStatuses": content_status})

    return assign_params(**params)


def prepare_cursor_for_content(response_json: dict[str, str]) -> str:
    """
    Split query string parameters from a link and extract value of parameter 'cursor'.

    :type response_json: ``Dict[str, str]``
    :param response_json: API response.

    :return: Next Page Token(Cursor).
    :rtype: ``str``
    """
    next_cursor = ""
    next_record = response_json.get('_links', {}).get('next', '')  # type:ignore
    if next_record:
        next_cursor_split = next_record.split('?')
        parsed_next_cursor = urllib.parse.parse_qs(next_cursor_split[1])
        next_cursor = parsed_next_cursor.get('cursor', [])[0]

    return next_cursor


def validate_list_content_args(args):
    """
    Validate arguments for confluence_cloud_content_list command, raise ValueError on invalid arguments.
    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: None
    """
    sort_order = args.get('sort_order', '').lower()
    sort_key = args.get('sort_key', '')

    if sort_order and not sort_key:
        raise ValueError(MESSAGES['REQUIRED_SORT_KEY'])
    content_type = args.get('type', 'page').lower()

    if content_type not in LEGAL_CONTENT_TYPES:
        raise ValueError(MESSAGES['INVALID_CONTENT_TYPE'])

    status = args.get('status', '').lower()
    if status and status not in LEGAL_CONTENT_STATUS:
        raise ValueError(MESSAGES['INVALID_STATUS_SEARCH'])


def prepare_list_content_argument(args: dict[str, str]) -> dict[str, Any]:
    """
    Prepare params for confluence_cloud_content_list command.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, Any]``
    """
    validate_list_content_args(args)
    limit, offset = validate_list_command_args(args)
    params = {'limit': limit,
              'start': offset,
              'spaceKey': args.get('space_key', ''),
              'type': args.get('type', 'page').lower()
              }

    sort_order = args.get('sort_order', '').lower()
    sort_key = args.get('sort_key', '')

    if sort_order and sort_key:
        params['orderby'] = f'{sort_key} {sort_order}'
    elif sort_key:
        params['orderby'] = f'{sort_key}'

    content_creation_date = arg_to_datetime(args.get('creation_date'))
    if content_creation_date:
        params['postingDay'] = content_creation_date.date()  # type: ignore

    params['status'] = args.get('status', '').lower()

    params['expand'] = DEFAULT_EXPANDED_FIELD_CONTENT
    expand = args.get('expand', '')
    if expand:
        params['expand'] = prepare_expand_argument(expand, DEFAULT_EXPANDED_FIELD_CONTENT)

    return assign_params(**params)


def validate_create_space_args(args: dict[str, str]):
    """
    Validate arguments for confluence-cloud-space-create command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: None
    """
    unique_key = args.get('unique_key')
    if not unique_key:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("unique_key"))
    if len(unique_key) > 255 or not unique_key.isalnum():
        raise ValueError(MESSAGES["INVALID_SPACE_KEY"])

    name = args.get('name')
    if not name:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("name"))
    if len(name) > 200:
        raise ValueError(MESSAGES["INVALID_SPACE_NAME_LENGTH"])

    is_private_space = argToBoolean(args.get('is_private_space', False))
    if is_private_space and (args.get('advanced_permissions') or args.get('permission_operations')):
        raise ValueError(MESSAGES["PRIVATE_SPACE_PERMISSION"])

    if args.get('advanced_permissions'):
        try:
            json.loads(args['advanced_permissions'])
        except (json.JSONDecodeError, json.decoder.JSONDecodeError, AttributeError):
            raise ValueError(MESSAGES["ADVANCE_PERMISSION_FORMAT"])


def prepare_create_space_args(args: dict[str, str]) -> tuple[dict, Union[bool, str]]:
    """
    Prepare json object for confluence-cloud-space-create command.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, Any]``
    """

    is_private_space = argToBoolean(args.get('is_private_space', False))

    if args.get('advanced_permissions'):
        permissions = json.loads(args['advanced_permissions'])
    else:
        permissions = validate_permissions(args)

    params = {
        "key": args['unique_key'],
        "name": args['name'],
        "description": {
            "plain": {
                "value": args.get('description', ''),
                "representation": "plain"
            }
        },
        "permissions": permissions
    }
    params = remove_empty_elements_for_context(params)

    return params, is_private_space


def prepare_hr_for_space_create(space: dict[str, Any]) -> str:
    """
    Prepare human-readable for create space command.

    :type space: ``List[Dict[str, Any]]``
    :param space: The space data.

    :rtype: ``str``
    :return: Human readable.
    """
    hr_record = {
        'ID': space.get('id', ''),
        'Name': f"[{space.get('name', '')}]"
                f"({space.get('_links', {}).get('base', '')}{space.get('_links', {}).get('webui', '')})",
        'Type': space.get('type', ''),
        'Status': space.get('status', ''),
    }

    return tableToMarkdown('Space', hr_record,
                           ['ID', 'Name', 'Type', 'Status'],
                           removeNull=True)


def validate_status_argument(args: dict[str, str]):
    """
    Validates the status argument of confluence-cloud-space-list command, raise ValueError on invalid arguments.
    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: None
    """
    status = args.get('status')
    if status and status.lower() not in LEGAL_SPACE_STATUS:
        raise ValueError(MESSAGES["INVALID_SPACE_STATUS"])


def prepare_list_space_args(args: dict[str, str]) -> dict[str, Any]:
    """
    Prepare params for confluence-cloud-space-list command.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, Any]``
    """
    validate_status_argument(args)
    limit, offset = validate_list_command_args(args)
    params = {'limit': limit, 'start': offset,
              'spaceKey': argToList(args.get('space_key')),
              'spaceId': argToList(args.get('space_id')),
              'type': args.get('type'),
              'status': args.get('status')
              }

    favourite = args.get('favourite', '')
    if favourite:
        favourite = "true" if argToBoolean(favourite) else "false"
        params['favourite'] = favourite

    params['expand'] = DEFAULT_EXPANDED_FIELD_SPACE
    expand = args.get('expand', '')
    if expand:
        params['expand'] = prepare_expand_argument(expand, DEFAULT_EXPANDED_FIELD_SPACE)

    return assign_params(**params)


def prepare_hr_for_space_list(spaces: list[dict[str, Any]], url_prefix: str) -> str:
    """
    Prepare human-readable for list space command.

    :param url_prefix:
    :type spaces: ``List[Dict[str, Any]]``
    :param spaces: The space data.

    :rtype: ``str``
    :return: Human readable.
    """
    hr_list = []
    for space in spaces:
        hr_record = {
            'ID': space.get('id', ''),
            'Space Key': space.get('key', ''),
            'Name': f"[{space.get('name', '')}]"
                    f"({url_prefix}{space.get('_links', {}).get('webui', '')})",
            'Type': space.get('type', ''),
            'Status': space.get('status', ''),
            'Created By': space.get('history', {}).get('createdBy', {}).get('displayName', ''),
            'Created At': space.get('history', {}).get('createdDate', '')
        }

        hr_list.append(hr_record)

    hr = tableToMarkdown('Space(s)', hr_list,
                         ['ID', 'Space Key', 'Name', 'Type', 'Status', 'Created By', 'Created At'], removeNull=True)
    return hr


def validate_update_content_args(args: dict[str, str]):
    """
    Validate arguments for confluence-cloud-content-update command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: None
    """
    validate_create_content_args(args, is_update=True)

    content_id = args["content_id"]
    if not content_id:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("content_id"))

    version = args["version"]
    if not version:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("version"))


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    params: dict = {
        "cql": "type=page",
        "limit": 1
    }
    client.http_request(method='GET', url_suffix=URL_SUFFIX["CONTENT_SEARCH"], params=params)
    return 'ok'


def confluence_cloud_user_list_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Returns a list of users.

    :type client: ``Client``
    :param client: Client object to be used.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Standard command result or no records found message.
    :rtype: ``CommandResults``
    """
    limit, offset = validate_list_command_args(args)
    params = assign_params(limit=limit, start=offset)
    response = client.http_request(method="GET", url_suffix=URL_SUFFIX["USER"], params=params)

    response_json = response.json()
    total_records = response_json.get('results', [])

    if not total_records:
        return CommandResults(readable_output=MESSAGES['NO_RECORDS_FOUND'].format('user(s)'))

    context = []
    for user in total_records:
        context.append(remove_empty_elements_for_context(user.get('user', {})))

    readable_hr = prepare_hr_for_users(total_records)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX['USER'],
        outputs_key_field='accountId',
        outputs=context,
        readable_output=readable_hr,
        raw_response=response_json)


def confluence_cloud_content_search_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Returns the list of content that matches a Confluence Query Language (CQL) query.
    The type of content can be a page, blogpost, or comment.

    :type client: ``Client``
    :param client: Client object to be used.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Standard command result or no records found message.
    :rtype: ``CommandResults``
    """
    params = prepare_search_content_argument(args)

    response = client.http_request(method="GET", url_suffix=URL_SUFFIX["CONTENT_SEARCH"], params=params)
    response_json = response.json()
    total_records = response_json.get('results', [])

    if not total_records:
        return CommandResults(readable_output=MESSAGES['NO_RECORDS_FOUND'].format('content(s)'))

    # Creating Context data
    context = remove_empty_elements_for_context(total_records)
    next_cursor = prepare_cursor_for_content(response_json)
    next_page_context = {
        "next_page_token": next_cursor,
        "name": "confluence-cloud-content-search"
    }
    next_page_context = remove_empty_elements_for_context(next_page_context)
    outputs = {
        f"{OUTPUT_PREFIX['CONTENT']}(val.id == obj.id)": context,
        f"{OUTPUT_PREFIX['PAGETOKEN']}(val.name == obj.name)": next_page_context
    }

    # Creating Human Readable
    url_prefix = response_json.get('_links', {}).get('base', '')
    readable_hr = prepare_hr_for_content_search(total_records, url_prefix)
    if next_cursor:
        readable_hr += f'Run the command with argument next_page_token={next_cursor} to see the next set of contents.\n'

    return CommandResults(
        outputs=outputs,
        readable_output=readable_hr,
        raw_response=response_json)


def confluence_cloud_content_update_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Update the existing content with new content.

    :type client: ``Client``
    :param client: Client object to be used.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Standard command result or no records found message.
    :rtype: ``CommandResults``
    """
    validate_update_content_args(args)

    content_id = args["content_id"]
    params = prepare_content_create_params(args)
    params["version"] = {
        "number": args["version"]
    }
    request_url = URL_SUFFIX["CONTENT"] + f"/{content_id}"

    response = client.http_request(method="PUT", url_suffix=request_url, json_data=params)
    response_json = response.json()

    context = remove_empty_elements_for_context(response_json)
    readable_hr = prepare_hr_for_content_create(response_json, "Content")

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX['CONTENT'],
        outputs_key_field='id',
        outputs=context,
        readable_output=readable_hr,
        raw_response=response_json)


def confluence_cloud_content_delete_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    This command moves a piece of content to the space's trash or purges it from the trash,
    depending on the content's type and status.

    :type client: ``Client``
    :param client: Client object to be used.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Standard command result or no records found message.
    :rtype: ``CommandResults``
    """

    validate_delete_content_args(args)

    content_id = args["content_id"]
    status = args.get("deletion_type", "").lower()
    params = assign_params(status=LEGAL_DELETION_TYPES.get(status))

    request_url = URL_SUFFIX["CONTENT"] + f"/{content_id}"

    client.http_request(method="DELETE", url_suffix=request_url, params=params)

    return CommandResults(readable_output=MESSAGES["HR_DELETE_CONTENT"].format(content_id))


def confluence_cloud_content_list_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
        Returns the list of contents of confluence.

        :type client: ``Client``
        :param client: Client object to be used.

        :type args: ``Dict[str, str]``
        :param args: The command arguments provided by the user.

        :return: Standard command result or no records found message.
        :rtype: ``CommandResults``
    """
    params = prepare_list_content_argument(args)

    response = client.http_request(method="GET", url_suffix=URL_SUFFIX["CONTENT"], params=params)

    response_json = response.json()
    total_records = response_json.get('results', [])

    if not total_records:
        return CommandResults(readable_output=MESSAGES['NO_RECORDS_FOUND'].format('content(s)'))

    context = remove_empty_elements_for_context(total_records)

    url_prefix = response_json.get('_links', {}).get('base', '')
    readable_hr = prepare_hr_for_content_search(total_records, url_prefix)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX['CONTENT'],
        outputs_key_field="id",
        outputs=context,
        readable_output=readable_hr,
        raw_response=response_json)


def confluence_cloud_space_list_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
      Returns a list of all Confluence spaces.

      :type client: ``Client``
      :param client: Client object to be used.

      :type args: ``Dict[str, str]``
      :param args: The command arguments provided by the user.

      :return: Standard command result or no records found message.
      :rtype: ``CommandResults``
    """
    params = prepare_list_space_args(args)

    response = client.http_request(method="GET", url_suffix=URL_SUFFIX["SPACE"], params=params)

    response_json = response.json()
    total_records = response_json.get('results', [])

    if not total_records:
        return CommandResults(readable_output=MESSAGES['NO_RECORDS_FOUND'].format('space(s)'))

    context = remove_empty_elements_for_context(total_records)

    url_prefix = response_json.get('_links', {}).get('base', '')
    readable_hr = prepare_hr_for_space_list(total_records, url_prefix)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX['SPACE'],
        outputs_key_field='id',
        outputs=context,
        readable_output=readable_hr,
        raw_response=response_json)


def confluence_cloud_comment_create_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
       Creates a comment for a given content.

       :type client: ``Client``
       :param client: Client object to be used.

       :type args: ``Dict[str, str]``
       :param args: The command arguments provided by the user.

       :return: Standard command result or no records found message.
       :rtype: ``CommandResults``
    """
    validate_comment_args(args)
    params = prepare_comment_create_params(args)
    response = client.http_request(method="POST", url_suffix=URL_SUFFIX["CONTENT"], json_data=params)
    response_json = response.json()
    context = remove_empty_elements_for_context(response_json)
    readable_hr = prepare_hr_for_content_create(response_json, "Comment")
    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX['COMMENT'],
        outputs_key_field='id',
        outputs=context,
        readable_output=readable_hr,
        raw_response=response_json)


def confluence_cloud_content_create_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
       Create a page or blogpost for a specified space .

       :type client: ``Client``
       :param client: Client object to be used.

       :type args: ``Dict[str, str]``
       :param args: The command arguments provided by the user.

       :return: Standard command result or no records found message.
       :rtype: ``CommandResults``
    """
    validate_create_content_args(args)
    params = prepare_content_create_params(args)
    response = client.http_request(method="POST", url_suffix=URL_SUFFIX["CONTENT"], json_data=params)
    response_json = response.json()
    context = remove_empty_elements_for_context(response_json)
    readable_hr = prepare_hr_for_content_create(response_json, "Content")
    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX['CONTENT'],
        outputs_key_field='id',
        outputs=context,
        readable_output=readable_hr,
        raw_response=response_json)


def confluence_cloud_space_create_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
       Creates a new space in confluence cloud.

       :type client: ``Client``
       :param client: Client object to be used.

       :type args: ``Dict[str, str]``
       :param args: The command arguments provided by the user.

       :return: Standard command result or no records found message.
       :rtype: ``CommandResults``
    """
    validate_create_space_args(args)
    params, is_private_space = prepare_create_space_args(args)

    url_suffix = URL_SUFFIX["SPACE"]

    if is_private_space:

        url_suffix = URL_SUFFIX["PRIVATE_SPACE"]
        if 'permissions' in params:
            del params['permissions']

    response = client.http_request(method="POST", url_suffix=url_suffix, json_data=params)

    response_json = response.json()

    # Creating the Context data
    context = remove_empty_elements_for_context(response_json)

    # Creating the Human Readable
    readable_hr = prepare_hr_for_space_create(response_json)
    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX['SPACE'],
        outputs_key_field='id',
        outputs=context,
        readable_output=readable_hr,
        raw_response=response_json

    )


def confluence_cloud_group_list_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
       Retrieves the list of groups.

       :type client: ``Client``
       :param client: Client object to be used.

       :type args: ``Dict[str, str]``
       :param args: The command arguments provided by the user.

       :return: Standard command result or no records found message.
       :rtype: ``CommandResults``
       """
    params = prepare_group_args(args)

    response = client.http_request(method="GET", url_suffix=URL_SUFFIX["GROUP"], params=params)

    response_json = response.json()
    total_records = response_json.get('results', [])

    if not total_records:
        return CommandResults(readable_output=MESSAGES['NO_RECORDS_FOUND'].format('group(s)'))

    context = remove_empty_elements(total_records)
    readable_hr = prepare_hr_for_groups(total_records)
    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX['GROUP'],
        outputs_key_field='id',
        outputs=context,
        readable_output=readable_hr,
        raw_response=response_json)


def fetch_events(client: Client, fetch_limit: int, last_run: Dict[str, Any]) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    # constants for this run
    last_end_date: Final[int] = last_run.get('end_date', 0)
    end_date: Final[int] = int((time.time() - 5) * 1000)
    start_date: Final[int] = last_end_date + 1 if last_end_date else end_date - ONE_MINUTE_IN_MILL_SECONDS

    # updated in loop
    next_link = last_run.get('next_link', '')

    demisto.debug(f'Starting fetch_events with {last_run=} and {fetch_limit=}')
    all_events, started_new_query, next_link = run_fetch_mechanism(client, fetch_limit, next_link, start_date, end_date)

    if not all_events:
        demisto.debug('No events found')
        return [], {'next_link': None, 'end_date': last_end_date}

    return all_events, {'next_link': next_link, 'end_date': end_date if started_new_query else last_end_date}


def get_events(client: Client, args: dict) -> tuple[list[dict], CommandResults]:
    end_date = args.get('end_date', int((time.time() - 5) * 1000))
    start_date = int(args.get('start_date', end_date - ONE_MINUTE_IN_MILL_SECONDS))
    fetch_limit = int(args.get('limit', DEFAULT_GET_EVENTS_LIMIT))
    events, _, _ = run_fetch_mechanism(client, fetch_limit, '', start_date, end_date)

    return events, CommandResults(outputs=events,
                                  outputs_prefix=OUTPUT_PREFIX['EVENT'],
                                  readable_output=tableToMarkdown('Events', t=events, removeNull=True)
                                  )


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """
    params = demisto.params()

    # get the service API url
    url = params['url'].strip()
    base_url = f"https://{url}.atlassian.net"
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    credentials = params.get("username", {})
    username = credentials.get('identifier').strip()
    password = credentials.get('password')

    demisto.debug(f'{LOGGING_INTEGRATION_NAME} Command being called is {demisto.command()}')
    try:
        validate_url(url)
        headers: dict = {
            "Accept": "application/json"
        }

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            headers=headers,
            auth=(username, password)
        )

        # Commands dictionary
        commands: dict[str, Callable] = {
            'confluence-cloud-group-list': confluence_cloud_group_list_command,
            'confluence-cloud-user-list': confluence_cloud_user_list_command,
            'confluence-cloud-content-search': confluence_cloud_content_search_command,
            'confluence-cloud-content-update': confluence_cloud_content_update_command,
            'confluence-cloud-content-delete': confluence_cloud_content_delete_command,
            'confluence-cloud-content-list': confluence_cloud_content_list_command,
            'confluence-cloud-space-list': confluence_cloud_space_list_command,
            'confluence-cloud-comment-create': confluence_cloud_comment_create_command,
            'confluence-cloud-content-create': confluence_cloud_content_create_command,
            'confluence-cloud-space-create': confluence_cloud_space_create_command,
        }
        command = demisto.command()
        args = demisto.args()
        strip_args(args)
        remove_nulls_from_dictionary(args)
        limit = int(arg_to_number(params.get('max_events_per_fetch', 10000)))   # type:ignore

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))
        elif command in commands:
            return_results(commands[command](client, args))

        elif command == 'fetch-events':

            events, last_run_object = fetch_events(client, limit, demisto.getLastRun())
            if events:
                add_time_to_events(events)
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                demisto.setLastRun(last_run_object)

            # demisto.updateModuleHealth({'eventsPulled': len(events)})
        elif command == 'confluence-cloud-get-events':
            demisto.debug(f'Fetching Confluence Cloud events with the following parameters: {args}')
            should_push_events = argToBoolean(args.get('should_push_events', False))
            events, command_results = get_events(client, args)
            return_results(command_results)
            if should_push_events:
                send_events_to_xsiam(
                    events,
                    vendor=VENDOR,
                    product=PRODUCT
                )
    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

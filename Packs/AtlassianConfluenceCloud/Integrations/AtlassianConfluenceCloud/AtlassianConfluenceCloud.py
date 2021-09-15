import json
import urllib.parse
from typing import Callable, Dict, Tuple, List

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

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
    "PRIVATE_SPACE": "/wiki/rest/api/space/_private"
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
                          "the 'permission_operation' argument must also be given.",
    "INVALID_PERMISSIONS_OPERATION": "If the 'permission_operation' argument is given, "
                                     "'permission_account_id' or 'permission_group_name' argument must also be given.",
    "PERMISSION_FORMAT": "Please provide the permission in the valid JSON format. "
                         "Format accepted - 'operation1:targetType1,operation2:targetType2'",
    "ADVANCE_PERMISSION_FORMAT": "Please provide the 'advance_permission' in the valid JSON format. ",
    "INVALID_SPACE_STATUS": "Invalid value for status. Status must be one of 'current' or 'archived'.",
    "INVALID_CONTENT_TYPE_UPDATE_CONTENT": "Invalid value for content type. Content type parameter can be 'page', "
                                           "'blogpost', 'comment' or 'attachment'.",
    "INVALID_BODY_REPRESENTATION": "Invalid value for body_representation. Body representation must be one of "
                                   "'editor', 'editor2' or 'storage'.",
    "INVALID_DELETION_TYPE": "Invalid value for deletion_type. Deletion type must be one of 'move to trash', "
                             "'permanent delete' or 'permanent delete draft'."
}
OUTPUT_PREFIX = {
    "GROUP": "ConfluenceCloud.Group",
    "USER": "ConfluenceCloud.User",
    "CONTENT": "ConfluenceCloud.Content",
    "COMMENT": "ConfluenceCloud.Comment",
    "SPACE": "ConfluenceCloud.Space",
    "PAGETOKEN": "ConfluenceCloud.PageToken.Content"
}
DEFAULT_LIMIT = "50"
DEFAULT_START = "0"
ACCESS_TYPE = ["user", "site-admin", "admin"]
CONTENT_STATUS = ['current', 'trashed', 'draft']
CONTENT_TYPE = ["page", "blogpost"]
CONTENT_TYPE_UPDATE_COMMAND = ["page", "blogpost", "comment", "attachment"]
EXPANDED_FIELD_CONTENT = "childTypes.all,space,version,history,ancestors,container,body"
EXPANDED_FIELD_SPACE = "history"
SPACE_STATUS = ['current', 'archived']
BODY_REPRESENTATION = ['editor', 'editor2', 'storage']
DELETION_TYPE = {
    "move to trash": "current",
    "permanent delete": "trashed",
    "permanent delete draft": "draft"
}
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
                err_msg = '{}'.format(response.text)

        raise DemistoException(err_msg)


''' HELPER FUNCTIONS '''


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

    if not isinstance(src, (dict, list)):
        return src
    elif isinstance(src, list):
        return [v for v in (remove_empty_elements_for_context(v) for v in src) if not empty(v)]
    else:
        return {k: v for k, v in ((k, remove_empty_elements_for_context(v))
                                  for k, v in src.items()) if not empty(v)}


def validated_required_args_for_permission(permission_account_id, permission_group_name, permission_operation):
    """
    Raise value-error when null-values or whitespaces are provided for permission arguments.

    :type permission_account_id: ``str``
    :param permission_account_id: Account ID

    :type permission_group_name: ``str``
    :param permission_group_name: Name of the group

    :type permission_operation: ``str``
    :param permission_operation: Permissions to be granted

    :return: None
    """
    if (permission_account_id or permission_group_name) and not permission_operation:
        raise ValueError(MESSAGES["INVALID_PERMISSION"])

    if permission_operation and (not permission_group_name and not permission_account_id):
        raise ValueError(MESSAGES["INVALID_PERMISSIONS_OPERATION"])


def validate_permissions(args: Dict[str, Any]) -> List:
    """
         Validates the permission argument provided by user

        :type args: ``dict``
        :param args: Input dictionary.

        :return: Permission object.
        :rtype: ``List``
    """
    space_permission = []
    permission_account_id = args.get('permission_account_id', '')
    permission_group_name = args.get('permission_group_name', '')
    permission_operation = args.get('permission_operation', '')

    validated_required_args_for_permission(permission_account_id, permission_group_name, permission_operation)

    if permission_operation:
        permissions = [x.strip() for x in permission_operation.split(",") if x.strip()]
        for permission in permissions:
            if permission:
                attr = [f.strip() for f in permission.split(":") if f.strip()]
                if len(attr) != 2:
                    raise ValueError(MESSAGES["PERMISSION_FORMAT"])
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
                space_permission.append(permission_object)
    return space_permission


def validate_list_command_args(args: Dict[str, str]) -> dict:
    """
    Validate arguments for all list commands, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``dict``
    """

    params: Dict[str, Any] = {}

    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    if limit is not None:
        if limit < 0 or limit > 2147483647:
            raise ValueError(MESSAGES["LIMIT"].format(limit))
    else:
        limit = int(DEFAULT_LIMIT)
    params["limit"] = limit

    offset = arg_to_number(args.get('offset', DEFAULT_START))
    if offset is not None:
        if offset < 0 or offset > 2147483647:
            raise ValueError(MESSAGES["START"].format(offset))
    else:
        offset = int(DEFAULT_START)
    params["start"] = offset

    return params


def validate_list_group_args(args: Dict[str, str]) -> Dict[str, Any]:
    """
    Validate arguments for confluence-cloud-group-list command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, Any]``
    """
    params = validate_list_command_args(args)
    access_type = args.get("access_type", "").lower()
    if access_type:
        if access_type not in ACCESS_TYPE:
            raise ValueError(MESSAGES["INVALID_ACCESS_TYPE"])
        params['accessType'] = access_type

    return params


def prepare_hr_for_groups(groups: List[Dict[str, Any]]) -> str:
    """
       Prepare human readable for list groups command.

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


def validate_create_content_args(args: Dict[str, str], is_update: bool = False) -> Dict[str, Any]:
    """
    Validate arguments for confluence-cloud-content-create command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

     :type is_update: ``bool``
    :param is_update: Whether command is update content or not.

    :return: Parameters to send in request
    :rtype: ``Dict[str, Any]``
    """

    title = args.get('title', '')
    if not title:
        raise ValueError(MESSAGES['REQUIRED_ARGUMENT'].format("title"))

    content_type = args.get('type', '').lower()
    if not content_type:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("type"))
    if not is_update and content_type not in CONTENT_TYPE:
        raise ValueError(MESSAGES["INVALID_CONTENT_TYPE"])

    space_key = args.get('space_key', '')
    if not is_update and not space_key:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("space_key"))
    status = args.get('status', 'current')

    body_value = args.get('body_value', '')
    body_representation = args.get('body_representation', '')
    if content_type == "comment":
        if body_value and body_representation:
            if body_representation not in BODY_REPRESENTATION:
                raise ValueError(MESSAGES["INVALID_BODY_REPRESENTATION"])
        else:
            raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("'body_value' and 'body_representation'"))

    ancestor_id = args.get('ancestor_id', '')
    json_data = {
        "title": title,
        "type": content_type,
        "space": {
            "key": space_key
        },
        "status": status,
        "body": {
            body_representation: {
                "value": body_value,
                "representation": body_representation
            }
        },
        "ancestors": [
            {
                "id": ancestor_id
            }
        ]
    }
    params = remove_empty_elements_for_context(json_data)
    return params


def prepare_hr_for_content_create(content: Dict[str, Any], content_type: str) -> str:
    """
       Prepare human readable for content create, comment create and content update command.

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
    Prepare human readable for content search and content list command.

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


def validate_delete_content_args(args: Dict[str, str]) -> Tuple[Union[str, Any], Dict[str, Any]]:
    """
    Validate arguments for confluence-cloud-content-delete command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, Any]``
    """
    content_id = args.get("content_id", "")
    if not args.get("content_id"):
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("content_id"))

    params: Dict[str, Any] = {}
    status = args.get("deletion_type", "").lower()
    if status:
        if status not in DELETION_TYPE.keys():
            raise ValueError(MESSAGES["INVALID_DELETION_TYPE"])
        params["status"] = DELETION_TYPE[status]

    return content_id, params


def validate_create_comment_args(args: Dict[str, str]) -> Dict[str, Any]:
    """
    Validate arguments for confluence-cloud-comment-create command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, Any]``
    """

    status = args.get('status', 'current')

    body_value = args.get('body_value')
    if not body_value:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("Comment body_value"))

    body_representation = args.get('body_representation')
    if not body_representation:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("body_representation"))
    if body_representation not in BODY_REPRESENTATION:
        raise ValueError(MESSAGES["INVALID_BODY_REPRESENTATION"])

    ancestor_id = args.get('ancestor_id', '')

    container_id = args.get('container_id')
    if not container_id:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("container_id"))

    container_type = args.get('container_type', '')

    json_data = {
        "type": "comment",
        "status": status,
        "container": {
            "id": container_id,
            "type": container_type
        },
        "body": {
            body_representation: {
                "value": body_value,
                "representation": body_representation
            }
        },
        "ancestors": [
            {
                "id": ancestor_id
            }
        ]
    }
    params = remove_empty_elements_for_context(json_data)
    params["container"]["type"] = container_type
    return params


def prepare_hr_for_users(users: List[Dict[str, Any]]) -> str:
    """
    Prepare human readable for list users command.

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
    Combines the default expand fields and the user provided expand fields

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


def validate_search_content_argument(args: Dict[str, str]) -> Dict[str, Any]:
    """
    Validate arguments for confluence-cloud-content-search command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, Any]``
    """
    params = validate_list_command_args(args)

    query = args.get('query', '')
    if not query:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("query"))
    params['cql'] = query

    cursor = args.get('next_page_token')
    if cursor:
        params['cursor'] = cursor

    params['expand'] = EXPANDED_FIELD_CONTENT
    expand = args.get('expand', '')
    if expand:
        params['expand'] = prepare_expand_argument(expand, EXPANDED_FIELD_CONTENT)

    content_status = argToList(args.get('content_status', ''))
    params["cqlcontext"] = json.dumps({"contentStatuses": content_status})

    return params


def prepare_cursor_for_content(response_json: Dict[str, str]) -> str:
    """
    Prepare cursor to support pagination for contents.

    :type response_json: ``Dict[str, str]``
    :param response_json: API response.

    :return: Next token.
    :rtype: ``str``
    """
    next_cursor = ""
    next_record = response_json.get('_links', {}).get('next', '')  # type:ignore
    if next_record:
        next_cursor_split = next_record.split('?')
        parsed_next_cursor = urllib.parse.parse_qs(next_cursor_split[1])
        next_cursor = parsed_next_cursor.get('cursor', [])[0]

    return next_cursor


def validate_list_content_argument(args: Dict[str, str]) -> Dict[str, Any]:
    """
    Validate arguments for confluence_cloud_content_list command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, Any]``
    """
    params = validate_list_command_args(args)

    space_key = args.get('space_key', '')
    if space_key:
        params['spaceKey'] = space_key

    content_type = args.get('type', 'page').lower()
    if content_type in CONTENT_TYPE:
        params['type'] = content_type
    else:
        raise ValueError(MESSAGES['INVALID_CONTENT_TYPE'])

    sort_order = args.get('sort_order', '').lower()
    sort_key = args.get('sort_key', '')
    if sort_key:
        params['orderby'] = f'{sort_key}'
    if sort_order:
        if sort_key:
            params['orderby'] = f'{sort_key} {sort_order}'
        else:
            raise ValueError(MESSAGES['REQUIRED_SORT_KEY'])

    date = args.get('date', '')
    if date:
        posting_date = arg_to_datetime(date)
        params['postingDay'] = posting_date.date()  # type: ignore

    status = args.get('status', '').lower()
    CONTENT_STATUS.append('archived')
    CONTENT_STATUS.append('any')
    if status:
        if status in CONTENT_STATUS:
            params['status'] = status
        else:
            raise ValueError(MESSAGES['INVALID_STATUS_SEARCH'])

    params['expand'] = EXPANDED_FIELD_CONTENT
    expand = args.get('expand', '')
    if expand:
        params['expand'] = prepare_expand_argument(expand, EXPANDED_FIELD_CONTENT)

    return params


def validate_create_space_args(args: Dict[str, str]) -> Tuple[dict, Union[bool, str]]:
    """
    Validate arguments for confluence-cloud-space-create command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, Any]``
    """
    permissions = []
    unique_key = args.get('unique_key')
    if not unique_key:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("unique_key"))

    name = args.get('name')
    if not name:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("name"))

    description = args.get('description', '')

    is_private_space = args.get('is_private_space', False)
    if is_private_space:
        is_private_space = True if argToBoolean(is_private_space) else False

    if not is_private_space:
        if args.get('advance_permission'):
            try:
                advance_permission = json.loads(args['advance_permission'])
                permissions = advance_permission
            except (json.JSONDecodeError, json.decoder.JSONDecodeError, AttributeError):
                raise ValueError(MESSAGES["ADVANCE_PERMISSION_FORMAT"])
        else:
            permissions = validate_permissions(args)

    json_object = {
        "key": unique_key,
        "name": name,
        "description": {
            "plain": {
                "value": description,
                "representation": "plain"
            }
        },
        "permissions": permissions
    }
    params = remove_empty_elements_for_context(json_object)

    return params, is_private_space


def prepare_hr_for_space_create(space: Dict[str, Any]) -> str:
    """
    Prepare human readable for create space command.

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


def validate_list_space_args(args: Dict[str, str]) -> Dict[str, Any]:
    """
    Validate arguments for confluence-cloud-space-list command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, Any]``
    """
    params = validate_list_command_args(args)
    space_key = argToList(args.get('space_key'))
    params['spaceKey'] = space_key

    space_id = argToList(args.get('space_id'))
    params['spaceId'] = space_id

    space_type = args.get('type')
    if space_type:
        params['type'] = space_type

    status = args.get('status')
    if status:
        if status.lower() not in SPACE_STATUS:
            raise ValueError(MESSAGES["INVALID_SPACE_STATUS"])
        params['status'] = status

    favourite = args.get('favourite', '')
    if favourite:
        favourite = "true" if argToBoolean(favourite) else "false"
        params['favourite'] = favourite

    params['expand'] = EXPANDED_FIELD_SPACE
    expand = args.get('expand', '')
    if expand:
        params['expand'] = prepare_expand_argument(expand, EXPANDED_FIELD_SPACE)

    return params


def prepare_hr_for_space_list(spaces: List[Dict[str, Any]], url_prefix: str) -> str:
    """
    Prepare human readable for list space command.

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


def validate_update_content_args(args: Dict[str, str]) -> Tuple[str, Dict[str, Any]]:
    """
    Validate arguments for confluence-cloud-content-update command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, Any]``
    """
    params = validate_create_content_args(args, is_update=True)

    content_id = args.get("content_id", "")
    if not content_id:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("content_id"))

    version = args.get("version", "")
    if not version:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("version"))
    params["version"] = {
        "number": version
    }

    content_type = params['type']
    if content_type not in CONTENT_TYPE_UPDATE_COMMAND:
        raise ValueError(MESSAGES["INVALID_CONTENT_TYPE_UPDATE_CONTENT"])

    return content_id, params


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
    params: Dict = {
        "cql": "type=page",
        "limit": 1
    }
    client.http_request(method='GET', url_suffix=URL_SUFFIX["CONTENT_SEARCH"], params=params)
    return 'ok'


def confluence_cloud_user_list_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
    Returns a list of users.

    :type client: ``Client``
    :param client: Client object to be used.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Standard command result or no records found message.
    :rtype: ``CommandResults``
    """
    params = validate_list_command_args(args)

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


def confluence_cloud_content_search_command(client: Client, args: Dict[str, str]) -> CommandResults:
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
    params = validate_search_content_argument(args)

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


def confluence_cloud_content_update_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
    Update the existing content with new content.

    :type client: ``Client``
    :param client: Client object to be used.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Standard command result or no records found message.
    :rtype: ``CommandResults``
    """
    content_id, params = validate_update_content_args(args)

    request_url = URL_SUFFIX["CONTENT"] + "/{}".format(content_id)

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


def confluence_cloud_content_delete_command(client: Client, args: Dict[str, str]) -> CommandResults:
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
    content_id, params = validate_delete_content_args(args)

    request_url = URL_SUFFIX["CONTENT"] + "/{}".format(content_id)

    client.http_request(method="DELETE", url_suffix=request_url, params=params)

    return CommandResults(readable_output=MESSAGES["HR_DELETE_CONTENT"].format(content_id))


def confluence_cloud_content_list_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
        Returns the list of contents of confluence.

        :type client: ``Client``
        :param client: Client object to be used.

        :type args: ``Dict[str, str]``
        :param args: The command arguments provided by the user.

        :return: Standard command result or no records found message.
        :rtype: ``CommandResults``
    """
    params = validate_list_content_argument(args)

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


def confluence_cloud_space_list_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
      Returns a list of all Confluence spaces.

      :type client: ``Client``
      :param client: Client object to be used.

      :type args: ``Dict[str, str]``
      :param args: The command arguments provided by the user.

      :return: Standard command result or no records found message.
      :rtype: ``CommandResults``
    """
    params = validate_list_space_args(args)

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


def confluence_cloud_comment_create_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
           Creates a comment for a given content.

           :type client: ``Client``
           :param client: Client object to be used.

           :type args: ``Dict[str, str]``
           :param args: The command arguments provided by the user.

           :return: Standard command result or no records found message.
           :rtype: ``CommandResults``
        """
    params = validate_create_comment_args(args)
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


def confluence_cloud_content_create_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
       Create a page or blogpost for a specified space .

       :type client: ``Client``
       :param client: Client object to be used.

       :type args: ``Dict[str, str]``
       :param args: The command arguments provided by the user.

       :return: Standard command result or no records found message.
       :rtype: ``CommandResults``
    """
    params = validate_create_content_args(args)
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


def confluence_cloud_space_create_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
           Creates a new space in confluence cloud.

           :type client: ``Client``
           :param client: Client object to be used.

           :type args: ``Dict[str, str]``
           :param args: The command arguments provided by the user.

           :return: Standard command result or no records found message.
           :rtype: ``CommandResults``
    """

    params, is_private_space = validate_create_space_args(args)

    url_suffix = URL_SUFFIX["SPACE"]

    if is_private_space:

        url_suffix = URL_SUFFIX["PRIVATE_SPACE"]
        if 'permissions' in params.keys():
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


def confluence_cloud_group_list_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
       Retrieves the list of groups.

       :type client: ``Client``
       :param client: Client object to be used.

       :type args: ``Dict[str, str]``
       :param args: The command arguments provided by the user.

       :return: Standard command result or no records found message.
       :rtype: ``CommandResults``
       """
    params = validate_list_group_args(args)

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


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()

    # get the service API url
    url = params['url'].strip()
    base_url = "https://{}.atlassian.net".format(url)
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    credentials = params.get("username", {})
    username = credentials.get('identifier').strip()
    password = credentials.get('password')

    demisto.debug(f'{LOGGING_INTEGRATION_NAME} Command being called is {demisto.command()}')
    try:
        validate_url(url)
        headers: Dict = {
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
        commands: Dict[str, Callable] = {
            'confluence-cloud-group-list': confluence_cloud_group_list_command,
            'confluence-cloud-user-list': confluence_cloud_user_list_command,
            'confluence-cloud-content-search': confluence_cloud_content_search_command,
            'confluence-cloud-content-update': confluence_cloud_content_update_command,
            'confluence-cloud-content-delete': confluence_cloud_content_delete_command,
            'confluence-cloud-content-list': confluence_cloud_content_list_command,
            'confluence-cloud-space-list': confluence_cloud_space_list_command,
            'confluence-cloud-comment-create': confluence_cloud_comment_create_command,
            'confluence-cloud-content-create': confluence_cloud_content_create_command,
            'confluence-cloud-space-create': confluence_cloud_space_create_command
        }
        command = demisto.command()
        args = demisto.args()
        strip_args(args)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))
        elif command in commands:
            return_results(commands[command](client, args))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

from CommonServerPython import *

from CommonServerUserPython import *

from typing import Any

""" CONSTANTS """
PAGE_SIZE_DEFAULT_INT = 50
DEFAULT_LIMIT_NUMBER = 25
BASE_DEFAULT_PAGE_NUMBER_INT = 1
BASE_DEFAULT_OFFSET_NUMBER = 0
MAX_LIMIT = 100
MIN_LIMIT = 0

INVALID_ID_DEMISTO_ERROR = (
    "Error. This may be due to Invalid ID for one or more fields that request IDs. " "Please make sure all IDs are correct."
)
RESPONSE_NOT_IN_FORMAT_ERROR = "The request succeeded, but a parse error occurred."

HR_SHOW_ONLY_NAME = JsonTransformer(keys=["name"], func=lambda hdr: hdr.get("name", ""))

USER_STATUS_DICT = {
    "Active": "1",
    "Registered": "2",
    "Locked": "3",
}

ISSUE_STATUS_FOR_LIST_COMMAND = {"Open": "open", "Closed": "closed", "All": "*"}

DICT_OF_ISSUE_ARGS = {
    "trackers": {"key_in_response": "trackers", "url_suffix": "/trackers.json", "singular": "tracker"},
    "statuses": {"key_in_response": "issue_statuses", "url_suffix": "/issue_statuses.json", "singular": "status"},
    "priorities": {
        "key_in_response": "issue_priorities",
        "url_suffix": "/enumerations/issue_priorities.json",
        "singular": "priority",
    },
}
""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(self, server_url, api_key, verify=True, proxy=False, headers=None, auth=None, project_id=None):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

        self._post_put_header = {"Content-Type": "application/json", "X-Redmine-API-Key": api_key}
        self._upload_file_header = {"Content-Type": "application/octet-stream", "X-Redmine-API-Key": api_key}
        self._get_header = {"X-Redmine-API-Key": api_key}
        self._project_id = project_id

    def create_file_token_request(self, args, entry_id):
        file_content = get_file_content(entry_id)
        response = self._http_request("POST", "/uploads.json", params=args, headers=self._upload_file_header, data=file_content)
        return response

    def create_issue_request(self, args, watcher_user_ids, project_id):
        args["project_id"] = project_id
        args["watcher_user_ids"] = watcher_user_ids
        remove_nulls_from_dictionary(args)
        body_for_request = {"issue": args}
        response = self._http_request(
            "POST", "/issues.json", params={}, json_data=body_for_request, headers=self._post_put_header
        )
        return response

    def update_issue_request(self, args, project_id, watcher_user_ids):
        issue_id = args.pop("issue_id")
        args["project_id"] = project_id
        args["watcher_user_ids"] = watcher_user_ids
        remove_nulls_from_dictionary(args)
        response = self._http_request(
            "PUT",
            f"/issues/{issue_id}.json",
            json_data={"issue": args},
            headers=self._post_put_header,
            empty_valid_codes=[204],
            return_empty_response=True,
        )
        return response

    def get_issues_list_request(
        self, project_id, status_id, offset_to_dict, limit_to_dict, exclude_subproject, args: dict[str, Any]
    ):
        if exclude_subproject and args.get("subproject_id", None):
            raise DemistoException("Specify only one of the following, subproject_id or exclude.")
        elif exclude_subproject:
            args["subproject_id"] = f"!{exclude_subproject}"
        params = assign_params(project_id=project_id, status_id=status_id, offset=offset_to_dict, limit=limit_to_dict, **args)
        response = self._http_request("GET", "/issues.json", params=params, headers=self._get_header)
        return response

    def delete_issue_by_id_request(self, issue_id):
        response = self._http_request(
            "DELETE",
            f"/issues/{issue_id}.json",
            headers=self._post_put_header,
            empty_valid_codes=[200, 204, 201],
            return_empty_response=True,
        )
        return response

    def get_issue_by_id_request(self, issue_id, included_fields):
        response = self._http_request(
            "GET", f"/issues/{issue_id}.json", params={"include": included_fields}, headers=self._get_header
        )
        return response

    def add_issue_watcher_request(self, issue_id, watcher_id):
        args_to_add = {"user_id": watcher_id}
        response = self._http_request(
            "POST",
            f"/issues/{issue_id}/watchers.json",
            params=args_to_add,
            headers=self._post_put_header,
            empty_valid_codes=[200, 204, 201],
            return_empty_response=True,
        )
        return response

    def remove_issue_watcher_request(self, issue_id, watcher_id):
        response = self._http_request(
            "DELETE",
            f"/issues/{issue_id}/watchers/{watcher_id}.json",
            headers=self._post_put_header,
            empty_valid_codes=[200, 204, 201],
            return_empty_response=True,
        )
        return response

    def get_project_list_request(self, args: dict[str, Any]):
        response = self._http_request("GET", "/projects.json", params=args, headers=self._get_header)
        return response

    def get_custom_fields_request(self):
        response = self._http_request("GET", "/custom_fields.json", headers=self._get_header)
        return response

    def get_users_request(self, args: dict[str, Any]):
        response = self._http_request("GET", "/users.json", params=args, headers=self._get_header)
        return response

    def field_from_name_to_id_list_request(self, field):
        response = self._http_request("GET", DICT_OF_ISSUE_ARGS.get(field, {}).get("url_suffix", ""), headers=self._get_header)
        return response


""" HELPER FUNCTIONS """


def check_include_validity(included_args, include_options):
    """Checks if all include string is valid- all arguments are from predefined options

    Args:
        include_arg (str): The string argument.
        include_options (str): The include options for the request.

    Raises:
        Raises a demisto error if one or more from the include are not given in the predefined options.
    """
    included_args = argToList(included_args)
    invalid_values = set(included_args) - set(include_options)
    if invalid_values:
        raise DemistoException(
            f"The 'include' argument should only contain values from {include_options}, separated by commas. "
            f"These values are not in options {invalid_values}."
        )


def create_paging_header(page_size: int, page_number: int):
    return "#### Showing" + (f" {page_size}") + " results" + (f" from page {page_number}") + ":\n"


def adjust_paging_to_request(page_number, page_size, limit):
    if page_number or page_size:
        page_size = arg_to_number(page_size) or PAGE_SIZE_DEFAULT_INT
        page_number = arg_to_number(page_number) or BASE_DEFAULT_PAGE_NUMBER_INT
        generated_offset = (page_number - 1) * page_size
        return generated_offset, page_size, page_number
    limit = arg_to_number(limit) or DEFAULT_LIMIT_NUMBER
    if limit > MAX_LIMIT or limit <= MIN_LIMIT:
        raise DemistoException(f"Maximum limit is 100 and Minimum limit is 0, you provided {limit}")
    return BASE_DEFAULT_OFFSET_NUMBER, limit, BASE_DEFAULT_PAGE_NUMBER_INT


def format_custom_field_to_request(args: Dict[str, Any]):
    if custom_fields := args.pop("custom_fields", ""):
        try:
            custom_fields_for_request = []
            custom_fields_dict = json.loads(custom_fields)
            for key, value in custom_fields_dict.items():
                custom_fields_for_request.append({"id": key, "value": value})
            args["custom_fields"] = custom_fields_for_request
        except Exception as e:
            raise DemistoException(
                f"Custom fields not in format, please follow this format:"
                f' `{{"customFieldID2": "value3", "customFieldID1": ["value1","value2"]}}` - Please use an array if '
                f"the field is of multiselect type. with error: {e}"
            )


def get_file_content(entry_id: str) -> bytes:
    """Returns the XSOAR file entry's content.

    Args:
        entry_id (str): The entry id inside XSOAR.

    Returns:
        Tuple[str, bytes]: A tuple, where the first value is the file name, and the second is the
        content of the file in bytes.
    """
    get_file_path_res = demisto.getFilePath(entry_id)
    file_path = get_file_path_res.pop("path")
    file_bytes: bytes = b""
    with open(file_path, "rb") as f:
        file_bytes = f.read()
    return file_bytes


def handle_file_attachment(client: Client, args: Dict[str, Any], entry_id: str):
    """If a file was provided create a token and add to args

    Args:
        client (Client)
        args (Dict[str,Any]): Raw arguments dict from user

    Raises:
        DemistoException: response not in format or could not create a token
    """
    try:
        file_name = args.pop("file_name", "")
        file_description = args.pop("file_description", "")
        content_type = args.pop("file_content_type", "")
        args_for_file = assign_params(file_name=file_name, content_type=content_type)
        token_response = client.create_file_token_request(args_for_file, entry_id)
        if "upload" not in token_response or "token" not in token_response["upload"]:
            raise DemistoException(f"Could not upload file with entry id {entry_id}, please try again.")
        uploads = assign_params(
            token=token_response["upload"].get("token", ""),
            content_type=content_type,
            filename=file_name,
            description=file_description,
        )
        args["uploads"] = [uploads]
    except DemistoException as e:
        if "Could not upload file with entry id" in e.message:
            raise DemistoException(e.message)
        raise DemistoException("Could not create a token for your file- please try again." f"With error {e}.")


""" COMMAND FUNCTIONS """


def test_module(client: Client):
    message: str = ""
    try:
        if get_users_command(client, {}):
            message = "ok"
        return return_results(message)
    except DemistoException as e:
        if "401" in str(e) or "Unauthorized" in str(e):
            message = f"Authorization Error: make sure API Key is correctly set. Error: {e}"
        else:
            raise e
    return return_results(message)


def create_issue_command(client: Client, args: dict[str, Any]) -> CommandResults:
    project_id = args.pop("project_id", client._project_id)
    if not project_id:
        raise DemistoException("project_id field is missing in order to create an issue")
    # Checks if a file needs to be added
    entry_id = args.pop("file_entry_id", None)
    if entry_id:
        handle_file_attachment(client, args, entry_id)
    # Change predefined values to id
    format_custom_field_to_request(args)
    watcher_user_ids = argToList(args.pop("watcher_user_ids", None))
    try:
        response = client.create_issue_request(args, watcher_user_ids, project_id)
    except DemistoException as e:
        if "Error in API call [422]" in e.message or "Error in API call [404]" in e.message:
            raise DemistoException(f"{INVALID_ID_DEMISTO_ERROR} With error: {e}")
        raise
    if "issue" not in response:
        raise DemistoException(RESPONSE_NOT_IN_FORMAT_ERROR)
    issue_response = response["issue"]
    headers = [
        "id",
        "project",
        "tracker",
        "status",
        "priority",
        "author",
        "estimated_hours",
        "created_on",
        "subject",
        "description",
        "start_date",
        "estimated_hours",
        "custom_fields",
    ]
    # Issue id is a number and tableToMarkdown can't transform it if is_auto_json_transform is True
    issue_response["id"] = str(issue_response["id"])
    command_results = CommandResults(
        outputs_prefix="Redmine.Issue",
        outputs_key_field="id",
        outputs=issue_response,
        raw_response=issue_response,
        readable_output=tableToMarkdown(
            "The issue you created:",
            issue_response,
            headers=headers,
            removeNull=True,
            headerTransform=string_to_table_header,
            json_transform_mapping={
                "tracker": HR_SHOW_ONLY_NAME,
                "status": HR_SHOW_ONLY_NAME,
                "priority": HR_SHOW_ONLY_NAME,
                "author": HR_SHOW_ONLY_NAME,
                "project": HR_SHOW_ONLY_NAME,
                "custom_fields": JsonTransformer(keys=["name", "value"]),
            },
        ),
    )

    return command_results


def update_issue_command(client: Client, args: dict[str, Any]):
    issue_id = args.get("issue_id")
    # Checks if a file needs to be added
    entry_id = args.pop("file_entry_id", None)
    if entry_id:
        handle_file_attachment(client, args, entry_id)
    format_custom_field_to_request(args)
    watcher_user_ids = args.pop("watcher_user_ids", None)
    if watcher_user_ids:
        watcher_user_ids = argToList(watcher_user_ids)
    project_id = args.pop("project_id", client._project_id)
    try:
        client.update_issue_request(args, project_id, watcher_user_ids)
    except DemistoException as e:
        if "Error in API call [422]" in e.message or "Error in API call [404]" in e.message:
            raise DemistoException(f"{INVALID_ID_DEMISTO_ERROR} With error: {e}")
        raise
    command_results = CommandResults(readable_output=f"Issue with id {issue_id} was successfully updated.")
    return command_results


def get_issues_list_command(client: Client, args: dict[str, Any]):
    def format_and_validate_fields_to_request(custom_field: str, status: str):
        if custom_field:
            try:
                cf_in_format = custom_field.split(":", 1)
                args[f"cf_{cf_in_format[0]}"] = cf_in_format[1]
            except Exception as e:
                if "list index out of range" in e.args[0] or "substring not found" in e.args[0]:
                    raise DemistoException(f"Invalid custom field format, please follow the command description. Error: {e}.")
                raise
        # If the user used predefined values, convert to values accepted by the API using ISSUE_STATUS_FOR_LIST_COMMAND
        status_id = ISSUE_STATUS_FOR_LIST_COMMAND.get(status)
        # If the user did not used predefined values, make sure it is a number
        if not status_id:
            status_id = status
            try:
                arg_to_number(status_id)
            except ValueError as e:
                raise DemistoException(
                    f"Status argument has to be a predefined value (Open/Closed/All) or a valid status ID but "
                    f"got {status_id}. with error: {e}."
                )
        return status_id

    page_number = args.pop("page_number", None)
    page_size = args.pop("page_size", None)
    limit = args.pop("limit", None)
    offset_to_dict, limit_to_dict, page_number_for_header = adjust_paging_to_request(page_number, page_size, limit)
    status = args.pop("status", "Open")
    custom_field = args.pop("custom_field", None)
    status_id = format_and_validate_fields_to_request(custom_field, status)
    project_id = args.pop("project_id", client._project_id)
    exclude_sub_project = args.pop("exclude", None)
    try:
        response = client.get_issues_list_request(project_id, status_id, offset_to_dict, limit_to_dict, exclude_sub_project, args)
    except DemistoException as e:
        if "Error in API call [422]" in e.message or "Error in API call [404]" in e.message:
            raise DemistoException(f"{INVALID_ID_DEMISTO_ERROR} With error: {e}")
        raise
    try:
        issues_response = response["issues"]
    except Exception:
        raise DemistoException(RESPONSE_NOT_IN_FORMAT_ERROR)
    page_header = create_paging_header(len(issues_response), page_number_for_header)

    # Issue id is a number and tableToMarkdown can't transform it if is_auto_json_transform is True
    for issue in issues_response:
        issue["id"] = str(issue["id"])

    headers = [
        "id",
        "tracker",
        "status",
        "priority",
        "author",
        "subject",
        "description",
        "start_date",
        "due_date",
        "done_ratio",
        "is_private",
        "estimated_hours",
        "custom_fields",
        "created_on",
        "updated_on",
        "closed_on",
        "attachments",
        "relations",
    ]

    command_results = CommandResults(
        outputs_prefix="Redmine.Issue",
        outputs_key_field="id",
        outputs=issues_response,
        raw_response=issues_response,
        readable_output=page_header
        + tableToMarkdown(
            "Issues Results:",
            issues_response,
            headers=headers,
            removeNull=True,
            headerTransform=string_to_table_header,
            is_auto_json_transform=True,
            json_transform_mapping={
                "tracker": HR_SHOW_ONLY_NAME,
                "status": HR_SHOW_ONLY_NAME,
                "priority": HR_SHOW_ONLY_NAME,
                "author": HR_SHOW_ONLY_NAME,
                "custom_fields": JsonTransformer(keys=["name", "value"]),
            },
        ),
    )
    return command_results


def get_issue_by_id_command(client: Client, args: dict[str, Any]):
    try:
        issue_id = args.get("issue_id")
        included_fields = args.get("include")
        if included_fields:
            check_include_validity(
                included_fields,
                ["children", "attachments", "relations", "changesets", "journals", "watchers", "allowed_statuses"],
            )
        try:
            response = client.get_issue_by_id_request(issue_id, included_fields)
        except DemistoException as e:
            if "Error in API call [422]" in e.message or "Error in API call [404]" in e.message:
                raise DemistoException(f"{INVALID_ID_DEMISTO_ERROR} With error: {e}")
            elif "Error in API call [403]" in e.message:
                raise DemistoException(
                    f"{e.message} It can be due to Invalid ID for one or more fields that request IDs, "
                    "Please make sure all IDs are correct"
                )
            raise
        if "issue" not in response:
            raise DemistoException(RESPONSE_NOT_IN_FORMAT_ERROR)
        response_issue = response["issue"]
        headers = [
            "id",
            "project",
            "tracker",
            "status",
            "priority",
            "author",
            "subject",
            "description",
            "start_date",
            "due_date",
            "done_ratio",
            "is_private",
            "estimated_hours",
            "custom_fields",
            "created_on",
            "closed_on",
            "attachments",
            "watchers",
            "children",
            "relations",
            "changesets",
            "journals",
            "allowed_statuses",
        ]

        # Issue id is a number and tableToMarkdown can't transform it if is_auto_json_transform is True
        if "id" in response_issue:
            response_issue["id"] = str(response_issue["id"])
        command_results = CommandResults(
            outputs_prefix="Redmine.Issue",
            outputs_key_field="id",
            outputs=response_issue,
            raw_response=response_issue,
            readable_output=tableToMarkdown(
                "Issues List:",
                response_issue,
                headers=headers,
                removeNull=True,
                headerTransform=underscoreToCamelCase,
                is_auto_json_transform=True,
                json_transform_mapping={
                    "tracker": HR_SHOW_ONLY_NAME,
                    "project": HR_SHOW_ONLY_NAME,
                    "status": HR_SHOW_ONLY_NAME,
                    "priority": HR_SHOW_ONLY_NAME,
                    "author": HR_SHOW_ONLY_NAME,
                    "custom_fields": JsonTransformer(keys=["name", "value"]),
                    "watchers": JsonTransformer(keys=["name"]),
                    "attachments": JsonTransformer(keys=["filename", "content_url", "content_type", "description"]),
                },
            ),
        )
        return command_results
    except Exception as e:
        if "Error in API call [422]" in e.args[0] or "Error in API call [404]" in e.args[0]:
            raise DemistoException("Invalid ID for one or more fields that request IDs " "Please make sure all IDs are correct")
        raise


def delete_issue_by_id_command(client: Client, args: dict[str, Any]):
    issue_id = args.get("issue_id")
    try:
        client.delete_issue_by_id_request(issue_id)
    except DemistoException as e:
        if "Error in API call [422]" in e.message or "Error in API call [404]" in e.message:
            raise DemistoException(f"{INVALID_ID_DEMISTO_ERROR} With error: {e}")
        raise
    command_results = CommandResults(readable_output=f"Issue with id {issue_id} was deleted successfully.")
    return command_results


def add_issue_watcher_command(client: Client, args: dict[str, Any]):
    issue_id = args.get("issue_id")
    watcher_id = args.get("watcher_id")
    try:
        client.add_issue_watcher_request(issue_id, watcher_id)
    except DemistoException as e:
        if "Error in API call [422]" in e.message or "Error in API call [404]" in e.message:
            raise DemistoException(f"{INVALID_ID_DEMISTO_ERROR} With error: {e}")
        elif "Error in API call [403]" in e.message:
            raise DemistoException(
                f"{e.message} It can be due to Invalid ID for one or more fields that request IDs, "
                "Please make sure all IDs are correct"
            )
        raise
    command_results = CommandResults(
        readable_output=f"Watcher with id {watcher_id} was added successfully to issue with id {issue_id}."
    )
    return command_results


def remove_issue_watcher_command(client: Client, args: dict[str, Any]):
    issue_id = args.get("issue_id")
    watcher_id = args.get("watcher_id")
    try:
        client.remove_issue_watcher_request(issue_id, watcher_id)
    except DemistoException as e:
        if "Error in API call [422]" in e.message or "Error in API call [404]" in e.message:
            raise DemistoException(f"{INVALID_ID_DEMISTO_ERROR} With error: {e}")
        elif "Error in API call [403]" in e.message:
            raise DemistoException(
                f"{e.message} It can be due to Invalid ID for one or more fields that request IDs, "
                "Please make sure all IDs are correct."
            )
        raise
    command_results = CommandResults(
        readable_output=f"Watcher with id {watcher_id} was removed successfully from issue with id {issue_id}."
    )
    return command_results


def get_project_list_command(client: Client, args: dict[str, Any]):
    include_arg = args.get("include", None)
    if include_arg:
        check_include_validity(
            include_arg, ["trackers", "issue_categories", "enabled_modules", "time_entry_activities", "issue_custom_fields"]
        )
    response = client.get_project_list_request(args)
    if "projects" not in response:
        raise DemistoException(RESPONSE_NOT_IN_FORMAT_ERROR)
    projects_response = response["projects"]

    headers = [
        "id",
        "name",
        "identifier",
        "description",
        "status",
        "is_public",
        "time_entry_activities",
        "created_on",
        "updated_on",
        "default_value",
        "visible",
        "roles",
        "issue_custom_fields",
        "enabled_modules",
        "issue_categories",
        "trackers",
    ]
    # Some project fields are numbers and tableToMarkdown can't transform it if is_auto_json_transform is true
    for project in projects_response:
        project["id"] = str(project["id"])
        project["status"] = str(project["status"])
        project["is_public"] = str(project["is_public"])

    command_results = CommandResults(
        outputs_prefix="Redmine.Project",
        outputs_key_field="id",
        outputs=projects_response,
        raw_response=projects_response,
        readable_output=tableToMarkdown(
            "Projects List:",
            projects_response,
            headers=headers,
            removeNull=True,
            headerTransform=underscoreToCamelCase,
            is_auto_json_transform=True,
        ),
    )
    return command_results


def get_custom_fields_command(client: Client, args):
    response = client.get_custom_fields_request()
    if "custom_fields" not in response:
        raise DemistoException(RESPONSE_NOT_IN_FORMAT_ERROR)
    custom_fields_response = response["custom_fields"]
    headers = [
        "id",
        "name",
        "customized_type",
        "field_format",
        "regexp",
        "max_length",
        "is_required",
        "is_filter",
        "searchable",
        "trackers",
        "issue_categories",
        "enabled_modules",
        "time_entry_activities",
        "issue_custom_fields",
    ]
    # Some custom fields are numbers and tableToMarkdown can't transform it if is_auto_json_transform is True
    for custom_field in custom_fields_response:
        custom_field["id"] = str(custom_field["id"])
        custom_field["is_required"] = str(custom_field["is_required"])
        custom_field["is_filter"] = str(custom_field["is_filter"])

    command_results = CommandResults(
        outputs_prefix="Redmine.CustomField",
        outputs_key_field="id",
        outputs=custom_fields_response,
        raw_response=custom_fields_response,
        readable_output=tableToMarkdown(
            "Custom Fields List:",
            custom_fields_response,
            headers=headers,
            removeNull=True,
            headerTransform=underscoreToCamelCase,
            is_auto_json_transform=True,
        ),
    )
    return command_results


def get_users_command(client: Client, args: dict[str, Any]):
    status_string = args.get("status")
    if status_string:
        try:
            args["status"] = USER_STATUS_DICT[status_string]
        except Exception:
            raise DemistoException("Invalid status value- please use the predefined options only.")
    response = client.get_users_request(args)
    try:
        users_response = response["users"]
    except Exception:
        raise DemistoException(RESPONSE_NOT_IN_FORMAT_ERROR)
    headers = ["id", "login", "admin", "firstname", "lastname", "mail", "created_on", "last_login_on"]
    # Some issue fields are numbers and tableToMarkdown can't transform it.
    for user in users_response:
        user["id"] = str(user["id"])
        user["admin"] = str(user["admin"])
    command_results = CommandResults(
        outputs_prefix="Redmine.Users",
        outputs_key_field="id",
        outputs=users_response,
        raw_response=users_response,
        readable_output=tableToMarkdown(
            "Users List:",
            users_response,
            headers=headers,
            removeNull=True,
            headerTransform=string_to_table_header,
            is_auto_json_transform=True,
        ),
    )
    return command_results


def field_from_name_to_id_list_command(client, field: str):
    response = client.field_from_name_to_id_list_request(field)
    key_in_response = DICT_OF_ISSUE_ARGS.get(field, {}).get("key_in_response", "")
    if key_in_response not in response:
        singular = DICT_OF_ISSUE_ARGS.get(field, {}).get("singular", "")
        raise DemistoException(f"Failed to retrieve {singular} IDs due to a parsing error.")
    mapping_name_to_id_of_field = [{"ID": item["id"], "Name": item["name"]} for item in response[key_in_response]]
    command_results = CommandResults(
        outputs_prefix=f"Redmine.{field}",
        outputs_key_field="ID",
        outputs=mapping_name_to_id_of_field,
        raw_response=mapping_name_to_id_of_field,
        readable_output=tableToMarkdown(
            f"{field} name to id List:",
            mapping_name_to_id_of_field,
            headers=["ID", "Name"],
            removeNull=True,
        ),
    )
    return command_results


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    base_url = params.get("url")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    api_key = params.get("credentials", {}).get("password", "")
    project_id = params.get("project_id", None)

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        commands = {
            "redmine-issue-create": create_issue_command,
            "redmine-issue-update": update_issue_command,
            "redmine-issue-get": get_issue_by_id_command,
            "redmine-issue-delete": delete_issue_by_id_command,
            "redmine-issue-watcher-add": add_issue_watcher_command,
            "redmine-issue-watcher-remove": remove_issue_watcher_command,
            "redmine-issue-list": get_issues_list_command,
            "redmine-project-list": get_project_list_command,
            "redmine-custom-field-list": get_custom_fields_command,
            "redmine-user-id-list": get_users_command,
        }

        client = Client(server_url=base_url, verify=verify_certificate, proxy=proxy, api_key=api_key, project_id=project_id)

        if command == "test-module":
            return_results(test_module(client))
        elif command == "redmine-status-id-list":
            return_results(field_from_name_to_id_list_command(client, "statuses"))
        elif command == "redmine-priority-id-list":
            return_results(field_from_name_to_id_list_command(client, "priorities"))
        elif command == "redmine-tracker-id-list":
            return_results(field_from_name_to_id_list_command(client, "trackers"))
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f"command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

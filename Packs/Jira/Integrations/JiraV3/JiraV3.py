import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from abc import ABCMeta
from collections.abc import Callable
from collections import defaultdict
from bs4 import BeautifulSoup
import hashlib
from copy import deepcopy
from mimetypes import guess_type

# Note: time.time_ns() is used instead of time.time() to avoid the precision loss caused by the float type.
# Source: https://docs.python.org/3/library/time.html#time.time_ns

""" CONSTANTS """
JIRA_INCIDENT_TYPE_NAME = 'JiraV3 Incident'
ISSUE_INCIDENT_FIELDS = {'issue_id': 'The ID of the issue to edit',
                         'summary': 'The summary of the issue.',
                         'description': 'The description of the issue.',
                         'labels': 'A CSV list of labels.',
                         'components': 'A CSV list of components',
                         'priority': 'A priority name, for example "High" or "Medium".',
                         'due_date': 'The due date for the issue (in the format 2018-03-11).',
                         'assignee': 'The name of the assignee. Relevant for Jira Server only',
                         'status': 'The name of the status.',
                         'assignee_id': 'The account ID of the assignee. Use'
                                        ' the jira-get-id-by-attribute command to get the user\'s Account ID.',
                         'original_estimate': 'The original estimate of the Jira issue.'
                         }
DEFAULT_FETCH_LIMIT = 50
DEFAULT_FIRST_FETCH_INTERVAL = '3 days'
DEFAULT_FETCH_INTERVAL = 1  # Unit is in minutes
DEFAULT_PAGE = 0
DEFAULT_PAGE_SIZE = 50
# Errors
ID_OR_KEY_MISSING_ERROR = 'Please provide either an issue ID or issue key.'
ID_AND_KEY_GIVEN = 'Please provide only one, either an issue Id or issue key.'
EPIC_ID_OR_KEY_MISSING_ERROR = 'Please provide either an epic ID or epic key.'
CLOSE_INCIDENT_REASON = 'Issue was marked as "Resolved", or status was changed to "Done"'
MIRROR_DIRECTION_DICT = {
    'None': None,
    'Incoming': 'In',
    'Outgoing': 'Out',
    'Incoming And Outgoing': 'Both'
}
# This will be appended to the attachment's name when mirroring an attachment from XSOAR to Jira
ATTACHMENT_MIRRORED_FROM_XSOAR = '_mirrored_from_xsoar'
COMMENT_MIRRORED_FROM_XSOAR = 'Mirrored from Cortex XSOAR'
V2_ARGS_TO_V3: Dict[str, str] = {
    'startAt': 'start_at',
    'maxResults': 'max_results',
    'extraFields': 'fields',
    'getAttachments': 'get_attachments',
    'expandLinks': 'expand_links',
    'issueJson': 'issue_json',
    'projectKey': 'project_key',
    'issueTypeName': 'issue_type_name',
    'issueTypeId': 'issue_type_id',
    'projectName': 'project_name',
    'dueDate': 'due_date',
    'parentIssueKey': 'parent_issue_key',
    'parentIssueId': 'parent_issue_id',
    'attachmentName': 'attachment_name',
    'globalId': 'global_id',
    'applicationType': 'application_type',
    'applicationName': 'application_name',
    'field': 'fields'
}


class JiraBaseClient(BaseClient, metaclass=ABCMeta):
    """
    This class is an abstract class. By using metaclass=ABCMeta, we tell python that this class behaves as an abstract
    class, where we want to define the definition of methods without implementing them, and the child classes will need to
    implement these methods.
    """

    # This will hold a mapping between the issue fields arguments that is supplied by the user, and the path
    # of them in the issue fields object when creating a new issue, in dotted string format. For example, when
    # creating a new issue, we send to the API an issue fields object that holds data about the new issue, and if we want to add
    # the project_key, then we supply it as: {fields: {project: {key: THE_PROJECT_KEY}}}
    ISSUE_FIELDS_CREATE_MAPPER = {
        'summary': 'fields.summary',
        'project_key': 'fields.project.key',
        'project_id': 'fields.project.id',
        'issue_type_name': 'fields.issuetype.name',
        'issue_type_id': 'fields.issuetype.id',
        'description': 'fields.description',
        'labels': 'fields.labels',
        'priority': 'fields.priority.name',
        'due_date': 'fields.duedate',
        'assignee': 'fields.assignee.name',  # Does not work for Jira Cloud
        'assignee_id': 'fields.assignee.accountId',
        'reporter': 'fields.reporter.name',
        'reporter_id': 'fields.reporter.accountId',
        'parent_issue_key': 'fields.parent.key',
        'parent_issue_id': 'fields.parent.id',
        'environment': 'fields.environment',
        'security': 'fields.security.name',
        'components': 'fields.components',
        'original_estimate': 'fields.timetracking.originalEstimate'
    }

    AGILE_API_ENDPOINT = 'rest/agile/1.0'

    def __init__(self, base_url: str, proxy: bool, verify: bool,
                 callback_url: str, api_version: str, username: str, api_key: str):
        self.username = username
        self.api_key = api_key
        self.is_basic_auth = bool(self.username and self.api_key)
        headers: Dict[str, str] = {'Accept': 'application/json'}
        self.callback_url = callback_url
        self.api_version = api_version
        super().__init__(base_url=base_url, proxy=proxy, verify=verify, headers=headers)

    @abstractmethod
    def test_instance_connection(self) -> None:
        """This method is used to test the connectivity of each instance, each child will implement
        their own connectivity test
        """

    def http_request(self, method: str, headers: dict[str, str] | None = None, url_suffix='', params=None,
                     data=None, json_data=None, resp_type='json', ok_codes=None, full_url='',
                     files: Dict[str, Any] | None = None) -> Any:
        """This method wraps the _http_request that comes from the BaseClient class,
        and adds the headers request, by calling one of both method `get_headers_with_access_token` or
        `get_headers_with_basic_auth` depends on the type of authentication the customer has chosen.
        Returns:
            Depends on the resp_type parameter: The response of the API endpoint.
        """
        if self.is_basic_auth:
            request_headers = self.get_headers_with_basic_auth(headers=headers)
        else:
            request_headers = self.get_headers_with_access_token(headers=headers)
        return self._http_request(method, url_suffix=url_suffix, full_url=full_url, params=params, data=data,
                                  json_data=json_data, resp_type=resp_type, ok_codes=ok_codes, files=files,
                                  headers=request_headers)

    def get_headers_with_access_token(self, headers: dict[str, str] | None = None) -> dict[str, str]:
        """This method inserts the access_token of the client to the headers request,
        by calling the get_access_token method, which is an abstract method,
        and every child class must implement it.
        """
        access_token = self.get_access_token()
        # We unite multiple headers (using the '|' character, pipe operator) since some requests may require extra headers
        # to work, and this way, we have the option to receive the extra headers and send them in the API request.
        return self._headers | (headers or {}) | {'Authorization': f'Bearer {access_token}'}

    def get_headers_with_basic_auth(self, headers: Dict[str, str] | None = None) -> dict[str, str]:
        """
        This method inserts the encoded key into the request headers.
        """
        basic_auth_bytes = f"{self.username}:{self.api_key}".encode()
        encoded_key = base64.b64encode(basic_auth_bytes).decode("utf-8")
        return self._headers | (headers or {}) | {"Authorization": f"Basic {encoded_key}"}

    # Authorization methods
    def get_access_token(self) -> str:
        # CONFLUENCE Explain the process of saving and retrieving the access token from the integration's context
        """This function is in charge of returning the access token stored in the integration's context. If the access token
        has expired, we try to retrieve another access token using a refresh token that is configured in the integration's context

        Raises:
            DemistoException: If no access token was configured.
            DemistoException: If no refresh token was configured.

        Returns:
            str: The access token to send with the requests.
        """
        integration_context = get_integration_context()
        token = integration_context.get('token', '')
        if not token:
            raise DemistoException('No access token was configured, please complete the authorization process'
                                   ' as shown in the documentation')
        # The valid_until key stores the valid date in seconds to make it easier for comparison
        valid_until = integration_context.get('valid_until', 0)
        current_time = get_current_time_in_seconds()
        if current_time >= valid_until - 10:
            refresh_token = integration_context.get('refresh_token', '')
            if not refresh_token:
                raise DemistoException('No refresh token was configured, please complete the authorization process'
                                       ' as shown in the documentation')
            # We try to retrieve a new access token and store it in the integration's context using the method bellow
            self.oauth2_retrieve_access_token(refresh_token=refresh_token)
            integration_context = get_integration_context()
            token = integration_context.get('token', '')
        return token

    @abstractmethod
    def oauth2_retrieve_access_token(self, code: str = '', refresh_token: str = '') -> None:
        """This method is in charge of exchanging an authorization code or refresh token for an access token,
        that is retrieved using a Jira endpoint.

        Args:
            code (str, optional): The authorization code supplied by the user, if authenticating using it. Defaults to ''.
            refresh_token (str, optional): The refresh token that is stored in the integration's context. Defaults to ''.

        Raises:
            DemistoException: If both an authorization code and refresh token were given, only one must be supplied.
            DemistoException: If neither an authorization code nor a refresh token were given.
        """

    @abstractmethod
    def oauth_start(self) -> str:
        """This method is used to start the OAuth process in order to retrieve the access and refresh token of the client,
        by returning a callback URL that the user must interact with in order to continue the process.

        Returns:
            str: The callback URL that the user will use in order to authenticate
        himself
        """

    @abstractmethod
    def oauth_complete(self, code: str) -> None:
        """This method is used to finish the authentication process. It receives a code string that was acquired
        after interacting with the callback URL, and this code string is sent to a Jira endpoint as an exchange
        for the access and refresh token, in which these tokens will be saved to the integration's context, along with
        any necessary data.

        Args:
            code (str): A code string that was acquired after interacting with the callback URL
        """

    # Query Requests
    def run_query(self, query_params: Dict[str, Any]) -> Dict[str, Any]:
        """This method is in charge of running a JQL (Jira Query Language), and retrieving its results.

        Args:
            query_params (Dict[str, Any]): The query parameters, which will hold the query string itself,
            and any pagination data (using startAt and maxResults, as required by the API)

        Returns:
            Dict[str, Any]: The query results, which will hold the issues acquired from the query.
        """
        # We supply the renderedFields query parameter to retrieve some content in HTML format, since Jira uses a format
        # called ADF (for api version 3), or a custom complex format (for api version 2) and it is easier to parse the
        # content in HTML format, using a 3rd party package, rather than complex format.
        # We also supply the fields: *all to return all the fields from an issue (specifically the field that holds
        # data about the attachments in the issue), otherwise, it won't get returned in the query.
        query_params |= {'expand': 'renderedFields,transitions,names', 'fields': ['*all']}
        return self.http_request(
            method='GET', url_suffix=f'rest/api/{self.api_version}/search', params=query_params
        )

    # Board Requests
    def get_issues_from_backlog(self, board_id: str, jql_query: str | None = None,
                                start_at: int | None = None, max_results: int | None = None) -> Dict[str, Any]:
        """This method is in charge of retrieving issues from the backlog of a specific board.

        Args:
            board_id (str): The board id
            jql_query (str | None, optional): The JQL query to filter specific issues. Defaults to None.
            start_at (int | None, optional): The starting index of the returned issues . Defaults to None.
            max_results (int | None, optional): The maximum number of issues to return per page. Defaults to None.

        Returns:
            Dict[str, Any]: The result of the API, which will hold the relevant issues.
        """
        query_params = assign_params(
            jql=jql_query,
            startAt=start_at,
            maxResults=max_results,
        )
        return self.http_request(
            method='GET',
            url_suffix=f'{self.AGILE_API_ENDPOINT}/board/{board_id}/backlog',
            params=query_params
        )

    def get_issues_from_board(self, board_id: str, jql_query: str | None = None,
                              start_at: int | None = None, max_results: int | None = None) -> Dict[str, Any]:
        """This method is in charge of returning issues from a specific board.

        Args:
            board_id (str): The board id
            jql_query (str | None, optional): The JQL query to filter specific issues. Defaults to None.
            start_at (int | None, optional): The starting index of the returned issues. Defaults to None.
            max_results (int | None, optional): The maximum number of issues to return per page. Defaults to None.

        Returns:
            Dict[str, Any]: The result of the API, which will hold the relevant issues.
        """
        query_params = assign_params(
            jql=jql_query,
            startAt=start_at,
            maxResults=max_results
        )
        return self.http_request(
            method='GET',
            url_suffix=f'{self.AGILE_API_ENDPOINT}/board/{board_id}/issue',
            params=query_params
        )

    def get_sprints_from_board(self, board_id: str, start_at: int | None = None,
                               max_results: int | None = None) -> Dict[str, Any]:
        """This method is in charge of returning the sprints of a specific board, if the board supports sprints.

        Args:
            board_id (str): The board id
            start_at (int | None, optional): The starting index of the returned issues. Defaults to None.
            max_results (int | None, optional): The maximum number of issues to return per page. Defaults to None.

        Returns:
            Dict[str, Any]: The result of the API, which will hold the relevant sprints.
        """
        query_params = assign_params(
            startAt=start_at,
            maxResults=max_results
        )
        return self.http_request(
            method='GET',
            url_suffix=f'{self.AGILE_API_ENDPOINT}/board/{board_id}/sprint',
            params=query_params
        )

    def get_epics_from_board(self, board_id: str, done: str, start_at: int | None = None,
                             max_results: int | None = None) -> Dict[str, Any]:
        """This method is in charge of returning the issues with issue type `epic`, of a specific board.

        Args:
            board_id (str): The board id
            done (str): _description_
            start_at (int | None, optional): The starting index of the returned issues. Defaults to None.
            max_results (int | None, optional): The maximum number of issues to return per page. Defaults to None.

        Returns:
            Dict[str, Any]: The result of the API, which will hold the relevant epic issues.
        """
        query_params = assign_params(
            startAt=start_at,
            maxResults=max_results,
            done=done
        )
        return self.http_request(
            method='GET',
            url_suffix=f'{self.AGILE_API_ENDPOINT}/board/{board_id}/epic',
            params=query_params
        )

    def issues_from_sprint_to_backlog(self, json_data: Dict[str, Any]) -> requests.Response:
        """This method is in charge of moving issues from a sprint, back to backlog of their board.

        Args:
            json_data (Dict[str, Any]): The data that is sent to the endpoint to move the issues from a sprint
            back to the backlog board.

        Returns:
            requests.Response: The raw response of the endpoint.
        """
        return self.http_request(
            method='POST',
            url_suffix=f'{self.AGILE_API_ENDPOINT}/backlog/issue',
            json_data=json_data,
            resp_type='response',
        )

    def get_boards(self, board_type: str | None = None, project_key_id: str | None = None, board_name: str | None = None,
                   start_at: int | None = None, max_results: int | None = None) -> Dict[str, Any]:
        """This method is in charge of retrieving the boards found in the Jira instance.

        Args:
            board_type (str | None, optional): Filters results to boards of the specified types. Valid values: scrum, kanban,
            simple. Defaults to None.
            project_key_id (str | None, optional): Filters results to boards that are relevant to a project. Defaults to None.
            board_name (str | None, optional): Filters results to boards that match or partially match the specified name.
            Defaults to None.
            start_at (int | None, optional): The starting index of the returned issues. Defaults to None.
            max_results (int | None, optional): The maximum number of issues to return per page. Defaults to None.

        Returns:
            Dict[str, Any]: The result of the API, which will hold the relevant boards.
        """
        query_params = assign_params(
            type=board_type,
            projectKeyOrId=project_key_id,
            name=board_name,
            startAt=start_at,
            maxResults=max_results
        )
        return self.http_request(
            method='GET',
            url_suffix=f'{self.AGILE_API_ENDPOINT}/board',
            params=query_params
        )

    def get_board(self, board_id: str) -> Dict[str, Any]:
        """This method is in charge of retrieving the board corresponding to the board_id.

        Args:
            board_id (str): The board id to retrieve.

        Returns:
            Dict[str, Any]: The result of the API, which will hold the relevant board.
        """
        return self.http_request(
            method='GET',
            url_suffix=f'{self.AGILE_API_ENDPOINT}/board/{board_id}',
        )

    def get_issues_from_sprint(self, sprint_id: str, start_at: int | None = None, max_results: int | None = None,
                               jql_query: str | None = None) -> Dict[str, Any]:
        """This method is in charge of retrieving the issues from a specific sprint.

        Args:
            sprint_id (str): The sprint id.
            start_at (int | None, optional): The starting index of the returned issues. Defaults to None.
            max_results (int | None, optional): The maximum number of issues to return per page. Defaults to None.
            jql_query (str | None, optional):  The JQL query to filter specific issues. Defaults to None.

        Returns:
            Dict[str, Any]: The result of the API, which will hold the issues of the sprint.
        """
        query_params = assign_params(
            jql=jql_query,
            startAt=start_at,
            maxResults=max_results
        )
        return self.http_request(
            method='GET',
            url_suffix=f'{self.AGILE_API_ENDPOINT}/sprint/{sprint_id}/issue',
            params=query_params
        )

    def get_sprint_issues_from_board(self, sprint_id: str, board_id: str, start_at: int | None = None,
                                     max_results: int | None = None, jql_query: str | None = None) -> Dict[str, Any]:
        """This method is in charge of retrieving the issues from a specific sprint.

        Args:
            sprint_id (str): The sprint id.
            board_id (str): The board id which holds the specified sprint.
            start_at (int | None, optional): The starting index of the returned issues. Defaults to None.
            max_results (int | None, optional): The maximum number of issues to return per page. Defaults to None.
            jql_query (str | None, optional):  The JQL query to filter specific issues. Defaults to None.

        Returns:
            Dict[str, Any]: The result of the API, which will hold the issues of the sprint.
        """
        query_params = assign_params(
            jql=jql_query,
            startAt=start_at,
            maxResults=max_results
        )
        return self.http_request(
            method='GET',
            url_suffix=f'{self.AGILE_API_ENDPOINT}/board/{board_id}/sprint/{sprint_id}/issue',
            params=query_params
        )

    def issues_to_sprint(self, sprint_id: str, json_data: Dict[str, Any]) -> requests.Response:
        """This method is in charge of moving issues to a specified sprint.

        Args:
            sprint_id (str): The sprint id where we want to move the issues to.
            json_data (Dict[str, Any]): The data that is sent to the endpoint to move the issues to a specified sprint.

        Returns:
            requests.Response: The raw response of the endpoint.
        """
        return self.http_request(
            method='POST',
            url_suffix=f'{self.AGILE_API_ENDPOINT}/sprint/{sprint_id}/issue',
            json_data=json_data,
            resp_type='response',
        )

    # Issue Fields Requests
    def get_issue_fields(self) -> List[Dict[str, Any]]:
        """This method is in charge of returning system and custom issue fields

        Returns:
            List[Dict[str, Any]]: The result of the API, which will hold the issue fields.
        """
        return self.http_request(
            method='GET', url_suffix=f'rest/api/{self.api_version}/field'
        )

    # Issue Requests
    def transition_issue(self, issue_id_or_key: str, json_data: Dict[str, Any]) -> requests.Response:
        """This method is in charge of transitioning an issue to a different status using a transition.

        Args:
            issue_id_or_key (str): The issue id or key.
            json_data (Dict[str, Any]): The data that is sent to the endpoint to transition an issue to another status.

        Returns:
            requests.Response: The raw response of the endpoint.
        """
        return self.http_request(
            method='POST',
            url_suffix=f'rest/api/{self.api_version}/issue/{issue_id_or_key}/transitions?expand=transitions.fields',
            json_data=json_data,
            resp_type='response',
        )

    def add_link(self, issue_id_or_key: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """This method is in charge of adding a link (web link) to a specific issue.

        Args:
            issue_id_or_key (str): The issue id or key.
            json_data (Dict[str, Any]): The data that is sent to the endpoint to add the web link to the issue.

        Returns:
            Dict[str, Any]: The result of the API, which will hold data about the added web link.
        """
        return self.http_request(
            method='POST',
            url_suffix=f'rest/api/{self.api_version}/issue/{issue_id_or_key}/remotelink',
            json_data=json_data,
        )

    def get_comments(self, issue_id_or_key: str, max_results: int = DEFAULT_PAGE_SIZE) -> Dict[str, Any]:
        """This method is in charge of returning the comments of a specific issue.

        Args:
            issue_id_or_key (str): The issue id or key.
            max_results (int, optional): The maximum number of comments. Defaults to DEFAULT_PAGE_SIZE (50).

        Returns:
            Dict[str, Any]: The result of the API, which will hold the comments of the issue.
        """
        query_params = {'expand': 'renderedBody', 'maxResults': max_results}
        return self.http_request(
            method='GET',
            url_suffix=f'rest/api/{self.api_version}/issue/{issue_id_or_key}/comment',
            params=query_params,
        )

    def delete_comment(self, issue_id_or_key: str, comment_id: str) -> requests.Response:
        """This method is in charge of deleting a comment from an issue.

        Args:
            issue_id_or_key (str): The issue id or key.
            comment_id (str): The id of the comment to delete.

        Returns:
            requests.Response: The raw response of the endpoint.
        """
        return self.http_request(
            method='DELETE',
            url_suffix=f'rest/api/{self.api_version}/issue/{issue_id_or_key}/comment/{comment_id}',
            resp_type='response',
        )

    def add_comment(self, issue_id_or_key: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """This method is in charge of adding a comment to an issue.

        Args:
            issue_id_or_key (str): The issue id or key.
            json_data (Dict[str, Any]): The data that is sent to the endpoint to add a comment to the issue.

        Returns:
            Dict[str, Any]: The result of the API, which will hold the newly added comment.
        """
        query_params = {'expand': 'renderedBody'}
        return self.http_request(
            method='POST',
            url_suffix=f'rest/api/{self.api_version}/issue/{issue_id_or_key}/comment',
            json_data=json_data,
            params=query_params,
        )

    def edit_comment(self, issue_id_or_key: str, comment_id: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """This method is in charge of editing a comment that is part of an issue.

        Args:
            issue_id_or_key (str): The issue id or key.
            comment_id (str): The id of the comment to edit.
            json_data (Dict[str, Any]): The data that is sent to the endpoint to edit the comment.

        Returns:
            Dict[str, Any]: The result of the API, which will hold the edited comment.
        """
        query_params = {'expand': 'renderedBody'}
        return self.http_request(
            method='PUT',
            url_suffix=f'rest/api/{self.api_version}/issue/{issue_id_or_key}/comment/{comment_id}',
            json_data=json_data,
            params=query_params,
        )

    def get_issue(self, issue_id_or_key: str = '', full_issue_url: str = '') -> Dict[str, Any]:
        """This method is in charge of returning a specific issue.

        Args:
            issue_id_or_key (str, optional): The id or key of the issue to return. Defaults to ''.
            full_issue_url (str, optional): The full issue url, if given, it will act as the endpoint to retrieve the issue.
            Defaults to ''.

        Returns:
            Dict[str, Any]: The result of the API, which will hold issue.
        """
        query_params = {'expand': 'renderedFields,transitions,names'}
        return self.http_request(
            method='GET',
            url_suffix=f'rest/api/{self.api_version}/issue/{issue_id_or_key}',
            params=query_params,
            full_url=full_issue_url,
        )

    def edit_issue(self, issue_id_or_key: str, json_data: Dict[str, Any]) -> requests.Response:
        """This method is in charge of editing a specific issue.

        Args:
            issue_id_or_key (str): The id or key of the issue to edit.
            json_data (Dict[str, Any]): The data that is sent to the endpoint to edit the issue,
            which will hold the information about the issue fields we want to edit.

        Returns:
            requests.Response: The raw response of the endpoint.
        """
        return self.http_request(
            method='PUT',
            url_suffix=f'rest/api/{self.api_version}/issue/{issue_id_or_key}',
            json_data=json_data,
            resp_type='response',
        )

    def delete_issue(self, issue_id_or_key: str) -> requests.Response:
        """This method is in charge of deleting a specific issue.

        Args:
            issue_id_or_key (str): The id or the key of the issue to delete.

        Returns:
            requests.Response: The raw response of the endpoint.
        """
        query_params = {'deleteSubtasks': 'true'}
        return self.http_request(
            method='DELETE',
            url_suffix=f'rest/api/{self.api_version}/issue/{issue_id_or_key}',
            params=query_params,
            resp_type='response',
        )

    def get_create_metadata_issue_types(self, project_id_or_key: str, start_at: int = 0, max_results: int = 50) -> Dict[str, Any]:
        """This method is in charge of returning the issue types for a project.

        Args:
            project_id_or_key (str): The id or key of the project to return.
            start_at (int, optional): The starting index of the returned issues. Defaults to None.
            max_results (int, optional): The maximum number of issues to return per page. Defaults to None.

        Returns:
            Dict[str, Any]: The result of the API, which will hold the issue types.
        """

        query_params = assign_params(
            startAt=start_at,
            maxResults=max_results
        )

        return self.http_request(
            method="GET",
            url_suffix=f"rest/api/{self.api_version}/issue/createmeta/{project_id_or_key}/issuetypes",
            params=query_params
        )

    def get_create_metadata_field(self, project_id_or_key: str, issue_type_id: str, start_at: int = 0,
                                  max_results: int = 50) -> Dict[str, Any]:
        """This method is in charge of returning the fields for a project issue type.

        Args:
            project_id_or_key (str): The id or key of the project to return.
            issue_type_id (str): The id of the issue type.
            start_at (int, optional): The starting index of the returned issues. Defaults to None.
            max_results (int, optional): The maximum number of issues to return per page. Defaults to None.

        Returns:
            Dict[str, Any]: The result of the API, which will hold the fields.
        """

        query_params = assign_params(
            startAt=start_at,
            maxResults=max_results
        )

        return self.http_request(
            method="GET",
            url_suffix=f"rest/api/{self.api_version}/issue/createmeta/{project_id_or_key}/issuetypes/{issue_type_id}",
            params=query_params
        )

    def update_assignee(self, issue_id_or_key: str, assignee_body: Dict[str, Any]) -> requests.Response:
        """This method is in charge of assigning an assignee to a specific issue.

        Args:
            issue_id_or_key (str): The id or the key of the issue to delete.
            assignee_body (Dict[str, Any]): Dictionary containing assignee_id / assignee

        Returns:
            requests.Response: The raw response of the endpoint.
        """
        return self.http_request(
            method='PUT',
            url_suffix=f'rest/api/{self.api_version}/issue/{issue_id_or_key}/assignee',
            json_data=assignee_body,
            resp_type="response"
        )

    def get_transitions(self, issue_id_or_key: str) -> Dict[str, Any]:
        """This method is in charge of returning the available transitions of a specific issue.

        Args:
            issue_id_or_key (str): The issue id or key.

        Returns:
            Dict[str, Any]: The result of the API, which will hold available transitions.
        """
        return self.http_request(
            method='GET',
            url_suffix=f'rest/api/{self.api_version}/issue/{issue_id_or_key}/transitions',
        )

    def create_issue(self, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """This method is in charge of creating a new issue.

        Args:
            json_data (Dict[str, Any]): The data that is sent to the endpoint to create the issue.

        Returns:
            Dict[str, Any]: The results of the API, which will hold the newly created issue.
        """
        return self.http_request(
            method='POST', url_suffix=f'rest/api/{self.api_version}/issue', json_data=json_data
        )

    def get_epic_issues(self, epic_id_or_key: str, start_at: int | None = None, max_results: int | None = None,
                        jql_query: str | None = None) -> Dict[str, Any]:
        """This method is in charge of returning the issues that belong to a specific epic issue.

        Args:
            epic_id_or_key (str): The id or key of the epic issue.
            start_at (int | None, optional): The starting index of the returned issues. Defaults to None.
            max_results (int | None, optional): The maximum number of issues to return per page. Defaults to None.
            jql_query (str | None, optional): The JQL query to filter specific issues. Defaults to None.

        Returns:
            Dict[str, Any]: The results of the API, which will hold the issues that belong to the epic issue.
        """
        query_params = assign_params(
            jql=jql_query,
            startAt=start_at,
            maxResults=max_results
        )
        return self.http_request(
            method='GET',
            url_suffix=f'{self.AGILE_API_ENDPOINT}/epic/{epic_id_or_key}/issue',
            params=query_params
        )

    def get_issue_link_types(self) -> Dict[str, Any]:
        """This method is in charge of returning a list of all issue link types.

        Returns:
            Dict[str, Any]: The results of the API, which will hold the issue link types.
        """
        return self.http_request(
            method='GET',
            url_suffix=f'rest/api/{self.api_version}/issueLinkType',
        )

    def create_issue_link(self, json_data: Dict[str, Any]) -> requests.Response:
        """This method is in charge of creating an issue link between two issues.

        Args:
            json_data (Dict[str, Any]): The data that is sent to the endpoint to create the issue link.

        Returns:
            requests.Response: The raw response of the endpoint.
        """
        return self.http_request(
            method='POST',
            url_suffix=f'rest/api/{self.api_version}/issueLink',
            json_data=json_data,
            resp_type='response'
        )

    # Attachments Requests
    def upload_attachment(self, issue_id_or_key: str, files: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
        """This method is in charge of uploading an attachment to an issue.

        Args:
            issue_id_or_key (str): The issue id or key.
            files (Dict[str, Any] | None, optional): The data of the attachment to upload. Defaults to None.

        Returns:
            List[Dict[str, Any]]: The results of the API, which will hold the newly added attachment.
        """
        headers = {
            'X-Atlassian-Token': 'no-check',
        }
        return self.http_request(
            method='POST',
            url_suffix=f'rest/api/{self.api_version}/issue/{issue_id_or_key}/attachments',
            files=files,
            headers=headers,
        )

    def get_attachment_metadata(self, attachment_id: str) -> Dict[str, Any]:
        """This method is in charge of returning the metadata for an attachment.

        Args:
            attachment_id (str): The attachment id.

        Returns:
            Dict[str, Any]: The results of the API, which will hold the metadata of the attachment.
        """
        return self.http_request(
            method='GET', url_suffix=f'rest/api/{self.api_version}/attachment/{attachment_id}'
        )

    def delete_attachment_file(self, attachment_id: str):
        """This method is in charge of deleting an attached file.

        Args:
            attachment_id (str): The id of the attachment file.

        Returns:
            requests.Response: The raw response of the endpoint.
        """
        return self.http_request(
            method='DELETE',
            url_suffix=f'rest/api/{self.api_version}/attachment/{attachment_id}',
            resp_type='response',
        )

    @abstractmethod
    def get_attachment_content(self, attachment_id: str = '', attachment_content_url: str = '') -> str:
        """This method is in charge of returning the content for an attachment.

        Args:
            attachment_id (str): The attachment id, this is used to retrieve
            the content of the attachment on Jira Cloud. Default value is an empty string.
            attachment_content_url (str): The url of the attachment's content, this is used to retrieve
            the content of the attachment on Jira OnPrem. Default value is an empty string.

        Returns:
            Dict[str, Any]: The results of the API, which will hold the content of the attachment.
        """

    # User Requests
    @abstractmethod
    def get_id_by_attribute(self, attribute: str, max_results: int) -> List[Dict[str, Any]]:
        """This method is in charge of returning a list of users that match the attribute.

        Args:
            attribute (str): The attribute that will be matched against user attributes to find relevant users.
            max_results (int): The maximum number of issues to return per page

        Returns:
            List[Dict[str, Any]]: The results of the API, which will hold the users that match the attribute.
        """

    def get_user_info(self, identifier='') -> Dict[str, Any]:
        """Gets the user from Jira via API, if no identifier is supplied
        it returns information for the user the API credentials belong to

        :param identifier: The URL parameter used to identify the user,
                           i.e. `f'key={key}'`, `f'username={username}'` or `f'accountId={accountId}'`
        :type identifier: str
        :return: The user's information as returned by the API
        :rtype: Dict[str, Any]
        """

        if identifier:
            response = self.http_request(
                method='GET',
                url_suffix=f'rest/api/{self.api_version}/user?{identifier}',
                ok_codes=[200, 404],
                resp_type='response'
            )
            if response.status_code == 404:
                return {}
            else:
                return response.json()
        else:
            return self.http_request(
                method='GET',
                url_suffix=f'rest/api/{self.api_version}/myself'
            )


class JiraCloudClient(JiraBaseClient):
    """This class inherits the JiraBaseClient class and implements the required abstract methods,
    with the addition of any required configurations and implementations of methods that are specific
    for Jira Cloud.
    """
    ATLASSIAN_AUTH_URL = 'https://auth.atlassian.com'

    def __init__(self, proxy: bool, verify: bool, client_id: str, client_secret: str,
                 callback_url: str, cloud_id: str, server_url: str, username: str, api_key: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.cloud_id = cloud_id
        self.scopes = [
            # Jira Cloud
            'read:jira-work', 'read:jira-user', 'write:jira-work',
            # Jira Software
            'write:board-scope:jira-software',
            'read:board-scope:jira-software',
            'read:issue-details:jira',
            'read:sprint:jira-software',
            'read:epic:jira-software',
            'read:jql:jira',
            'write:sprint:jira-software',
            # For refresh token
            'offline_access']
        super().__init__(proxy=proxy, verify=verify, callback_url=callback_url,
                         base_url=urljoin(server_url, cloud_id), api_version='3',
                         username=username, api_key=api_key)

    def test_instance_connection(self) -> None:
        self.get_user_info()

    def oauth_start(self) -> str:
        return self.oauth2_start(scopes=self.scopes)

    def oauth_complete(self, code: str) -> None:
        self.oauth2_retrieve_access_token(code=code)

    def oauth2_start(self, scopes: List[str]) -> str:
        """This function is in charge of returning the URL that the user will use in order to authenticate
        himself and be redirected to the callback URL in order to retrieve the authorization code.

        Args:
            scopes (List[str]): A list of the desired scopes.

        Raises:
            DemistoException: If no URL was returned from the response

        Returns:
            str: The URL that the user will use in order to authenticate
                himself
        """
        params = assign_params(audience='api.atlassian.com',
                               client_id=self.client_id,
                               scope=' '.join(scopes),  # Scopes are separated with spaces
                               redirect_uri=self.callback_url,
                               response_type='code',
                               prompt='consent')
        res_auth_url = self._http_request(method='GET',
                                          full_url=urljoin(self.ATLASSIAN_AUTH_URL, 'authorize'),
                                          params=params,
                                          resp_type='response')
        if res_auth_url.url:
            return res_auth_url.url
        raise DemistoException('No URL was returned.')

    def oauth2_retrieve_access_token(self, code: str = '', refresh_token: str = '') -> None:
        if code and refresh_token:
            # The code argument is used when the user authenticates using the authorization URL process
            # (which uses the callback URL), and the refresh_token is used when we want to authenticate the user using a
            # refresh token saved in the integration's context.
            demisto.debug('Both the code, and refresh token were given to obtain a new access token, this is not normal behavior')
            raise DemistoException('Both authorization code and refresh token were given to retrieve an'
                                   ' access token, please only provide one')
        if not (code or refresh_token):
            # If reached here, that means both the authorization code and refresh tokens were empty.
            demisto.debug('Both the code, and refresh token were not given to obtain a new access token, this could'
                          ' happen if the user deleted the integration"s context')
            raise DemistoException('No authorization code or refresh token were supplied in order to authenticate.')

        data = assign_params(
            client_id=self.client_id,
            client_secret=self.client_secret,
            code=code,
            redirect_uri=self.callback_url if code else '',  # Redirect_uri is needed only when we use an authorization code
            refresh_token=refresh_token,
            grant_type='authorization_code' if code else 'refresh_token',
        )
        res_access_token = self._http_request(
            method='POST',
            full_url=urljoin(self.ATLASSIAN_AUTH_URL, 'oauth/token'),
            data=data,
            resp_type='json',
        )
        integration_context = get_integration_context()
        new_authorization_context = {
            'token': res_access_token.get('access_token', ''),
            'scopes': res_access_token.get('scope', ''),
            # res_access_token.get('expires_in') returns the lifetime of the access token in seconds.
            'valid_until': get_current_time_in_seconds() + res_access_token.get('expires_in', 0),
            'refresh_token': res_access_token.get('refresh_token', '')
        }
        integration_context |= new_authorization_context
        set_integration_context(integration_context)

    def run_project_query(self, query_params: Dict[str, Any]) -> Dict[str, Any]:
        """Queries projects with respect to the query_params. This method is mainly used to
        retrieve the board id of a board, given its name.

        Args:
            query_params (Dict[str, Any]): The query parameters to send to the request.

        Returns:
            Dict[str, Any]: The results of the queried projects.
        """
        return self.http_request(
            method='GET', url_suffix='rest/api/3/project/search', params=query_params
        )

    def issues_to_backlog(self, board_id: str, json_data: Dict[str, Any]) -> requests.Response:
        """This method is in charge of moving issues, back to backlog of their board.

        Args:
            board_id (str): The id of the board that the issues reside in.
            json_data (Dict[str, Any]): The data that is sent to the endpoint to move the issues back to backlog.

        Returns:
            requests.Response: The raw response of the endpoint.
        """
        return self.http_request(
            method='POST',
            url_suffix=f'{self.AGILE_API_ENDPOINT}/backlog/{board_id}/issue',
            json_data=json_data,
            resp_type='response',
        )

    def issues_to_board(self, board_id: str, json_data: Dict[str, Any]) -> requests.Response:
        """This method is in charge of moving issues from backlog to board.

        Args:
            board_id (str): The id of the board that the issues reside in.
            json_data (Dict[str, Any]): The data that is sent to the endpoint to move the issues back to the
            board from the backlog.

        Returns:
            requests.Response: The raw response of the endpoint.
        """
        return self.http_request(
            method='POST',
            url_suffix=f'{self.AGILE_API_ENDPOINT}/board/{board_id}/issue',
            json_data=json_data,
            resp_type='response',
        )

    def get_attachment_content(self, attachment_id: str = '', attachment_content_url: str = '') -> str:
        return self.http_request(
            method='GET',
            url_suffix=f'rest/api/3/attachment/content/{attachment_id}',
            resp_type='content',
        )

    # User Requests
    def get_id_by_attribute(self, attribute: str, max_results: int = DEFAULT_PAGE_SIZE) -> List[Dict[str, Any]]:
        query = {'query': attribute, 'maxResults': max_results}
        return self.http_request(
            method='GET', url_suffix=f'rest/api/{self.api_version}/user/search', params=query
        )


class JiraOnPremClient(JiraBaseClient):
    """This class inherits the JiraBaseClient class and implements the required abstract methods,
    with the addition of any required configurations and implementations of methods that are specific
    for Jira OnPrem.
    """

    def __init__(self, proxy: bool, verify: bool, client_id: str, client_secret: str,
                 callback_url: str, server_url: str, username: str, api_key: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = 'WRITE'
        super().__init__(proxy=proxy, verify=verify, callback_url=callback_url,
                         base_url=f'{server_url}', api_version='2',
                         username=username, api_key=api_key)

    def oauth_start(self) -> str:
        return self.oauth2_start(scopes=self.scopes)

    def oauth2_start(self, scopes: str) -> str:
        """This function is in charge of returning the URL that the user will use in order to authenticate
        himself and be redirected to the callback URL in order to retrieve the authorization code.

        Args:
            scopes (List[str]): A list of the desired scopes.

        Raises:
            DemistoException: If no URL was returned from the response

        Returns:
            str: The URL that the user will use in order to authenticate
                himself
        """
        # Documentation on how to use the code_verifier, and the code_challenge to authenticate using
        # PKCE (Proof Key for Code Exchange)
        code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
        code_verifier = re.sub('[^a-zA-Z0-9]+', '', code_verifier)
        code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
        code_challenge = code_challenge.replace('=', '')
        integration_context = get_integration_context()
        # To start the authorization process for the user, we send them to the authorization url, including the code_challenge,
        # which was created using the code_verifier, and after retrieving the authorization code from the callback URL,
        # we need to do a POST method to the token URL, including the code_verifier that was created above, in order to
        # exchange them for the access token, therefore, we need to store the code_verifier in the integration's context
        # to use it in the second part of the authorization flow.
        new_authorization_context = {
            'code_verifier': code_verifier,
        }
        integration_context |= new_authorization_context
        set_integration_context(integration_context)
        params = assign_params(client_id=self.client_id,
                               scope=scopes,  # Scopes are separated with spaces
                               redirect_uri=self.callback_url,
                               code_challenge=code_challenge,
                               code_challenge_method='S256',
                               response_type='code')
        res_auth_url = self._http_request(method='GET',
                                          url_suffix='rest/oauth2/latest/authorize',
                                          params=params,
                                          resp_type='response')
        if res_auth_url.url:
            return res_auth_url.url
        raise DemistoException('No URL was returned.')

    def oauth_complete(self, code: str) -> None:
        self.oauth2_retrieve_access_token(code=code)

    def oauth2_retrieve_access_token(self, code: str = '', refresh_token: str = '') -> None:
        if code and refresh_token:
            # The code argument is used when the user authenticates using the authorization URL process
            # (which uses the callback URL), and the refresh_token is used when we want to authenticate the user using a
            # refresh token saved in the integration's context.
            demisto.debug('Both the code, and refresh token were given to get a new access token, this is not normal behavior')
            raise DemistoException('Both authorization code and refresh token were given to retrieve an'
                                   ' access token, please only provide one')
        if not (code or refresh_token):
            # If reached here, that means both the authorization code and refresh tokens were empty.
            demisto.debug('Both the code, and refresh token were not given to obtain a new access token, this could'
                          ' happen if the user deleted the integration"s context')
            raise DemistoException('No authorization code or refresh token were supplied in order to authenticate.')
        integration_context = get_integration_context()
        # We pop the key code_verifier, since we only want to use it when the user is authenticating using an authorization code,
        # and not a refresh token, therefore, there is no need to keep it in the integration's context throughout its lifecycle.
        code_verifier = integration_context.pop('code_verifier', '')
        data = assign_params(
            client_id=self.client_id,
            client_secret=self.client_secret,
            code_verifier=code_verifier if code else '',
            code=code,
            redirect_uri=self.callback_url if code else '',  # Redirect_uri is needed only when we use an authorization code
            refresh_token=refresh_token,
            grant_type='authorization_code' if code else 'refresh_token',
        )
        res_access_token = self._http_request(
            method='POST',
            url_suffix='rest/oauth2/latest/token',
            data=data,
            resp_type='json',
        )
        new_authorization_context = {
            'token': res_access_token.get('access_token', ''),
            'scopes': res_access_token.get('scope', ''),
            # res_access_token.get('expires_in') returns the lifetime of the access token in seconds.
            'valid_until': get_current_time_in_seconds() + res_access_token.get('expires_in', 0),
            'refresh_token': res_access_token.get('refresh_token', '')
        }
        integration_context |= new_authorization_context
        set_integration_context(integration_context)

    def test_instance_connection(self) -> None:
        self.get_user_info()

    def get_attachment_content(self, attachment_id: str = '', attachment_content_url: str = '') -> str:
        return self.http_request(
            method='GET',
            full_url=attachment_content_url,
            resp_type='content',
        )

    # User Requests

    def get_id_by_attribute(self, attribute: str, max_results: int = DEFAULT_PAGE_SIZE) -> List[Dict[str, Any]]:
        query = {'username': attribute, 'maxResults': max_results}
        return self.http_request(
            method='GET', url_suffix=f'rest/api/{self.api_version}/user/search', params=query
        )

    def get_all_projects(self) -> List[Dict[str, Any]]:
        """Returns all projects which are found in the Jira instance

        Returns:
            List[Dict[str, Any]]: A list of all the projects found in the Jira instance.
        """
        return self.http_request(
            method='GET',
            url_suffix='rest/api/2/project'
        )

    def issue_get_forms(self, issue_id: str) -> List:
        """Retrieve forms' data for a specified issue_id

        :param issue_id: Issue to pull forms for
        :type issue_id: str
        :return: The raw response and a cleaned up response
        :rtype: tuple[List, List]
        """
        response = self.http_request(
            method='GET',
            url_suffix=f'rest/proforma/api/{self.api_version}/issues/{issue_id}/forms',
            ok_codes=[200, 404],
            resp_type='response'
        )
        if response.status_code == 404:
            return []
        elif response.status_code == 200:
            return response.json()
        else:
            demisto.debug('Received unexpected response.')
            return []


class JiraIssueFieldsParser:
    """This class is in charge of parsing the issue fields returned from a response. The data of the fields are mostly
    returned as nested dictionaries, and it is not intuitive to retrieve the data of specific fields, therefore, this class
    helps the parsing process and encapsulates it in one place.
    The static methods that end with the word `context` are used to parse a specific field and return a dictionary, where
    the key is in human readable form that represents the specific field, and the value is the parsed data of that specific field.
    The issue_data: Dict[str, Any] is the full issue object that is returned from the API, which holds all the data about the
    issue.
    """

    @staticmethod
    def get_id_context(issue_data: Dict[str, Any]) -> Dict[str, str]:
        return {'Id': issue_data.get('id', '') or ''}

    @staticmethod
    def get_key_context(issue_data: Dict[str, Any]) -> Dict[str, str]:
        return {'Key': issue_data.get('key', '') or ''}

    @staticmethod
    def get_summary_context(issue_data: Dict[str, Any]) -> Dict[str, str]:
        return {'Summary': demisto.get(issue_data, 'fields.summary', '') or ''}

    @staticmethod
    def get_status_context(issue_data: Dict[str, Any]) -> Dict[str, str]:
        return {'Status': demisto.get(issue_data, 'fields.status.name', '') or ''}

    @staticmethod
    def get_priority_context(issue_data: Dict[str, Any]) -> Dict[str, str]:
        return {'Priority': demisto.get(issue_data, 'fields.priority.name', '') or ''}

    @staticmethod
    def get_project_name_context(issue_data: Dict[str, Any]) -> Dict[str, str]:
        return {'ProjectName': demisto.get(issue_data, 'fields.project.name', '') or ''}

    @staticmethod
    def get_due_date_context(issue_data: Dict[str, Any]) -> Dict[str, str]:
        return {'DueDate': demisto.get(issue_data, 'fields.duedate', '') or ''}

    @staticmethod
    def get_created_date_context(issue_data: Dict[str, Any]) -> Dict[str, str]:
        return {'Created': demisto.get(issue_data, 'fields.created', '') or ''}

    @staticmethod
    def get_labels_context(issue_data: Dict[str, Any]) -> Dict[str, List[str]]:
        return {'Labels': demisto.get(issue_data, 'fields.labels', []) or []}

    @staticmethod
    def get_last_seen_context(issue_data: Dict[str, Any]) -> Dict[str, str]:
        return {'LastSeen': demisto.get(issue_data, 'fields.lastViewed', '') or ''}

    @staticmethod
    def get_last_update_context(issue_data: Dict[str, Any]) -> Dict[str, str]:
        return {'LastUpdate': demisto.get(issue_data, 'fields.updated', '') or ''}

    @staticmethod
    def get_issue_type_context(issue_data: Dict[str, Any]) -> Dict[str, str]:
        return {'IssueType': demisto.get(issue_data, 'fields.issuetype.name', '') or ''}

    @staticmethod
    def get_ticket_link_context(issue_data: Dict[str, Any]) -> Dict[str, str]:
        return {'TicketLink': issue_data.get('self', '') or ''}

    @staticmethod
    def get_assignee_context(issue_data: Dict[str, Any]) -> Dict[str, str]:
        assignee = demisto.get(issue_data, 'fields.assignee', {}) or {}
        return {'Assignee': f'{assignee.get("displayName", "")}({assignee.get("emailAddress", "")})'
                if assignee else ''}

    @staticmethod
    def get_creator_context(issue_data: Dict[str, Any]) -> Dict[str, str]:
        creator = demisto.get(issue_data, 'fields.creator', {}) or {}
        return {'Creator': f'{creator.get("displayName", "")}({creator.get("emailAddress", "")})'
                if creator else ''}

    @staticmethod
    def get_reporter_context(issue_data: Dict[str, Any]) -> Dict[str, str]:
        reporter = demisto.get(issue_data, 'fields.reporter', {}) or {}
        return {'Reporter': f'{reporter.get("displayName", "")}({reporter.get("emailAddress", "")})'
                if reporter else ''}

    @staticmethod
    def get_description_context(issue_data: Dict[str, Any]) -> Dict[str, str]:
        # Since the description can be returned in Atlassian Document Format
        # (which holds nested dictionaries that includes the content and also metadata about it), we check if the response
        # returns the fields rendered in HTML format (by accessing the renderedFields).
        rendered_issue_fields = issue_data.get('renderedFields', {}) or {}
        description_raw: str = ''
        description_text: str
        if rendered_issue_fields:
            description_raw = rendered_issue_fields.get('description', '')
            description_text = BeautifulSoup(description_raw, features="html.parser").get_text()
        else:
            description_text = demisto.get(issue_data, 'fields.description', '') or ''
        return {'Description': description_text, "RawDescription": description_raw}

    @staticmethod
    def get_attachments_context(issue_data: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        attachments: List[Dict[str, Any]] = [
            {
                'id': attachment.get('id'),
                'filename': attachment.get('filename'),
                'created': attachment.get('created'),
                'size': attachment.get('size'),
            }
            for attachment in demisto.get(issue_data, 'fields.attachment', [])
        ]
        return {'Attachments': attachments}

    @staticmethod
    def get_subtasks_context(issue_data: Dict[str, Any]) -> Dict[str, List[Dict[str, str]]]:
        subtasks: List[Dict[str, str]] = []
        subtasks.extend(
            {
                'id': subtask.get('id', '') or '',
                'key': subtask.get('key', '') or ''
            }
            for subtask in demisto.get(issue_data, 'fields.subtasks', [])
        )
        return {'Subtasks': subtasks}

    @staticmethod
    def get_components_context(issue_data: Dict[str, Any]) -> Dict[str, List[str]]:
        components = [(component.get('name') or '') for component in (demisto.get(issue_data, 'fields.components') or [])]
        return {'Components': components}

    @staticmethod
    def get_raw_field_data_context(issue_data: Dict[str, Any], issue_field_id: str,
                                   issue_fields_id_to_name_mapping: Dict[str, str]) -> Dict[str, Any]:
        """To return the raw data (not parsed) of the field corresponding to the id issue_field_id.

        Args:
            issue_data (Dict[str, Any]): The issue response from the API.
            issue_field_id (str): The field id of the issue to return its data.
            issue_fields_id_to_name_mapping (Dict[str, str]): This holds a mapping between the IDs and display names of the
            issue fields.

        Returns:
            Dict[str, Any]: A dictionary where the key is the field id, and the value is a dictionary that holds the raw data
            of the field, and the display name of the field.
        """
        issue_field_display_name = issue_fields_id_to_name_mapping.get(issue_field_id) or ''
        return {issue_field_id: ({'issueFieldDisplayName': issue_field_display_name} if issue_field_display_name else {})
                | {'rawData': issue_data.get('fields', {}).get(issue_field_id, '') or {}}}

    # The following dictionary holds keys that represent the fields' ids, and parser methods as values for every key,
    # which is in charge or receiving the issue response from the API, and parsing the required field.
    ISSUE_FIELDS_ID_TO_CONTEXT: Dict[str, Callable] = {
        'id': get_id_context,
        'key': get_key_context,
        'summary': get_summary_context,
        'status': get_status_context,
        'priority': get_priority_context,
        'project': get_project_name_context,
        'duedate': get_due_date_context,
        'created': get_created_date_context,
        'labels': get_labels_context,
        'lastViewed': get_last_seen_context,
        'updated': get_last_update_context,
        'issuetype': get_issue_type_context,
        'self': get_ticket_link_context,
        'attachment': get_attachments_context,
        'description': get_description_context,
        'creator': get_creator_context,
        'reporter': get_reporter_context,
        'assignee': get_assignee_context,
        'components': get_components_context,
    }

    @classmethod
    def get_issue_fields_context_from_id(cls, issue_data: Dict[str, Any], issue_fields_ids: List[str],
                                         issue_fields_id_to_name_mapping: Dict[str, str]) -> Dict[str, Any]:
        """This method is in charge of receiving the issue object from the API, and parse the fields that are found
        in the constant ISSUE_FIELDS_ID_TO_CONTEXT's keys to human readable outputs, and parse the corresponding fields
        found in issue_fields_ids to show their raw data and display names, using the method get_raw_field_data_context.

        Args:
            issue_data (Dict[str, Any]): The issue response from the API, which holds the data about a specific issue.
            issue_fields_ids (List[str]): A list of ids of specific issue fields.
            issue_fields_id_to_name_mapping (Dict[str, str]): This will hold a mapping between the issue fields' ids, to their
            display names, so the display names can be displayed to the user.

        Returns:
            Dict[str, Any]: A dictionary that holds human readable mapping of the issues' fields.
        """
        issue_fields_context: Dict[str, Any] = {}
        for issue_field_id in issue_fields_ids:
            if issue_field_id in cls.ISSUE_FIELDS_ID_TO_CONTEXT:
                issue_fields_context |= cls.ISSUE_FIELDS_ID_TO_CONTEXT[issue_field_id](issue_data)
            else:
                issue_fields_context |= cls.get_raw_field_data_context(issue_data, issue_field_id,
                                                                       issue_fields_id_to_name_mapping)
        return issue_fields_context


# Utility functions
def get_project_id_from_name(client: JiraBaseClient, project_name: str) -> str:
    """Returns the project id of the project with the name project_name

    Args:
        client (JiraBaseClient): The Jira client.
        project_name (str): The project name for which we want to return the project id that corresponds
        to it.

    Raises:
        DemistoException: If no projects were found with the respective project name.
        DemistoException: If more than one project was found with the respective project name.

    Returns:
        str: The project id corresponding to the project name.
    """
    queried_projects: List[Dict[str, Any]] = []
    if isinstance(client, JiraCloudClient):
        query_params = {'query': f'{project_name}'}
        cloud_res = client.run_project_query(query_params=query_params)
        if not (queried_projects := cloud_res.get('values', [])):
            raise DemistoException(f'No projects were found with the respective project name {project_name}')
    elif isinstance(client, JiraOnPremClient):
        all_projects = client.get_all_projects()
        queried_projects = list(filter(
            lambda project: project.get('name', '').lower() == project_name.lower(),
            all_projects))
        if not (all_projects or queried_projects):
            raise DemistoException(f'No projects were found with the respective project name {project_name}')
    if len(queried_projects) > 1:
        raise DemistoException(f'Found more than one project with the name {project_name}')
    return queried_projects[0].get('id', '')


def prepare_pagination_args(page: int | None = None, page_size: int | None = None, limit: int | None = None) -> Dict[str, int]:
    """This function takes in the pagination arguments supported by XSOAR, and maps them to a corresponding pagination dictionary
    that the API supports.

    Args:
        page (int | None, optional): The page number. Defaults to None.
        page_size (int | None, optional): The page size. Defaults to None.
        limit (int | None, optional): The maximum amount of results to return. Defaults to None.

    Returns:
        Dict[str, int]: A pagination dictionary supported by the API.
    """
    # If all three arguments were given, we will only take into consideration the page and page_size case.
    if page or page_size:
        page = page or DEFAULT_PAGE
        page_size = page_size or DEFAULT_PAGE_SIZE
        return {
            'start_at': page * page_size,
            'max_results': page_size,
        }
    else:
        limit = limit or DEFAULT_PAGE_SIZE
        return {'start_at': DEFAULT_PAGE, 'max_results': limit}


def create_query_params(jql_query: str, start_at: int | None = None,
                        max_results: int | None = None) -> Dict[str, Any]:
    """Create the query parameters when issuing a query.

    Args:
        jql_query (str): The JQL query. The Jira Query Language string, used to search for issues in a project using
        SQL-like syntax.
        start_at (int | None, optional): The starting index of the returned issues. Defaults to None.
        max_results (int | None, optional): The maximum number of issues to return per page. Defaults to None.

    Returns:
        Dict[str, Any]: The query parameters to be sent when issuing a query request to the API.
    """
    start_at = start_at or 0
    max_results = max_results or DEFAULT_PAGE_SIZE
    demisto.debug(f'Querying with: {jql_query}\nstart_at: {start_at}\nmax_results: {max_results}\n')
    return {
        'jql': jql_query,
        'startAt': start_at,
        'maxResults': max_results,
    }


def get_issue_fields_id_to_name_mapping(client: JiraBaseClient) -> Dict[str, str]:
    """ Returns a dictionary that holds a mapping between the ids of the issue fields to their human readable names.
    NOTE: Might delete later.
    """
    issue_fields_res = client.get_issue_fields()
    return {
        custom_field.get('id', ''): custom_field.get('name', '')
        for custom_field in issue_fields_res
    }


def get_issue_fields_id_to_description_mapping(client: JiraBaseClient) -> Dict[str, str]:
    """ Returns a dictionary that holds a mapping between the ids of the issue fields to their description.
    """
    issue_fields_res = client.get_issue_fields()
    return {
        issue_field.get('id', ''): issue_field.get('description', '')
        for issue_field in issue_fields_res
    }


def get_current_time_in_seconds() -> float:
    """A function to return time as a float number of nanoseconds since the epoch

    Returns:
        float: Number of nanoseconds since the epoch
    """
    return time.time_ns() / (10 ** 9)


def create_files_to_upload(file_mime_type: str, file_name: str, file_bytes: bytes, attachment_name: str | None = None) -> tuple:
    """ Creates the file object to upload to Jira
        Args:
            file_mime_type (str): The mime type of the file.
            file_name (str): The name of the file.
            file_bytes(bytes): The bytes of the file.
            attachment_name (str | None): A custom attachment name, if it is empty or None then the attachment's name will be the
            same one as in XSOAR. Default is None

        Returns:
            tuple([Dict[tuple(str, bytes, str)]], str): The dift is The file object of new attachment (file name, content in
            bytes, mime type), and the str is the mime type to upload with the file.
        """
    # guess_type can return a None mime type if the type can’t be guessed (missing or unknown suffix). In this case, we should use
    # a default mime type
    mime_type_to_upload = file_mime_type if file_mime_type else guess_type(file_name)[0] or 'application-type'
    demisto.debug(f'In create_files_to_upload {mime_type_to_upload=}')
    return {'file': (attachment_name or file_name, file_bytes, mime_type_to_upload)}, mime_type_to_upload


def create_file_info_from_attachment(client: JiraBaseClient, attachment_id: str, file_name: str = '') -> Dict[str, Any]:
    """Create an XSOAR file entry to return to the server.

    Args:
        client (JiraBaseClient): The Jira client, which will be used to fetch the content of the attachment.
        attachment_id (str): The attachment id.
        file_name (str, optional): The file name of the attachment. Defaults to ''.

    Returns:
        Dict[str, Any]: An XSOAR file entry.
    """
    attachment_file_name = file_name
    if not attachment_file_name:
        res_attachment_metadata = client.get_attachment_metadata(attachment_id=attachment_id)
        attachment_file_name = res_attachment_metadata.get('filename', '')
    res_attachment_content = client.get_attachment_content(
        attachment_id=attachment_id if isinstance(client, JiraCloudClient) else '',
        attachment_content_url=res_attachment_metadata.get('content', '') if isinstance(client, JiraOnPremClient) else '')
    return fileResult(filename=attachment_file_name, data=res_attachment_content, file_type=EntryType.ENTRY_INFO_FILE)


def create_fields_dict_from_dotted_string(issue_fields: Dict[str, Any], dotted_string: str, value: Any) -> Dict[str, Any]:
    """Create a nested dictionary from keys separated by dots(.), and insert the value as part of the last key in the dotted
    string.
    For example, dotted_string=key1.key2.key3 with value=jira results in {key1: {key2: {key3: jira}}}
    This function is used to create the dictionary that will be sent when creating a new Jira issue. Let us look at the following
    scenario, we get that we want to enter a value of `Dummy summary` for the dotted field `field.summary`, which will result
    in {field: {summary: Dummy summary}}, but since we might have already created issue fields, for instance, we already added to
    it the field label -> {fields: {labels: [dummy_label]}}, we pass the issue_fields argument so we can update what we have
    already inserted, so when we come to add the new field that we want, the issue_fields will
    be {fields: {labels: [dummy_label]}, {summary: Dummy summary}}, therefore we pass it to the function so we can insert the new
    fields without overriding the previous iterations.
    Args:
        dotted_string (str): A dotted string that holds the keys of the dictionary
        value (Any): The value to insert in the nested dictionary
    """
    if not dotted_string:
        return {}
    nested_dict: Dict[str, Any] = {}
    keys = dotted_string.split(".")
    for count, sub_key in enumerate(keys[::-1]):
        inner_dict = demisto.get(issue_fields, '.'.join(keys[: len(keys) - count]), defaultdict(dict))
        if count == 0:
            inner_dict[sub_key] = value
        else:
            inner_dict = {sub_key: inner_dict | nested_dict}
        nested_dict = inner_dict
    return nested_dict


def create_issue_fields(client: JiraBaseClient, issue_args: Dict[str, str],
                        issue_fields_mapper: Dict[str, str]) -> Dict[str, Any]:
    """This will create the issue fields object that will be sent to the API in order to create/edit a Jira issue.

    Args:
        client (JiraBaseClient): The Jira client, which is necessary since constructing the data that will be sent to
        the API endpoint can vary, according to the Jira instance.
        issue_args (Dict[str, str]): The issue arguments supplied by the user
        issue_fields_mapper (Dict[str, str]): A mapper that will map between the issue fields arguments that are supplied by
        the user, and the path of them in the issue fields object when creating a new issue, in dotted string format,
        for reference, look at the ISSUE_FIELDS_CREATE_MAPPER constant in JiraBaseClient

    Raises:
        DemistoException: If the issue_json that is supplied is not in valid json format.

    Returns:
        Dict[str, Any]: The issue fields object to send to the API, to create/edit a new Jira issue.
    """
    issue_fields: Dict[str, Any] = defaultdict(dict)
    if 'issue_json' in issue_args:
        try:
            return json.loads(issue_args['issue_json'], strict=False)
        except TypeError as e:
            demisto.debug(str(e))
            raise DemistoException('issue_json must be in a valid json format') from e

    for issue_arg, value in issue_args.items():
        parsed_value: Any = ''  # This is used to hold any parsed arguments passed from the user, e.g the labels
        # argument is provided as a string in CSV format, and the API expects to receive a list of labels.
        if issue_arg == 'labels':
            parsed_value = argToList(value)
        elif issue_arg == 'components':
            parsed_value = [{"name": component} for component in argToList(value)]
        elif issue_arg in ['description', 'environment']:
            parsed_value = text_to_adf(value) if isinstance(client, JiraCloudClient) else value
        elif not (isinstance(value, dict | list)):
            # If the value is not a list or a dictionary, we will try to parse it as a json object.
            try:
                parsed_value = json.loads(value)
            except (json.JSONDecodeError, TypeError):
                pass    # Some values should not be in a JSON format so it makes sense for them to fail parsing.
        dotted_string = issue_fields_mapper.get(issue_arg, '')
        if not dotted_string and issue_arg.startswith('customfield'):
            # This is used to deal with the case when the user creates a custom incident field, using
            # the custom fields of Jira.
            dotted_string = f'fields.{issue_arg}'

        issue_fields |= create_fields_dict_from_dotted_string(
            issue_fields=issue_fields, dotted_string=dotted_string, value=parsed_value or value)
    return issue_fields


def create_issue_fields_for_appending(client: JiraBaseClient, issue_args: Dict[str, Any],
                                      issue_id_or_key: str) -> Dict[str, Any]:
    """This will create the issue fields object that will be sent to the API in order append data to the Jira issue.
    We first fetch the issue fields of the Jira issue that we want to edit, and append the data to the specified fields.
    We only support appending to fields that are either strings, or arrays.
    If the supplied argument is of type string, then the new appended value will be: "old data, new data", where they will
    be separated by a comma.

    Args:
        client (JiraBaseClient): The Jira client
        issue_args (Dict[str, Any]): The issue arguments supplied by the user
        issue_id_or_key (str): The issue ID or key.

    Raises:
        DemistoException: If the supplied argument is not a string or an array.

    Returns:
        Dict[str, Any]: The issue fields object to send to the API, to edit the Jira issue.
    """
    issue_fields = create_issue_fields(client=client, issue_args=issue_args,
                                       issue_fields_mapper=client.ISSUE_FIELDS_CREATE_MAPPER).get('fields', {})
    current_issue_fields = client.get_issue(issue_id_or_key=issue_id_or_key).get('fields', {})
    for issue_field, value in issue_fields.items():
        if isinstance(value, str):
            # We append strings using a comma (,)
            issue_fields[issue_field] = f'{current_issue_fields.get(issue_field, "")}, {value}'
        elif isinstance(value, list):
            # We also support appending lists
            issue_fields[issue_field] = current_issue_fields.get(issue_field, []) + value
        else:
            raise DemistoException(
                'Only strings and arrays support appending when editing an issue,'
                f' the field that caused this error is "{issue_field}", of type {type(value)}')
    return {'fields': issue_fields}


def extract_issue_id_from_comment_url(comment_url: str) -> str:
    """This function will extract the issue id using the comment url.
    For example: https://your-domain.atlassian.net/rest/api/3/issue/10010/comment/10000, the issue id
    can be found between the issue and comment path (issue/{issue_id}/comment/{comment_id})

    Args:
        comment_url (str): The comment url that will hold the issue id which the comment belongs to

    Returns:
        str: The issue id if found, otherwise, an empty string
    """
    if issue_id_search := re.search(r'issue/(\d+)/comment', comment_url):
        return issue_id_search.group(1)
    return ''


def text_to_adf(text: str) -> Dict[str, Any]:
    """This function receives a text and converts the text to Atlassian Document Format (ADF),
    which is used in order to send data to the API (such as, summary, content, when creating an issue for instance).
    This format is only currently used for Jira Cloud.

    Args:
        text (str): A text to convert to ADF.

    Returns:
        Dict[str, Any]: An ADF object (dictionary).
    """
    return {
        'type': 'doc',
        'version': 1,
        'content': [{
            'type': 'paragraph',
            'content': [{
                'text': text,
                'type': 'text'
            }]
        }]
    }


def get_specific_fields_ids(issue_data: Dict[str, Any], specific_fields: List[str],
                            issue_fields_id_to_name_mapping: Dict[str, str]) -> List[str]:
    """This function is in charge of returning the ids of the issue fields that are specified in the
    specific_fields argument, which can hold the display name OR the id of the issue field. This will
    help map the issue fields (whether their display names or ids) that the user enters, to their respective id, so it
    can be further processed if needed.

    Args:
        issue_data (Dict[str, Any]): The issue object returned from the API.
        specific_fields (List[str]): The specific fields for which to return their respective ids. (They can either be the
        display name or id of the issue field)
        issue_fields_id_to_name_mapping (Dict[str, str]): A dictionary that holds mapping between ids and display names of the
        issue fields.

    Returns:
        List[str]: A list of the issue fields' ids, corresponding to the issue fields specified in specific_fields.
    """
    if 'all' in specific_fields:
        # By design, if the user enters `all`, then we return the ids of all the issue fields.
        all_issue_fields_ids: List[str] = list(issue_data.get('fields', {}).keys())
        if 'comment' in all_issue_fields_ids:
            # Since the `comment` field needs further parsing, it is advised that the user calls the command
            # !jira-get-comments if they want the content of the comments.
            all_issue_fields_ids.remove('comment')
        return ['id', 'key', 'self', *all_issue_fields_ids]
    # To support display names in upper and lower case from the user
    issue_fields_name_to_id_mapping = {issue_name.lower(): issue_id for issue_id,
                                       issue_name in issue_fields_id_to_name_mapping.items()}
    issue_fields_ids: List[str] = []
    wrong_issue_fields_ids: List[str] = []
    for specific_field in specific_fields:
        if specific_field in issue_fields_id_to_name_mapping:
            # This means an id was given
            issue_fields_ids.append(specific_field)
        elif issue_id := issue_fields_name_to_id_mapping.get(specific_field.lower(), ''):
            # This means a display name was given, and we mapped it to its respective id
            issue_fields_ids.append(issue_id)
        else:
            # This means the given issue field given was not found
            wrong_issue_fields_ids.append(specific_field)
    warning_message = ''
    if 'comment' in issue_fields_ids:
        # If the user entered the issue field `comment`, we will return a warning stating which command yields the comments
        warning_message = 'In order to retrieve the comments of the issue, please run the command `!jira-get-comments`\n'
        # We loop over the ids and remove all occurrences of the field id `comment`, since the user can by accident enter
        # id `comment` multiple times
        for issue_field_id in issue_fields_ids:
            if issue_field_id == 'comment':
                issue_fields_ids.remove(issue_field_id)
    if wrong_issue_fields_ids:
        issue_key = issue_data.get('key', '') or ''
        warning_message += f'The field/s [{",".join(wrong_issue_fields_ids)}] was/were not found for issue {issue_key}\n'
    if warning_message:
        return_warning(warning_message)
    return issue_fields_ids


def create_issue_md_and_outputs_dict(issue_data: Dict[str, Any],
                                     specific_issue_fields: List[str] | None = None,
                                     issue_fields_id_to_name_mapping: Dict[str, str] | None = None
                                     ) -> tuple[Dict[str, Any], Dict[str, Any]]:
    """Creates the markdown and outputs dictionaries (context outputs) of the issue object that is returned from the API,
    to return to the user.

    Args:
        issue_data (Dict[str, Any]): The issue object that holds data about the Jira issue that is returned from the API.
        specific_issue_fields (List[str] | None, optional): Specific issue fields to parse their data, in addition to the default
        fields configured in this function. Defaults to None.
        issue_fields_id_to_name_mapping (Dict[str, str] | None, optional): The dictionary that holds the mapping between
        the fields' ids to their display names. Defaults to None.

    Returns:
        tuple[Dict[str, Any], Dict[str, Any]]: A tuple where the first entry is the markdown dictionary, and the second is the
        context outputs dictionary.
    """
    md_and_outputs_shared_issue_keys = ['id', 'key', 'summary', 'status', 'priority', 'project', 'duedate',
                                        'created', 'labels', 'assignee', 'creator',
                                        'description']
    issue_fields_id_to_name_mapping = issue_fields_id_to_name_mapping or {}
    issue_fields_ids = get_specific_fields_ids(issue_data=issue_data, specific_fields=specific_issue_fields or [],
                                               issue_fields_id_to_name_mapping=issue_fields_id_to_name_mapping)
    # The `*` is used to unpack the content of a list into another list.
    context_outputs = JiraIssueFieldsParser.get_issue_fields_context_from_id(
        issue_data=issue_data, issue_fields_ids=['lastViewed', 'updated', 'attachment', 'components',
                                                 *md_and_outputs_shared_issue_keys,
                                                 *issue_fields_ids],
        issue_fields_id_to_name_mapping=issue_fields_id_to_name_mapping)
    markdown_dict = JiraIssueFieldsParser.get_issue_fields_context_from_id(
        issue_data=issue_data, issue_fields_ids=['issuetype', 'self', 'reporter',
                                                 *md_and_outputs_shared_issue_keys],
        issue_fields_id_to_name_mapping=issue_fields_id_to_name_mapping)

    return markdown_dict, context_outputs


def is_issue_id(issue_id_or_key: str) -> bool:
    """
    Checks if the identifier supplied by the user is an ID or Key. (IDs are made up of numeric characters)
    """
    return issue_id_or_key.isnumeric()


def get_file_name_and_content(entry_id: str) -> tuple[str, bytes]:
    """Returns the XSOAR file entry's name and content.

    Args:
        entry_id (str): The entry id inside XSOAR.

    Returns:
        Tuple[str, bytes]: A tuple, where the first value is the file name, and the second is the
        content of the file in bytes.
    """
    get_file_path_res = demisto.getFilePath(entry_id)
    file_path = get_file_path_res.get('path')
    file_name = get_file_path_res.get('name')
    file_bytes: bytes = b''
    with open(file_path, 'rb') as f:
        file_bytes = f.read()
    return file_name, file_bytes


def apply_issue_status(client: JiraBaseClient, issue_id_or_key: str, status_name: str,
                       issue_fields: dict[str, Any]) -> requests.Response:
    """This function is in charge of receiving a status of an issue and try to apply it, if it can't, it will throw an error.

    Args:
        client (JiraBaseClient): The Jira client.
        issue_id_or_key (str): The issue id or key.
        status_name (str): The name of the status to transition to.
        issue_fields (dict[str, Any]): Other issue fields to edit while applying the status.

    Raises:
        DemistoException: If the given status name was not found or not valid.

    Returns:
        Any: Raw response of the API request.
    """
    res_transitions = client.get_transitions(issue_id_or_key=issue_id_or_key)
    all_transitions = res_transitions.get('transitions', [])
    statuses_name = [transition.get('to', {}).get('name', '') for transition in all_transitions]
    for i, status in enumerate(statuses_name):
        if status.lower() == status_name.lower():
            json_data = {'transition': {"id": str(all_transitions[i].get('id', ''))}} | issue_fields
            return client.transition_issue(
                issue_id_or_key=issue_id_or_key, json_data=json_data
            )
    raise DemistoException(f'Status "{status_name}" not found. \nValid statuses are: {statuses_name} \n')


def apply_issue_transition(client: JiraBaseClient, issue_id_or_key: str, transition_name: str,
                           issue_fields: dict[str, Any]) -> requests.Response:
    """In charge of receiving a transition to perform on an issue and try to apply it, if it can't, it will throw an error.

    Args:
        client (JiraBaseClient): The Jira client.
        issue_id_or_key (str): The issue id or key.
        transition_name (str): The name of the transition to apply.
        issue_fields (dict[str, Any]): Other issue fields to edit while applying the transition.

    Raises:
        DemistoException: If the given transition was not found or not valid.

    Returns:
        Any: Raw response of the API request.
    """
    res_transitions = client.get_transitions(issue_id_or_key=issue_id_or_key)
    all_transitions = res_transitions.get('transitions', [])
    transitions_name = [transition.get('name', '') for transition in all_transitions]
    for i, transition in enumerate(transitions_name):
        if transition.lower() == transition_name.lower():
            json_data = {'transition': {"id": str(all_transitions[i].get('id', ''))}} | issue_fields
            return client.transition_issue(
                issue_id_or_key=issue_id_or_key, json_data=json_data
            )
    raise DemistoException(f'Transition "{transition_name}" not found. \nValid transitions are: {transitions_name} \n')


def get_issue_forms(client: JiraOnPremClient, issue_id: str) -> tuple[List, List]:
    """Gets the forms from the client and processes them into a usable JSON format.

    :param client: Client to make the API call with
    :type client: JiraOnPremClient
    :param issue_id: Issue ID to get the forms for
    :type issue_id: str
    :return: The raw JSON response and the formatted outputs
    :rtype: tuple[List, List]
    """
    try:
        response = client.issue_get_forms(issue_id=issue_id)
    except Exception as e:
        raise DemistoException(f"Forms fetching exception {str(e)}")

    demisto.debug('Finished getting forms.')
    outputs = []

    for form in response:
        demisto.debug(f'FORMS - Running on {form}')

        questions = []
        for question_id, question_data in form.get('design', {}).get('questions').items():
            answer = form.get('state', {}).get('answers', {}).get(question_id)
            name = form.get('design', {}).get('settings', {}).get('name')
            # Get choice details if the answer type was a choice
            if answer and answer.get('choices', ''):
                final_answer: Dict[str, Any] = {
                    'choices': []
                }
                choices = question_data.get('choices')
                for choice in choices:
                    for answer_choice in answer.get('choices'):
                        if answer_choice == choice.get('id'):
                            final_answer.get('choices').append(choice)  # type: ignore[union-attr]
            elif answer:
                final_answer = answer
            else:  # Not all questions are required to be answered.
                final_answer = {}

            questions.append({
                'ID': question_id,
                'Label': question_data.get('label'),
                'Type': question_data.get('type'),
                'Description': question_data.get('description'),
                'Key': question_data.get('questionKey'),
                'Answer': final_answer,
            })
        outputs.append({
            'ID': form.get('id'),
            'Name': name,
            'Issue': issue_id,
            'Questions': questions
        })
    return response, outputs


# Issues Commands
def add_link_command(client: JiraBaseClient, args: Dict[str, str]) -> CommandResults:
    """This command is in charge of adding a link (web url) to a Jira issue.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, str]): The arguments supplied by the user.

    Raises:
        DemistoException: If neither an issue id nor a key was supplied.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    issue_id_or_key = get_issue_id_or_key(issue_id=args.get('issue_id', ''),
                                          issue_key=args.get('issue_key', ''))
    url = args.get('url', '')
    title = args.get('title', '')
    summary = args.get('summary', '')
    global_id = args.get('global_id', '')
    relationship = args.get('relationship', '')
    application_type = args.get('application_type', '')
    application_name = args.get('application_name', '')
    link: Dict[str, Any] = defaultdict(dict)  # This is used to make sure that when we try to access or modify a missing key,
    # then defaultdict will automatically create the key and generate a default value for it (in our case, an empty dictionary)
    link['object'] = {
        'url': url,
        'title': title
    }
    link |= assign_params(
        summary=summary,
        globalId=global_id,
        relationship=relationship,
    )
    if application_type:
        link['application']['type'] = application_type
    if application_name:
        link['application']['name'] = application_name
    res = client.add_link(issue_id_or_key=issue_id_or_key, json_data=link)
    markdown_dict = {
        'id': res.get('id', ''),
        'key': demisto.get(res, 'updateAuthor.key'),
        'comment': res.get('body', ''),
        'ticket_link': res.get('self', '')
    }
    human_readable = tableToMarkdown(name='Remote Issue Link', t=markdown_dict, removeNull=True)

    return CommandResults(readable_output=human_readable, raw_response=res)


def issue_query_command(client: JiraBaseClient, args: Dict[str, str]) -> List[CommandResults] | CommandResults:
    """This command is in charge of issuing a query on issues.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, str]): The arguments supplied by the user.

    Returns:
        List[CommandResults] | CommandResults: CommandResults to return to XSOAR.
    """
    jql_query = args.get('query', '')
    start_at = arg_to_number(args.get('start_at', ''))
    max_results = arg_to_number(args.get('max_results', DEFAULT_PAGE_SIZE)) or DEFAULT_PAGE_SIZE
    headers = args.get('headers', '')
    specific_fields = argToList(args.get('fields', ''))
    query_params = create_query_params(jql_query=jql_query, start_at=start_at, max_results=max_results)
    res = client.run_query(query_params=query_params)
    if issues := res.get('issues', []):
        issue_fields_id_to_name_mapping = res.get('names', {}) or {}
        command_results: List[CommandResults] = []
        for issue in issues:
            markdown_dict, outputs = create_issue_md_and_outputs_dict(
                issue_data=issue, specific_issue_fields=specific_fields,
                issue_fields_id_to_name_mapping=issue_fields_id_to_name_mapping)
            command_results.append(
                CommandResults(
                    outputs_prefix='Ticket',
                    outputs=outputs,
                    outputs_key_field='Id',
                    readable_output=tableToMarkdown(name=f'Issue {outputs.get("Key", "")}', t=markdown_dict,
                                                    headers=argToList(headers),
                                                    headerTransform=pascalToSpace),
                    raw_response=issue
                ),
            )
        return command_results
    return CommandResults(readable_output='No issues matched the query.')


def get_issue_command(client: JiraBaseClient, args: Dict[str, str]) -> List[CommandResults]:
    """This command is in charge of returning the data of a specific issue.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, str]): The arguments supplied by the user.

    Raises:
        DemistoException: If neither an issue id nor a key was supplied.

    Returns:
        List[CommandResults]: CommandResults to return to XSOAR.
    """
    issue_id_or_key = get_issue_id_or_key(issue_id=args.get('issue_id', ''),
                                          issue_key=args.get('issue_key', ''))
    headers = args.get('headers', '')
    get_attachments = argToBoolean(args.get('get_attachments', False))
    expand_links = argToBoolean(args.get('expand_links', False))
    specific_fields = argToList(args.get('fields', ''))
    res = client.get_issue(issue_id_or_key=issue_id_or_key)
    responses: List[Dict[str, Any]] = [res]
    responses.extend(get_expanded_issues(client=client, issue=res,
                                         expand_links=expand_links))
    command_results: List[CommandResults] = []
    if get_attachments:
        download_issue_attachments_to_war_room(client=client, issue=res)
    for response in responses:
        markdown_dict, outputs = create_issue_md_and_outputs_dict(issue_data=response, specific_issue_fields=specific_fields,
                                                                  issue_fields_id_to_name_mapping=response.get('names', {}) or {})
        command_results.append(
            CommandResults(
                outputs_prefix='Ticket',
                outputs=outputs,
                outputs_key_field='Id',
                readable_output=tableToMarkdown(name=f'Issue {outputs.get("Key", "")}', t=markdown_dict,
                                                headers=argToList(headers),
                                                headerTransform=pascalToSpace),
                raw_response=response
            ))
    return command_results


def get_create_metadata_issue_types_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
    """This command is in charge of returning the metadata of a specific project.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, str]): The arguments supplied by the user.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    project_id_or_key = args.get('project_id_or_key', '')
    start_at = args.get('start_at', 0)
    max_results = args.get('max_results', 50)

    if not project_id_or_key:
        raise ValueError("No project_id_or_key specified for jira-create-metadata-issue-types-list")

    res = client.get_create_metadata_issue_types(
        project_id_or_key=project_id_or_key,
        start_at=start_at,
        max_results=max_results
    )

    outputs = []
    for result in res.get('values', []):
        outputs.append(
            {
                "AvatarID": result.get('avatarId'),
                "Description": result.get('description'),
                "EntityID": result.get('entityId'),
                "Expand": result.get('expand'),
                "IconURL": result.get('iconUrl'),
                "ID": result.get('id'),
                "Name": result.get('name'),
                "Self": result.get('self'),
                "Subtask": result.get('subtask'),
                "Scope": result.get('scope'),
            }
        )

    command_results = CommandResults(
        outputs_prefix="Jira.IssueType",
        outputs=outputs,
        outputs_key_field="ID",
        raw_response=res,
        readable_output=tableToMarkdown(
            name=f"Issue types for project {project_id_or_key}",
            t=outputs,
            headerTransform=pascalToSpace,
            removeNull=True
        )
    )

    return command_results


def get_create_metadata_field_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
    """This command is in charge of returning the field metadata of a specific project and issue type.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, str]): The arguments supplied by the user.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    project_id_or_key = args.get('project_id_or_key', '')
    issue_type_id = args.get('issue_type_id', '')
    start_at = args.get('start_at', 0)
    max_results = args.get('max_results', 50)

    if not project_id_or_key:
        raise ValueError("No project_id_or_key specified for jira-create-metadata-field-list")

    if not issue_type_id:
        raise ValueError("No issue_type_id specified for jira-create-metadata-field-list")

    res = client.get_create_metadata_field(
        project_id_or_key=project_id_or_key,
        issue_type_id=issue_type_id,
        start_at=start_at,
        max_results=max_results
    )

    outputs = []
    for result in res.get('values', []):
        outputs.append(
            {
                "AllowedValues": result.get('allowedValues'),
                "AutoCompleteURL": result.get('autoCompleteUrl'),
                "Configuration": result.get('configuration'),
                "DefaultValue": result.get('defaultValue'),
                "FieldID": result.get('fieldId'),
                "HasDefaultValue": result.get('hasDefaultValue'),
                "Key": result.get('key'),
                "Operations": result.get('operations'),
                "Required": result.get('required'),
                "Schema": result.get('schema'),
                "Name": result.get('name'),
            }
        )

    command_results = CommandResults(
        outputs_prefix="Jira.IssueField",
        outputs=outputs,
        outputs_key_field="FieldID",
        raw_response=res,
        readable_output=tableToMarkdown(
            name=f"Issue fields for project {project_id_or_key} and issue type {issue_type_id}",
            t=outputs,
            headerTransform=pascalToSpace,
            removeNull=True
        )
    )

    return command_results


def download_issue_attachments_to_war_room(client: JiraBaseClient, issue: Dict[str, Any]) -> None:
    """Downloads the attachments of an issue to the War Room.

    Args:
        client (JiraBaseClient): The Jira client
        issue (Dict[str, Any]): The issue to retrieve and download its attachments
        get_attachments (bool, optional): Whether to download the attachments or not. Defaults to False.
    """
    for attachment in demisto.get(issue, 'fields.attachment', []):
        return_results(create_file_info_from_attachment(client=client, attachment_id=attachment.get('id')))


def get_expanded_issues(client: JiraBaseClient, issue: Dict[str, Any],
                        expand_links: bool = False) -> List[Dict[str, Any]]:
    """Returns a list of subtasks and linked issues corresponding to the given issue.

    Args:
        client (JiraBaseClient): The Jira client
        issue (Dict[str, Any]): The issue to retrieve its subtasks and linked issues.
        expand_links (bool, optional): Whether to retrieve the subtasks and linked issues. Defaults to False.

    Returns:
        List[Dict[str, Any]]:  A list of subtasks and linked issues corresponding to the given issue.
    """
    responses: List[Dict[str, Any]] = []
    if expand_links:
        responses.extend(
            client.get_issue(full_issue_url=sub_task.get('self', ''))
            for sub_task in issue.get('fields', {}).get('subtasks', [])
        )
        for linked_issues in issue.get('fields', {}).get('issuelinks', []):
            if inward_issue := linked_issues.get('inwardIssue'):
                responses.append(client.get_issue(full_issue_url=inward_issue.get('self', '')))
            elif outward_issue := linked_issues.get('outwardIssue'):
                responses.append(client.get_issue(full_issue_url=outward_issue.get('self', '')))
    return responses


def create_issue_command(client: JiraBaseClient, args: Dict[str, str]) -> CommandResults:
    """This command is in charge of creating a new issue.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, str]): The arguments supplied by the user.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """

    # Validate that no more args are sent when the issue_json arg is used
    if "issue_json" in args and len(args) > 1:
        raise DemistoException(
            "When using the argument `issue_json`, additional arguments cannot be used.ֿֿֿ\n see the argument description"
        )

    args_for_api = deepcopy(args)
    if project_name := args_for_api.get('project_name'):
        args_for_api['project_id'] = get_project_id_from_name(client=client, project_name=project_name)

    issue_fields = create_issue_fields(client=client, issue_args=args_for_api,
                                       issue_fields_mapper=client.ISSUE_FIELDS_CREATE_MAPPER)
    if "summary" not in issue_fields.get("fields", {}):
        raise DemistoException('The summary argument must be provided.')
    res = client.create_issue(json_data=issue_fields)
    outputs = {'Id': res.get('id', ''), 'Key': res.get('key', '')}
    markdown_dict = outputs | {'Ticket Link': res.get('self', ''),
                               'Project Key': res.get('key', '').split('-')[0]}
    return CommandResults(
        outputs_prefix='Ticket',
        outputs=outputs,
        outputs_key_field='Id',
        readable_output=tableToMarkdown(name=f'Issue {outputs.get("Key", "")}', t=markdown_dict),
        raw_response=res
    )


def edit_issue_command(client: JiraBaseClient, args: Dict[str, str]) -> CommandResults:
    """This command is in charge of editing an existing issue.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, str]): The arguments supplied by the user.

    Raises:
        DemistoException: If both the status and transition are provided.
        DemistoException: If neither an issue id nor a key was supplied.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    if "issue_json" in args and [
        k
        for k in args
        if k
        not in ("status", "transition", "action", "issue_id", "issue_key", "issue_json")
    ]:
        raise DemistoException(
            "When using the `issue_json` argument, additional arguments cannot be used "
            "except `issue_id`, `issue_key`, `status`, `transition`, and `action` arguments.ֿֿֿ"
            "\n see the argument description"
        )

    issue_id_or_key = get_issue_id_or_key(
        issue_id=args.get("issue_id", ""), issue_key=args.get("issue_key", "")
    )
    status = args.get("status", "")
    transition = args.get("transition", "")
    if status and transition:
        raise DemistoException(
            "Please provide only status or transition, but not both."
        )

    # Arrangement of the issue fields
    action = args.get("action", "rewrite")
    issue_fields: dict[str, Any] = {}
    if action == "rewrite":
        issue_fields = create_issue_fields(
            client=client,
            issue_args=args,
            issue_fields_mapper=client.ISSUE_FIELDS_CREATE_MAPPER,
        )
    else:
        # That means the action was `append`
        issue_fields = create_issue_fields_for_appending(
            client=client, issue_args=args, issue_id_or_key=issue_id_or_key
        )

    demisto.debug(f"Updating the issue with the issue fields: {issue_fields}")

    if status:
        demisto.debug(f"Updating the status to: {status}")
        apply_issue_status(
            client=client,
            issue_id_or_key=issue_id_or_key,
            status_name=status,
            issue_fields=issue_fields,
        )
    elif transition:
        demisto.debug(f"Updating the status using the transition: {transition}")
        apply_issue_transition(
            client=client,
            issue_id_or_key=issue_id_or_key,
            transition_name=transition,
            issue_fields=issue_fields,
        )
    elif issue_fields:
        client.edit_issue(issue_id_or_key=issue_id_or_key, json_data=issue_fields)
    else:
        return CommandResults(
            readable_output="No issue fields were given to update the issue."
        )

    demisto.debug(f"Issue {issue_id_or_key} was updated successfully")
    res = client.get_issue(issue_id_or_key=issue_id_or_key)
    markdown_dict, outputs = create_issue_md_and_outputs_dict(issue_data=res)
    return CommandResults(
        outputs_prefix="Ticket",
        outputs=outputs,
        outputs_key_field="Id",
        readable_output=tableToMarkdown(
            name=f'Issue {outputs.get("Key", "")}',
            t=markdown_dict,
            headerTransform=pascalToSpace,
        ),
        raw_response=res,
    )


def delete_issue_command(client: JiraBaseClient, args: Dict[str, str]) -> CommandResults:
    """This command is in charge of deleting an issue.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, str]): The arguments supplied by the user.

    Raises:
        DemistoException: If neither an issue id nor a key was supplied.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    issue_id_or_key = get_issue_id_or_key(issue_id=args.get('issue_id', ''),
                                          issue_key=args.get('issue_key', ''))
    client.delete_issue(issue_id_or_key=issue_id_or_key)
    return CommandResults(readable_output='Issue deleted successfully.')


def delete_attachment_file_command(client: JiraBaseClient, args: Dict[str, str]) -> CommandResults:
    """This command is in charge of deleting an attachment file.

    Args:
        client (JiraBaseClient): The jira client.
        args (Dict[str, str]): The argument supplied by the user.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    attachment_id = args['attachment_id']
    client.delete_attachment_file(attachment_id=attachment_id)
    return CommandResults(readable_output=f'Attachment id {attachment_id} was deleted successfully.')


def update_issue_assignee_command(client: JiraBaseClient, args: Dict) -> CommandResults:
    """This command is in charge of assigning an assignee to an issue.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict): The arguments supplied by the user.

    Raises:
        DemistoException: If neither an assignee nor an assignee id was supplied.
        DemistoException: If both an assignee and assignee id were supplied.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    assignee_name = args.get('assignee', '')  # For Jira OnPrem
    assignee_id = args.get('assignee_id', '')  # For Jira Cloud
    if not (assignee_name or assignee_id):
        raise DemistoException('Please provide assignee for Jira Server or assignee_id for Jira Cloud.')
    if (assignee_name and assignee_id):
        raise DemistoException('Please provide only one, assignee for Jira Server or assignee_id for Jira Cloud.')
    body = {'accountId': assignee_id} if isinstance(client, JiraCloudClient) else {'name': assignee_name}

    issue_id_or_key = get_issue_id_or_key(issue_id=args.get('issue_id', ''),
                                          issue_key=args.get('issue_key', ''))

    demisto.debug(f'Updating assignee of the issue with the issue fields: {body}')
    client.update_assignee(issue_id_or_key=issue_id_or_key, assignee_body=body)
    demisto.debug(f'Issue {issue_id_or_key} was updated successfully')

    res = client.get_issue(issue_id_or_key=issue_id_or_key)
    markdown_dict, outputs = create_issue_md_and_outputs_dict(issue_data=res)
    return CommandResults(
        outputs_prefix='Ticket',
        outputs=outputs,
        outputs_key_field='Id',
        readable_output=tableToMarkdown(name=f'Issue {outputs.get("Key", "")}', t=markdown_dict,
                                        headerTransform=pascalToSpace),
        raw_response=res
    )


def delete_comment_command(client: JiraBaseClient, args: Dict[str, str]) -> CommandResults:
    """This command is in charge of deleting a comment from an issue.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, str]): The arguments supplied by the user.

    Raises:
        DemistoException: If neither an issue id nor a key was supplied.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    issue_id_or_key = get_issue_id_or_key(issue_id=args.get('issue_id', ''),
                                          issue_key=args.get('issue_key', ''))
    comment_id = args.get('comment_id', '')
    client.delete_comment(issue_id_or_key=issue_id_or_key, comment_id=comment_id)
    return CommandResults(readable_output='Comment deleted successfully.')


def get_comments_command(client: JiraBaseClient, args: Dict[str, str]) -> CommandResults:
    """This command is in charge of getting the comments of an issue

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, str]): The arguments supplied by the user.

    Raises:
        DemistoException: If neither an issue id nor a key was supplied.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    issue_id_or_key = get_issue_id_or_key(issue_id=args.get('issue_id', ''),
                                          issue_key=args.get('issue_key', ''))
    limit = arg_to_number(args.get('limit', DEFAULT_PAGE_SIZE)) or DEFAULT_PAGE_SIZE
    res = client.get_comments(issue_id_or_key=issue_id_or_key, max_results=limit)
    if comments_response := res.get('comments', []):
        human_readable, outputs = create_comments_command_results(
            comments_response=comments_response, issue_id_or_key=issue_id_or_key
        )
        return CommandResults(
            outputs_prefix='Ticket',
            outputs=outputs,
            outputs_key_field='Id',
            readable_output=human_readable,
            raw_response=res
        )
    else:
        return CommandResults(readable_output='No comments were found in the ticket')


def create_comments_command_results(comments_response: List[Dict[str, Any]],
                                    issue_id_or_key: str) -> tuple[str, Dict[str, Any]]:
    """Returns the human readable and context output of the get_comments_command.

    Args:
        comments_response (List[Dict[str, Any]]): The comments object returned from the API (not empty!).
        issue_id_or_key (str): The issue id or key that holds the comments.

    Returns:
        Tuple[str, Dict[str, Any]]: A tuple where that first element is the human readable to return to the
        user, and the second is to return to the context data.
    """
    if not comments_response:
        raise DemistoException('The list of comments can not be empty!')
    is_id = is_issue_id(issue_id_or_key=issue_id_or_key)
    comments = [extract_comment_entry_from_raw_response(comment_response) for comment_response in comments_response]
    outputs: Dict[str, Any] = {'Comment': comments}
    if is_id:
        outputs |= {'Id': issue_id_or_key}
    else:
        extracted_issue_id = extract_issue_id_from_comment_url(comment_url=comments_response[0].get('self', ''))
        outputs |= {'Id': extracted_issue_id, 'Key': issue_id_or_key}
    human_readable = tableToMarkdown("Comments", comments)
    return human_readable, outputs


def extract_comment_entry_from_raw_response(comment_response: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the comment entry from the raw response of the comment.

    Args:
        comment_response (Dict[str, Any]): The comment object returned from the API.

    Returns:
        Dict[str, Any]: The comment entry that will be used to return to the user.
    """
    comment_body = BeautifulSoup(comment_response.get('renderedBody'), features="html.parser").get_text(
    ) if comment_response.get('renderedBody') else comment_response.get('body')
    return {
        'Id': comment_response.get('id'),
        'Comment': comment_body,
        'User': demisto.get(comment_response, 'author.displayName') or '',
        'Created': comment_response.get('created') or '',
        'Updated': comment_response.get('updated') or '',
        'UpdateUser': demisto.get(comment_response, 'updateAuthor.displayName') or '',
    }


def edit_comment_command(client: JiraBaseClient, args: Dict[str, str]) -> CommandResults:
    """This command is in charge of editing a comment inside an issue.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, str]): The arguments supplied by the user.

    Raises:
        DemistoException: If neither an issue id nor a key was supplied.

    Returns:
        CommandResults:  CommandResults to return to XSOAR.
    """
    issue_id_or_key = get_issue_id_or_key(issue_id=args.get('issue_id', ''),
                                          issue_key=args.get('issue_key', ''))
    comment_id = args.get('comment_id', '')
    comment = args.get('comment', '')
    visibility = args.get('visibility', '')
    payload = {
        'body': text_to_adf(text=comment) if isinstance(client, JiraCloudClient) else comment
    }
    if visibility:
        payload['visibility'] = {
            "type": "role",
            "value": visibility
        }
    # The edit_comment actually returns the edited comment (the API returns the newly edited comment), but
    # since I don't know if we have a way to append a CommandResults to a List of CommandResults in the context data,
    # I just call get_comments, which will also get the newly edited comment, and return them.
    client.edit_comment(issue_id_or_key=issue_id_or_key, comment_id=comment_id, json_data=payload)
    res = client.get_comments(issue_id_or_key=issue_id_or_key)
    if comments_response := res.get('comments', []):
        _, outputs = create_comments_command_results(
            comments_response=comments_response, issue_id_or_key=issue_id_or_key
        )
        return CommandResults(
            outputs_prefix='Ticket',
            outputs=outputs,
            outputs_key_field='Id',
            readable_output='The comment has been edited successfully',
            raw_response=res
        )
    else:
        return CommandResults(readable_output='No comments were found in the ticket')


def add_comment_command(client: JiraBaseClient, args: Dict[str, str]) -> CommandResults:
    """This command is in charge of adding a comment to an existing issue.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, str]): The arguments supplied by the user.

    Raises:
        DemistoException: If neither an issue id nor a key was supplied.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    issue_id_or_key = get_issue_id_or_key(issue_id=args.get('issue_id', ''),
                                          issue_key=args.get('issue_key', ''))
    comment = args.get('comment', '')
    visibility = args.get('visibility', )
    payload = {
        'body': text_to_adf(text=comment) if isinstance(client, JiraCloudClient) else comment
    }
    if visibility:
        payload['visibility'] = {
            "type": "role",
            "value": visibility
        }
    res = client.add_comment(issue_id_or_key=issue_id_or_key, json_data=payload)
    markdown_dict = {
        'Comment': BeautifulSoup(res.get('renderedBody'), features="html.parser").get_text()
        if res.get('renderedBody')
        else res.get('body'),
        'Id': res.get('id', ''),
        'Ticket Link': res.get('self', ''),
    }
    return CommandResults(
        readable_output=tableToMarkdown('Comment added successfully', markdown_dict)
    )


def get_transitions_command(client: JiraBaseClient, args: Dict[str, str]) -> CommandResults:
    """This command is in charge of returning all possible transitions for a given ticket in its current status.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, str]): The arguments supplied by the user.

    Raises:
        DemistoException: If neither an issue id nor a key was supplied.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    issue_id_or_key = get_issue_id_or_key(issue_id=args.get('issue_id', ''),
                                          issue_key=args.get('issue_key', ''))
    res = client.get_transitions(issue_id_or_key=issue_id_or_key)
    transitions_names: List[str] = [
        transition.get('name', '') for transition in res.get('transitions', [])
    ]
    readable_output = tableToMarkdown(
        'List Transitions:', transitions_names, headers=['Transition Names']
    )
    outputs: Dict[str, Any] = {'Transitions': {'transitions': transitions_names, 'ticketId': issue_id_or_key}}
    is_id = is_issue_id(issue_id_or_key=issue_id_or_key)
    outputs |= {'Id': issue_id_or_key} if is_id else {'Key': issue_id_or_key}
    # The scripts script-JiraListTransition, and JiraListStatus use this command, therefore any change here (if necessary)
    # must be reflected in the scripts.
    return CommandResults(
        outputs_prefix='Ticket',
        outputs=outputs,
        outputs_key_field='Id' if is_id else 'Key',
        readable_output=readable_output,
        raw_response=res
    )


def get_id_offset_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
    """This command is in charge of returning the id of the first issue created.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, Any]): The arguments supplied by the user.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    res, first_issue_id = get_smallest_id_offset_for_query(client=client, query=args.get('query', ''))
    if not first_issue_id:
        return CommandResults(readable_output='No issues found to retrieve the ID offset', raw_response=res)
    return (
        CommandResults(
            outputs_prefix='Ticket',
            readable_output=f'ID Offset: {first_issue_id}',
            outputs={'idOffSet': first_issue_id},
            raw_response=res
        )
    )


def upload_file_command(client: JiraBaseClient, args: Dict[str, str]) -> CommandResults:
    """This command is in charge of uploading a file to a given issue.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, str]): The arguments supplied by the user.

    Raises:
        DemistoException: If neither an issue id nor a key was supplied.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    entry_id = args.get('upload', '')
    issue_id_or_key = get_issue_id_or_key(issue_id=args.get('issue_id', ''),
                                          issue_key=args.get('issue_key', ''))
    attachment_name = args.get('attachment_name', '')
    res = upload_XSOAR_attachment_to_jira(client=client, entry_id=entry_id, attachment_name=attachment_name,
                                          issue_id_or_key=issue_id_or_key)
    is_id = is_issue_id(issue_id_or_key=issue_id_or_key)
    markdown_dict: List[Dict[str, str]] = []
    for attachment_entry in res:
        attachment_dict = {
            'Attachment Link': attachment_entry.get('self', ''),
            'Id': attachment_entry.get('id', ''),
            'Attachment Name': attachment_entry.get('filename', ''),
        } | (
            {'Issue Id': issue_id_or_key}
            if is_id
            else {'Issue Key': issue_id_or_key}
        )
        markdown_dict.append(attachment_dict)
    return CommandResults(
        readable_output=tableToMarkdown('Attachment added successfully', markdown_dict)
    )


def upload_XSOAR_attachment_to_jira(client: JiraBaseClient, entry_id: str,
                                    issue_id_or_key: str,
                                    attachment_name: str | None = None) -> List[Dict[str, Any]]:
    """Uploads the given attachment (identified by the entry_id), to the jira issue
    that corresponds to the key or id issue_id_or_key.

    Args:
        client (JiraBaseClient): The Jira client.
        entry_id (str): The entry if of the attachment in XSOAR.
        attachment_name (str | None): A custom attachment name, if it is empty or None then the attachment's name will be the
        same one as in XSOAR. Default is None
        issue_id_or_key (str): The issue ID or key to upload the attachment to.

    Returns:
        List[Dict[str, Any]]: The results of the API, which will hold the newly added attachment.
    """
    file_name, file_bytes = get_file_name_and_content(entry_id=entry_id)
    files, chosen_file_mime_type = create_files_to_upload('', file_name, file_bytes, attachment_name)
    # try upload the attachment with the specific mime type
    try:
        return client.upload_attachment(issue_id_or_key=issue_id_or_key, files=files)
    except Exception as e:
        # in case the first call to upload_attachment() failed, check if file_mime_type is the default value,
        # if yes, we should raise exception
        if chosen_file_mime_type == 'application-type':
            raise e
        # if we used a specific mime type, try upload_attachment() again, with the default type.
        else:
            demisto.debug(f'The first call to upload_attachment() with {chosen_file_mime_type=} failed. '
                          f'Trying again with file_mime_type=application-type')
            files, _ = create_files_to_upload('application-type', file_name, file_bytes, attachment_name)
            return client.upload_attachment(issue_id_or_key=issue_id_or_key, files=files)


def issue_get_attachment_command(client: JiraBaseClient, args: Dict[str, str]) -> List[Dict[str, Any]]:
    """This command is in charge of getting an attachment's content that is found in an issue.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, str]): The arguments supplied by the user.

    Returns:
        Dict[str, Any]: A dictionary the represents file entries to be returned to the user.
    """
    attachments_ids = argToList(args.get('attachment_id', ''))
    files_result: List[Dict[str, Any]] = [
        create_file_info_from_attachment(
            client=client, attachment_id=attachment_id
        )
        for attachment_id in attachments_ids
    ]
    return files_result


def get_specific_fields_command(client: JiraBaseClient, args: Dict[str, str]) -> CommandResults:
    """This command is in charge of adding specific issue fields to context (which can return nested values)

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, str]): The arguments supplied by the user.

    Raises:
        DemistoException: If neither an issue id nor a key was supplied.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    issue_id_or_key = get_issue_id_or_key(issue_id=args.get('issue_id', ''),
                                          issue_key=args.get('issue_key', ''))
    fields = argToList(args.get('fields', ''))
    res = client.get_issue(issue_id_or_key=issue_id_or_key)
    markdown_dict, outputs = create_issue_md_and_outputs_dict(issue_data=res, specific_issue_fields=fields,
                                                              issue_fields_id_to_name_mapping=res.get('names', {}) or {})
    return CommandResults(
        outputs_prefix='Ticket',
        outputs=outputs,
        outputs_key_field='Id',
        readable_output=tableToMarkdown(name=f'Issue {outputs.get("Key", "")}', t=markdown_dict,
                                        headerTransform=pascalToSpace),
        raw_response=res
    )


def list_fields_command(client: JiraBaseClient, args: Dict[str, str]) -> CommandResults:
    """This command is in charge of returning the issue fields found in the Jira system.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, str]): The arguments supplied by the user.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    res = client.get_issue_fields()
    pagination_args = prepare_pagination_args(page=arg_to_number(arg=args.get('page', None)),
                                              page_size=arg_to_number(arg=args.get('page_size', None)),
                                              limit=arg_to_number(arg=args.get('limit', None)))
    start_at = pagination_args.get('start_at', 0)
    max_results = pagination_args.get('max_results', DEFAULT_PAGE_SIZE)
    # Since the API does not support pagination, and the issue fields returned can carry hundreds of entries,
    # we decided to do the pagination manually.
    fields_entry = res[start_at: start_at + max_results]
    markdown_dict: List[Dict[str, Any]] = [
        {
            'Id': field.get('id', ''),
            'Name': field.get('name', ''),
            'Custom': field.get('custom', ''),
            'Searchable': field.get('searchable', ''),
            'Schema Type': demisto.get(field, 'schema.type'),
        }
        for field in fields_entry
    ]
    return CommandResults(
        outputs_prefix='Jira.IssueField',
        outputs=fields_entry,
        outputs_key_field='id',
        readable_output=tableToMarkdown(name='Issue Fields', t=markdown_dict),
        raw_response=res
    )


# User Commands
def get_id_by_attribute_command(client: JiraBaseClient, args: Dict[str, str]) -> CommandResults:
    """This command is in charge of returning the id of a specific user based on attribute.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, str]): The arguments supplied by the user.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    attribute = args.get('attribute', '')
    max_results = arg_to_number(args.get('max_results', DEFAULT_PAGE_SIZE)) or DEFAULT_PAGE_SIZE
    res = client.get_id_by_attribute(attribute=attribute, max_results=max_results)
    if not res:
        return CommandResults(readable_output=f'No Account ID was found for attribute: {attribute}.')
    outputs = {'Attribute': attribute}
    is_jira_cloud = isinstance(client, JiraCloudClient)
    account_ids: List[str] = []

    if len(res) == 1:
        # Since we compare the given attribute to the email address in order to retrieve the account id, and the email address
        # can be empty for privacy reasons, we want to avoid a situation where we actually receive a valid user, but since the
        # email address can be empty, we will output to the user than no user was found.
        # While using Jira Cloud, the account id is under the key 'accountId', and while using Jira OnPrem, it is under the
        # key 'name'
        account_ids = [res[0].get('accountId', '') or res[0].get('name', '')]

    elif is_jira_cloud:
        # We check the displayName and emailAddress, because that is what the Cloud API returns
        account_ids = [
            user.get('accountId', '') for user in res if (attribute.lower() in [user.get('displayName', '').lower(),
                                                                                user.get('emailAddress', '').lower()])
        ]

    else:
        # We check the displayName, emailAddress, and name, because that is what the OnPrem API returns
        account_ids = [
            user.get('name', '') for user in res if (attribute.lower() in [user.get('displayName', '').lower(),
                                                                           user.get('emailAddress', '').lower(),
                                                                           user.get('name', '').lower()])
        ]
    if not account_ids:
        # The email address is a private account field and sometimes is blank, therefore, if the response is not empty but
        # account_ids is, the user should try "DisplayName" attribute.
        demisto.debug(f'Multiple accounts found, but it was not possible to resolve which one of them is most '
                      f'relevant to attribute {attribute}.')
        return CommandResults(readable_output=(f'Multiple accounts found, but it was not possible to resolve which one'
                                               f' of them is most relevant to attribute {attribute}. Please try to provide'
                                               ' the "DisplayName" attribute if not done so before, or supply the full'
                                               ' attribute.'))

    elif len(account_ids) > 1:
        return CommandResults(readable_output=f'Multiple account IDs were found for attribute: {attribute}.\n'
                                              f'Please try to provide the other attributes available - Email or DisplayName'
                                              ' (and Name in the case of Jira OnPrem).')
    # If reached here, that means there is only one entry in account_ids that holds the right id for the given attribute
    outputs['AccountId'] = account_ids[0]
    return CommandResults(
        outputs_prefix='Jira.User',
        outputs_key_field='AccountId',
        outputs=outputs,
        readable_output=f'The account ID that holds the attribute `{attribute}`: {outputs["AccountId"]}'
    )


def sprint_issues_list_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
    """This command is in charge of returning the issues found in a specific sprint.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, Any]): The arguments supplied by the user.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    board_id = args.get('board_id', '')
    sprint_id = args.get('sprint_id', '')
    jql_query = args.get('jql_query', '')
    pagination_args = prepare_pagination_args(page=arg_to_number(arg=args.get('page', None)),
                                              page_size=arg_to_number(arg=args.get('page_size', None)),
                                              limit=arg_to_number(arg=args.get('limit', None)))
    if board_id:
        res = client.get_sprint_issues_from_board(sprint_id=sprint_id, board_id=board_id, jql_query=jql_query,
                                                  **pagination_args)
    else:
        res = client.get_issues_from_sprint(
            sprint_id=sprint_id,
            jql_query=jql_query,
            **pagination_args
        )
    if issues := res.get('issues', []):
        return create_sprint_issues_command_results(
            board_id, issues, sprint_id, res
        )
    return CommandResults(readable_output='No issues were found with the respective arguments.')


def create_sprint_issues_command_results(board_id: str, issues: List[Dict[str, Any]], sprint_id: str,
                                         res: Dict[str, Any]) -> CommandResults:
    """Create the CommandResults of the sprint_issues_list_command.

    Args:
        board_id (str): The board id, if given by the user
        issues (List[Dict[str, Any]]): The issues in the sprint (not empty!).
        sprint_id (str): The id of the sprint that holds the issues.
        res (Dict[str, Any]): The raw response when calling the API to retrieve the issues.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    if not board_id:
        # If board_id was not given by the user, we try to extract it from the issues.
        if not issues:
            return CommandResults(readable_output='No issues found to retrieve the board ID', raw_response=res)
        sprint = issues[0].get('fields', {}).get('sprint', {}) or {}
        board_id = sprint.get(
            'originBoardId', '') or ''
    markdown_list = []
    issues_list = []
    for issue in issues:
        markdown_dict, outputs = create_issue_md_and_outputs_dict(issue_data=issue)
        markdown_list.append(markdown_dict)
        issues_list.append(outputs)
    context_data_outputs: Dict[str, Any] = {'Ticket': issues_list or []}
    board_id = str(board_id)
    context_data_outputs |= {'boardId': board_id} if board_id else {}
    context_data_outputs |= {'sprintId': sprint_id}
    return CommandResults(
        outputs_prefix='Jira.SprintIssues',
        outputs_key_field=['boardId', 'sprintId'] if board_id else [
            'sprintId'],
        outputs=context_data_outputs or None,
        readable_output=tableToMarkdown(name=f'Sprint Issues in board {board_id}', t=markdown_list),
        raw_response=res
    )


def issues_to_sprint_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
    """This command is in charge of moving issues to a sprint.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, Any]): The arguments supplied by the user.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    issues = argToList(args.get('issues', ''))
    sprint_id = args.get('sprint_id', '')
    rank_before_issue = args.get('rank_before_issue', '')
    rank_after_issue = args.get('rank_after_issue', '')
    if rank_before_issue or rank_after_issue and isinstance(client, JiraOnPremClient):
        raise DemistoException('The arguments rank_before_issue, and rank_after_issue are not supported on Jira OnPrem')
    json_data = assign_params(
        issues=issues,
        rankBeforeIssue=rank_before_issue,
        rankAfterIssue=rank_after_issue
    )
    client.issues_to_sprint(sprint_id=sprint_id, json_data=json_data)
    return CommandResults(readable_output='Issues were moved to the Sprint successfully')


def epic_issues_list_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
    """This command is in charge of returning the issues that belong to a specific epic issue.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, Any]): The arguments supplied by the user.

    Raises:
        DemistoException: If neither an epic id nor a key was supplied.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    epic_id_or_key = args.get('epic_id', args.get('epic_key', ''))
    if not epic_id_or_key:
        raise DemistoException(EPIC_ID_OR_KEY_MISSING_ERROR)
    jql_query = args.get('jql_query', '')
    pagination_args = prepare_pagination_args(page=arg_to_number(arg=args.get('page', None)),
                                              page_size=arg_to_number(arg=args.get('page_size', None)),
                                              limit=arg_to_number(arg=args.get('limit', None)))
    res = client.get_epic_issues(epic_id_or_key=epic_id_or_key, jql_query=jql_query, **pagination_args)
    if issues := res.get('issues', []):
        return create_epic_issues_command_results(
            issues=issues, epic_id_or_key=epic_id_or_key, res=res
        )
    else:
        return CommandResults(readable_output=f'No child issues were found for epic {epic_id_or_key}')


def create_epic_issues_command_results(issues: List[Dict[str, Any]],
                                       epic_id_or_key: str, res: Dict[str, Any]) -> CommandResults:
    """Creates the CommandResults of the epic_issues_list_command.

    Args:
        issues (List[Dict[str, Any]]): The issues that belong to the epic (not empty!).
        epic_id_or_key (str): The epic id or key.
        res (Dict[str, Any]): The raw response when calling the API to retrieve the epic's issues.

    Returns:
       CommandResults: CommandResults to return to XSOAR.
    """
    markdown_list = []
    issues_list = []
    if not issues:
        return CommandResults(readable_output='No issues found to retrieve the epic, or board ID', raw_response=res)
    for issue in issues:
        markdown_dict, outputs_context_data = create_issue_md_and_outputs_dict(issue_data=issue)
        markdown_list.append(markdown_dict)
        issues_list.append(outputs_context_data)
    outputs: Dict[str, Any] = {'Ticket': issues_list}
    sprint = issues[0].get('fields', {}).get('sprint', {}) or {}
    board_id = str(sprint.get(
        'originBoardId', '')) or ''
    outputs |= {'boardId': board_id} if board_id else {}
    epic = issues[0].get('fields', {}).get('epic') or {}
    epic_id = str(epic.get('id', '')) or ''
    outputs |= {'epicId': epic_id} if epic_id else {}
    return CommandResults(
        outputs_prefix='Jira.EpicIssues',
        outputs_key_field=['epicId', 'boardId'] if board_id else ['epicId'],
        outputs=outputs,
        readable_output=tableToMarkdown(name=f'Child Issues in epic {epic_id_or_key}', t=markdown_list),
        raw_response=res
    )


def get_issue_link_types_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
    """This command is in charge of returning the issue links between issues (Blocked by, Duplicates,...)

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, Any]):  The arguments supplied by the user.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    res = client.get_issue_link_types()
    issue_link_types = res.get('issueLinkTypes', [])
    md_dict = [
        {
            'ID': issue_link_type.get('id', ''),
            'Name': issue_link_type.get('name', ''),
            'Inward': issue_link_type.get('inward', ''),
            'Outward': issue_link_type.get('outward', ''),
        }
        for issue_link_type in issue_link_types
    ]
    return CommandResults(
        outputs_prefix='Jira.IssueLinkType',
        outputs=issue_link_types,
        readable_output=tableToMarkdown(name='Issue Link Types', t=md_dict),
        raw_response=res
    )


def link_issue_to_issue_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
    """This command is in charge of adding an issue link between two issues.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, Any]): The arguments supplied by the user.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    outward_issue = args.get('outward_issue', '')
    inward_issue = args.get('inward_issue', '')
    link_type = args.get('link_type', '')
    comment = args.get('comment', '')

    json_data = assign_params(
        comment={'body': text_to_adf(text=comment) if isinstance(client, JiraCloudClient) else comment} if comment else '',
        inwardIssue={'id': inward_issue} if is_issue_id(inward_issue) else {'key': inward_issue},
        outwardIssue={'id': outward_issue} if is_issue_id(outward_issue) else {'key': outward_issue},
        type={'name': link_type}
    )
    client.create_issue_link(json_data=json_data)
    return CommandResults(readable_output='Issue link created successfully')


# Board Commands
def issues_to_backlog_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
    """This command is in charge of moving issues, that are part of a sprint or not, back to backlog of their board.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, Any]): The arguments supplied by the user.

    Raises:
        DemistoException: If the user supplied the rank_after_issue, or rank_before_issue, without the board id.
        DemistoException: If the board id was supplied, but the Jira instance is not a Cloud instance.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    issues = argToList(args.get('issues', ''))
    board_id = args.get('board_id', '')
    rank_before_issue = args.get('rank_before_issue', '')
    rank_after_issue = args.get('rank_after_issue', '')
    if (rank_after_issue or rank_before_issue) and not board_id:
        raise DemistoException('Please supply the board_id argument when supplying the rank_after_issue, and'
                               ' rank_before_issue arguments')
    json_data = {'issues': issues}
    if board_id:
        # The endpoint that accepts the board id is only supported by Jira Cloud and not Jira Server API.
        if isinstance(client, JiraCloudClient):

            json_data |= assign_params(
                rankBeforeIssue=rank_before_issue,
                rankAfterIssue=rank_after_issue
            )
            client.issues_to_backlog(board_id=board_id, json_data=json_data)
        else:
            raise DemistoException('The argument board_id is not supported for a Jira OnPrem instance.')
    else:
        # If the board_id is not given, then the issues that are meant to be moved to backlog, must be
        # part of a sprint, or in other words, the issues must be part of a board that supports sprints.
        client.issues_from_sprint_to_backlog(json_data=json_data)
    return CommandResults(readable_output='Issues were moved to Backlog successfully')


def issues_to_board_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
    """This command is in charge of moving issues from backlog to board.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, Any]): The arguments supplied by the user.

    Raises:
        DemistoException: If the configured Jira instance is an OnPrem instance.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    if isinstance(client, JiraCloudClient):
        # This command is only supported by a Jira Cloud instance
        issues = argToList(args.get('issues', ''))
        board_id = args.get('board_id', '')
        rank_before_issue = args.get('rank_before_issue', '')
        rank_after_issue = args.get('rank_after_issue', '')
        json_data = assign_params(
            issues=issues,
            rankBeforeIssue=rank_before_issue,
            rankAfterIssue=rank_after_issue
        )
        client.issues_to_board(board_id=board_id, json_data=json_data)
        return CommandResults(readable_output='Issues were moved to Board successfully')
    raise DemistoException('This command is not supported by a Jira OnPrem instance.')


def board_list_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
    """This command is in charge of retrieving the boards, or board, found in the Jira instance.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, Any]): The arguments supplied by the user.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    board_id = args.get('board_id', '')
    board_type = args.get('type', '')
    project_key_id = args.get('project_key_id', '')
    board_name = args.get('board_name')
    pagination_args = prepare_pagination_args(page=arg_to_number(arg=args.get('page', None)),
                                              page_size=arg_to_number(arg=args.get('page_size', None)),
                                              limit=arg_to_number(arg=args.get('limit', None)))
    boards: List[Dict[str, Any]] = []
    if board_id:
        res = client.get_board(board_id=board_id)
        boards = [res]
    else:
        res = client.get_boards(
            board_type=board_type,
            project_key_id=project_key_id,
            board_name=board_name,
            **pagination_args
        )
        boards = res.get('values', [])
    md_dict = [
        {
            'ID': board.get('id', ''),
            'Name': board.get('name', ''),
            'Type': board.get('type', ''),
            'Project ID': board.get('location', {}).get('projectId', ''),
            'Project Name': board.get('location', {}).get('projectName', ''),
        }
        for board in boards
    ]
    return CommandResults(
        outputs_prefix='Jira.Board',
        outputs_key_field='id',
        outputs=boards,
        readable_output=tableToMarkdown(name='Boards', t=md_dict),
        raw_response=res
    )


def board_backlog_list_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
    """This command is in charge of retrieving issues from the backlog of a specific board.
    For Jira OnPrem, the board must be of type scrum.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, Any]): The arguments supplied by the user.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    board_id = args.get('board_id', '')
    jql_query = args.get('jql_query', '')
    pagination_args = prepare_pagination_args(page=arg_to_number(arg=args.get('page', None)),
                                              page_size=arg_to_number(arg=args.get('page_size', None)),
                                              limit=arg_to_number(arg=args.get('limit', None)))
    res = client.get_issues_from_backlog(board_id=board_id, jql_query=jql_query, **pagination_args)
    markdown_list = []
    issues_list = []
    for issue in res.get('issues', []):
        markdown_dict, outputs = create_issue_md_and_outputs_dict(issue_data=issue)
        markdown_list.append(markdown_dict)
        issues_list.append(outputs)
    return CommandResults(
        outputs_prefix='Jira.BoardBacklog',
        outputs_key_field='boardId',
        outputs={'boardId': board_id, 'Ticket': issues_list},
        readable_output=tableToMarkdown(name='Backlog Issues', t=markdown_list),
        raw_response=res
    )


def board_issues_list_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
    """This method is in charge of returning issues from a specific board.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, Any]): The arguments supplied by the user.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    board_id = args.get('board_id', '')
    jql_query = args.get('jql_query', '')
    pagination_args = prepare_pagination_args(page=arg_to_number(arg=args.get('page', None)),
                                              page_size=arg_to_number(arg=args.get('page_size', None)),
                                              limit=arg_to_number(arg=args.get('limit', None)))
    res = client.get_issues_from_board(board_id=board_id, jql_query=jql_query, **pagination_args)
    markdown_list = []
    issues_list = []
    for issue in res.get('issues', []):
        markdown_dict, outputs = create_issue_md_and_outputs_dict(issue_data=issue)
        markdown_list.append(markdown_dict)
        issues_list.append(outputs)
    return CommandResults(
        outputs_prefix='Jira.BoardIssue',
        outputs_key_field='boardId',
        outputs={'boardId': board_id, 'Ticket': issues_list},
        readable_output=tableToMarkdown(name='Board Issues', t=markdown_list),
        raw_response=res
    )


def board_sprint_list_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
    """This command is in charge of returning the sprints of a specific board, if the board supports sprints.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, Any]): The arguments supplied by the user.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    board_id = args.get('board_id', '')
    pagination_args = prepare_pagination_args(page=arg_to_number(arg=args.get('page', None)),
                                              page_size=arg_to_number(arg=args.get('page_size', None)),
                                              limit=arg_to_number(arg=args.get('limit', None)))
    res = client.get_sprints_from_board(board_id=board_id, **pagination_args)
    sprints = res.get('values', [])
    md_dict = [
        {
            'ID': sprint.get('id', ''),
            'Name': sprint.get('name', ''),
            'State': sprint.get('state', ''),
            'Start Date': sprint.get('startDate', ''),
            'End Date': sprint.get('endDate', ''),
        }
        for sprint in sprints
    ]
    return CommandResults(
        outputs_prefix='Jira.BoardSprint',
        outputs_key_field='boardId',
        outputs={'boardId': board_id, 'Sprints': sprints},
        readable_output=tableToMarkdown(name='Sprints', t=md_dict),
        raw_response=res
    )


def board_epic_list_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
    """This command is in charge of returning issues with issue type `epic`, of a specific board.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, Any]): The arguments supplied by the user.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    board_id = args.get('board_id', '')
    pagination_args = prepare_pagination_args(page=arg_to_number(arg=args.get('page', None)),
                                              page_size=arg_to_number(arg=args.get('page_size', None)),
                                              limit=arg_to_number(arg=args.get('limit', None)))
    done = args.get('done', 'false')
    res = client.get_epics_from_board(board_id=board_id, done=done, **pagination_args)
    if epics := res.get('values', []):
        md_dict = [
            {
                'ID': epic.get('id', ''),
                'Name': epic.get('name', ''),
                'Key': epic.get('key', ''),
                'Summary': epic.get('summary', ''),
                'Done': epic.get('done', ''),
            }
            for epic in epics
        ]
        return CommandResults(
            outputs_prefix='Jira.BoardEpic',
            outputs_key_field='boardId',
            outputs={'boardId': board_id, 'Epics': epics},
            readable_output=tableToMarkdown(name='Epics', t=md_dict),
            raw_response=res
        )
    return CommandResults(readable_output=f'No epics were found on board {board_id} with the respective arguments.')


# Authentication
def ouath_start_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
    """This command is used to start the authentication process of the instance.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, Any], optional): The arguments supplied by the user.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    url = client.oauth_start()
    return CommandResults(readable_output=('In order to retrieve the authorization code,'
                                           f' use the following link:\n{create_clickable_url(url)}\n'
                                           'After authorizing, you will be redirected to the configured callback URL, where you'
                                           ' will retrieve the authorization code provided as a query parameter called `code`,'
                                           ' and insert it as an argument to the `!jira-oauth-complete` command'))


def oauth_complete_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
    """This command is used to complete the authentication process of the instance.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, Any]): The arguments supplied by the user.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    code = args.get('code', '')
    client.oauth_complete(code=code)
    return CommandResults(
        readable_output=('### Logged in successfully.\n A refresh token was saved to the integration context. This token will be '
                         'used to generate a new access token once the current one expires.'))


def test_authorization(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
    """This command is used to test the connectivity of the Jira instance configured.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, Any]): The arguments supplied by the user.

    Returns:
        CommandResults: CommandResults to return to XSOAR.
    """
    client.test_instance_connection()
    return CommandResults(readable_output='Successful connection.')


def test_module(client: JiraBaseClient) -> str:
    """This method will return an error since in order for the user to test the connectivity of the instance,
    they have to run a separate command, therefore, pressing the `test` button on the configuration screen will
    show them the steps in order to test the instance.
    """
    if client.is_basic_auth:
        client.test_instance_connection()  # raises on failure
        return "ok"
    else:
        raise DemistoException(
            'In order to authorize the instance, first run the command `!jira-oauth-start`,'
            ' and complete the process in the URL that is returned. You will then be redirected'
            ' to the callback URL. Copy the authorization code found in the query parameter'
            ' `code`, and paste that value in the command `!jira-ouath-complete` as an argument to finish'
            ' the process.'
        )


def get_smallest_id_offset_for_query(client: JiraBaseClient, query: str) -> tuple[Dict[str, Any], int | None]:
    """Returns the smallest issue ID with respect to the query argument.

    Args:
        client (JiraBaseClient): The Jira client.
        query (str): The query that will be used to retrieve the first issue ID in it.

    Returns:
        int | None: The smallest issue ID with respect to the query argument, and None if the query
        returns an empty list.
    """
    jql_query = f'{query} ORDER BY created ASC' if query else 'ORDER BY created ASC'
    query_params = create_query_params(jql_query=jql_query, max_results=1)
    res = client.run_query(query_params=query_params)

    if (issues := res.get('issues', [])):
        return res, issues[0].get('id', '')
    return res, None


# Fetch Incidents
def fetch_incidents(client: JiraBaseClient, issue_field_to_fetch_from: str, fetch_query: str, id_offset: int,
                    fetch_attachments: bool, fetch_comments: bool, mirror_direction: str, max_fetch_incidents: int,
                    first_fetch_interval: str, comment_tag_from_jira: str, comment_tag_to_jira: str,
                    attachment_tag_from_jira: str, attachment_tag_to_jira: str) -> List[Dict[str, Any]]:
    """This function is the entry point of fetching incidents.

    Args:
        client (JiraBaseClient): The Jira client.
        issue_field_to_fetch_from (str): The issue field to fetch from, id, created time, or updated time.
        fetch_query (str): The fetch query configured.
        id_offset (int): The id from which to start the fetching from if we are fetching using id.
        fetch_attachments (bool): Whether to fetch the attachments or not.
        fetch_comments (bool): Whether to fetch the comments or not.
        max_fetch_incidents (int): The maximum number of incidents to fetch per fetch.
        first_fetch_interval (str): The first fetch interval to fetch from if the fetch timestamp is empty, and we are
        fetching using created, or updated time.
        and we are fetching using created time.
        mirror_direction (str): The mirroring direction.
        comment_tag_to_jira (str): The comment tag to add to an entry to mirror it as a comment in Jira.
        comment_tag_from_jira (str): The comment tag to add to an entry to mirror it as a comment from Jira.
        attachment_tag_to_jira (str): The attachment tag to add to an entry to mirror it as an attachment in Jira.
        attachment_tag_from_jira (str): The attachment tag to add to an entry to mirror it as an attachment from Jira.

    Returns:
        List[Dict[str, Any]]: A list of incidents.
    """
    last_run = demisto.getLastRun()
    demisto.debug(f'last_run: {last_run}' if last_run else 'last_run is empty')
    # This list will hold all the ids of the issues that were fetched in the last fetch, to eliminate fetching duplicate
    # incidents. Since when we get the list from the last run, all the values in the list are strings, and we may need them
    # to be integers (if we want to use the issues' ids in the query, they must be passed on as integers and not strings),
    # we convert the list to hold integer values
    last_fetch_issue_ids: List[int] = convert_list_of_str_to_int(last_run.get('issue_ids', []))
    last_fetch_id = last_run.get('id', id_offset)
    if last_fetch_id in [0, '0'] and issue_field_to_fetch_from == 'id':
        # If last_fetch_id is equal to zero, and the user wants to fetch using the issue ID, then we automatically
        # acquire the smallest issue ID with respect to the query
        _, smallest_id_offset = get_smallest_id_offset_for_query(client=client, query=fetch_query)
        if not smallest_id_offset:
            raise DemistoException('The fetch query configured returned no Jira issues, please update it.')
        last_fetch_id = smallest_id_offset
        demisto.debug(f'The smallest ID offset with respect to the fetch query is {last_fetch_id}' if last_fetch_id else
                      'No smallest ID found since the fetch query returns 0 results')
    new_fetch_created_time = last_fetch_created_time = last_run.get('created_date', '')
    new_fetch_updated_time = last_fetch_updated_time = last_run.get('updated_date', '')
    incidents: List[Dict[str, Any]] = []
    demisto.debug('Creating the fetch query')
    fetch_incidents_query = create_fetch_incidents_query(
        issue_field_to_fetch_from=issue_field_to_fetch_from,
        fetch_query=fetch_query,
        last_fetch_id=last_fetch_id,
        last_fetch_created_time=last_fetch_created_time,
        last_fetch_updated_time=last_fetch_updated_time,
        first_fetch_interval=convert_string_date_to_specific_format(
            string_date=first_fetch_interval),
        issue_ids_to_exclude=last_fetch_issue_ids)
    demisto.debug(f'The fetch query: {fetch_incidents_query}' if fetch_incidents_query else 'No fetch query created')
    query_params = create_query_params(jql_query=fetch_incidents_query, max_results=max_fetch_incidents)
    new_issue_ids: List[int] = []
    demisto.debug(f'Running the query with the following parameters {query_params}')
    try:
        if query_res := client.run_query(query_params=query_params):
            for issue in query_res.get('issues', []):
                demisto.debug(f'Creating an incident for Jira issue: {issue}')

                issue_id: int = int(issue.get('id'))  # The ID returned by the API is an integer
                demisto.debug(f'Creating an incident for Jira issue with ID: {issue_id}')
                new_issue_ids.append(issue_id)
                last_fetch_id = issue_id
                demisto.debug(f'Incident we got so far: {new_issue_ids}')
                new_fetch_created_time = convert_string_date_to_specific_format(
                    string_date=demisto.get(issue, 'fields.created') or '')
                demisto.debug(f'Converted created time to {new_fetch_created_time}')
                new_fetch_updated_time = convert_string_date_to_specific_format(
                    string_date=demisto.get(issue, 'fields.updated') or '')
                demisto.debug(f'Converted updated time to {new_fetch_updated_time}')
                demisto.debug('Starting to parse custom fields.')

                parse_custom_fields(issue=issue, issue_fields_id_to_name_mapping=query_res.get('names', {}))
                demisto.debug('Finished parsing custom fields. Starting build an incident')

                incidents.append(create_incident_from_issue(
                    client=client, issue=issue, fetch_attachments=fetch_attachments, fetch_comments=fetch_comments,
                    mirror_direction=mirror_direction,
                    comment_tag_from_jira=comment_tag_from_jira,
                    comment_tag_to_jira=comment_tag_to_jira,
                    attachment_tag_from_jira=attachment_tag_from_jira,
                    attachment_tag_to_jira=attachment_tag_to_jira))
                demisto.debug('Finished building incident.')

    except Exception as e:
        demisto.debug('Failure detected: {e}.')

        if 'Issue does not exist' in str(e) and issue_field_to_fetch_from == 'id' and str(id_offset) == str(last_fetch_id):
            # If entered here, this means the user wants to fetch using the issue ID, and has given an incorrect issue ID
            # to start fetching from, other than 0.
            _, smallest_issue_id = get_smallest_id_offset_for_query(client=client, query=fetch_query)
            raise DemistoException(
                f'The smallest issue ID with respect to the fetch query is {smallest_issue_id}, please configure it in the'
                ' "Issue index to start fetching incidents from" parameter.'
                if smallest_issue_id
                else 'The id that was configured does not exist in the Jira instance, '
                     'and the fetch query returned no results, therefore, could not start fetching.'
            ) from e
    # If we did no progress in terms of time (the created, or updated time stayed the same as the last fetch), we should keep the
    # ids of the last fetch until progress is made, so we exclude them in the next fetch.
    demisto.debug(
        f'Params to validate: {issue_field_to_fetch_from=}'
        f'{new_fetch_created_time=}, {last_fetch_created_time=}'
        f'{new_fetch_updated_time=},{last_fetch_updated_time=}'
    )

    if (
        (issue_field_to_fetch_from == 'created date'
         and new_fetch_created_time == last_fetch_created_time)
        or (issue_field_to_fetch_from == 'updated date'
            and new_fetch_updated_time == last_fetch_updated_time)
    ):
        new_issue_ids.extend(last_fetch_issue_ids)
    demisto.debug('Setting last run.')

    demisto.setLastRun({
        'issue_ids': new_issue_ids or last_fetch_issue_ids,
        'id': last_fetch_id,
        'created_date': new_fetch_created_time or last_fetch_created_time,
        'updated_date': new_fetch_updated_time or last_fetch_updated_time,
    })
    return incidents


def parse_custom_fields(issue: Dict[str, Any], issue_fields_id_to_name_mapping: Dict[str, str]):
    """This function will parse custom fields returned by the API, where it will show the display name of
    the custom field, since the ids of the custom fields are not intuitive.

    Args:
        issue (Dict[str, Any]): The issue object returned from the API.
        issue_fields_id_to_name_mapping (Dict[str, str]): A mapping between the ids and the display names of the
        issue fields.
    """
    issue_fields = issue.get('fields', {})
    for issue_field_id in issue_fields:
        if issue_field_id.startswith('customfield'):
            issue_fields |= JiraIssueFieldsParser.get_raw_field_data_context(
                issue_data=issue, issue_field_id=issue_field_id,
                issue_fields_id_to_name_mapping=issue_fields_id_to_name_mapping)


def convert_list_of_str_to_int(list_to_convert: List[str] | List[int]) -> List[int]:
    """This function converts a list of strings to a list of integers.

    Args:
        list_to_convert (List[str] | List[int]): A list of strings in numeric form.

    Raises:
        DemistoException: If the list has a string that is not in numeric form.

    Returns:
        List[int]: A list of integers
    """
    converted_list: List[int] = []
    for item in list_to_convert:
        try:
            converted_list.append(int(item))
        except Exception as e:
            raise DemistoException(
                f'Could not convert list of strings to int, error message: {e}\n'
            ) from e
    return converted_list


def create_fetch_incidents_query(issue_field_to_fetch_from: str, fetch_query: str, last_fetch_id: int,
                                 last_fetch_created_time: str, last_fetch_updated_time: str,
                                 first_fetch_interval: str, issue_ids_to_exclude: List[int]) -> str:
    """This is in charge of returning the query to use to fetch the appropriate incidents.
    NOTE: It is important to add 'ORDER BY {the issue field to fetch from} ASC' in order to retrieve the data in ascending order,
    so we could keep save the latest fetch incident (according to issue_field_to_fetch_from) and fetch only new incidents,
    in other words, incidents that are newer with respect to issue_field_to_fetch_from.
    Args:
        issue_field_to_fetch_from (str): The issue field to fetch from, id or created time.
        fetch_query (str): The fetch query configured.
        last_fetch_id (str): The id of the last fetched issue.
        last_fetch_created_time (str): The created time of the last fetch issue.
        last_fetch_updated_time (str): The updated time of the last fetch issue.
        first_fetch_interval (str): The first fetch interval to fetch from if the fetch timestamp is empty,
        and we are fetching using created or updated time.
        issue_ids_to_exclude (List[int]): The ids of the issues that we want to exclude.

    Raises:
        DemistoException: If we were not able to create a fetch query.

    Returns:
        str: The query to use to fetch the appropriate incidents.
    """
    issue_field_in_fetch_query_error_message = 'The issue field to fetch by cannot be in the fetch query'
    if issue_field_to_fetch_from in fetch_query:
        raise DemistoException(issue_field_in_fetch_query_error_message)
    error_message = f'Could not create the proper fetch query for the issue field {issue_field_to_fetch_from}'
    exclude_issue_ids_query = f" AND ID NOT IN ({', '.join(map(str, issue_ids_to_exclude))}) " if issue_ids_to_exclude else ' '
    if issue_field_to_fetch_from == 'id':
        if 'id' not in fetch_query:
            return f'{fetch_query} AND id >= {last_fetch_id}{exclude_issue_ids_query}ORDER BY id ASC'
        error_message = f'{error_message}\n{issue_field_in_fetch_query_error_message}'
    elif issue_field_to_fetch_from == 'created date':
        if 'created' not in fetch_query:
            return (f'{fetch_query} AND created >= "{last_fetch_created_time or first_fetch_interval}"{exclude_issue_ids_query}'
                    'ORDER BY created ASC')
        error_message = f'{error_message}\n{issue_field_in_fetch_query_error_message}'
    elif issue_field_to_fetch_from == 'updated date':
        if 'updated' not in fetch_query:
            return (f'{fetch_query} AND updated >= "{last_fetch_updated_time or first_fetch_interval}"{exclude_issue_ids_query}'
                    'ORDER BY updated ASC')
        error_message = f'{error_message}\n{issue_field_in_fetch_query_error_message}'
    raise DemistoException(error_message)


def get_comments_entries_for_fetched_incident(
        client: JiraBaseClient, issue_id_or_key: str) -> List[Dict[str, str]]:
    """Return the comments' entries, for a fetched incident.

    Args:
        client (JiraBaseClient): The Jira client.
        issue_id_or_key (str): The issue id or key.

    Returns:
        List[Dict[str, Any]]: The comment entries for a fetched or mirrored incident.
    """
    comments_entries: List[Dict[str, str]] = []
    get_comments_response = client.get_comments(issue_id_or_key=issue_id_or_key)
    if comments_response := get_comments_response.get('comments', []):
        for comment_response in comments_response:
            comment_entry = extract_comment_entry_from_raw_response(comment_response)
            comments_entries.append(comment_entry)
    return comments_entries


def get_attachments_entries_for_fetched_incident(
        client: JiraBaseClient,
        attachments_metadata: List[Dict[str, Any]],
        incident_modified_date: datetime | None = None,
        user_timezone_name: str = "") -> List[Dict[str, Any]]:
    """Return the attachments' entries for a fetched and mirrored incident

    Args:
        client (JiraBaseClient): The Jira client.
        attachments_metadata (List[str]): The metadata of the attachments, which includes the ids and created time of the
        attachments.
        incident_modified_date (datetime | None): The modified date of the incident.
        user_timezone_name (str): The timezone of the user.

    Returns:
        List[Dict[str, Any]]: The attachment entries for a fetched or mirrored incident.
    """
    attachment_ids: List[str] = []
    attachments_entries: List[Dict[str, Any]] = []
    for attachment_metadata in attachments_metadata:
        if (incident_modified_date
            and (attachment_created_date := dateparser.parse(attachment_metadata.get('created', ''),
                                                             settings={'TIMEZONE': user_timezone_name}))
                and attachment_created_date <= incident_modified_date):
            demisto.debug(f"The attachment with the id {attachment_metadata.get('id', '')} was created before the incident"
                          f" was modified, therefore, it will not be fetched.")
            continue
        attachment_id = attachment_metadata.get('id', '')
        attachments_entries.append(create_file_info_from_attachment(
            client=client, attachment_id=attachment_id
        ))
        attachment_ids.append(attachment_id)
    demisto.debug(f"The fetched attachments' ids {attachment_ids}")
    return attachments_entries


def create_incident_from_issue(client: JiraBaseClient, issue: Dict[str, Any], fetch_attachments: bool, fetch_comments: bool,
                               mirror_direction: str, comment_tag_from_jira: str, comment_tag_to_jira: str,
                               attachment_tag_from_jira: str, attachment_tag_to_jira: str) -> Dict[str, Any]:
    """Create an incident from a Jira Issue.

    Args:
        client (JiraBaseClient): The Jira client.
        issue (Dict[str, Any]): The issue object to create the incident from.
        fetch_attachments (bool): Whether to fetch the attachments or not.
        fetch_comments (bool): Whether to fetch the comments or not.
        mirror_direction (str): The mirroring direction.
        comment_tag_from_jira (str): The comment tag to add to the entry if the comment is from Jira.
        attachment_tag_from_jira (str): The attachment tag to add to the attachment if it is from Jira.
        comment_tag_to_jira (str): The comment tag to add to the entry if the comment should be mirrored to Jira.
        attachment_tag_to_jira (str): The attachment tag to add to the attachment if it should be mirrored to Jira.

    Returns:
        Dict[str, Any]: A dictionary that is represents an incident.
    """
    issue_description: dict = JiraIssueFieldsParser.get_description_context(issue_data=issue)
    issue_parsed_description: str = issue_description.get('Description', '')
    issue_raw_description: str = issue_description.get('RawDescription', '')
    issue_id = str(issue.get('id'))
    labels = [
        {'type': 'issue', 'value': json.dumps(issue)},
        {'type': 'id', 'value': issue_id},
        {'type': 'lastViewed', 'value': str(demisto.get(issue, 'fields.lastViewed'))},
        {'type': 'priority', 'value': str(demisto.get(issue, 'fields.priority.name'))},
        {'type': 'status', 'value': str(demisto.get(issue, 'fields.status.name'))},
        {'type': 'project', 'value': str(demisto.get(issue, 'fields.project.name'))},
        {'type': 'updated', 'value': str(demisto.get(issue, 'fields.updated'))},
        {'type': 'reportername', 'value': str(demisto.get(issue, 'fields.reporter.displayName'))},
        {'type': 'reporteremail', 'value': str(demisto.get(issue, 'fields.reporter.emailAddress'))},
        {'type': 'created', 'value': str(demisto.get(issue, 'fields.created'))},
        {'type': 'summary', 'value': str(demisto.get(issue, 'fields.summary'))},
        {'type': 'description', 'value': issue_parsed_description},
        {'type': 'rawDescription', 'value': issue_raw_description},
    ]
    issue['parsedDescription'] = issue_parsed_description
    demisto.debug(f'Extracting extra data for {issue_id}.')

    issue |= add_extracted_data_to_incident(issue=issue)
    incident_name = f"Jira issue: {issue.get('id')}"

    severity = get_jira_issue_severity(issue_field_priority=demisto.get(issue, 'fields.priority') or {})

    attachments: List[Dict[str, Any]] = []
    if fetch_attachments:
        demisto.debug(f'Fetching attachment for {issue_id}.')
        attachments = get_fetched_attachments(client=client, issue=issue)
    if fetch_comments:
        demisto.debug(f'Fetching comments for {issue_id}.')

        comments_entries = get_fetched_comments(client, issue_id)
        issue['extractedComments'] = comments_entries
        labels.append({'type': 'comments', 'value': str(comments_entries)})

    issue['mirror_direction'] = MIRROR_DIRECTION_DICT.get(mirror_direction)

    issue['mirror_tags'] = [
        comment_tag_from_jira,
        comment_tag_to_jira,
        attachment_tag_from_jira,
        attachment_tag_to_jira
    ]
    issue['mirror_instance'] = demisto.integrationInstance()
    issue['extractedAttachments'] = attachments

    # Fetch any forms for the issue. When using DataCenter onPrem this will fail.
    if isinstance(client, JiraOnPremClient):
        try:
            _, forms = get_issue_forms(client, str(issue.get('key')))
            issue['forms'] = forms
        except DemistoException:
            demisto.debug(f'Failed to get reports for {issue_id}, Not retrieving. Error: {traceback.format_exc()}')
            pass

    demisto.debug(f'Incident for issue {issue_id} is being created.')

    return {
        "name": incident_name,
        "labels": labels,
        "details": issue_parsed_description,
        "severity": severity,
        "attachment": attachments,
        "rawJSON": json.dumps(issue)
    }


def get_fetched_attachments(client: JiraBaseClient, issue: Dict[str, Any]) -> List[Dict[str, Any]]:
    """This function is in charge of fetching the attachments when fetching an incident if the user configured to fetch
    the attachments.

    Args:
        client (JiraBaseClient): The Jira client.
        issue (Dict[str, Any]): The issue object returned from the API, which holds the data of the incident.

    Returns:
        List[Dict[str, Any]]: The attachments' entries to return as part of the incident.
    """
    attachments: List[Dict[str, Any]] = []
    demisto.debug('Fetching attachments')
    attachments_entries = get_attachments_entries_for_fetched_incident(
        client=client,
        attachments_metadata=demisto.get(issue, 'fields.attachment') or [],
    )
    for attachment_entry in attachments_entries:
        if attachment_entry['Type'] != EntryType.ERROR:
            attachments.append({'path': attachment_entry.get('FileID', ''),
                                'name': attachment_entry.get('File', '')})
        else:
            demisto.debug(f'The attachment entry {attachment_entry} has an error')
    return attachments


def get_fetched_comments(client: JiraBaseClient, issue_id: str) -> List[Dict[str, str]]:
    """This function is in charge of fetching the comments when fetching an incident if the user configured to fetch
    the comments.

    Args:
        client (JiraBaseClient): The Jira client.
        issue_id (str): The issue id that was fetched.

    Returns:
        List[Dict[str, str]]: The fetched comments' entries.
    """
    demisto.debug('Fetching comments')
    comments_entries = get_comments_entries_for_fetched_incident(client=client, issue_id_or_key=issue_id)
    demisto.debug(f'Fetched comments {comments_entries}')
    return comments_entries


def add_extracted_data_to_incident(issue: Dict[str, Any]) -> Dict[str, Any]:
    """This function extracts data from the issue response returned from the API, to add it to the given issue object,
    so it can be forwarded as part of the incident's data, since most of the data returned from the API contains a lot
    of nested objects, which require further extraction.
    The data that is extracted: Subtasks, Creator, Components

    Args:
        issue (Dict[str, Any]): The issue object returned from the API.

    Returns:
        Dict[str, Any]: The extracted data which will be added to the incident.
    """
    return {
        'extractedSubtasks': JiraIssueFieldsParser.get_subtasks_context(issue_data=issue).get('Subtasks') or [],
        'extractedCreator': JiraIssueFieldsParser.get_creator_context(issue_data=issue).get('Creator') or '',
        'extractedComponents': JiraIssueFieldsParser.get_components_context(issue_data=issue).get('Components') or []
    }


def get_jira_issue_severity(issue_field_priority: Dict[str, Any]) -> int:
    """Returns the severity of the incident according to the priority of the issue.

    Args:
        issue_field_priority (Dict[str, Any]): The priority field of the issue.

    Returns:
        int: A severity integer, where 4 is the highest, and 0 the lowest.
    """
    severity = 0
    if issue_priority_name := issue_field_priority.get('name', ''):
        if issue_priority_name == 'Highest':
            severity = 4
        elif issue_priority_name == 'High':
            severity = 3
        elif issue_priority_name == 'Medium':
            severity = 2
        elif issue_priority_name in ['Low', 'Lowest']:
            severity = 1
    return severity


def convert_string_date_to_specific_format(string_date: str, date_format: str = '%Y-%m-%d %H:%M',
                                           dateparser_settings: Any | None = None) -> str:
    """Convert a string that acts as a date to a specific format. Default is %Y-%m-%d %H:%M

    Args:
        string_date (str): The date as a string, or an empty string if there is not last fetch date.
        date_format (str): The format of the date to return. Default is %Y-%m-%d %H:%M
        dateparser_settings (Any): Configured settings to use in dateparser.parse()

    Raises:
        DemistoException: When last_fetch_date is not a valid date.

    Returns:
        str: A string representing the date in %Y-%m-%d %H:%M format, or an empty string if string_date is an
        empty string.
    """
    if not string_date:
        return ''
    if parsed_string_date := dateparser.parse(string_date, settings=dateparser_settings):
        return parsed_string_date.strftime(date_format)
    raise DemistoException(f'Could not parse the following date: {string_date}.')


# Mirroring
def get_user_timezone(client: JiraBaseClient) -> str:
    """Returns the timezone of the Jira user.
    This will also print to the debug console the timezone of the Jira user.

    Args:
        client (JiraBaseClient): The Jira client

    Returns:
        str: The timezone of the Jira user.
    """
    user_info_res = client.get_user_info()
    if not (timezone_name := user_info_res.get('timeZone', '')):
        raise DemistoException('Could not get Jira\'s timezone, the following response was'
                               f' returned:\n{user_info_res}, with timezone:\n{timezone_name}')
    demisto.debug(f'Timezone of the Jira user: {timezone_name}')
    return timezone_name


def get_system_timezone() -> Any:
    """Returns the system's timezone.
    This will also print to the debug console the system timezone.
    """
    system_timezone = datetime.utcnow().astimezone().tzinfo
    demisto.debug(f'Timezone of the system: {system_timezone}')
    return system_timezone


def get_modified_remote_data_command(client: JiraBaseClient, args: Dict[str, Any]) -> GetModifiedRemoteDataResponse:
    """Available from Cortex XSOAR version 6.1.0. This command queries for incidents that were modified since the last
    update. If the command is implemented in the integration, the get-remote-data command will only be performed on
    incidents returned from this command, rather than on all existing incidents.

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, Any]): args['last_update'] - Date string represents the last time we retrieved modified incidents for this
     integration.

    Returns:
        GetModifiedRemoteDataResponse: The object that maintains a list of incident ids to run
     'get-remote-data' on.
    """
    demisto.debug('Running get_modified_remote_data_command')
    remote_args = GetModifiedRemoteDataArgs(args)
    last_update_date: str = remote_args.last_update
    modified_issues_ids = []
    try:
        user_timezone_name = get_user_timezone(client=client)
        modified_issues_ids = get_modified_issue_ids(
            client=client, last_update_date=last_update_date, timezone_name=user_timezone_name,
        )
    except Exception as e:
        demisto.error(f'An error has occurred. Error message:\n{e}')
    finally:
        return GetModifiedRemoteDataResponse(modified_issues_ids)


def get_modified_issue_ids(client: JiraBaseClient, last_update_date: str, timezone_name: str) -> List:
    last_update = convert_string_date_to_specific_format(last_update_date,
                                                         dateparser_settings={'TIMEZONE': timezone_name})
    demisto.debug(f'Performing get-modified-remote-data command. Last update is: {last_update}')
    query_params = create_query_params(jql_query=f'updated > "{last_update}"', max_results=100)
    query_res = client.run_query(query_params=query_params)
    modified_issues = query_res.get('issues', [])
    result = [issue.get('id', '') for issue in modified_issues]
    demisto.debug(
        f'The number of modified issues to update in XSOAR in this run is {len(result)}: {",".join(result)}'
    )
    return result


def get_remote_data_command(client: JiraBaseClient, args: Dict[str, Any],
                            attachment_tag_from_jira: str, comment_tag_from_jira: str,
                            mirror_resolved_issue: bool, fetch_attachments: bool,
                            fetch_comments: bool) -> GetRemoteDataResponse:
    """ Mirror-in data to incident from Jira into XSOAR 'JiraV3 Incident' incident.

    NOTE: Documentation on mirroring - https://xsoar.pan.dev/docs/integrations/mirroring_integration

    Args:
        client (JiraBaseClient): The Jira client.
        attachment_tag (str): The attachment tag, to tag the mirrored attachments.
        comment_tag (str): The comment tag, to tag the mirrored comments.
        fetch_attachments (bool): Whether to fetch the attachments or not.
        fetch_comments (bool): Whether to fetch the comments or not.
        mirror_resolved_issue (bool): Whether to mirror Jira issues that have been resolved, or have the status `Done`.
        args:
            id: Remote incident id.
            lastUpdate: Server last sync time with remote server.

    Returns:
        GetRemoteDataResponse: Structured incident response.
    """
    updated_incident: Dict[str, Any] = {}
    parsed_entries: List[Dict[str, Any]] = []
    parsed_args = GetRemoteDataArgs(args)
    try:
        issue_id = parsed_args.remote_incident_id
        demisto.debug(f'Performing get-remote-data command with incident id: {issue_id} '
                      f'and last_update: {parsed_args.last_update}')
        # Get raw response for issue ID
        issue = client.get_issue(issue_id_or_key=issue_id)
        demisto.debug(f'Got remote data for incident {issue_id}')
        parse_custom_fields(issue=issue,
                            issue_fields_id_to_name_mapping=issue.get('names', {}) or {})
        demisto.debug(f'Raw issue response: {issue}')
        issue['parsedDescription'] = JiraIssueFieldsParser.get_description_context(
            issue).get('Description') or ''
        issue |= add_extracted_data_to_incident(issue=issue)
        user_timezone_name = get_user_timezone(client=client)
        _ = get_system_timezone()
        demisto.debug(f'Issue modified date in Jira: {dateparser.parse(demisto.get(issue, "fields.updated"))}')
        demisto.debug(f'Incident Last update time: {dateparser.parse(parsed_args.last_update)}')
        demisto.debug('Updating incident from remote system')
        incident_modified_date = dateparser.parse(parsed_args.last_update, settings={'TIMEZONE': user_timezone_name})
        updated_incident = issue
        parsed_entries = get_updated_remote_data(
            client=client, issue=issue, updated_incident=updated_incident,
            issue_id=issue_id, mirror_resolved_issue=mirror_resolved_issue,
            attachment_tag_from_jira=attachment_tag_from_jira,
            comment_tag_from_jira=comment_tag_from_jira,
            user_timezone_name=user_timezone_name, incident_modified_date=incident_modified_date,
            fetch_attachments=fetch_attachments, fetch_comments=fetch_comments)
        if parsed_entries:
            demisto.debug(f'Update the next entries: {parsed_entries}')
        else:
            demisto.debug('No new entries to update.')

        return GetRemoteDataResponse(updated_incident, parsed_entries)

    except Exception as e:
        demisto.debug(f"Error in Jira incoming mirror for incident {parsed_args.remote_incident_id}"
                      f"Error message: {str(e)}")

        if "Rate limit exceeded" in str(e):
            return_error("API rate limit")

        incident_update = {}
        if updated_incident:
            updated_incident['in_mirror_error'] = str(e)
        else:
            incident_update = {
                'id': parsed_args.remote_incident_id,
                'in_mirror_error': str(e)
            }
        return GetRemoteDataResponse(
            mirrored_object=incident_update,
            entries=[]
        )


def get_updated_remote_data(client: JiraBaseClient, issue: Dict[str, Any], updated_incident: Dict[str, Any], issue_id: str,
                            mirror_resolved_issue: bool, attachment_tag_from_jira: str, comment_tag_from_jira: str,
                            user_timezone_name: str, incident_modified_date: datetime | None,
                            fetch_attachments: bool, fetch_comments: bool) -> List[Dict[str, Any]]:
    """This function is in charge of returning the parsed entries of the updated incident, while updating
    the content of updated_incident, which is in charge of holding the updated data of the incident (since arguments
    are passed by reference, we can update the object in this function, and the changes to the object will be reflected
    when we return to the function that called this function).

    Args:
        client (JiraBaseClient): The Jira client.
        issue (Dict[str, Any]): The issue object returned from the API.
        updated_incident (Dict[str, Any]): The object that will hold the updated data of the incident.
        issue_modified_date (datetime): Timestamp of the last updated time of the issue in Jira.
        attachment_tag_from_jira (str): The attachment tag to add to an entry to mirror it as an attachment from Jira.
        comment_tag_from_jira (str): The comment tag to add to an entry to mirror it as a comment from Jira.
        incident_modified_date (datetime): Timestamp of the last updated time of the incident in XSOAR, with timezone equal
        to the Jira user's timezone (using {'TIMEZONE': user_timezone_name} setting in dateparser.parse)
        issue_id (str): The issue id.
        user_timezone_name (str): The timezone of the Jira user.
        mirror_resolved_issue (bool): Whether to mirror Jira issues that have been resolved, or have the status `Done`.
        fetch_attachments (bool): Whether to fetch the attachments or not.
        fetch_comments (bool): Whether to fetch the comments or not.

    Returns:
        List[Dict[str, Any]]:  Parsed entries of the updated incident, which will be supplied to the class GetRemoteDataResponse.
    """
    parsed_entries: List[Dict[str, Any]] = []
    demisto.debug(f"Update incident, Incident name: Jira issue {issue.get('id')}"
                  f"Reason: Issue modified in remote")
    # Close incident if the Jira issue gets resolved, or its status gets updated to Done.
    if mirror_resolved_issue and (closed_issue := handle_incoming_resolved_issue(
        updated_incident
    )):
        demisto.debug(
            f'Closing incident with ID: {issue_id}, since corresponding issue was resolved')
        parsed_entries.append(closed_issue)

    # Mirroring attachments
    if fetch_attachments:
        attachments_entries = get_attachments_entries_for_fetched_incident(
            client=client,
            attachments_metadata=demisto.get(issue, 'fields.attachment') or [],
            incident_modified_date=incident_modified_date,
            user_timezone_name=user_timezone_name
        )
        attachments_incident_field = []
        demisto.debug(f'Got the following attachments entries {attachments_entries}')
        for attachment_entry in attachments_entries:
            if ATTACHMENT_MIRRORED_FROM_XSOAR not in attachment_entry.get('File', ''):
                attachment_entry['Tags'] = [attachment_tag_from_jira]
                parsed_entries.append(attachment_entry)
            attachments_incident_field.append({'path': attachment_entry.get('FileID', ''),
                                               'name': attachment_entry.get('File', '')})
        updated_incident['extractedAttachments'] = attachments_incident_field
    # Mirroring comments
    if fetch_comments:
        comments_entries = get_comments_entries_for_fetched_incident(
            client=client,
            issue_id_or_key=issue_id
        )
        for comment_entry in comments_entries:
            comment_body = comment_entry.get('Comment', '')
            if comment_updated_date := dateparser.parse(comment_entry.get('Updated', ''),
                                                        settings={'TIMEZONE': user_timezone_name}):
                if (
                    COMMENT_MIRRORED_FROM_XSOAR not in comment_body
                    and incident_modified_date
                    and comment_updated_date > incident_modified_date
                ):
                    # We only want to add comments as a Note Entry if it is newer than the incident's modified date.
                    parsed_entries.append({
                        'Type': EntryType.NOTE,
                        'Contents': f'{comment_body}\nJira Author: {comment_entry.get("UpdateUser")}',
                        'ContentsFormat': EntryFormat.TEXT,
                        'Tags': [comment_tag_from_jira],  # The list of tags to add to the entry
                        'Note': True,
                    })
                elif not incident_modified_date:
                    demisto.debug(f'Could not parse the incident updated date, got the following date: {incident_modified_date}')
            else:
                demisto.debug(
                    f'Could not parse the comment updated date, got the following date: {comment_entry.get("Updated", "")}')
        updated_incident['extractedComments'] = comments_entries
    return parsed_entries


def handle_incoming_resolved_issue(issue: Dict[str, Any]) -> Dict[str, Any]:
    """This function creates an entry to send to XSOAR, which will indicate that the incident that corresponds
    to the issue, transitioned to status `Done`, or has been resolved and closed, by checking the resolution time.
    NOTE: Checking the status if it equals to `Done` is not enough, since not every
    workflow has these two statuses, therefore, to make the implementation backwards compatible, this condition
    was left in V3, and an extra condition was added to check if the issue was `resolved`.

    Args:
        issue (Dict[str, Any]): The issue object returned from the API, which will be mirrored to XSOAR.

    Returns:
        Dict[str, Any]: An entry that indicates that the incident that corresponds to the issue will be closed.
    """
    closing_entry: Dict[str, Any] = {}
    issue_id = issue.get('id', '') or ''
    issue_fields = issue.get('fields') or {}
    resolution_date = ''
    if (demisto.get(issue_fields, 'status.name', '') == 'Done') \
            or (resolution_date := demisto.get(issue, 'fields.resolutiondate', '')):
        demisto.debug(f'Handling incoming resolved issue (id {issue_id}) with resolution date: {resolution_date}'
                      if resolution_date
                      else f'Handling incoming resolved issue (id {issue_id}) with status `Done`')
        closing_entry = {
            'Type': EntryType.NOTE,
            'Contents': {
                'dbotIncidentClose': True,
                'closeReason': CLOSE_INCIDENT_REASON,
            },
            'ContentsFormat': EntryFormat.JSON
        }
    return closing_entry


def issue_get_forms_command(client: JiraBaseClient, args: Dict[str, Any]) -> List[CommandResults]:
    """Retrieves all forms, including corresponding questions and answers, for a specified issue.

    :param client: The Jira client to use for making the API calls
    :type client: JiraBaseClient
    :param args: Generic arguments dict which has the argument `issue_id` for finding
                 the specific issue and it's forms
    :type args: Dict[str, Any]
    :raises DemistoException: When the command is tried for a Jira Cloud platform which is not supported.
    :raises ValueError: When the `issue_id` argument is not supplied
    :return: One CommandResult per form that is found with the form data
    :rtype: List[CommandResults]
    """
    if not isinstance(client, JiraOnPremClient):
        raise DemistoException('This command is only supported on Jira OnPrem')

    issue_id = args.get('issue_id', '')
    if not issue_id:
        raise ValueError('No issue_id specified for jira-get-issue-forms')

    raw, forms = get_issue_forms(client, issue_id)
    if not forms:
        return [CommandResults(readable_output="No forms found")]

    results = []
    for form in forms:
        results.append(CommandResults(
            outputs_prefix='Jira.Forms',
            outputs_key_field='ID',
            outputs=form,
            readable_output=f'Pulled data for form {form.get("ID")} from issue {issue_id}.',
            raw_response=raw
        ))
    return results


def get_user_info_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
    """Gets a user's information from Jira

    :param client: The Jira client for calling the API
    :type client: JiraBaseClient
    :param args: Generic arguments dict which has the argument `username` or `key` for finding
                 the user
    :type args: Dict[str, Any]
    :raises ValueError: When no key, username or accountId is provided to the command
    :return: The CommandResults object with the data returned by the API
    :rtype: CommandResults
    """
    if isinstance(client, JiraOnPremClient):
        demisto.debug("On prem check")
        # On prem allows key or username
        key = args.get('key', '')
        username = args.get('username', '')
        if key:
            identifier = f'key={key}'
        elif username:
            identifier = f'username={username}'
        else:
            raise ValueError('No key or username specified for jira-get-user-info')
        key_field = "Key"
    else:
        # Jira Cloud requires using account_id
        demisto.debug("Cloud check")
        account_id = args.get('account_id', '')
        if not account_id:
            raise ValueError('No account_id specified for jira-get-user-info')
        identifier = f'accountId={account_id}'
        key_field = "AccountID"

    response = client.get_user_info(identifier)
    if not response:
        return CommandResults(readable_output="No users found")

    output = {
        'Key': response.get('key', ''),
        'Name': response.get('name', ''),
        'Email': response.get('emailAddress', ''),
        'DisplayName': response.get('displayName', ''),
        'Active': response.get('active', ''),
        'Deleted': response.get('deleted', ''),
        'Timezone': response.get('timeZone', ''),
        'Locale': response.get('locale', ''),
        'AccountID': response.get('accountId', ''),  # Cloud only
        'AccountType': response.get('accountType', ''),  # Cloud only
    }

    remove_nulls_from_dictionary(output)

    return CommandResults(
        outputs_prefix='Jira.Users',
        outputs_key_field=key_field,
        outputs=output,
        raw_response=response
    )


def get_mapping_fields_command(client: JiraBaseClient) -> GetMappingFieldsResponse:
    """
    This command pulls the remote schema for the different incident types, and their associated incident fields,
    from the remote system.
    Returns: A list of keys you want to map
    """
    jira_incident_type_scheme = SchemeTypeMapping(type_name=JIRA_INCIDENT_TYPE_NAME)
    custom_fields = get_issue_fields_id_to_description_mapping(client=client)
    custom_fields.update(ISSUE_INCIDENT_FIELDS)
    for argument, description in custom_fields.items():
        jira_incident_type_scheme.add_field(name=argument, description=description)

    mapping_response = GetMappingFieldsResponse()
    mapping_response.add_scheme_type(jira_incident_type_scheme)

    return mapping_response


def update_remote_system_command(client: JiraBaseClient, args: Dict[str, Any], comment_tag_to_jira: str,
                                 attachment_tag_to_jira: str) -> str:
    """  Mirror-out data that is in XSOAR into a Jira issue.

    Notes:
        1. Documentation on mirroring - https://xsoar.pan.dev/docs/integrations/mirroring_integration

    Args:
        client (JiraBaseClient): The Jira client.
        args (Dict[str, Any]): A dictionary contains the next data regarding a modified incident: data, entries,
            incident_changed, remote_incident_id, inc_status, delta.
        comment_tag_to_jira (str): The comment tag to add to an entry to mirror it as a comment in Jira.
        attachment_tag_to_jira (str): The attachment tag to add to an entry to mirror it as an attachment in Jira.

    Returns: The incident id that was modified.
    """
    remote_args = UpdateRemoteSystemArgs(args)
    entries = remote_args.entries
    remote_id = remote_args.remote_incident_id
    delta = remote_args.delta
    demisto.debug(
        f'Update remote system check if need to update: remoteId: {remote_id}, incidentChanged: '
        f'{remote_args.incident_changed}, data:'
        f' {remote_args.data}, entries: {entries}')
    try:
        if delta and remote_args.incident_changed:
            demisto.debug(f'Got the following delta object: {delta}')
            demisto.debug(
                f'Got the following delta keys {list(delta.keys())} to update JiraV3 Incident {remote_id}'
            )
            # take the val from data as it's the updated value
            delta = {k: remote_args.data.get(k) for k in delta}
            demisto.debug(f'Sending the following data to edit the issue with: {delta}')
            if issue_fields := create_issue_fields(
                client=client,
                issue_args=delta,
                issue_fields_mapper=client.ISSUE_FIELDS_CREATE_MAPPER,
            ):
                demisto.debug(f'Updating the issue with the following issue fields: {issue_fields}')
                client.edit_issue(issue_id_or_key=remote_id, json_data=issue_fields)
                demisto.debug('Updated the fields of the remote system successfully')

        else:
            demisto.debug(f'Skipping updating remote incident fields [{remote_id}] '
                          f'as it is neither new nor changed')

        if entries:
            for entry in entries:
                entry_id = entry.get('id', '')
                entry_type = entry.get('type', '')
                entry_tags = entry.get('tags', [])
                demisto.debug(f'Got the entry tags: {entry_tags}')
                demisto.debug(f'Sending entry {entry_id}, type: {entry_type}')
                if entry_type == EntryType.FILE and attachment_tag_to_jira in entry_tags:
                    demisto.debug('Add new file')
                    file_path = demisto.getFilePath(entry_id)
                    file_name, file_extension = os.path.splitext(file_path.get('name', ''))
                    upload_XSOAR_attachment_to_jira(
                        client=client, entry_id=entry_id,
                        issue_id_or_key=remote_id,
                        attachment_name=f'{file_name}{ATTACHMENT_MIRRORED_FROM_XSOAR}{file_extension}')
                elif comment_tag_to_jira in entry_tags:
                    demisto.debug('Add new comment')
                    entry_content = f'{entry.get("contents", "")}\n\n{COMMENT_MIRRORED_FROM_XSOAR}'
                    comment_body = text_to_adf(entry_content) if isinstance(client, JiraCloudClient) else entry_content
                    payload = {
                        'body': comment_body
                    }
                    client.add_comment(issue_id_or_key=remote_id, json_data=payload)
            demisto.debug('Updated the entries (attachments and/or comments) of the remote system successfully')
    except Exception as e:
        demisto.error(f"Error in Jira outgoing mirror for incident {remote_args.remote_incident_id} \n"
                      f"Error message: {str(e)}")
    finally:
        return remote_id


def map_v2_args_to_v3(args: Dict[str, Any]) -> Dict[str, Any]:
    """As part of keeping Jira V3 backwards compatible, this function is in charge of mapping
    the command arguments of Jira V2 to the command arguments of Jira V3, since the command arguments
    of Jira V2 were inconsistent.
    """
    v3_args: Dict[str, Any] = {}
    demisto.debug(f'Got the following command arguments: {args}')
    for arg, value in args.items():
        if arg in ['issueId', 'issueIdOrKey']:
            # In v2, there was no differentiation between issue id and key arguments,
            # and in v3, we do differentiate.
            if is_issue_id(value):
                v3_args['issue_id'] = value
            else:
                v3_args['issue_key'] = value
        elif arg in V2_ARGS_TO_V3 and arg not in v3_args:
            v3_args[V2_ARGS_TO_V3[arg]] = value
        elif arg not in v3_args:
            # Since we are not breaking BC, we want to give the v2 arguments the priority.
            # therefore, the if statement that converts the v2 argument to v3 is executed before
            # this if statement, this way, the final argument is prioritized to v2.
            v3_args[arg] = value
    return v3_args


def get_issue_id_or_key(issue_id: str = '', issue_key: str = '') -> str:
    """Returns either the issue ID, or issue key.

    Args:
        issue_id (str, optional): The issue ID. Defaults to ''.
        issue_key (str, optional): issue key. Defaults to ''.

    Raises:
        DemistoException: If both issue ID, and key were given.
        DemistoException: If both issue ID, and key were not given.

    Returns:
        str: The issue ID, or key.
    """
    if not (issue_id or issue_key):
        raise DemistoException(ID_OR_KEY_MISSING_ERROR)
    if (issue_id and issue_key):
        raise DemistoException(ID_AND_KEY_GIVEN)
    return issue_id or issue_key


def validate_auth_params(
    username: str, api_key: str, client_id: str, client_secret: str
) -> None:
    is_basic_auth = bool(username or api_key)
    is_oauth2 = bool(client_id or client_secret)

    if (not is_basic_auth) and (not is_oauth2):
        raise DemistoException("The required parameters were not provided. See the help window for more information.")
    if is_basic_auth and is_oauth2:
        raise DemistoException("The `User name` or `API key` parameters cannot be provided together"
                               " with the `Client ID` or `Client Secret` parameters. See the help window for more information.")
    if is_basic_auth and not (username and api_key):
        raise DemistoException(
            "To use basic authentication, the 'User name' and 'API key' parameters are mandatory."
        )
    if is_oauth2 and not (client_id and client_secret):
        raise DemistoException(
            "To use OAuth 2.0, the 'Client ID' and 'Client Secret' parameters are mandatory."
        )


def main():  # pragma: no cover
    params: Dict[str, Any] = demisto.params()
    args = map_v2_args_to_v3(demisto.args())
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    # Basic authentication configuration params
    username = params.get("basic_credentials", {}).get('identifier', '')
    api_key = params.get("basic_credentials", {}).get('password', '')

    # Cloud + on-prem configuration params
    server_url = params.get('server_url', 'https://api.atlassian.com/ex/jira')
    client_id = params.get('credentials', {}).get('identifier', '')
    client_secret = params.get('credentials', {}).get('password', '')
    callback_url = params.get('callback_url', '')

    validate_auth_params(username, api_key, client_id, client_secret)

    # Cloud configuration params
    cloud_id = params.get('cloud_id', '')

    # Fetch params
    issue_field_to_fetch_from = params.get('issue_field_to_fetch_from', 'id')
    fetch_query = params.get('fetch_query', 'status!=done')
    id_offset = params.get('id_offset', 0)
    fetch_attachments = argToBoolean(params.get('fetch_attachments', False))
    fetch_comments = argToBoolean(params.get('fetch_comments', False))
    max_fetch = params.get('max_fetch', DEFAULT_FETCH_LIMIT)
    # This is used in the first fetch of an instance, when issue_field_to_fetch_from is either, updated date, or created date
    # It holds values such as: 3 days, 1 minute, 5 hours,...
    first_fetch_interval = params.get('first_fetch', DEFAULT_FIRST_FETCH_INTERVAL)
    mirror_direction = params.get('mirror_direction', 'None')
    comment_tag_to_jira = params.get('comment_tag_to_jira', 'comment tag')
    comment_tag_from_jira = params.get('comment_tag_from_jira', 'comment tag from Jira')
    if comment_tag_to_jira == comment_tag_from_jira:
        raise DemistoException('Comment Entry Tag to Jira and Comment Entry Tag '
                               'from jira cannot have the same value.')

    attachment_tag_to_jira = params.get('attachment_tag_to_jira', 'attachment tag')
    attachment_tag_from_jira = params.get('attachment_tag_from_jira', 'attachment tag from Jira')
    if attachment_tag_to_jira == attachment_tag_from_jira:
        raise DemistoException('Attachment Entry Tag to Jira and Attachment Entry Tag '
                               'from jira cannot have the same value.')
    # Mirroring params
    mirror_resolved_issue = argToBoolean(params.get('close_incident', False))
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    commands: Dict[str, Callable] = {
        'jira-oauth-start': ouath_start_command,
        'jira-oauth-complete': oauth_complete_command,
        'jira-oauth-test': test_authorization,
        'jira-get-comments': get_comments_command,
        'jira-get-issue': get_issue_command,
        'jira-create-issue': create_issue_command,
        'jira-issue-assign': update_issue_assignee_command,
        'jira-edit-issue': edit_issue_command,
        'jira-delete-issue': delete_issue_command,
        'jira-list-transitions': get_transitions_command,
        'jira-issue-upload-file': upload_file_command,
        'jira-issue-add-comment': add_comment_command,
        'jira-get-id-offset': get_id_offset_command,
        'jira-get-id-by-attribute': get_id_by_attribute_command,
        'jira-get-specific-field': get_specific_fields_command,
        'jira-issue-query': issue_query_command,
        'jira-issue-add-link': add_link_command,
        # New Commands
        'jira-issue-get-attachment': issue_get_attachment_command,
        'jira-issue-delete-comment': delete_comment_command,
        'jira-issue-edit-comment': edit_comment_command,
        'jira-issue-list-fields': list_fields_command,
        'jira-issue-to-backlog': issues_to_backlog_command,
        'jira-issue-to-board': issues_to_board_command,
        'jira-board-list': board_list_command,
        'jira-board-backlog-list': board_backlog_list_command,
        'jira-board-issue-list': board_issues_list_command,
        'jira-board-sprint-list': board_sprint_list_command,
        'jira-board-epic-list': board_epic_list_command,
        'jira-sprint-issue-list': sprint_issues_list_command,
        'jira-sprint-issue-move': issues_to_sprint_command,
        'jira-epic-issue-list': epic_issues_list_command,
        'jira-issue-link-type-get': get_issue_link_types_command,
        'jira-issue-to-issue-link': link_issue_to_issue_command,
        'jira-issue-delete-file': delete_attachment_file_command,
        'jira-issue-get-forms': issue_get_forms_command,
        'jira-get-user-info': get_user_info_command,
        'jira-create-metadata-field-list': get_create_metadata_field_command,
        'jira-create-metadata-issue-types-list': get_create_metadata_issue_types_command
    }
    try:
        client: JiraBaseClient
        if cloud_id:
            # Configure JiraCloudClient
            client = JiraCloudClient(
                cloud_id=cloud_id,
                verify=verify_certificate,
                proxy=proxy,
                client_id=client_id,
                client_secret=client_secret,
                callback_url=callback_url,
                server_url=server_url,
                username=username,
                api_key=api_key)
        else:
            # Configure JiraOnPremClient
            client = JiraOnPremClient(
                verify=verify_certificate,
                proxy=proxy,
                client_id=client_id,
                client_secret=client_secret,
                callback_url=callback_url,
                server_url=server_url,
                username=username,
                api_key=api_key)
        demisto.debug(f'The configured Jira client is: {type(client)}')

        if command == 'test-module':
            return_results(test_module(client=client))
        elif command in commands:
            return_results(commands[command](client, args))
        elif command == 'fetch-incidents':
            demisto.incidents(fetch_incidents(
                client=client,
                issue_field_to_fetch_from=issue_field_to_fetch_from,
                fetch_query=fetch_query,
                id_offset=arg_to_number(id_offset) or 0,
                fetch_attachments=fetch_attachments,
                fetch_comments=fetch_comments,
                max_fetch_incidents=arg_to_number(max_fetch) or DEFAULT_FETCH_LIMIT,
                first_fetch_interval=first_fetch_interval,
                mirror_direction=mirror_direction,
                comment_tag_to_jira=comment_tag_to_jira,
                comment_tag_from_jira=comment_tag_from_jira,
                attachment_tag_to_jira=attachment_tag_to_jira,
                attachment_tag_from_jira=attachment_tag_from_jira
            ),
            )

        elif demisto.command() == 'get-remote-data':
            return_results(get_remote_data_command(client=client, args=args, comment_tag_from_jira=comment_tag_from_jira,
                                                   attachment_tag_from_jira=attachment_tag_from_jira,
                                                   mirror_resolved_issue=mirror_resolved_issue,
                                                   fetch_attachments=fetch_attachments,
                                                   fetch_comments=fetch_comments))
        elif demisto.command() == 'get-modified-remote-data':
            return_results(get_modified_remote_data_command(client=client, args=args))
        elif demisto.command() == 'get-mapping-fields':
            return_results(get_mapping_fields_command(client=client))
        elif demisto.command() == 'update-remote-system':
            return_results(update_remote_system_command(client=client, args=args, comment_tag_to_jira=comment_tag_to_jira,
                                                        attachment_tag_to_jira=attachment_tag_to_jira))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

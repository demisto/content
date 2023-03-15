import urllib3
from abc import ABCMeta
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Callable
from collections import defaultdict
from bs4 import BeautifulSoup
urllib3.disable_warnings()
# Note: time.time_ns() is used instead of time.time() to avoid the precision loss caused by the float type.
# Source: https://docs.python.org/3/library/time.html#time.time_ns

""" CONSTANTS """
DEFAULT_FETCH_LIMIT = 50
DEFAULT_FIRST_FETCH_INTERVAL = '3 days'
DEFAULT_FETCH_INTERVAL = 1  # Unit is in minutes
DEFAULT_PAGE = 0
DEFAULT_PAGE_SIZE = 50
# Errors
OAUTH2_AUTH_NOT_APPLICABLE_ERROR = ('This command is not applicable to run with a Jira On Prem instance since On Prem instances'
                                    ' do not use OAuth2 for authorization.')
ID_OR_KEY_MISSING_ERROR = 'Please provide either the issue ID or key.'
EPIC_ID_OR_KEY_MISSING_ERROR = 'Please provide either the epic ID or key.'
# Scopes
SCOPES = [
    'write:jira-work',
    'read:jira-work',
    'read:jql:jira',
    'read:issue-details:jira',
    'read:epic:jira-software',
    'write:sprint:jira-software',
    'read:sprint:jira-software',
    'read:board-scope:jira-software',
    'write:board-scope:jira-software',
]


# Exception Classes
class RevokedAccessTokenError(Exception):
    """This class is used to raise exceptions when the access token stored in the integration context has been revoked
    or not valid anymore, so we could try to retrieve another access token using the refresh token or show an error message
    to the user.
    """

    def __init__(self):
        super().__init__(('The access token has been revoked or no authorization was done for your instance, if so,'
                          ' please refer to the documentation to authorize your instance'))
    pass


class JiraBaseClient(BaseClient, metaclass=ABCMeta):
    """
    This class is an abstract class. By using metaclass=ABCMeta, we tell python that this class behaves as an abstract
    class, where we want to define the definition of methods without implementing them, and the child classes will need to
    implement these methods.
    """
    # CONFLUENCE Add a simple description about the class hierarchy and why it was needed

    # CONFLUENCE Add the purpose of the two mappers
    ISSUE_FIELDS_MAPPER = {
        'summary': 'fields.summary',
        'project_key': 'fields.project.key',
        'project_id': 'fields.project.id',
        'issue_type_name': 'fields.issuetype.name',
        'issue_type_id': 'fields.issuetype.id',
        'project_name': 'fields.project.name',
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
        'components': 'fields.components'
    }

    ISSUE_UPDATE_MAPPER: Dict[str, tuple[str, str]] = {
        'summary': ('update.summary', ''),
        'project_key': ('update.project', 'key'),  # TODO Can we update ??
        'issue_type_name': ('update.issuetype', 'name'),
        'issue_type_id': ('update.issuetype', 'id'),
        'project_name': ('update.project', 'name'),  # TODO Can we update ??
        # 'description': 'fields.description',
        'labels': ('update.labels', ''),
        'priority': ('update.priority', 'name'),
        'due_date': ('update.duedate', ''),
        'assignee': ('update.assignee', 'name'),  # Does not work for Jira Cloud
        'assignee_id': ('update.assignee', 'accountId'),
        'reporter': ('update.reporter', 'name'),
        'reporter_id': ('update.reporter', 'accountId'),
        'parent_issue_key': ('update.parent', 'key'),
        'parent_issue_id': ('update.parent', 'id'),
        'environment': ('update.environment', ''),
        'security': ('update.security', 'name'),
        'components': ('update.components', '')
    }

    def __init__(self, base_url: str, proxy: bool, verify: bool,
                 callback_url: str):
        headers: Dict[str, str] = {'Accept': 'application/json'}
        self.callback_url = callback_url
        super().__init__(base_url=base_url, proxy=proxy, verify=verify, headers=headers)

    @abstractmethod
    def test_instance_connection(self) -> None:
        """This method is used to test the connectivity of each instance, each child will implement
        their own connectivity test
        """
        pass

    def http_request_with_access_token(self, method, headers: Dict[str, str] | None = None, url_suffix='', params=None, data=None,
                                       json_data=None, resp_type='json', ok_codes=None, full_url='',
                                       files: Dict[str, Any] | None = None) -> Any:
        """This method wraps the _http_request that comes from the BaseClient class, and adds the access_token
        of the client to the headers request, by calling the get_access_token method, which is an abstract method,
        and every child class mush implement it.
        Returns:
            _type_: _description_
        """
        if headers is None:
            headers = {}
        access_token = self.get_access_token()
        # We unite multiple headers (using the '|' character, pipe operator) since some requests may require extra headers
        # to work, and this way, we have the option to receive the extra headers and send them in the API request.
        request_headers = self._headers | headers | {'Authorization': f'Bearer {access_token}'}
        return self._http_request(method, url_suffix=url_suffix, full_url=full_url, params=params, data=data,
                                  json_data=json_data, resp_type=resp_type, ok_codes=ok_codes, files=files,
                                  headers=request_headers)

    # Authorization methods
    @abstractmethod
    def get_access_token(self) -> str:
        """This method is in charge of returning the access token stored in the integration context

        Returns:
            str: Returns the access token
        """
        pass

    @abstractmethod
    def oauth_start(self) -> str:
        """This method is used to start the OAuth process in order to retrieve the access and refresh token of the client,
        by returning a callback URL that the user must interact with in order to continue the process.

        Returns:
            str: The callback URL that the user will use in order to authenticate
        himself
        """
        pass

    @abstractmethod
    def oauth_complete(self, code: str) -> None:
        """This method is used to finish the authentication process. It receives a code string that was acquired
        after interacting with the callback URL, and this code string is sent to a Jira endpoint as an exchange
        for the access and refresh token, in which these tokens will be saved to the integration's context, along with
        any necessary data.

        Args:
            code (str): A code string that was acquired after interacting with the callback URL
        """
        pass

    # Query Requests
    @abstractmethod
    def run_query(self, query_params: Dict[str, Any]) -> Dict[str, Any]:
        """This method is in charge of running a JQL (Jira Query Language), and retrieving its results.

        Args:
            query_params (Dict[str, Any]): The query parameters, which will hold the query string itself,
            and any pagination data (using startAt and maxResults, as required by the API)

        Returns:
            Dict[str, Any]: The query results, which will hold the issues acquired from the query.
        """
        pass

    # Board Requests
    @abstractmethod
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
        pass

    @abstractmethod
    def get_issues_from_board(self, board_id: str, jql_query: str | None = None,
                              start_at: int | None = None, max_results: int | None = None) -> Dict[str, Any]:
        """This method is in charge of returning all issues from a specific board.

        Args:
            board_id (str): The board id
            jql_query (str | None, optional): The JQL query to filter specific issues. Defaults to None.
            start_at (int | None, optional): The starting index of the returned issues. Defaults to None.
            max_results (int | None, optional): The maximum number of issues to return per page. Defaults to None.

        Returns:
            Dict[str, Any]: The result of the API, which will hold the relevant issues.
        """
        pass

    @abstractmethod
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
        pass

    @abstractmethod
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
        pass

    @abstractmethod
    def issues_from_sprint_to_backlog(self, json_data: Dict[str, Any]) -> requests.Response:
        """This method is in charge of moving issues from a sprint, back to backlog of their board.

        Args:
            json_data (Dict[str, Any]): The data that is sent to the endpoint to move the issues from a sprint
            back to the backlog board.

        Returns:
            requests.Response: The raw response of the endpoint.
        """
        pass

    @abstractmethod
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
        pass

    @abstractmethod
    def get_board(self, board_id: str) -> Dict[str, Any]:
        """This method is in charge of retrieving the board corresponding to the board_id.

        Args:
            board_id (str): The board id to retrieve.

        Returns:
            Dict[str, Any]: The result of the API, which will hold the relevant board.
        """
        pass

    @abstractmethod
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
        pass

    @abstractmethod
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
        pass

    @abstractmethod
    def issues_to_sprint(self, sprint_id: str, json_data: Dict[str, Any]) -> requests.Response:
        """This method is in charge of moving issues to a specified sprint.

        Args:
            sprint_id (str): The sprint id where we want to move the issues to.
            json_data (Dict[str, Any]): The data that is sent to the endpoint to move the issues to a specified sprint.

        Returns:
            requests.Response: The raw response of the endpoint.
        """
        pass

    # Issue Fields Requests
    @abstractmethod
    def get_issue_fields(self) -> List[Dict[str, Any]]:
        """This method is in charge of returning system and custom issue fields

        Returns:
            List[Dict[str, Any]]: The result of the API, which will hold the issue fields.
        """
        pass

    # Issue Requests
    @abstractmethod
    def transition_issue(self, issue_id_or_key: str, json_data: Dict[str, Any]) -> requests.Response:
        """This method is in charge of transitioning an issue to a different status using a transition.

        Args:
            issue_id_or_key (str): The issue id or key.
            json_data (Dict[str, Any]): The data that is sent to the endpoint to transition an issue to another status.

        Returns:
            requests.Response: The raw response of the endpoint.
        """
        pass

    @abstractmethod
    def add_link(self, issue_id_or_key: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """This method is in charge of adding a link (web link) to a specific issue.

        Args:
            issue_id_or_key (str): The issue id or key.
            json_data (Dict[str, Any]): The data that is sent to the endpoint to add the web link to the issue.

        Returns:
            Dict[str, Any]: The result of the API, which will hold data about the added web link.
        """
        pass

    @abstractmethod
    def get_comments(self, issue_id_or_key: str, max_results: int = 50) -> Dict[str, Any]:
        """This method is in charge of returning the comments of a specific issue.

        Args:
            issue_id_or_key (str): The issue id or key.
            max_results (int, optional): The maximum number of comments. Defaults to 50.

        Returns:
            Dict[str, Any]: The result of the API, which will hold the comments of the issue.
        """
        pass

    @abstractmethod
    def delete_comment(self, issue_id_or_key: str, comment_id: str) -> requests.Response:
        """This method is in charge of deleting a comment from an issue.

        Args:
            issue_id_or_key (str): The issue id or key.
            comment_id (str): The id of the comment to delete.

        Returns:
            requests.Response: The raw response of the endpoint.
        """
        pass

    @abstractmethod
    def add_comment(self, issue_id_or_key: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """This method is in charge of adding a comment to an issue.

        Args:
            issue_id_or_key (str): The issue id or key.
            json_data (Dict[str, Any]): The data that is sent to the endpoint to add a comment to the issue.

        Returns:
            Dict[str, Any]: The result of the API, which will hold the newly added comment.
        """
        pass

    @abstractmethod
    def edit_comment(self, issue_id_or_key: str, comment_id: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """This method is in charge of editing a comment that is part of an issue.

        Args:
            issue_id_or_key (str): The issue id or key.
            comment_id (str): The id of the comment to edit.
            json_data (Dict[str, Any]): The data that is sent to the endpoint to edit the comment.

        Returns:
            Dict[str, Any]: The result of the API, which will hold the edited comment.
        """
        pass

    @ abstractmethod
    def get_issue(self, issue_id_or_key: str = '', full_issue_url: str = '') -> Dict[str, Any]:
        """This method is in charge of returning a specific issue.

        Args:
            issue_id_or_key (str, optional): The id or key of the issue to return. Defaults to ''.
            full_issue_url (str, optional): The full issue url, if given, it will act as the endpoint to retrieve the issue.
            Defaults to ''.

        Returns:
            Dict[str, Any]: The result of the API, which will hold issue.
        """
        pass

    @ abstractmethod
    def edit_issue(self, issue_id_or_key: str, json_data: Dict[str, Any]) -> requests.Response:
        """This method is in charge of editing a specific issue.

        Args:
            issue_id_or_key (str): The id or key of the issue to edit.
            json_data (Dict[str, Any]): The data that is sent to the endpoint to edit the issue.

        Returns:
            requests.Response: The raw response of the endpoint.
        """
        pass

    @ abstractmethod
    def delete_issue(self, issue_id_or_key: str) -> requests.Response:
        """This method is in charge of deleting a specific issue.

        Args:
            issue_id_or_key (str): The id or the key of the issue to delete.

        Returns:
            requests.Response: The raw response of the endpoint.
        """
        pass

    @ abstractmethod
    def get_transitions(self, issue_id_or_key: str) -> Dict[str, Any]:
        """This method is in charge of returning the available transitions of a specific issue.

        Args:
            issue_id_or_key (str): The issue id or key.

        Returns:
            Dict[str, Any]: The result of the API, which will hold available transitions.
        """
        pass

    @ abstractmethod
    def create_issue(self, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """This method is in charge of creating a new issue.

        Args:
            json_data (Dict[str, Any]): The data that is sent to the endpoint to create the issue.

        Returns:
            Dict[str, Any]: The results of the API, which will hold the newly created issue.
        """
        pass

    @abstractmethod
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
        pass

    @abstractmethod
    def get_issue_link_types(self) -> Dict[str, Any]:
        """This method is in charge of returning a list of all issue link types.

        Returns:
            Dict[str, Any]: The results of the API, which will hold the issue link types.
        """
        pass

    @abstractmethod
    def create_issue_link(self, json_data: Dict[str, Any]) -> requests.Response:
        """This method is in charge of creating an issue link between two issues.

        Args:
            json_data (Dict[str, Any]): The data that is sent to the endpoint to create the issue link.

        Returns:
            requests.Response: The raw response of the endpoint.
        """
        pass

    # Attachments Requests
    @ abstractmethod
    def add_attachment(self, issue_id_or_key: str, files: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
        """This method is in charge of adding an attachment to an issue.

        Args:
            issue_id_or_key (str): The issue id or key.
            files (Dict[str, Any] | None, optional): The data of the attachment to add. Defaults to None.

        Returns:
            List[Dict[str, Any]]: The results of the API, which will hold the newly added attachment.
        """
        pass

    @ abstractmethod
    def get_attachment_metadata(self, attachment_id: str) -> Dict[str, Any]:
        """This method is in charge of returning the metadata for an attachment.

        Args:
            attachment_id (str): The attachment id.

        Returns:
            Dict[str, Any]: The results of the API, which will hold the metadata of the attachment.
        """
        pass

    @ abstractmethod
    def get_attachment_content(self, attachment_id: str) -> str:
        """This method is in charge of returning the content for an attachment.

        Args:
            attachment_id (str): The attachment id.

        Returns:
            Dict[str, Any]: The results of the API, which will hold the content of the attachment.
        """
        pass

    # User Requests
    @ abstractmethod
    def get_id_by_attribute(self, attribute: str, max_results: int) -> List[Dict[str, Any]]:
        """This method is in charge of returning a list of users that match the attribute.

        Args:
            attribute (str): The attribute that will be matched against user attributes to find relevant users.
            max_results (int): The maximum number of issues to return per page

        Returns:
            List[Dict[str, Any]]: The results of the API, which will hold the users that match the attribute.
        """
        pass


class JiraCloudClient(JiraBaseClient):
    """This class inherits the JiraBaseClient class and implements the required abstract methods,
    with the addition of any required configurations and implementations of methods that are specific
    for Jira Cloud.
    """

    def __init__(self, proxy: bool, verify: bool, client_id: str, client_secret: str,
                 callback_url: str, cloud_id: str, server_url: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.cloud_id = cloud_id
        # TODO Need to add the scopes in the documentation (README and description)
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
                         base_url=f'{server_url}/{cloud_id}')

    def test_instance_connection(self) -> None:
        self.http_request_with_access_token(method='GET', url_suffix='rest/api/3/myself',
                                            resp_type='json')

    def get_access_token(self) -> str:
        # CONFLUENCE Explain the process of saving and retrieving the access token from the integration's context
        """This function is in charge of returning the access token stored in the integration context

        Raises:
            RevokedAccessTokenError: If the access token is not valid anymore

        Returns:
            str: The access token
        """
        integration_context = get_integration_context()
        token = integration_context.get('token', '')
        if not token:
            raise DemistoException(('No access token was configured, please complete the authorization process'
                                    ' as shown in the documentation'))
        valid_until = integration_context.get('valid_until', 0)
        current_time = get_current_time_in_seconds()
        if current_time >= valid_until:
            refresh_token = integration_context.get('refresh_token', '')
            if not refresh_token:
                raise DemistoException(('No refresh token was configured, please complete the authorization process'
                                        ' as shown in the documentation'))
            self.oauth2_retrieve_access_token(refresh_token=refresh_token)
            integration_context = get_integration_context()
            token = integration_context.get('token', '')
        return token

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
                               state='some_state',
                               response_type='code',
                               prompt='consent')
        res_auth_url = self._http_request(method='GET',
                                          full_url='https://auth.atlassian.com/authorize',
                                          params=params,
                                          resp_type='response')
        if(res_auth_url.url):
            return res_auth_url.url
        raise DemistoException('No URL was returned.')

    def oauth2_retrieve_access_token(self, code: str = '', refresh_token: str = '') -> None:
        if(code and refresh_token):
            # The code argument is used when the user authenticates using the authorization URL process
            # (which uses the callback URL), and the refresh_token is used when we want to authenticate the user using a
            # refresh token saved in the integration's context.
            raise DemistoException(('Both authorization code and refresh token were given to retrieve an'
                                   ' access token, please only provide one'))
        if(not (code or refresh_token)):
            # If reached here, that means both the authorization code and refresh tokens were empty.
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
            full_url='https://auth.atlassian.com/oauth/token',
            data=data,
            resp_type='json',
        )
        integration_context = get_integration_context()
        new_authorization_context = {
            'token': res_access_token.get('access_token', ''),
            'scopes': res_access_token.get('scope', ''),
            'valid_until': get_current_time_in_seconds() + res_access_token.get('expires_in', 0),
            'refresh_token': res_access_token.get('refresh_token', '')
        }
        integration_context |= new_authorization_context
        set_integration_context(integration_context)

    # Query Requests
    def run_query(self, query_params: Dict[str, Any]) -> Dict[str, Any]:
        # We supply the renderedFields query parameter to retrieve some content in HTML format, since Jira uses a format
        # called ADF, and it is easier to parse the content in HTML format, rather than ADF.
        # We also supply the fields: *all to return all the fields from an issue (specifically the field that holds
        # data about the attachments in the issue), otherwise, it won't get returned in the query.
        query_params |= {'expand': 'renderedFields,transitions,names', 'fields': ['*all']}
        return self.http_request_with_access_token(
            method='GET', url_suffix='rest/api/3/search', params=query_params
        )

    # Board Requests
    def get_issues_from_backlog(self, board_id: str, jql_query: str | None = None,
                                start_at: int | None = None, max_results: int | None = None) -> Dict[str, Any]:
        query_params = assign_params(
            jql=jql_query,
            startAt=start_at,
            maxResults=max_results,
        )
        return self.http_request_with_access_token(
            method='GET',
            url_suffix=f'rest/agile/1.0/board/{board_id}/backlog',
            params=query_params
        )

    def get_issues_from_board(self, board_id: str, jql_query: str | None = None,
                              start_at: int | None = None, max_results: int | None = None) -> Dict[str, Any]:
        query_params = assign_params(
            jql=jql_query,
            startAt=start_at,
            maxResults=max_results
        )
        return self.http_request_with_access_token(
            method='GET',
            url_suffix=f'rest/agile/1.0/board/{board_id}/issue',
            params=query_params
        )

    def get_sprints_from_board(self, board_id: str, start_at: int | None = None,
                               max_results: int | None = None) -> Dict[str, Any]:
        query_params = assign_params(
            startAt=start_at,
            maxResults=max_results
        )
        return self.http_request_with_access_token(
            method='GET',
            url_suffix=f'rest/agile/1.0/board/{board_id}/sprint',
            params=query_params
        )

    def get_epics_from_board(self, board_id: str, done: str, start_at: int | None = None,
                             max_results: int | None = None) -> Dict[str, Any]:
        query_params = assign_params(
            startAt=start_at,
            maxResults=max_results,
            done=done
        )
        return self.http_request_with_access_token(
            method='GET',
            url_suffix=f'rest/agile/1.0/board/{board_id}/epic',
            params=query_params
        )

    def get_board(self, board_id: str) -> Dict[str, Any]:
        return self.http_request_with_access_token(
            method='GET',
            url_suffix=f'rest/agile/1.0/board/{board_id}',
        )

    def get_boards(self, board_type: str | None = None, project_key_id: str | None = None, board_name: str | None = None,
                   start_at: int | None = None, max_results: int | None = None) -> Dict[str, Any]:
        query_params = assign_params(
            type=board_type,
            projectKeyOrId=project_key_id,
            name=board_name,
            startAt=start_at,
            maxResults=max_results
        )
        return self.http_request_with_access_token(
            method='GET',
            url_suffix='rest/agile/1.0/board',
            params=query_params
        )

    def issues_from_sprint_to_backlog(self, json_data: Dict[str, Any]) -> requests.Response:
        return self.http_request_with_access_token(
            method='POST',
            url_suffix='rest/agile/1.0/backlog/issue',
            json_data=json_data,
            resp_type='response',
        )

    def issues_to_backlog(self, board_id, json_data: Dict[str, Any]) -> requests.Response:
        """This method is in charge of moving issues, back to backlog of their board.

        Args:
            board_id (_type_): The id of the board that the issues reside in.
            json_data (Dict[str, Any]): The data that is sent to the endpoint to move the issues back to backlog.

        Returns:
            requests.Response: The raw response of the endpoint.
        """
        return self.http_request_with_access_token(
            method='POST',
            url_suffix=f'rest/agile/1.0/backlog/{board_id}/issue',
            json_data=json_data,
            resp_type='response',
        )

    def issues_to_board(self, board_id, json_data: Dict[str, Any]) -> requests.Response:
        """This method is in charge of moving issues from backlog to board.

        Args:
            board_id (_type_): The id of the board that the issues reside in.
            json_data (Dict[str, Any]): The data that is sent to the endpoint to move the issues back to the
            board from the backlog.

        Returns:
            requests.Response: The raw response of the endpoint.
        """
        return self.http_request_with_access_token(
            method='POST',
            url_suffix=f'rest/agile/1.0/board/{board_id}/issue',
            json_data=json_data,
            resp_type='response',
        )

    def issues_to_sprint(self, sprint_id: str, json_data: Dict[str, Any]) -> requests.Response:
        return self.http_request_with_access_token(
            method='POST',
            url_suffix=f'rest/agile/1.0/sprint/{sprint_id}/issue',
            json_data=json_data,
            resp_type='response',
        )

    def get_issues_from_sprint(self, sprint_id: str, start_at: int | None = None, max_results: int | None = None,
                               jql_query: str | None = None) -> Dict[str, Any]:
        query_params = assign_params(
            jql=jql_query,
            startAt=start_at,
            maxResults=max_results
        )
        return self.http_request_with_access_token(
            method='GET',
            url_suffix=f'rest/agile/1.0/sprint/{sprint_id}/issue',
            params=query_params
        )

    def get_sprint_issues_from_board(self, sprint_id: str, board_id: str, start_at: int | None = None,
                                     max_results: int | None = None,
                                     jql_query: str | None = None) -> Dict[str, Any]:
        query_params = assign_params(
            jql=jql_query,
            startAt=start_at,
            maxResults=max_results
        )
        return self.http_request_with_access_token(
            method='GET',
            url_suffix=f'rest/agile/1.0/board/{board_id}/sprint/{sprint_id}/issue',
            params=query_params
        )

    # Issue Fields Requests
    def get_issue_fields(self) -> List[Dict[str, Any]]:
        return self.http_request_with_access_token(
            method='GET', url_suffix='rest/api/3/field'
        )

    #  Issue Requests
    def transition_issue(self, issue_id_or_key: str, json_data: Dict[str, Any]) -> requests.Response:
        return self.http_request_with_access_token(
            method='POST',
            url_suffix=f'rest/api/latest/issue/{issue_id_or_key}/transitions',
            json_data=json_data,
            resp_type='response',
        )

    def add_link(self, issue_id_or_key: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        return self.http_request_with_access_token(
            method='POST',
            url_suffix=f'rest/api/latest/issue/{issue_id_or_key}/remotelink',
            json_data=json_data,
        )

    def get_comments(self, issue_id_or_key: str, max_results: int = 50) -> Dict[str, Any]:
        query_params = {'expand': 'renderedBody', 'maxResults': max_results}
        return self.http_request_with_access_token(
            method='GET',
            url_suffix=f'rest/api/3/issue/{issue_id_or_key}/comment',
            params=query_params,
        )

    def delete_comment(self, issue_id_or_key: str, comment_id: str) -> requests.Response:
        return self.http_request_with_access_token(
            method='DELETE',
            url_suffix=f'rest/api/3/issue/{issue_id_or_key}/comment/{comment_id}',
            resp_type='response',
        )

    def edit_comment(self, issue_id_or_key: str, comment_id: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        query_params = {'expand': 'renderedBody'}
        return self.http_request_with_access_token(
            method='PUT',
            url_suffix=f'rest/api/3/issue/{issue_id_or_key}/comment/{comment_id}',
            json_data=json_data,
            params=query_params,
        )

    def get_issue(self, issue_id_or_key: str = '', full_issue_url: str = '') -> Dict[str, Any]:
        query_params = {'expand': 'renderedFields,transitions,names'}
        return self.http_request_with_access_token(
            method='GET',
            url_suffix=f'rest/api/3/issue/{issue_id_or_key}',
            params=query_params,
            full_url=full_issue_url,
        )

    def edit_issue(self, issue_id_or_key: str, json_data: Dict[str, Any]) -> requests.Response:
        return self.http_request_with_access_token(
            method='PUT',
            url_suffix=f'rest/api/3/issue/{issue_id_or_key}',
            json_data=json_data,
            resp_type='response',
        )

    def delete_issue(self, issue_id_or_key: str) -> requests.Response:
        query_params = {'deleteSubtasks': 'true'}
        return self.http_request_with_access_token(
            method='DELETE',
            url_suffix=f'rest/api/3/issue/{issue_id_or_key}',
            params=query_params,
            resp_type='response',
        )

    def create_issue(self, json_data: Dict[str, Any]) -> Dict[str, Any]:
        return self.http_request_with_access_token(
            method='POST', url_suffix='rest/api/3/issue', json_data=json_data
        )

    def get_transitions(self, issue_id_or_key: str) -> Dict[str, Any]:
        return self.http_request_with_access_token(
            method='GET',
            url_suffix=f'rest/api/3/issue/{issue_id_or_key}/transitions',
        )

    def add_comment(self, issue_id_or_key: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        query_params = {'expand': 'renderedBody'}
        return self.http_request_with_access_token(
            method='POST',
            url_suffix=f'rest/api/3/issue/{issue_id_or_key}/comment',
            json_data=json_data,
            params=query_params,
        )

    def get_epic_issues(self, epic_id_or_key: str, start_at: int | None = None, max_results: int | None = None,
                        jql_query: str | None = None) -> Dict[str, Any]:
        query_params = assign_params(
            jql=jql_query,
            startAt=start_at,
            maxResults=max_results
        )
        return self.http_request_with_access_token(
            method='GET',
            url_suffix=f'rest/agile/1.0/epic/{epic_id_or_key}/issue',
            params=query_params
        )

    def get_issue_link_types(self) -> Dict[str, Any]:
        return self.http_request_with_access_token(
            method='GET',
            url_suffix='rest/api/3/issueLinkType',
        )

    def create_issue_link(self, json_data: Dict[str, Any]) -> requests.Response:
        return self.http_request_with_access_token(
            method='POST',
            url_suffix='rest/api/3/issueLink',
            json_data=json_data,
            resp_type='response'
        )

    # Attachments Requests
    def add_attachment(self, issue_id_or_key: str, files: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
        headers = {
            'X-Atlassian-Token': 'no-check',
        }
        return self.http_request_with_access_token(
            method='POST',
            url_suffix=f'rest/api/3/issue/{issue_id_or_key}/attachments',
            files=files,
            headers=headers,
        )

    def get_attachment_metadata(self, attachment_id: str) -> Dict[str, Any]:
        return self.http_request_with_access_token(
            method='GET', url_suffix=f'rest/api/3/attachment/{attachment_id}'
        )

    def get_attachment_content(self, attachment_id: str) -> str:
        return self.http_request_with_access_token(
            method='GET',
            url_suffix=f'rest/api/3/attachment/content/{attachment_id}',
            resp_type='content',
        )

    # User Requests
    def get_id_by_attribute(self, attribute: str, max_results: int = 50) -> List[Dict[str, Any]]:
        query = {'query': attribute, 'maxResults': max_results}
        return self.http_request_with_access_token(
            method='GET', url_suffix='rest/api/3/user/search', params=query
        )


class JiraOnPremClient(JiraBaseClient):
    # Will implement the abstract methods

    def test_instance_connection(self) -> None:
        pass


class JiraIssueFieldsParser():
    """This class is in charge of parsing the issue fields returned from a response. The data of the fields are mostly
    returned as nested dictionaries, and it is not intuitive to retrieve the data of specific fields, therefore, this class
    helps the parsing process and encapsulates it in one place.
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
        return {'Assignee': f'{assignee.get("displayName","")}({assignee.get("emailAddress", "")})'
                if assignee else ''}

    @staticmethod
    def get_creator_context(issue_data: Dict[str, Any]) -> Dict[str, str]:
        creator = demisto.get(issue_data, 'fields.creator', {}) or {}
        return {'Creator': f'{creator.get("displayName","")}({creator.get("emailAddress", "")})'
                if creator else ''}

    @staticmethod
    def get_reporter_context(issue_data: Dict[str, Any]) -> Dict[str, str]:
        reporter = demisto.get(issue_data, 'fields.reporter', {}) or {}
        return {'Reporter': f'{reporter.get("displayName","")}({reporter.get("emailAddress", "")})'
                if reporter else ''}

    @staticmethod
    def get_description_context(issue_data: Dict[str, Any]) -> Dict[str, str]:
        # Since the description can be returned in Atlassian Document Format
        # (which holds nested dictionaries that includes the content and also metadata about it), we check if the response
        # returns the fields rendered in HTML format (by accessing the renderedFields).
        rendered_issue_fields = issue_data.get('renderedFields', {}) or {}
        return {'Description': BeautifulSoup(rendered_issue_fields.get('description')).get_text() if rendered_issue_fields
                else (demisto.get(issue_data, 'fields.description', '') or '')}

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

        Returns:
            Dict[str, Any]: The raw data of the field.
        """
        issue_field_display_name = issue_fields_id_to_name_mapping.get(issue_field_id) or ''
        return {issue_field_id: ({'issueFieldDisplayName': issue_field_display_name} if issue_field_display_name else {})
                | {'rawData': issue_data.get('fields', {}).get(issue_field_id, '') or {}}}

    # The following dictionary holds the keys (in dotted string format, with respect how they appear in the issue
    # response (# TODO add link)), and parser methods as values for every key, which is in charge or receiving the
    # issue response from the API, and parsing the required field.
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
        'assignee': get_assignee_context
    }

    @classmethod
    def get_issue_fields_to_context_from_id(cls, issue_data: Dict[str, Any], issue_fields_ids: List[str],
                                            issue_fields_id_to_name_mapping: Dict[str, str]) -> Dict[str, Any]:
        """_summary_

        Args:
            issue_data (Dict[str, Any]): The issue response from the API, which holds the data about a specific issue.
            issue_fields_ids (List[str]): A list of ids of specific issue fields.

        Returns:
            Dict[str, Any]: A dictionary that holds human readable mapping of the issues' fields.
        """
        issue_fields_context: Dict[str, Any] = {}
        for issue_field_id in issue_fields_ids:
            if issue_field_id in cls.ISSUE_FIELDS_ID_TO_CONTEXT:
                issue_fields_context |= cls.ISSUE_FIELDS_ID_TO_CONTEXT[issue_field_id](issue_data)
            else:
                # issue_field_id = issue_field.split('.')[-1]
                issue_fields_context |= cls.get_raw_field_data_context(issue_data, issue_field_id,
                                                                       issue_fields_id_to_name_mapping)
        return issue_fields_context


# Utility functions
def prepare_pagination_args(page: int | None = None, page_size: int | None = None, limit: int | None = None) -> Dict[str, int]:
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


def str_to_number(arg: str, default_value: int) -> int:
    return to_number if (to_number := arg_to_number(arg)) else default_value


def create_query_params(jql_query: str, start_at: int | None = None,
                        max_results: int | None = None) -> Dict[str, Any]:
    start_at = start_at or 0
    max_results = max_results or 50
    demisto.debug(f'Querying with: {jql_query}\nstart_at: {start_at}\nmax_results: {max_results}\n')
    return {
        'jql': jql_query,  # The Jira Query Language string, used to search for issues in a project using SQL-like syntax.
        'startAt': start_at,  # The index of the first item to return in a page of results (page offset).
        'maxResults': max_results,  # The maximum number of items to return per page.
    }


def get_issue_fields_id_to_name_mapping(client: JiraBaseClient) -> Dict[str, str]:
    """ Returns a dictionary that holds a mapping between the ids of the issue fields to their human readable names.
    """
    issue_fields_res = client.get_issue_fields()
    return {
        custom_field.get('id', ''): custom_field.get('name', '')
        for custom_field in issue_fields_res
    }


def get_current_time_in_seconds() -> float:
    """A function to return time as a float number of nanoseconds since the epoch

    Returns:
        float: Number of nanoseconds since the epoch
    """
    return time.time_ns() / (10 ** 9)


def create_file_info_from_attachment(client: JiraBaseClient, attachment_id: str, file_name: str = '') -> Dict[str, Any]:
    attachment_file_name = file_name
    if not attachment_file_name:
        res_attachment_metadata = client.get_attachment_metadata(attachment_id=attachment_id)
        attachment_file_name = res_attachment_metadata.get('filename', '')
    res_attachment_content = client.get_attachment_content(attachment_id=attachment_id)
    return fileResult(filename=attachment_file_name, data=res_attachment_content, file_type=EntryType.ENTRY_INFO_FILE)


def create_fields_dict_from_dotted_string(issue_fields: Dict[str, Any], dotted_string: str, value: Any) -> Dict[str, Any]:
    # CONFLUENCE Add why we need this and give an example
    """Create a nested dictionary from keys separated by dots(.), and insert the value as part of the last key in the dotted string.
    For example, dotted_string=key1.key2.key3 with value=jira results in {key1: {key2: {key3: jira}}}

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


def get_issue_fields_for_create(issue_args: Dict[str, str], issue_fields_mapper: Dict[str, str]) -> Dict[str, Any]:
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
            parsed_value = text_to_adf(value)
        issue_fields |= create_fields_dict_from_dotted_string(
            issue_fields=issue_fields, dotted_string=issue_fields_mapper.get(issue_arg, ''), value=parsed_value or value)
    return issue_fields


def create_update_dict_from_dotted_string(issue_fields: Dict[str, Any], dotted_string: str, update_key: str,
                                          value: Any,
                                          action: str = 'rewrite') -> Dict[str, Any]:
    # TODO Update documentation
    """Create a nested dictionary from keys separated by dot(.)

    Args:
        dotted_string (str): A dotted string that holds the keys of the dictionary
        value (Any): The value to insert in the nested dictionary
    """
    if not dotted_string:
        return {}
    nested_dict: Dict[str, Any] = {}
    keys = dotted_string.split(".")
    action_key = 'add' if action == 'append' else 'set'
    values = value if isinstance(value, list) else [value]
    for count, sub_key in enumerate(keys[::-1]):
        inner_dict = demisto.get(issue_fields, '.'.join(keys[: len(keys) - count]), defaultdict(dict))
        if count == 0:
            update_key_list = []
            if(action_key == 'add'):
                # Example: https://community.atlassian.com/t5/Jira-questions/How-to-use-SET-to-set-components-via-REST-API/qaq-p/845590
                # If we need to add, then each value must be added in a separate {add: value} dictionary
                for appended_value in values:
                    if update_key:
                        update_key_list.append({action_key: {update_key: appended_value}})
                    else:
                        update_key_list.append({action_key: appended_value})
                    update_key_list += inner_dict if isinstance(inner_dict, list) else []
            else:
                # If we need to set, then all the array (or whatever value) must be in only one {set: value} dictionary
                if update_key:
                    update_key_list.append({action_key: {update_key: value}})
                else:
                    update_key_list.append({action_key: value})
                update_key_list += inner_dict if isinstance(inner_dict, list) else []
            inner_dict = {sub_key: update_key_list}
        else:
            inner_dict = {sub_key: inner_dict | nested_dict}
        nested_dict = inner_dict
    return nested_dict


def get_issue_fields_for_update(issue_args: Dict[str, str], issue_update_mapper: Dict[str, tuple[str, str]],
                                action: str) -> Dict[str, Any]:
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
            parsed_value = [{'set': text_to_adf(text=value)}]
        dotted_string, update_key = issue_update_mapper.get(issue_arg, ('', ''))
        issue_fields |= create_update_dict_from_dotted_string(
            issue_fields=issue_fields, dotted_string=dotted_string, update_key=update_key, value=parsed_value or value,
            action=action)
    return issue_fields


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
    which is used in order to send data to the API (such as, summary, content, when creating an issue for instance.)

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
    # TODO Explain really well what we did here!
    # TODO Add that if we receive a comment key or id, to return a warning stating that this can be retrieved
    # with jira-get-comments
    # We offer the opportunity to insert the field name or ID in order to retrieve the data
    if 'all' in specific_fields:
        all_issue_fields_ids: List[str] = list(issue_data.get('fields', {}).keys())
        if 'comment' in all_issue_fields_ids:
            all_issue_fields_ids.remove('comment')
        return ['id', 'key', 'self', *all_issue_fields_ids]
    issue_fields_name_to_id_mapping = {issue_name.lower(): issue_id for issue_id,
                                       issue_name in issue_fields_id_to_name_mapping.items()}
    issue_fields_ids: List[str] = []
    wrong_issue_fields_ids: List[str] = []
    for specific_field in specific_fields:
        if specific_field in issue_fields_id_to_name_mapping:
            issue_fields_ids.append(specific_field)
        elif issue_id := issue_fields_name_to_id_mapping.get(specific_field.lower(), ''):
            issue_fields_ids.append(issue_id)
        else:
            wrong_issue_fields_ids.append(specific_field)
    warning_message = ''
    if 'comment' in issue_fields_ids:
        warning_message = 'In order to retrieve the comments of the issue, please run the command `!jira-get-comments`'
        for issue_field_id in issue_fields_ids:
            if issue_field_id == 'comment':
                issue_fields_ids.remove(issue_field_id)
    if wrong_issue_fields_ids:
        issue_key = issue_data.get('key', '') or ''
        warning_message = '\n'.join([f'The field/s [{",".join(wrong_issue_fields_ids)}] was/were not found for issue {issue_key}',
                                     warning_message])
    if warning_message:
        return_warning(warning_message)
    return issue_fields_ids


def create_issue_md_and_outputs_dict(issue_data: Dict[str, Any],
                                     specific_issue_fields: List[str] | None = None,
                                     issue_fields_id_to_name_mapping: Dict[str, str] | None = None) -> tuple[Dict[str, Any], Dict[str, Any]]:
    md_and_outputs_shared_issue_keys = ['id', 'key', 'summary', 'status', 'priority', 'project', 'duedate',
                                        'created', 'labels', 'assignee', 'creator']
    issue_fields_id_to_name_mapping = issue_fields_id_to_name_mapping or {}
    issue_fields_ids = get_specific_fields_ids(issue_data=issue_data, specific_fields=specific_issue_fields or [],
                                               issue_fields_id_to_name_mapping=issue_fields_id_to_name_mapping)
    # The `*` is used to unpack the content of a list into another list.
    context_outputs = JiraIssueFieldsParser.get_issue_fields_to_context_from_id(
        issue_data=issue_data, issue_fields_ids=['lastViewed', 'updated', 'attachment', *md_and_outputs_shared_issue_keys,
                                                 *issue_fields_ids],
        issue_fields_id_to_name_mapping=issue_fields_id_to_name_mapping)
    markdown_dict = JiraIssueFieldsParser.get_issue_fields_to_context_from_id(
        issue_data=issue_data, issue_fields_ids=['issuetype', 'self', 'reporter', 'description',
                                                 *md_and_outputs_shared_issue_keys],
        issue_fields_id_to_name_mapping=issue_fields_id_to_name_mapping)

    return markdown_dict, context_outputs


def is_issue_id(issue_id_or_key: str) -> bool:
    """
    Checks if the identifier supplied by the user is an ID or Key. (IDs are made up of numeric characters)
    """
    return issue_id_or_key.isnumeric()


def get_file_name_and_content(entry_id: str):
    get_file_path_res = demisto.getFilePath(entry_id)
    file_path = get_file_path_res["path"]
    file_name = get_file_path_res["name"]
    with open(file_path, 'rb') as f:
        file_bytes = f.read()
    return file_name, file_bytes


def apply_issue_status(client: JiraBaseClient, issue_id_or_key: str, status_name: str) -> Any:
    """
    In charge of receiving a status of an issue and try to apply it, if it can't, it will throw an error.
    """
    res_transitions = client.get_transitions(issue_id_or_key=issue_id_or_key)
    all_transitions = res_transitions.get('transitions', [])
    statuses_name = [transition.get('to', {}).get('name', '') for transition in all_transitions]
    for i, status in enumerate(statuses_name):
        if status.lower() == status_name.lower():
            json_data = {'transition': {"id": str(all_transitions[i].get('id', ''))}}
            return client.transition_issue(
                issue_id_or_key=issue_id_or_key, json_data=json_data
            )
    raise DemistoException(f'Status "{status_name}" not found. \nValid statuses are: {statuses_name} \n')


def apply_issue_transition(client: JiraBaseClient, issue_id_or_key: str, transition_name: str) -> Any:
    """
    In charge of receiving a transition to perform on an issue and try to apply it, if it can't, it will throw an error.
    """
    res_transitions = client.get_transitions(issue_id_or_key=issue_id_or_key)
    all_transitions = res_transitions.get('transitions', [])
    transitions_name = [transition.get('name', '') for transition in all_transitions]
    for i, transition in enumerate(transitions_name):
        if transition.lower() == transition_name.lower():
            json_data = {'transition': {"id": str(all_transitions[i].get('id', ''))}}
            return client.transition_issue(
                issue_id_or_key=issue_id_or_key, json_data=json_data
            )
    raise DemistoException(f'Transition "{transition_name}" not found. \nValid transitions are: {transitions_name} \n')


# Issues Commands
def add_link_command(client: JiraBaseClient, args: Dict[str, str]) -> CommandResults:
    # TODO Need to ask TPM what to do with this command
    issue_id_or_key = args.get('issue_id', args.get('issue_key', ''))
    if not issue_id_or_key:
        raise DemistoException(ID_OR_KEY_MISSING_ERROR)
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
    """_summary_

    Args:
        client (JiraBaseClient): _description_
        args (Dict[str, str]): _description_

    Returns:
        List[CommandResults] | CommandResults: _description_
    """
    jql_query = args.get('query', '')
    start_at = arg_to_number(args.get('start_at', ''))
    max_results = arg_to_number(args.get('max_results', ''))
    headers = args.get('headers', '')
    specific_fields = argToList(args.get('specific_fields', ''))
    query_params = create_query_params(jql_query=jql_query, start_at=start_at, max_results=max_results)
    res = client.run_query(query_params=query_params)
    if not res:
        return CommandResults(readable_output='No issues matched the query.')
    issue_fields_id_to_name_mapping = res.get('names', {}) or {}
    command_results: List[CommandResults] = []
    for issue in res.get('issues', []):
        markdown_dict, outputs = create_issue_md_and_outputs_dict(issue_data=issue, specific_issue_fields=specific_fields,
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


def get_issue_command(client: JiraBaseClient, args: Dict[str, str]) -> List[CommandResults]:
    """_summary_

    Args:
        client (JiraBaseClient): _description_
        args (Dict[str, str]): _description_

    Returns:
        List[CommandResults]: _description_
    """
    issue_id_or_key = args.get('issue_id', args.get('issue_key', ''))
    if not issue_id_or_key:
        raise DemistoException(ID_OR_KEY_MISSING_ERROR)
    headers = args.get('headers', '')
    get_attachments = argToBoolean(args.get('get_attachments', False))
    expand_links = argToBoolean(args.get('expand_links', False))
    specific_fields = argToList(args.get('fields', ''))
    res = client.get_issue(issue_id_or_key=issue_id_or_key)
    responses: List[Dict[str, Any]] = [res]
    responses.extend(get_expanded_issues(client=client, issue=res,
                                         expand_links=expand_links))
    command_results: List[CommandResults] = []
    download_issue_attachments_to_war_room(client=client, issue=res, get_attachments=get_attachments)
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


def download_issue_attachments_to_war_room(client: JiraBaseClient, issue: Dict[str, Any],
                                           get_attachments: bool = False) -> None:
    """Downloads the attachments of an issue to the War Room.

    Args:
        client (JiraBaseClient): The Jira client
        issue (Dict[str, Any]): The issue to retrieve and download its attachments
        get_attachments (bool, optional): Whether to download the attachments or not. Defaults to False.
    """
    if get_attachments:
        for attachment in demisto.get(issue, 'fields.attachment', []):
            return_results(create_file_info_from_attachment(client=client, attachment_id=attachment.get('id')))


def get_expanded_issues(client: JiraBaseClient, issue: Dict[str, Any],
                        expand_links: bool = False) -> List[Dict[str, Any]]:
    """Returns a list of subtasks and linked issues corresponding to the given issue in issue_response.

    Args:
        client (JiraBaseClient): The Jira client
        issue (Dict[str, Any]): The issue to retrieve its subtasks and linked issues.
        expand_links (bool, optional): Whether to retrieve the subtasks and linked issues. Defaults to False.

    Returns:
        List[Dict[str, Any]]:  A list of subtasks and linked issues corresponding to the given issue in issue_response.
    """
    responses: List[Dict[str, Any]] = []
    if expand_links:
        responses.extend(
            client.get_issue(full_issue_url=sub_task.get('self', ''))
            for sub_task in issue.get('fields', {}).get('subtasks', [])
        )
        responses.extend(
            client.get_issue(
                full_issue_url=link_issue.get('inwardIssue', {}).get(
                    'self', ''
                )
            )
            for link_issue in issue.get('fields', {}).get('issuelinks', [])
        )
    return responses


def create_issue_command(client: JiraBaseClient, args: Dict[str, str]) -> CommandResults:
    issue_fields = get_issue_fields_for_create(issue_args=args, issue_fields_mapper=client.ISSUE_FIELDS_MAPPER)
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
    issue_id_or_key = args.get('issue_id', args.get('issue_key', ''))
    if not issue_id_or_key:
        raise DemistoException(ID_OR_KEY_MISSING_ERROR)
    status = args.get('status', '')
    transition = args.get('transition', '')
    if status and transition:
        raise DemistoException("Please provide only status or transition, but not both.")
    elif status:
        demisto.log(f'Updating the status to: {status}')
        apply_issue_status(client=client, issue_id_or_key=issue_id_or_key, status_name=status)
    elif transition:
        demisto.log(f'Updating the status using the transition: {transition}')
        apply_issue_transition(client=client, issue_id_or_key=issue_id_or_key, transition_name=transition)
    # issue_args: Dict[str, Any] = args
    # issue_args['labels'] = issue_args.get('labels', '').split(',')
    # issue_args['components'] = [{"name": component} for component in argToList(issue_args.get('components'))]
    action = args.get('action', 'rewrite')
    update_fields = get_issue_fields_for_update(issue_args=args, issue_update_mapper=client.ISSUE_UPDATE_MAPPER, action=action)
    # if (action == 'append' and (args.get('description', '') or args.get('environment', ''))):
    # Description and Environment do not support the add operation
    # raise DemistoException('Description and Environment do not support the add operation')
    # update_fields.get('update', {})['description'] = [{'set': text_to_adf(text=args.get('description', ''))}]
    # update_fields.get('update', {})['environment'] = [{'set': text_to_adf(text=args.get('environment', ''))}]

    client.edit_issue(issue_id_or_key=issue_id_or_key, json_data=update_fields)
    demisto.log(f'Issue {issue_id_or_key} was updated successfully')
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


# def handle_edit_issue_arguments_parsing(issue_args: Dict[str, str], action: str) -> Dict[str, Any]:
#     issue_args['labels'] = issue_args.get('labels', '').split(',')
#     issue_args['components'] = [{"name": component} for component in argToList(issue_args.get('components'))]
#     action = args.get('action', 'rewrite')
#     update_fields = get_issue_fields_for_update(issue_args=args, issue_update_mapper=client.ISSUE_UPDATE_MAPPER, action=action)
#     if (action == 'append' and (args.get('description', '') or args.get('environment', ''))):
#         # Description and Environment do not support the add operation
#         raise DemistoException('Description and Environment do not support the add operation')
#     update_fields.get('update', {})['description'] = [{'set': text_to_adf(text=args.get('description', ''))}]
#     update_fields.get('update', {})['environment'] = [{'set': text_to_adf(text=args.get('environment', ''))}]

def delete_issue_command(client: JiraBaseClient, args: Dict[str, str]) -> CommandResults:
    issue_id_or_key = args.get('issue_id', args.get('issue_key', ''))
    if not issue_id_or_key:
        raise DemistoException(ID_OR_KEY_MISSING_ERROR)
    client.delete_issue(issue_id_or_key=issue_id_or_key)
    return CommandResults(readable_output='Issue deleted successfully.')


def delete_comment_command(client: JiraBaseClient, args: Dict[str, str]) -> CommandResults:
    issue_id_or_key = args.get('issue_id', args.get('issue_key', ''))
    if not issue_id_or_key:
        raise DemistoException(ID_OR_KEY_MISSING_ERROR)
    comment_id = args.get('comment_id', '')
    client.delete_comment(issue_id_or_key=issue_id_or_key, comment_id=comment_id)
    return CommandResults(readable_output='Comment deleted successfully.')


def get_comments_command(client: JiraBaseClient, args: Dict[str, str]) -> CommandResults:
    """_summary_

    Args:
        client (JiraBaseClient): _description_
        args (Dict[str, str]): _description_

    Returns:
        CommandResults: _description_
    """
    issue_id_or_key = args.get('issue_id', args.get('issue_key', ''))
    if not issue_id_or_key:
        raise DemistoException(ID_OR_KEY_MISSING_ERROR)
    limit = arg_to_number(args.get('limit', None))
    if not limit:
        limit = 50
    res = client.get_comments(issue_id_or_key=issue_id_or_key, max_results=limit)
    if response_comments := res.get('comments', []):
        return create_comments_command_results(
            response_comments=response_comments, issue_id_or_key=issue_id_or_key, res=res
        )
    else:
        return CommandResults(readable_output='No comments were found in the ticket')


def create_comments_command_results(response_comments: List[Dict[str, Any]],
                                    issue_id_or_key: str, res: Dict[str, Any]) -> CommandResults:
    is_id = is_issue_id(issue_id_or_key=issue_id_or_key)
    comments = extract_comments_entries_from_raw_response(response_comments=response_comments)
    # for comment in response_comments:
    #     comment_body = BeautifulSoup(comment.get('renderedBody')).get_text(
    #     ) if comment.get('renderedBody') else comment.get('body')
    #     comments.append({
    #         'Id': comment.get('id'),
    #         'Comment': comment_body,
    #         'User': demisto.get(comment, 'author.displayName'),
    #         'Created': comment.get('created')
    #     })
    outputs: Dict[str, Any] = {'Comment': comments}
    if(is_id):
        outputs |= {'Id': issue_id_or_key}
    else:
        extracted_issue_id = extract_issue_id_from_comment_url(comment_url=response_comments[0].get('self', ''))
        outputs |= {'Id': extracted_issue_id, 'Key': issue_id_or_key}
    human_readable = tableToMarkdown("Comments", comments)
    return CommandResults(
        outputs_prefix='Ticket',
        outputs=outputs,
        outputs_key_field='Id',
        readable_output=human_readable,
        raw_response=res
    )


def extract_comments_entries_from_raw_response(response_comments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    comments: List[Dict[str, Any]] = []
    for comment in response_comments:
        comment_body = BeautifulSoup(comment.get('renderedBody')).get_text(
        ) if comment.get('renderedBody') else comment.get('body')
        comments.append({
            'Id': comment.get('id'),
            'Comment': comment_body,
            'User': demisto.get(comment, 'author.displayName'),
            'Created': comment.get('created')
        })
    return comments


def edit_comment_command(client: JiraBaseClient, args: Dict[str, str]) -> CommandResults:
    issue_id_or_key = args.get('issue_id', args.get('issue_key', ''))
    if not issue_id_or_key:
        raise DemistoException(ID_OR_KEY_MISSING_ERROR)
    comment_id = args.get('comment_id', '')
    comment = args.get('comment', '')
    visibility = args.get('visibility', '')
    payload = {
        'body': text_to_adf(text=comment)
    }
    if visibility:
        payload['visibility'] = {
            "type": "role",
            "value": visibility
        }
    res = client.edit_comment(issue_id_or_key=issue_id_or_key, comment_id=comment_id, json_data=payload)
    comment_body = BeautifulSoup(res.get('renderedBody')).get_text(
    ) if res.get('renderedBody') else res.get('body')
    comment_data = {
        'Id': res.get('id'),
        'Comment': comment_body,
        'User': demisto.get(res, 'author.displayName'),
        'Created': res.get('created')
    }
    is_id = is_issue_id(issue_id_or_key=issue_id_or_key)
    outputs: Dict[str, Any] = {'Comments': comment_data}
    if(is_id):
        outputs |= {'Id': issue_id_or_key}
    else:
        extracted_issue_id = extract_issue_id_from_comment_url(comment_url=res.get('self', ''))
        outputs |= {'Id': extracted_issue_id, 'Key': issue_id_or_key}
    human_readable = tableToMarkdown("Comments", comment_data)

    # {'Ticket((val.Id && val.Id == obj.Id) || (val.Key && val.Key == obj.Key))': outputs},
    # TODO How to update the comment Id that is found in Ticket.Comments.Id == comment_id??
    return CommandResults(
        outputs_prefix='Ticket',
        outputs=outputs,
        outputs_key_field='Comments.Id',
        readable_output=human_readable,
        raw_response=res
    )


def add_comment_command(client: JiraBaseClient, args: Dict[str, str]) -> CommandResults:
    issue_id_or_key = args.get('issue_id', args.get('issue_key', ''))
    if not issue_id_or_key:
        raise DemistoException(ID_OR_KEY_MISSING_ERROR)
    comment = args.get('comment', '')
    visibility = args.get('visibility', )
    payload = {
        'body': text_to_adf(text=comment)
    }
    if(visibility):
        payload['visibility'] = {
            "type": "role",
            "value": visibility
        }
    res = client.add_comment(issue_id_or_key=issue_id_or_key, json_data=payload)
    markdown_dict = {
        'Comment': BeautifulSoup(res.get('renderedBody')).get_text() if res.get('renderedBody') else res.get('body'),
        'Id': res.get('id', ''),
        'Ticket Link': res.get('self', ''),
    }
    return CommandResults(
        readable_output=tableToMarkdown('Comment added successfully', markdown_dict)
    )


def get_transitions_command(client: JiraBaseClient, args: Dict[str, str]) -> CommandResults:
    issue_id_or_key = args.get('issue_id', args.get('issue_key', ''))
    if not issue_id_or_key:
        raise DemistoException(ID_OR_KEY_MISSING_ERROR)
    res = client.get_transitions(issue_id_or_key=issue_id_or_key)
    transitions_names: List[str] = [
        transition.get('name', '') for transition in res.get('transitions', [])
    ]
    readable_output = tableToMarkdown(
        'List Transitions:', transitions_names, headers=['Transition Name']
    )
    outputs: Dict[str, Any] = {'Transitions': transitions_names}
    is_id = is_issue_id(issue_id_or_key=issue_id_or_key)
    outputs |= {'Id': issue_id_or_key} if is_id else {'Key': issue_id_or_key}
    return CommandResults(
        outputs_prefix='Ticket',
        outputs=outputs,
        outputs_key_field='Id',
        readable_output=readable_output,
        raw_response=res
    )


def get_id_offset_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
    jql_query = 'ORDER BY created ASC'
    query_params = create_query_params(jql_query=jql_query)
    res = client.run_query(query_params=query_params)
    first_issue_id = res.get('issues', [])[0].get('id', '')
    return (
        CommandResults(
            outputs_prefix='Ticket',
            readable_output=f'ID Offset: {first_issue_id}',
            outputs={'IdOffSet': first_issue_id},
        )
        if first_issue_id
        else CommandResults(readable_output='No ID offset was found', raw_response=res)
    )


def upload_file_command(client: JiraBaseClient, args: Dict[str, str]):
    entry_id = args.get('entry_id', '')
    issue_id_or_key = args.get('issue_id', args.get('issue_key', ''))
    if not issue_id_or_key:
        raise DemistoException(ID_OR_KEY_MISSING_ERROR)
    attachment_name = args.get('attachment_name', '')
    file_name, file_bytes = get_file_name_and_content(entry_id=entry_id)
    files = {'file': (attachment_name or file_name, file_bytes, 'application-type')}
    res = client.add_attachment(issue_id_or_key=issue_id_or_key, files=files)
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


def issue_get_attachment_command(client: JiraBaseClient, args: Dict[str, str]) -> List[Dict[str, Any]]:
    """Get attachments content

    Returns:
        Dict[str, Any]: A dictionary the represents a file entry to be returned to the user
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
    issue_id_or_key = args.get('issue_id', args.get('issue_key', ''))
    if not issue_id_or_key:
        raise DemistoException(ID_OR_KEY_MISSING_ERROR)
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
    res = client.get_issue_fields()
    pagination_args = prepare_pagination_args(page=arg_to_number(arg=args.get('page', None)),
                                              page_size=arg_to_number(arg=args.get('page_size', None)),
                                              limit=arg_to_number(arg=args.get('limit', None)))
    start_at = pagination_args.get('start_at', 0)
    max_results = pagination_args.get('max_results', 50)
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
    attribute = args.get('attribute', '')
    max_results = arg_to_number(args.get('max_results', None))
    if not max_results:
        max_results = 50
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
        account_ids = [res[0].get('accountId', '')] if is_jira_cloud else [res[0].get('name', '')]

    elif(is_jira_cloud):
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
                                               ' the "DisplayName" attribute if not done so before, or supply the full attribute.'))

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
        if not board_id:
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
                'sprintId'],  # TODO Check if it is okay to use sprintID alone
            outputs=context_data_outputs or None,
            readable_output=tableToMarkdown(name=f'Sprint Issues in board {board_id}', t=markdown_list),
            raw_response=res
        )
    return CommandResults(readable_output='No issues were found with the respective arguments.')


def issues_to_sprint_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
    issues = argToList(args.get('issues', ''))
    sprint_id = args.get('sprint_id', '')
    rank_before_issue = args.get('rank_before_issue', '')
    rank_after_issue = args.get('rank_after_issue', '')
    json_data = assign_params(
        issues=issues,
        rankBeforeIssue=rank_before_issue,
        rankAfterIssue=rank_after_issue
    )
    client.issues_to_sprint(sprint_id=sprint_id, json_data=json_data)
    return CommandResults(readable_output='Issues were moved to the Sprint successfully')


def epic_issues_list_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
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
                                       epic_id_or_key: str, res: Dict[str, Any]):
    markdown_list = []
    issues_list = []
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
    outward_issue = args.get('outward_issue', '')
    inward_issue = args.get('inward_issue', '')
    link_type = args.get('link_type', '')
    comment = args.get('comment', '')
    json_data = assign_params(
        comment={'body': text_to_adf(text=comment)} if comment else '',
        inwardIssue={'key': inward_issue},
        outwardIssue={'key': outward_issue},
        type={'name': link_type}
    )
    client.create_issue_link(json_data=json_data)
    return CommandResults(readable_output='Issue link created successfully')


# Board Commands
def issues_to_backlog_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
    issues = argToList(args.get('issues', ''))
    board_id = args.get('board_id', '')
    rank_before_issue = args.get('rank_before_issue', '')
    rank_after_issue = args.get('rank_after_issue', '')
    if((rank_after_issue or rank_before_issue) and not board_id):
        raise DemistoException(('Please supply the board_id argument when supplying the rank_after_issue, and'
                                ' rank_before_issue arguments'))
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
            raise DemistoException('This argument is not supported for a Jira OnPrem instance.')
    else:
        # If the board_id is not given, then the issues that are meant to be moved to backlog, must be
        # part of a sprint, or in other words, the issues must be part of a board that supports sprints.
        client.issues_from_sprint_to_backlog(json_data=json_data)
    return CommandResults(readable_output='Issues were moved to Backlog successfully')


def issues_to_board_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
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
        outputs_key_field='id',
        outputs={'id': board_id, 'Ticket': issues_list},
        readable_output=tableToMarkdown(name='Backlog Issues', t=markdown_list),
        raw_response=res
    )


def board_issues_list_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
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
        outputs_key_field='id',
        outputs={'id': board_id, 'Ticket': issues_list},
        readable_output=tableToMarkdown(name='Board Issues', t=markdown_list),
        raw_response=res
    )


def board_sprint_list_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
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
        outputs_key_field='id',
        outputs={'id': board_id, 'Sprints': sprints},
        readable_output=tableToMarkdown(name='Sprints', t=md_dict),
        raw_response=res
    )


def board_epic_list_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
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
            outputs_key_field='id',
            outputs={'id': board_id, 'Epics': epics},
            readable_output=tableToMarkdown(name='Epics', t=md_dict),
            raw_response=res
        )
    return CommandResults(readable_output=f'No epics were found on board {board_id} with the respective arguments.')

# Fetch

# Polling


def ouath_start_command(client: JiraBaseClient, args: Dict[str, Any] = None) -> CommandResults:
    url = client.oauth_start()
    return CommandResults(readable_output=('In order to retrieve the authorization code, please authorize'
                                           f' yourself using the following link:\n{create_clickable_url(url)}\n'
                                           'After authorizing, you will be redirected to the configured callback url, where you'
                                           ' will retrieve the authorization code provided as a query parameter called `code`.'))


def oauth_complete_command(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
    code = args.get('code', '')
    client.oauth_complete(code=code)
    return CommandResults(readable_output=('Authentication process has completed successfully.'))


def test_authorization(client: JiraBaseClient, args: Dict[str, Any]) -> CommandResults:
    client.test_instance_connection()
    return CommandResults(readable_output=('Successful connection.'))


def test_module(client: JiraBaseClient) -> str:
    # Test functions here
    raise DemistoException(('In order to authorize the instance, first run the command `!jira-oauth-start`,'
                            ' and complete the process in the URL that is returned, after that, you will be redirected'
                            ' to the callback URL where you will copy the authorization code found in the query parameter'
                            ' `code`, and paste that value in the command `!jira-ouath-complete` as an argument to finish'
                            ' the process'))


# Fetch Incidents
def fetch_incidents(client: JiraBaseClient, issue_field_to_fetch_from: str, fetch_query: str, id_offset: int,
                    fetch_attachments: bool, fetch_comments: bool, max_fetch_incidents: int, fetch_interval: int,
                    first_fetch_interval: str, incoming_mirror: bool, outgoing_mirror: bool,
                    comment_tag: str, attachment_tag: str) -> List[Dict[str, Any]]:
    """issue_field_to_fetch_from options:
        - created date
        - updated date
        - status category change date
        - id

    Args:
        issue_field_to_fetch_from (str): _description_
        fetch_query (str): _description_
        id_offset (str): _description_
        fetch_attachments (str): _description_
        fetch_comments (str): _description_
    """
    last_run = demisto.getLastRun()
    demisto.debug(f'last_run: {last_run}' if last_run else 'last_run is empty')
    # This set will hold all the issues ids that were fetched in the last fetch, to eliminate fetching duplicate incidents.
    # TODO Mention that if we use set(), then an EOF error in XSOAR will return
    # Since when we get the list from the last run, all the values in the list are strings, and we may need them
    # to be integers (if we want to use the issues' ids in the query, they must be passed on as integers and not strings),
    # so we convert the list to hold integer values
    last_fetch_issue_ids: List[int] = convert_list_of_str_to_int(last_run.get('issue_ids', []))
    last_fetch_id = last_run.get('id', id_offset)
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
        last_fetch_issue_ids=last_fetch_issue_ids)
    demisto.debug(f'The fetch query: {fetch_incidents_query}' if fetch_incidents_query else 'No fetch query created')
    query_params = create_query_params(jql_query=fetch_incidents_query, max_results=max_fetch_incidents)
    new_issue_ids: List[int] = []
    demisto.debug(f'Running the query with the following parameters {query_params}')
    if query_res := client.run_query(query_params=query_params):
        for issue in query_res.get('issues', []):
            issue_id: int = issue.get('id')  # The ID returned by the API is an integer
            new_issue_ids.append(issue_id)
            last_fetch_id = issue_id
            new_fetch_created_time = convert_string_date_to_specific_format(
                string_date=demisto.get(issue, 'fields.created') or '')
            new_fetch_updated_time = convert_string_date_to_specific_format(
                string_date=demisto.get(issue, 'fields.updated') or '')
            demisto.debug(f'Creating an incident for Jira issue with ID: {issue_id}')
            remove_empty_custom_fields(issue=issue, issue_fields_id_to_name_mapping=query_res.get('names', {}))
            incidents.append(create_incident_from_issue(
                client=client, issue=issue, fetch_attachments=fetch_attachments, fetch_comments=fetch_comments,
                incoming_mirror=incoming_mirror, outgoing_mirror=outgoing_mirror,
                comment_tag=comment_tag,
                attachment_tag=attachment_tag))
    if (
        (issue_field_to_fetch_from == 'created date'
         and new_fetch_created_time == last_fetch_created_time)
        or (issue_field_to_fetch_from == 'updated date'
            and new_fetch_updated_time == last_fetch_updated_time)
    ):
        new_issue_ids.extend(last_fetch_issue_ids)
    demisto.setLastRun({
        'issue_ids': new_issue_ids or last_fetch_issue_ids,
        'id': last_fetch_id,
        'created_date': new_fetch_created_time or last_fetch_created_time,
        'updated_date': new_fetch_updated_time or last_fetch_updated_time,
    })
    return incidents


def remove_empty_custom_fields(issue: Dict[str, Any], issue_fields_id_to_name_mapping: Dict[str, str]):
    issue_fields = issue.get('fields', {})
    #  It is important to iterate over list(issue_fields) and not issue_fields or issue_fields.items(),
    # because we are deleting entries while iterating over the dictionary, if we do not, we will get the error,
    # RuntimeError: dictionary changed size during iteration
    for issue_field_id in list(issue_fields):
        if issue_field_id.startswith('customfield'):
            if issue_fields.get(issue_field_id):
                issue_fields |= JiraIssueFieldsParser.get_raw_field_data_context(
                    issue_data=issue, issue_field_id=issue_field_id,
                    issue_fields_id_to_name_mapping=issue_fields_id_to_name_mapping)
            else:
                del issue_fields[issue_field_id]


def convert_list_of_str_to_int(list_to_convert: List[str] | List[int]) -> List[int]:
    converted_list: List[int] = []
    for item in list_to_convert:
        try:
            converted_list.append(int(item))
        except Exception as e:
            raise DemistoException(
                f'Could not convert list of strings to int, error message: {e}\n'
            ) from e
    return converted_list


def create_fetch_incidents_query(issue_field_to_fetch_from: str, fetch_query: str,
                                 last_fetch_id: int, last_fetch_created_time: str, last_fetch_updated_time: str,
                                 first_fetch_interval: str, last_fetch_issue_ids: List[int]) -> str:
    """_summary_
    NOTE: It is important to add 'ORDER BY {the issue field to fetch from} ASC' in order to retrieve the data in ascending order,
    so we could keep save the latest fetch incident (according to issue_field_to_fetch_from) and fetch only new incidents,
    in other words, incidents that are newer with respect to issue_field_to_fetch_from.
    Args:
        issue_field_to_fetch_from (str): _description_
        fetch_interval (int): _description_
        fetch_query (str): _description_
        last_fetch_id (str): _description_
        last_fetch_created_time (str): _description_
        last_fetch_updated_time (str): _description_
        last_fetch_status_category_change_date (str): _description_
        first_fetch_interval (str): _description_

    Raises:
        DemistoException: _description_

    Returns:
        str: _description_
    """
    exclude_issue_ids_query = f"AND ID NOT IN ({', '.join(map(str, last_fetch_issue_ids))})" if last_fetch_issue_ids else ''
    if issue_field_to_fetch_from == 'id':
        return f'{fetch_query} AND id >= {last_fetch_id} {exclude_issue_ids_query} ORDER BY id ASC'
    if issue_field_to_fetch_from == 'created date':
        return (f'{fetch_query} AND created >= "{last_fetch_created_time or first_fetch_interval}" {exclude_issue_ids_query}'
                ' ORDER BY created ASC')
    elif issue_field_to_fetch_from == 'updated date':
        return (f'{fetch_query} AND updated >= "{last_fetch_updated_time or first_fetch_interval}" {exclude_issue_ids_query}'
                ' ORDER BY updated ASC')
    raise DemistoException('Could not create the proper fetch query')


def get_mirror_type(incoming_mirror: bool, outgoing_mirror: bool) -> str | None:
    """This function return the type of mirror to perform on a Jira incident.
    NOTE: in order to not mirror an incident, the type should be None.

    Args:
        should_mirror_in (bool): If we should implement mirroring in
        should_mirror_out (bool): If we should implement mirroring out

    Returns:
        _type_: The mirror type (Both, In, Out), or None if we should not mirror an incident.
    """
    mirror_type = None
    if incoming_mirror and outgoing_mirror:
        mirror_type = 'Both'
    elif incoming_mirror:
        mirror_type = 'In'
    elif outgoing_mirror:
        mirror_type = 'Out'
    return mirror_type


def get_comments_entries_for_fetched_incident(client: JiraBaseClient, issue_id_or_key: str) -> List[str]:
    """Return the comment entries for a fetched incident

    Args:
        issue_id_or_key (str): The issue id or key

    Returns:
        List[Dict[str, Any]]: _description_
    """
    try:
        get_comments_response = client.get_comments(issue_id_or_key=issue_id_or_key)
        if response_comments := get_comments_response.get('comments', []):
            comment_entries = extract_comments_entries_from_raw_response(response_comments=response_comments)
            return [comment_entry.get('Comment', '') for comment_entry in comment_entries]
    except Exception as e:
        demisto.debug(f'Could not get attachments for {issue_id_or_key} while fetching this incident because: {str(e)}')
    return []


def get_attachments_entries_for_fetched_incident(client: JiraBaseClient, attachment_ids: List[str]) -> List[Dict[str, Any]]:
    attachments_entries: List[Dict[str, Any]] = [
        create_file_info_from_attachment(
            client=client, attachment_id=attachment_id
        )
        for attachment_id in attachment_ids
    ]
    return attachments_entries


def create_incident_from_issue(client: JiraBaseClient, issue: Dict[str, Any], fetch_attachments: bool, fetch_comments: bool,
                               incoming_mirror: bool, outgoing_mirror: bool,
                               comment_tag: str, attachment_tag: str) -> Dict[str, Any]:
    issue_description: str = JiraIssueFieldsParser.get_description_context(issue_data=issue).get('Description') or ''
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
        {'type': 'description', 'value': issue_description},

    ]
    issue['parsedDescription'] = issue_description
    issue['extractedAttachments'] = JiraIssueFieldsParser.get_attachments_context(issue_data=issue).get('Attachments') or []
    issue['extractedSubtasks'] = JiraIssueFieldsParser.get_subtasks_context(issue_data=issue).get('Subtasks') or []
    issue['extractedCreator'] = JiraIssueFieldsParser.get_creator_context(issue_data=issue).get('Creator') or ''
    issue['extractedComponents'] = JiraIssueFieldsParser.get_components_context(issue_data=issue).get('Components') or []
    name = demisto.get(issue, 'fields.summary')
    if name:
        name = f"Jira issue: {issue.get('id')}"

    severity = get_jira_issue_severity(issue_field_priority=demisto.get(issue, 'fields.priority') or {})
    # if demisto.get(issue, 'fields.priority') and demisto.get(issue, 'fields.priority.name'):
    #     if demisto.get(issue, 'fields.priority.name') == 'Highest':
    #         severity = 4
    #     elif demisto.get(issue, 'fields.priority.name') == 'High':
    #         severity = 3
    #     elif demisto.get(issue, 'fields.priority.name') == 'Medium':
    #         severity = 2
    #     elif demisto.get(issue, 'fields.priority.name') == 'Low':
    #         severity = 1

    file_names: list = []
    if fetch_attachments:
        demisto.debug('Fetching attachments')
        attachment_ids: List[str] = [attachment.get('id', '') for attachment in (demisto.get(issue, 'fields.attachment') or [])]
        demisto.debug(f"The fetched attachments' ids {attachment_ids}")
        attachments_entries = get_attachments_entries_for_fetched_incident(client=client,
                                                                           attachment_ids=attachment_ids)
        file_names.extend(
            {
                'path': attachment_entry.get('FileID', ''),
                'name': attachment_entry.get('File', ''),
            }
            for attachment_entry in attachments_entries
            if attachment_entry['Type'] != entryTypes['error']
        )
    if fetch_comments:
        demisto.debug('Fetching comments')
        extracted_comment_bodies = get_comments_entries_for_fetched_incident(client=client, issue_id_or_key=issue_id)
        demisto.debug(f'Fetched comments {extracted_comment_bodies}')
        issue['extractedComments'] = extracted_comment_bodies
        labels.append({'type': 'comments', 'value': str(extracted_comment_bodies)})
    else:
        labels.append({'type': 'comments', 'value': '[]'})

    issue['mirror_direction'] = get_mirror_type(incoming_mirror, outgoing_mirror)

    issue['mirror_tags'] = [
        comment_tag,
        attachment_tag
    ]
    issue['mirror_instance'] = demisto.integrationInstance()
    return {
        "name": name,
        "labels": labels,
        "details": issue_description,
        "severity": severity,
        "attachment": file_names,
        "rawJSON": json.dumps(issue)
    }


def get_jira_issue_severity(issue_field_priority: Dict[str, Any]) -> int:
    severity = 0
    if issue_priority_name := issue_field_priority.get('name', ''):
        if issue_priority_name == 'Highest':
            severity = 4
        elif issue_priority_name == 'High':
            severity = 3
        elif issue_priority_name == 'Medium':
            severity = 2
        elif issue_priority_name == 'Low':
            severity = 1
    return severity


def convert_string_date_to_specific_format(string_date: str, date_format: str = '%Y-%m-%d %H:%M') -> str:
    """Convert a string that acts as a date to a specific format. Default is %Y-%m-%d %H:%M

    Args:
        string_date (str): The date as a string, or an empty string if there is not last fetch date.
        date_format (str): The format of the date to return. Default is %Y-%m-%d %H:%M

    Raises:
        DemistoException: When last_fetch_date is not a valid date.

    Returns:
        str: A string representing the date in %Y-%m-%d %H:%M format, or an empty string if string_date is an
        empty string.
    """
    if not string_date:
        return ''
    if parsed_string_date := dateparser.parse(string_date):
        return parsed_string_date.strftime(date_format)
    raise DemistoException(f'Could not parse the following date: {string_date}.')


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    # Cloud configuration params
    cloud_id = params.get('cloud_id', '')
    client_id = params.get('client_id', '')
    client_secret = params.get('client_secret', '')
    callback_url = params.get('callback_url', '')

    # OnPrem configuration params
    server_url = params.get('server_url', 'https://api.atlassian.com/ex/jira')

    # Fetch params
    issue_field_to_fetch_from = params.get('issue_field_to_fetch_from', 'id')
    fetch_query = params.get('fetch_query', 'status!=done')
    id_offset = params.get('id_offset', '0')
    fetch_attachments = params.get('fetch_attachments', False)
    fetch_comments = params.get('fetch_comments', False)
    max_fetch = params.get('max_fetch', DEFAULT_FETCH_LIMIT)
    fetch_interval = params.get('incidentFetchInterval', DEFAULT_FETCH_INTERVAL)  # in minutes
    # This is used for when issue_field_to_fetch_from is either, update date, created date, or status category change date,
    # it holds values such as: 3 days, 1 minute, 5 hours,...
    first_fetch_interval = params.get('first_fetch', DEFAULT_FIRST_FETCH_INTERVAL)
    incoming_mirror = params.get("incoming_mirror", False)
    outgoing_mirror = params.get('outgoing_mirror', False)
    comment_tag = params.get('comment_tag', 'comment tag')
    attachment_tag = params.get('file_tag', 'attachment tag')
    # Print to demisto.info which Jira instance the user supplied.
    # From param or if automatically
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    commands: Dict[str, Callable] = {
        'jira-oauth-start': ouath_start_command,
        'jira-oauth-complete': oauth_complete_command,
        'jira-oauth-test': test_authorization,
        'jira-get-comments': get_comments_command,
        'jira-get-issue': get_issue_command,
        'jira-create-issue': create_issue_command,
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
    }
    try:
        client: JiraBaseClient
        if cloud_id:
            client = JiraCloudClient(
                cloud_id=cloud_id,
                verify=verify_certificate,
                proxy=proxy,
                client_id=client_id,
                client_secret=client_secret,
                callback_url=callback_url,
                server_url=server_url)
        else:
            # Configure JiraOnPremClient
            # urljoin(url, '/')
            pass
        # else:
        #     raise DemistoException('Cloud ID and Server URL cannot be configured at the same time')

        if command == 'test-module':
            return_results(test_module(client))
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
                fetch_interval=arg_to_number(fetch_interval) or DEFAULT_FETCH_INTERVAL,
                first_fetch_interval=first_fetch_interval,
                incoming_mirror=argToBoolean(incoming_mirror),
                outgoing_mirror=argToBoolean(outgoing_mirror),
                comment_tag=comment_tag,
                attachment_tag=attachment_tag,
            ),
            )
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

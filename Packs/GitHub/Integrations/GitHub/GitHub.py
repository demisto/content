import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
import copy
import json
from datetime import datetime
from typing import Any, Union
import codecs
import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
BASE_URL: str
USER: str
TOKEN: str
PRIVATE_KEY: str
INTEGRATION_ID: str
INSTALLATION_ID: str
REPOSITORY: str
USE_SSL: bool
FETCH_TIME: str
MAX_FETCH_PAGE_RESULTS: int
USER_SUFFIX: str
ISSUE_SUFFIX: str
PROJECT_SUFFIX: str
RELEASE_SUFFIX: str
PULLS_SUFFIX: str
FILE_SUFFIX: str
HEADERS: dict

RELEASE_HEADERS = ['ID', 'Name', 'Download_count', 'Body', 'Created_at', 'Published_at']
ISSUE_HEADERS = ['ID', 'Repository', 'Organization', 'Title', 'State', 'Body', 'Created_at', 'Updated_at', 'Closed_at',
                 'Closed_by', 'Assignees', 'Labels']
PROJECT_HEADERS = ['Name', 'ID', 'Number', 'Columns']
FILE_HEADERS = ['Name', 'Path', 'Type', 'Size', 'SHA', 'DownloadUrl']

# Headers to be sent in requests
MEDIA_TYPE_INTEGRATION_PREVIEW = "application/vnd.github.machine-man-preview+json"
PROJECTS_PREVIEW = 'application/vnd.github.inertia-preview+json'

DEFAULT_PAGE_SIZE = 50
DEFAULT_PAGE_NUMBER = 1
''' HELPER FUNCTIONS '''


def create_jwt(private_key: str, integration_id: str):
    """
    Create a JWT token used for getting access token. It's needed for github bots.
    POSTs https://api.github.com/app/installations/<installation_id>/access_tokens
    :param private_key: str: github's private key
    :param integration_id: str: ID of the github integration (bot)
    """
    import jwt

    now = int(time.time())
    expiration = 60
    payload = {"iat": now, "exp": now + expiration, "iss": integration_id}
    jwt_token = jwt.encode(payload, private_key, algorithm='RS256')
    return jwt_token


def get_installation_access_token(installation_id: str, jwt_token: str):
    """
    Get an access token for the given installation id.
    POSTs https://api.github.com/app/installations/<installation_id>/access_tokens
    :param installation_id: str: the id of the installation (where the bot was installed)
    :param jwt_token: str token needed in the request for retrieving the access token
    """
    response = requests.post(
        "{}/app/installations/{}/access_tokens".format(
            BASE_URL, installation_id
        ),
        headers={
            "Authorization": "Bearer {}".format(jwt_token),
            "Accept": MEDIA_TYPE_INTEGRATION_PREVIEW,
        },
    )
    if response.status_code == 201:
        return response.json()['token']
    elif response.status_code == 403:
        return_error('403 Forbidden - The credentials are incorrect')
    elif response.status_code == 404:
        return_error('404 Not found - Installation wasn\'t found')
    else:
        return_error(f'Encountered an error: {response.text}')


def safe_get(obj_to_fetch_from: dict, what_to_fetch: str, default_val: Union[dict, list, str]) -> Any:
    """Guarantees the default value in place of a Nonetype object when the value for a given key is explicitly None

    Args:
        obj_to_fetch_from (dict): The dictionary to fetch from
        what_to_fetch (str): The key for the desired value
        default_val: The default value to set instead of None

    Returns:
        The fetched value unless it is None in which case the default is returned instead
    """
    val = obj_to_fetch_from.get(what_to_fetch, default_val)
    if val is None:
        val = default_val
    return val


def http_request(method, url_suffix, params=None, data=None, headers=None, is_raw_response=False):
    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        data=json.dumps(data),
        headers=headers or HEADERS
    )
    if res.status_code >= 400:
        try:
            json_res = res.json()
            # add message from GitHub if available
            err_msg = json_res.get('message', '')
            if err_msg and 'documentation_url' in json_res:
                err_msg += f' see: {json_res["documentation_url"]}'
            if json_res.get('errors') is None:
                err_msg = f'Error in API call to the GitHub Integration [{res.status_code}] {res.reason}. {err_msg}'
            else:
                error_code = json_res.get('errors')[0].get('code')
                if error_code == 'missing_field':
                    err_msg = f'Error: the field: "{json_res.get("errors")[0].get("field")}" requires a value. ' \
                              f'{err_msg}'
                elif error_code == 'invalid':
                    field = json_res.get('errors')[0].get('field')
                    if field == 'q':
                        err_msg = f'Error: invalid query - {json_res.get("errors")[0].get("message")}. {err_msg}'
                    else:
                        err_msg = f'Error: the field: "{field}" has an invalid value. {err_msg}'

                elif error_code == 'missing':
                    err_msg = f"Error: {json_res.get('errors')[0].get('resource')} does not exist. {err_msg}"

                elif error_code == 'already_exists':
                    err_msg = f"Error: the field {json_res.get('errors')[0].get('field')} must be unique. {err_msg}"

                else:
                    err_msg = f'Error in API call to the GitHub Integration [{res.status_code}] - {res.reason}. ' \
                              f'{err_msg}'
            raise DemistoException(err_msg)

        except ValueError:
            raise DemistoException(f'Error in API call to GitHub Integration [{res.status_code}] - {res.reason}')

    try:
        if res.status_code == 204:
            return res
        elif is_raw_response:
            return res.content.decode('utf-8')
        else:
            return res.json()

    except Exception as excep:
        return_error('Error in HTTP request - {}'.format(str(excep)))


def data_formatting(title, body, labels, assignees, state):
    """This method creates a dictionary to be used as "data" field in an http request."""
    data = {}
    if title is not None:
        data['title'] = title

    if body is not None:
        data['body'] = body

    if state is not None:
        data['state'] = state

    if labels is not None:
        data['labels'] = labels.split(',')

    if assignees is not None:
        data['assignees'] = assignees.split(',')

    return data


def context_create_issue(response, issue):
    """ Create GitHub.Issue EntryContext and results to be printed in Demisto.

    Args:
        response (dict): The raw HTTP response to be inserted to the 'Contents' field.
        issue (dict or list): A dictionary or a list of dictionaries formatted for Demisto results.
    """
    ec = {
        'GitHub.Issue(val.Repository == obj.Repository && val.ID == obj.ID)': issue
    }
    return_outputs(tableToMarkdown("Issues:", issue, headers=ISSUE_HEADERS, removeNull=True), ec, response)


def list_create(issue, list_name, element_name):
    """ Creates a list if parameters exist in issue.

    Args:
        issue(dict): an issue from GitHub.
        list_name (str): the name of the list in the issue.
        element_name (str): the field name of the element in the list.

    Returns:
        The created list or None if it does not exist.
    """
    if issue.get(list_name) is not None:
        return [element.get(element_name) for element in issue.get(list_name)]

    else:
        None


def issue_format(issue):
    """ Create a dictionary with selected fields representing an issue in Demisto.

    Args:
        issue (dict): An HTTP response representing an issue, formatted as a dictionary

    Returns:
        (dict). representing an issue in Demisto.
    """
    closed_by = None
    if issue.get('closed_by') is not None and issue.get('state') == 'closed':
        closed_by = issue.get('closed_by').get('login')

    org = ''
    repository_url = issue.get('repository_url').split('/')
    repo = repository_url[-1]
    if len(repository_url) > 1:
        org = repository_url[-2]

    form = {
        'ID': issue.get('number'),
        'Repository': repo,
        'Organization': org,
        'Title': issue.get('title'),
        'Body': issue.get('body'),
        'State': issue.get('state'),
        'Labels': list_create(issue, 'labels', 'name'),
        'Assignees': list_create(issue, 'assignees', 'login'),
        'Created_at': issue.get('created_at'),
        'Updated_at': issue.get('updated_at'),
        'Closed_at': issue.get('closed_at'),
        'Closed_by': closed_by,
        'Unique_ID': issue.get('id'),
    }
    return form


def create_issue_table(issue_list, response, limit):
    """ Get an HTTP response and a list containing several issues, sends each issue to be reformatted.

    Args:
        issue_list(list): derived from the HTTP response
        response (dict):A raw HTTP response sent for 'Contents' field in context

    Returns:
        The issues are sent to Demisto as a list.
    """
    issue_list.reverse()
    issue_table = []
    issue_count = 0
    for issue in issue_list:
        issue_table.append(issue_format(issue))
        issue_count = issue_count + 1
        if issue_count == limit:
            break

    context_create_issue(response, issue_table)


def format_commit_outputs(commit: dict = {}) -> dict:
    """Take GitHub API commit data and format to expected context outputs

    Args:
        commit (dict): commit data returned from GitHub API

    Returns:
        (dict): commit object formatted to expected context outputs
    """
    author = commit.get('author', {})
    ec_author = {
        'Date': author.get('date'),
        'Name': author.get('name'),
        'Email': author.get('email')
    }
    committer = commit.get('committer', {})
    ec_committer = {
        'Date': committer.get('date'),
        'Name': committer.get('name'),
        'Email': committer.get('email')
    }
    parents = commit.get('parents', [])
    formatted_parents = [{'SHA': parent.get('sha')} for parent in parents]

    verification = commit.get('verification', {})
    ec_verification = {
        'Verified': verification.get('verified'),
        'Reason': verification.get('reason'),
        'Signature': verification.get('signature'),
        'Payload': verification.get('payload')
    }

    ec_object = {
        'SHA': commit.get('sha'),
        'Author': ec_author,
        'Committer': ec_committer,
        'Message': commit.get('message'),
        'Parent': formatted_parents,
        'TreeSHA': commit.get('tree', {}).get('sha'),
        'Verification': ec_verification
    }
    return ec_object


def format_label_outputs(label: dict = {}) -> dict:
    """Take GitHub API label data and format to expected context outputs

    Args:
        label (dict): label data returned from GitHub API

    Returns:
        (dict): label object formatted to expected context outputs
    """
    ec_object = {
        'ID': label.get('id'),
        'NodeID': label.get('node_id'),
        'Name': label.get('name'),
        'Description': label.get('description'),
        'Color': label.get('Color'),
        'Default': label.get('default')
    }
    return ec_object


def format_user_outputs(user: dict = {}) -> dict:
    """Take GitHub API user data and format to expected context outputs

    Args:
        user (dict): user data returned from GitHub API

    Returns:
        (dict): user object formatted to expected context outputs
    """
    ec_user = {
        'Login': user.get('login'),
        'ID': user.get('id'),
        'NodeID': user.get('node_id'),
        'Type': user.get('type'),
        'SiteAdmin': user.get('site_admin')
    }
    return ec_user


def format_pr_review_comment_outputs(review_comment: dict = {}) -> dict:
    """Take GitHub API pr review comment data and format to expected context outputs

    Args:
        review_comment (dict): pre review comment data returned from GitHub API

    Returns:
        (dict): pr review comment object formatted to expected context outputs
    """
    ec_pr_review_comment = {
        'ID': review_comment.get('id'),
        'NodeID': review_comment.get('node_id'),
        'PullRequestReviewID': review_comment.get('pull_request_review_id'),
        'DiffHunk': review_comment.get('diff_hunk'),
        'Path': review_comment.get('path'),
        'Position': review_comment.get('position'),
        'OriginalPosition': review_comment.get('original_position'),
        'CommitID': review_comment.get('commit_id'),
        'OriginalCommitID': review_comment.get('original_commit_id'),
        'InReplyToID': review_comment.get('in_reply_to_id'),
        'User': format_user_outputs(review_comment.get('user', {})),
        'Body': review_comment.get('body'),
        'CreatedAt': review_comment.get('created_at'),
        'UpdatedAt': review_comment.get('updated_at'),
        'AuthorAssociation': review_comment.get('author_association')
    }
    return ec_pr_review_comment


def format_team_outputs(team: dict = {}) -> dict:
    """Take GitHub API team data and format to expected context outputs

    Args:
        team (dict): team data returned from GitHub API

    Returns:
        (dict): team object formatted to expected context outputs
    """
    ec_team = {
        'ID': team.get('id'),
        'NodeID': team.get('node_id'),
        'Name': team.get('name'),
        'Slug': team.get('slug'),
        'Description': team.get('description'),
        'Privacy': team.get('privacy'),
        'Permission': team.get('permission'),
        'Parent': team.get('parent')
    }
    return ec_team


def format_head_or_base_outputs(head_or_base: dict = {}) -> dict:
    """Take GitHub API head or base branch data and format to expected context outputs

    Args:
        head_or_base (dict): head or base branch data returned from GitHub API

    Returns:
        (dict): head or base branch object formatted to expected context outputs
    """
    head_or_base_user = head_or_base.get('user', {})
    ec_head_or_base_user = format_user_outputs(head_or_base_user)
    head_or_base_repo = head_or_base.get('repo', {})

    if head_or_base_repo:
        head_or_base_repo_owner = head_or_base_repo.get('owner', {})
    else:  # in case of a deleted fork
        head_or_base_repo = {}
        head_or_base_repo_owner = {
            "Login": "Unknown"
        }

    ec_head_or_base_repo_owner = format_user_outputs(head_or_base_repo_owner)
    ec_head_repo = {
        'ID': head_or_base_repo.get('id'),
        'NodeID': head_or_base_repo.get('node_id'),
        'Name': head_or_base_repo.get('name'),
        'FullName': head_or_base_repo.get('full_name'),
        'Owner': ec_head_or_base_repo_owner,
        'Private': head_or_base_repo.get('private'),
        'Description': head_or_base_repo.get('description'),
        'Fork': head_or_base_repo.get('fork'),
        'Language': head_or_base_repo.get('language'),
        'ForksCount': head_or_base_repo.get('forks_count'),
        'StargazersCount': head_or_base_repo.get('stargazers_count'),
        'WatchersCount': head_or_base_repo.get('watchers_count'),
        'Size': head_or_base_repo.get('size'),
        'DefaultBranch': head_or_base_repo.get('default_branch'),
        'OpenIssuesCount': head_or_base_repo.get('open_issues_count'),
        'Topics': head_or_base_repo.get('topics'),
        'HasIssues': head_or_base_repo.get('has_issues'),
        'HasProjects': head_or_base_repo.get('has_projects'),
        'HasWiki': head_or_base_repo.get('has_wiki'),
        'HasPages': head_or_base_repo.get('has_pages'),
        'HasDownloads': head_or_base_repo.get('has_downloads'),
        'Archived': head_or_base_repo.get('archived'),
        'Disabled': head_or_base_repo.get('disabled'),
        'PushedAt': head_or_base_repo.get('pushed_at'),
        'CreatedAt': head_or_base_repo.get('created_at'),
        'UpdatedAt': head_or_base_repo.get('updated_at'),
        'AllowRebaseMerge': head_or_base_repo.get('allow_rebase_merge'),
        'AllowSquashMerge': head_or_base_repo.get('allow_squash_merge'),
        'AllowMergeCommit': head_or_base_repo.get('allow_merge_commit'),
        'SucscribersCount': head_or_base_repo.get('subscribers_count')
    }
    ec_head_or_base = {
        'Label': head_or_base.get('label'),
        'Ref': head_or_base.get('ref'),
        'SHA': head_or_base.get('sha'),
        'User': ec_head_or_base_user,
        'Repo': ec_head_repo,
    }
    return ec_head_or_base


def format_pr_outputs(pull_request: dict = {}) -> dict:
    """Take GitHub API Pull Request data and format to expected context outputs

    Args:
        pull_request (dict): Pull Request data returned from GitHub API

    Returns:
        (dict): Pull Request object formatted to expected context outputs
    """
    user_data = safe_get(pull_request, 'user', {})
    ec_user = format_user_outputs(user_data)

    labels_data = safe_get(pull_request, 'labels', [])
    ec_labels = [format_label_outputs(label) for label in labels_data]

    milestone_data = safe_get(pull_request, 'milestone', {})
    creator = safe_get(milestone_data, 'creator', {})
    ec_creator = format_user_outputs(creator)
    ec_milestone = {
        'ID': milestone_data.get('id'),
        'NodeID': milestone_data.get('node_id'),
        'Number': milestone_data.get('number'),
        'State': milestone_data.get('state'),
        'Title': milestone_data.get('title'),
        'Description': milestone_data.get('description'),
        'OpenIssues': milestone_data.get('open_issues'),
        'ClosedIssues': milestone_data.get('closed_issues'),
        'CreatedAt': milestone_data.get('created_at'),
        'UpdatedAt': milestone_data.get('updated_at'),
        'ClosedAt': milestone_data.get('closed_at'),
        'DueOn': milestone_data.get('due_on'),
    }
    if creator:
        ec_milestone['Creator'] = ec_creator

    assignees_data = safe_get(pull_request, 'assignees', [])
    ec_assignee = [format_user_outputs(assignee) for assignee in assignees_data]

    requested_reviewers_data = safe_get(pull_request, 'requested_reviewers', [])
    ec_requested_reviewer = [format_user_outputs(requested_reviewer) for requested_reviewer in requested_reviewers_data]

    requested_teams_data = safe_get(pull_request, 'requested_teams', [])
    ec_requested_team = [format_team_outputs(requested_team) for requested_team in requested_teams_data]

    head_data = safe_get(pull_request, 'head', {})
    ec_head = format_head_or_base_outputs(head_data)

    base_data = safe_get(pull_request, 'base', {})
    ec_base = format_head_or_base_outputs(base_data)

    merged_by_data = safe_get(pull_request, 'merged_by', {})
    ec_merged_by = format_user_outputs(merged_by_data)

    ec_object = {
        'ID': pull_request.get('id'),
        'NodeID': pull_request.get('node_id'),
        'Number': pull_request.get('number'),
        'State': pull_request.get('state'),
        'Locked': pull_request.get('locked'),
        'Body': pull_request.get('body'),
        'ActiveLockReason': pull_request.get('active_lock_reason'),
        'CreatedAt': pull_request.get('created_at'),
        'UpdatedAt': pull_request.get('updated_at'),
        'ClosedAt': pull_request.get('closed_at'),
        'MergedAt': pull_request.get('merged_at'),
        'MergeCommitSHA': pull_request.get('merge_commit_sha'),
        'AuthorAssociation': pull_request.get('author_association'),
        'Draft': pull_request.get('draft'),
        'Merged': pull_request.get('merged'),
        'Mergeable': pull_request.get('mergeable'),
        'Rebaseable': pull_request.get('rebaseable'),
        'MergeableState': pull_request.get('mergeable_state'),
        'Comments': pull_request.get('comments'),
        'ReviewComments': pull_request.get('review_comments'),
        'MaintainerCanModify': pull_request.get('maintainer_can_modify'),
        'Commits': pull_request.get('commits'),
        'Additions': pull_request.get('additions'),
        'Deletions': pull_request.get('deletions'),
        'ChangedFiles': pull_request.get('changed_files')
    }
    if user_data:
        ec_object['User'] = ec_user
    if labels_data:
        ec_object['Label'] = ec_labels
    if assignees_data:
        ec_object['Assignee'] = ec_assignee
    if requested_reviewers_data:
        ec_object['RequestedReviewer'] = ec_requested_reviewer
    if requested_teams_data:
        ec_object['RequestedTeam'] = ec_requested_team
    if head_data:
        ec_object['Head'] = ec_head
    if base_data:
        ec_object['Base'] = ec_base
    if merged_by_data:
        ec_object['MergedBy'] = ec_merged_by
    if milestone_data:
        ec_object['Milestone'] = ec_milestone
    return ec_object


def format_comment_outputs(comment: dict, issue_number: Union[int, str]) -> dict:
    """Take GitHub API Comment data and format to expected context outputs

    Args:
        comment (dict): Comment data returned from GitHub API
        issue_number (int): The number of the issue to which the comment belongs

    Returns:
        (dict): Comment object formatted to expected context outputs
    """
    ec_object = {
        'IssueNumber': int(issue_number) if isinstance(issue_number, str) else issue_number,
        'ID': comment.get('id'),
        'NodeID': comment.get('node_id'),
        'Body': comment.get('body'),
        'User': format_user_outputs(comment.get('user', {}))
    }
    return ec_object


''' COMMANDS '''


def test_module():
    http_request(method='GET', url_suffix=ISSUE_SUFFIX, params={'state': 'all'})
    demisto.results("ok")


def create_pull_request(create_vals: dict = {}) -> dict:
    suffix = PULLS_SUFFIX
    response = http_request('POST', url_suffix=suffix, data=create_vals)
    return response


def create_pull_request_command():
    args = demisto.args()
    create_vals = {key: val for key, val in args.items()}
    maintainer_can_modify = args.get('maintainer_can_modify')
    if maintainer_can_modify:
        create_vals['maintainer_can_modify'] = maintainer_can_modify == 'true'
    draft = args.get('draft')
    if draft:
        create_vals['draft'] = draft == 'true'
    response = create_pull_request(create_vals)

    ec_object = format_pr_outputs(response)
    ec = {
        'GitHub.PR(val.Number === obj.Number)': ec_object
    }
    human_readable = tableToMarkdown(f'Created Pull Request #{response.get("number")}', ec_object, removeNull=True)
    return_outputs(readable_output=human_readable, outputs=ec, raw_response=response)


def list_branch_pull_requests(branch_name: str, repository: Optional[str] = None,
                              organization: Optional[str] = None) -> List[Dict]:
    """
    Performs API request to GitHub service and formats the returned pull requests details to outputs.
    Args:
        branch_name (str): Name of the branch to retrieve its PR.
        repository (Optional[str]): Repository the branch resides in. Defaults to 'REPOSITORY' if not given.
        organization (Optional[str]): Organization the branch resides in. Defaults to 'USER' if not given.

    Returns:
        (List[Dict]): List of the formatted pull requests outputs.
    """
    repository = repository if repository else REPOSITORY
    organization = organization if organization else USER
    suffix = f'/repos/{organization}/{repository}/pulls?head={organization}:{branch_name}'
    response = http_request('GET', url_suffix=suffix)
    formatted_outputs = [format_pr_outputs(output) for output in response]

    return formatted_outputs


def list_branch_pull_requests_command() -> None:
    """
    List all pull requests corresponding to the given 'branch_name' in 'organization'
    Args:
        - 'branch_name': Branch name to retrieve its pull requests.
        - 'organization': Organization the branch belongs to.
        - 'repository': The repository the branch belongs to. Uses 'REPOSITORY' parameter if not given.
    Returns:
        (None): Results to XSOAR.
    """
    args = demisto.args()
    branch_name = args.get('branch_name', '')
    organization = args.get('organization')
    repository = args.get('repository')
    formatted_outputs = list_branch_pull_requests(branch_name, repository, organization)

    return_results(CommandResults(
        outputs_prefix='GitHub.PR',
        outputs_key_field='Number',
        outputs=formatted_outputs,
        readable_output=tableToMarkdown(f'Pull Request For Branch #{branch_name}', formatted_outputs, removeNull=True)
    ))


def is_pr_merged(pull_number: Union[int, str]):
    suffix = PULLS_SUFFIX + f'/{pull_number}/merge'
    response = http_request('GET', url_suffix=suffix)
    return response


def is_pr_merged_command():
    args = demisto.args()
    pull_number = args.get('pull_number')

    # raises 404 not found error if the pr was not merged
    is_pr_merged(pull_number)
    demisto.results(f'Pull Request #{pull_number} was Merged')


def update_pull_request(pull_number: Union[int, str], update_vals: dict = {}) -> dict:
    suffix = PULLS_SUFFIX + f'/{pull_number}'
    response = http_request('PATCH', url_suffix=suffix, data=update_vals)
    return response


def update_pull_request_command():
    args = demisto.args()
    pull_number = args.get('pull_number')
    update_vals = {key: val for key, val in args.items() if key != 'pull_number'}
    if not update_vals:
        return_error('You must provide a value for at least one of the command\'s arguments "title", "body", "state",'
                     ' "base" or "maintainer_can_modify" that you would like to update the pull request with')
    maintainer_can_modify = update_vals.get('maintainer_can_modify')
    if maintainer_can_modify:
        update_vals['maintainer_can_modify'] = maintainer_can_modify == 'true'
    response = update_pull_request(pull_number, update_vals)

    ec_object = format_pr_outputs(response)
    ec = {
        'GitHub.PR(val.Number === obj.Number)': ec_object
    }
    human_readable = tableToMarkdown(f'Updated Pull Request #{pull_number}', ec_object, removeNull=True)
    return_outputs(readable_output=human_readable, outputs=ec, raw_response=response)


def list_teams(organization: str) -> list:
    suffix = f'/orgs/{organization}/teams'
    response = http_request('GET', url_suffix=suffix)
    return response


def list_teams_command():
    args = demisto.args()
    organization = args.get('organization')
    response = list_teams(organization)

    ec_object = [format_team_outputs(team) for team in response]
    ec = {
        'GitHub.Team(val.ID === obj.ID)': ec_object
    }
    human_readable = tableToMarkdown(f'Teams for Organization "{organization}"', ec_object, removeNull=True)
    return_outputs(readable_output=human_readable, outputs=ec, raw_response=response)


def get_pull_request(pull_number: Union[int, str], repository: str = None, organization: str = None):
    if repository and organization and pull_number:
        suffix = f'/repos/{organization}/{repository}/pulls/{pull_number}'
    else:
        suffix = PULLS_SUFFIX + f'/{pull_number}'
    response = http_request('GET', url_suffix=suffix)
    return response


def get_pull_request_command():
    args = demisto.args()
    pull_number = args.get('pull_number')
    organization = args.get('organization')
    repository = args.get('repository')
    response = get_pull_request(pull_number, repository, organization)

    ec_object = format_pr_outputs(response)
    ec = {
        'GitHub.PR(val.Number === obj.Number)': ec_object
    }
    human_readable = tableToMarkdown(f'Pull Request #{pull_number}', ec_object, removeNull=True)
    return_outputs(readable_output=human_readable, outputs=ec, raw_response=response)


def add_label(issue_number: Union[int, str], labels: list):
    suffix = ISSUE_SUFFIX + f'/{issue_number}/labels'
    response = http_request('POST', url_suffix=suffix, data={'labels': labels})
    return response


def add_label_command():
    args = demisto.args()
    issue_number = args.get('issue_number')
    labels = argToList(args.get('labels'))
    add_label(issue_number, labels)
    labels_for_msg = [f'"{label}"' for label in labels]
    msg = f'{" and ".join(labels_for_msg)} Successfully Added to Issue #{issue_number}'
    msg = 'Labels ' + msg if 'and' in msg else 'Label ' + msg
    demisto.results(msg)


def get_commit(commit_sha: str) -> dict:
    suffix = USER_SUFFIX + f'/git/commits/{commit_sha}'
    response = http_request('GET', url_suffix=suffix)
    return response


def get_commit_command():
    args = demisto.args()
    commit_sha = args.get('commit_sha')
    response = get_commit(commit_sha)

    ec_object = format_commit_outputs(response)
    ec = {
        'GitHub.Commit(val.SHA === obj.SHA)': ec_object
    }
    human_readable = tableToMarkdown(f'Commit *{commit_sha[:10]}*', ec_object, removeNull=True)
    return_outputs(readable_output=human_readable, outputs=ec, raw_response=response)


def list_pr_reviews(pull_number: Union[int, str]) -> list:
    suffix = PULLS_SUFFIX + f'/{pull_number}/reviews'
    response = http_request('GET', url_suffix=suffix)
    return response


def list_pr_reviews_command():
    args = demisto.args()
    pull_number = args.get('pull_number')
    response = list_pr_reviews(pull_number)

    formatted_pr_reviews = [
        {
            'ID': pr_review.get('id'),
            'NodeID': pr_review.get('node_id'),
            'Body': pr_review.get('body'),
            'CommitID': pr_review.get('commit_id'),
            'State': pr_review.get('state'),
            'User': format_user_outputs(pr_review.get('user', {}))
        }
        for pr_review in response
    ]
    ec_object = {
        'Number': pull_number,
        'Review': formatted_pr_reviews
    }
    ec = {
        'GitHub.PR(val.Number === obj.Number)': ec_object
    }
    human_readable = tableToMarkdown(f'Pull Request Reviews for #{pull_number}', formatted_pr_reviews, removeNull=True)
    return_outputs(readable_output=human_readable, outputs=ec, raw_response=response)


def list_pr_files(pull_number: Union[int, str], organization: str = None, repository: str = None) -> list:
    if pull_number and organization and repository:
        suffix = f'/repos/{organization}/{repository}/pulls/{pull_number}/files'
    else:
        suffix = PULLS_SUFFIX + f'/{pull_number}/files'
    response = http_request('GET', url_suffix=suffix)
    return response


def list_pr_files_command():
    args = demisto.args()
    pull_number = args.get('pull_number')
    organization = args.get('organization')
    repository = args.get('repository')
    response = list_pr_files(pull_number, organization, repository)

    formatted_pr_files = [
        {
            'SHA': pr_file.get('sha'),
            'Name': pr_file.get('filename'),
            'Status': pr_file.get('status'),
            'Additions': pr_file.get('additions'),
            'Deletions': pr_file.get('deletions'),
            'Changes': pr_file.get('changes')
        }
        for pr_file in response
    ]
    ec_object = {
        'Number': pull_number,
        'File': formatted_pr_files
    }
    ec = {
        'GitHub.PR(val.Number === obj.Number)': ec_object
    }
    human_readable = tableToMarkdown(f'Pull Request Files for #{pull_number}', formatted_pr_files, removeNull=True)
    return_outputs(readable_output=human_readable, outputs=ec, raw_response=response)


def list_pr_review_comments(pull_number: Union[int, str]) -> list:
    suffix = PULLS_SUFFIX + f'/{pull_number}/comments'
    response = http_request('GET', url_suffix=suffix)
    return response


def list_pr_review_comments_command():
    args = demisto.args()
    pull_number = args.get('pull_number')
    response = list_pr_review_comments(pull_number)

    formatted_pr_review_comments = [format_pr_review_comment_outputs(review_comment) for review_comment in response]
    ec_object = {
        'Number': pull_number,
        'ReviewComment': formatted_pr_review_comments
    }
    ec = {
        'GitHub.PR(val.Number === obj.Number)': ec_object
    }
    human_readable = tableToMarkdown(f'Pull Request Review Comments for #{pull_number}', formatted_pr_review_comments,
                                     removeNull=True)
    return_outputs(readable_output=human_readable, outputs=ec, raw_response=response)


def list_issue_comments(issue_number: Union[int, str], since_date: Optional[str]) -> list:
    suffix = ISSUE_SUFFIX + f'/{issue_number}/comments'
    params = {}
    if since_date:
        params = {'since': since_date}
    response = http_request('GET', url_suffix=suffix, params=params)
    return response


def list_issue_comments_command():
    args = demisto.args()
    issue_number = args.get('issue_number')
    since_date = args.get('since')
    response = list_issue_comments(issue_number, since_date)

    ec_object = [format_comment_outputs(comment, issue_number) for comment in response]
    ec = {
        'GitHub.Comment(val.IssueNumber === obj.IssueNumber && val.ID === obj.ID)': ec_object
    }
    human_readable = tableToMarkdown(f'Comments for Issue #{issue_number}', ec_object, removeNull=True)
    return_outputs(readable_output=human_readable, outputs=ec, raw_response=response)


def create_comment(issue_number: Union[int, str], msg: str) -> dict:
    suffix = ISSUE_SUFFIX + f'/{issue_number}/comments'
    response = http_request('POST', url_suffix=suffix, data={'body': msg})
    return response


def create_comment_command():
    args = demisto.args()
    issue_number = args.get('issue_number')
    body = args.get('body')
    response = create_comment(issue_number, body)

    ec_object = format_comment_outputs(response, issue_number)
    ec = {
        'GitHub.Comment(val.IssueNumber === obj.IssueNumber && val.ID === obj.ID)': ec_object
    }
    human_readable = tableToMarkdown('Created Comment', ec_object, removeNull=True)
    return_outputs(readable_output=human_readable, outputs=ec, raw_response=response)


def request_review(pull_number: Union[int, str], reviewers: list) -> dict:
    """Make an API call to GitHub to request reviews from a list of users for a given PR

    Args:
        pull_number (int): The number of the PR for which the review request(s) is/are being made
        reviewers (list): The list of GitHub usernames from which you wish to request a review

    Returns:
        dict: API response

    Raises:
        Exception: An exception will be raised if one or more of the requested reviewers is not
            a collaborator of the repo and therefore the API call returns a 'Status: 422 Unprocessable Entity'
    """
    suffix = PULLS_SUFFIX + f'/{pull_number}/requested_reviewers'
    response = http_request('POST', url_suffix=suffix, data={'reviewers': reviewers})
    return response


def request_review_command():
    args = demisto.args()
    pull_number = args.get('pull_number')
    reviewers = argToList(args.get('reviewers'))
    response = request_review(pull_number, reviewers)

    requested_reviewers = response.get('requested_reviewers', [])
    formatted_requested_reviewers = [format_user_outputs(reviewer) for reviewer in requested_reviewers]
    ec_object = {
        'Number': response.get('number'),
        'RequestedReviewer': formatted_requested_reviewers
    }
    ec = {
        'GitHub.PR(val.Number === obj.Number)': ec_object
    }
    human_readable = tableToMarkdown(f'Requested Reviewers for #{response.get("number")}',
                                     formatted_requested_reviewers, removeNull=True)
    return_outputs(readable_output=human_readable, outputs=ec, raw_response=response)


def get_team_membership(team_id: Union[int, str], user_name: str) -> dict:
    suffix = f'/teams/{team_id}/memberships/{user_name}'
    response = http_request('GET', url_suffix=suffix)
    return response


def get_team_members(organization: str, team_slug: str, maximum_users: int = 30) -> list:
    page = 1
    results: list = []
    while len(results) < maximum_users:
        results_per_page = maximum_users - len(results)
        results_per_page = min(results_per_page, 100)
        params = {'page': page, 'per_page': results_per_page}
        suffix = f'/orgs/{organization}/teams/{team_slug}/members'
        response = http_request('GET', url_suffix=suffix, params=params)
        if not response:
            break
        results.extend(response)
        page += 1

    return results


def get_team_membership_command():
    args = demisto.args()
    team_id = args.get('team_id')
    try:
        team_id = int(team_id)
    except ValueError as e:
        return_error('"team_id" command argument must be an integer value.', e)
    user_name = args.get('user_name')
    response = get_team_membership(team_id, user_name)

    ec_object = {
        'ID': team_id,
        'Member': {
            'Login': user_name,
            'Role': response.get('role'),
            'State': response.get('state')
        }
    }
    ec = {
        'GitHub.Team': ec_object
    }
    human_readable = tableToMarkdown(f'Team Membership of {user_name}', ec_object, removeNull=True)
    return_outputs(readable_output=human_readable, outputs=ec, raw_response=response)


def get_branch(branch: str) -> dict:
    suffix = USER_SUFFIX + f'/branches/{branch}'
    response = http_request('GET', url_suffix=suffix)
    return response


def get_branch_command():
    args = demisto.args()
    branch_name = args.get('branch_name')
    response = get_branch(branch_name)

    commit = response.get('commit', {}) or {}
    author = commit.get('author', {}) or {}
    parents = commit.get('parents', []) or []
    ec_object = {
        'Name': response.get('name'),
        'CommitSHA': commit.get('sha'),
        'CommitNodeID': commit.get('node_id'),
        'CommitAuthorID': author.get('id'),
        'CommitAuthorLogin': author.get('login'),
        'CommitParentSHA': [parent.get('sha') for parent in parents],
        'Protected': response.get('protected')
    }
    ec = {
        'GitHub.Branch(val.Name === obj.Name && val.CommitSHA === obj.CommitSHA)': ec_object
    }
    human_readable = tableToMarkdown(f'Branch "{branch_name}"', ec_object, removeNull=True)
    return_outputs(readable_output=human_readable, outputs=ec, raw_response=response)


def create_branch(name: str, sha: str) -> dict:
    suffix = USER_SUFFIX + '/git/refs'
    data = {
        'ref': f'refs/heads/{name}',
        'sha': sha
    }
    response = http_request('POST', url_suffix=suffix, data=data)
    return response


def create_branch_command():
    args = demisto.args()
    branch_name = args.get('branch_name')
    commit_sha = args.get('commit_sha')
    create_branch(branch_name, commit_sha)
    msg = f'Branch "{branch_name}" Created Successfully'
    demisto.results(msg)


def delete_branch(name: str):
    suffix = USER_SUFFIX + f'/git/refs/heads/{name}'
    http_request('DELETE', url_suffix=suffix)


def delete_branch_command():
    args = demisto.args()
    branch_name = args.get('branch_name')
    delete_branch(branch_name)
    msg = f'Branch "{branch_name}" Deleted Successfully'
    demisto.results(msg)


def get_stale_prs(stale_time: str, label: str) -> list:
    time_range_start, _ = parse_date_range(stale_time)
    # regex for removing the digits from the end of the isoformat timestamp that don't conform to API expectations
    timestamp_regex = re.compile(r'\.\d{6}$')
    timestamp, _ = timestamp_regex.subn('', time_range_start.isoformat())
    query = f'repo:{USER}/{REPOSITORY} is:open updated:<{timestamp} is:pr'
    if label:
        query += f' label:{label}'
    matching_issues = search_issue(query, 100).get('items', [])
    relevant_prs = [get_pull_request(issue.get('number')) for issue in matching_issues]
    return relevant_prs


def get_stale_prs_command():
    args = demisto.args()
    stale_time = args.get('stale_time', '3 days')
    label = args.get('label')
    results = get_stale_prs(stale_time, label)
    if results:
        formatted_results = []
        for pr in results:
            requested_reviewers = [
                requested_reviewer.get('login') for requested_reviewer in pr.get('requested_reviewers', [])
            ]
            formatted_pr = {
                'URL': f'<{pr.get("html_url")}>',
                'Number': pr.get('number'),
                'RequestedReviewer': requested_reviewers
            }
            formatted_results.append(formatted_pr)
        ec = {
            'GitHub.PR(val.Number === obj.Number)': formatted_results
        }
        human_readable = tableToMarkdown('Stale PRs', formatted_results, removeNull=True)
        return_outputs(readable_output=human_readable, outputs=ec, raw_response=results)
    else:
        demisto.results('No stale external PRs found')


def create_issue(title, body, labels, assignees):
    data = data_formatting(title=title,
                           body=body,
                           labels=labels,
                           assignees=assignees,
                           state=None)

    response = http_request(method='POST',
                            url_suffix=ISSUE_SUFFIX,
                            data=data)
    return response


def create_command():
    args = demisto.args()
    response = create_issue(args.get('title'), args.get('body'),
                            args.get('labels'), args.get('assignees'))
    issue = issue_format(response)
    context_create_issue(response, issue)


def close_issue(id):
    response = http_request(method='PATCH',
                            url_suffix=ISSUE_SUFFIX + '/{}'.format(str(id)),
                            data={'state': 'closed'})
    return response


def close_command():
    id = demisto.args().get('ID')
    response = close_issue(id)
    issue = issue_format(response)
    context_create_issue(response, issue)


def update_issue(id, title, body, state, labels, assign):
    data = data_formatting(title=title,
                           body=body,
                           labels=labels,
                           assignees=assign,
                           state=state)

    response = http_request(method='PATCH',
                            url_suffix=ISSUE_SUFFIX + '/{}'.format(str(id)),
                            data=data)
    return response


def update_command():
    args = demisto.args()
    response = update_issue(args.get('ID'), args.get('title'), args.get('body'), args.get('state'),
                            args.get('labels'), args.get('assignees'))
    issue = issue_format(response)
    context_create_issue(response, issue)


def list_all_issue(state, page=1):
    params = {'state': state, 'page': page, 'per_page': MAX_FETCH_PAGE_RESULTS, }
    response = http_request(method='GET',
                            url_suffix=ISSUE_SUFFIX,
                            params=params)
    if len(response) == MAX_FETCH_PAGE_RESULTS:
        return response + list_all_issue(state=state, page=page + 1)
    else:
        return response


def get_cards(url, header, page=1):
    resp = requests.get(url=url,
                        headers=header,
                        verify=USE_SSL,
                        params={'page': page, 'per_page': MAX_FETCH_PAGE_RESULTS}
                        )
    cards = resp.json()
    column_issues = []
    for card in cards:
        if "content_url" in card:
            column_issues.append({"CardID": card["id"], "ContentNumber": int(card["content_url"].rsplit('/', 1)[1])})
    if len(cards) == MAX_FETCH_PAGE_RESULTS:
        return column_issues + get_cards(url=url, header=header, page=page + 1)
    else:
        return column_issues


def get_project_details(project, header):
    resp_column = requests.get(url=project["columns_url"],
                               headers=header,
                               verify=USE_SSL)

    json_column = resp_column.json()
    columns_data = {}
    all_project_issues = []

    for column in json_column:
        cards = get_cards(url=column["cards_url"], header=header)
        columns_data[column["name"]] = {'Name': column["name"],
                                        'ColumnID': column["id"],
                                        'Cards': cards}
        for card in cards:
            all_project_issues.append(card["ContentNumber"])

    return {'Name': project["name"],
            'ID': project["id"],
            'Number': project["number"],
            'Columns': columns_data,
            'Issues': all_project_issues,
            }


def list_all_projects_command():
    project_f = demisto.args().get('project_filter', [])
    limit = demisto.args().get('limit', MAX_FETCH_PAGE_RESULTS)

    if int(limit) > MAX_FETCH_PAGE_RESULTS or project_f:
        limit = MAX_FETCH_PAGE_RESULTS

    if project_f:
        project_f = project_f.split(",")

    header = HEADERS
    header.update({'Accept': PROJECTS_PREVIEW})
    params = {'per_page': limit}
    resp_projects = requests.get(url=BASE_URL + PROJECT_SUFFIX,
                                 headers=header,
                                 verify=USE_SSL,
                                 params=params
                                 )
    projects = resp_projects.json()
    projects_obj = []
    for proj in projects:
        if project_f:
            if str(proj["number"]) in project_f:
                projects_obj.append(get_project_details(project=proj, header=header))
        else:
            projects_obj.append(get_project_details(project=proj, header=header))

    human_readable_projects = [{'Name': proj['Name'], 'ID': proj['ID'], 'Number': proj['Number'],
                                'Columns': [column for column in proj['Columns']]} for proj in projects_obj]

    if projects_obj:
        human_readable = tableToMarkdown('Projects:', t=human_readable_projects, headers=PROJECT_HEADERS,
                                         removeNull=True)
    else:
        human_readable = f'Not found projects with number - {",".join(project_f)}.'

    command_results = CommandResults(
        outputs_prefix='GitHub.Project',
        outputs_key_field='Name',
        outputs=projects_obj,
        readable_output=human_readable
    )
    return_results(command_results)


def add_issue_to_project_board_command():
    content_type = "Issue"

    args = demisto.args()
    column_id = args.get('column_id')
    content_id = int(args.get('issue_unique_id'))
    if "content_type" in demisto.args():
        content_type = args.get('content_type')

    header = HEADERS
    header.update({'Accept': PROJECTS_PREVIEW})

    post_url = "%s/projects/columns/%s/cards" % (BASE_URL, column_id)
    post_data = {"content_id": content_id,
                 "content_type": content_type,
                 }
    response = requests.post(url=post_url,
                             headers=header,
                             verify=USE_SSL,
                             data=json.dumps(post_data)
                             )

    if response.status_code >= 400:
        message = response.json().get('message', f'Failed to add the issue with ID {content_id} to column with ID '
                                                 f'{column_id}')
        return_error(f"Post result {response}\nMessage: {message}")

    return_results(f"The issue was successfully added to column ID {column_id}.")


def list_all_command():
    state = demisto.args().get('state')
    limit = int(demisto.args().get('limit'))
    if limit > 200:
        limit = 200

    response = list_all_issue(state)
    create_issue_table(response, response, limit)


def search_code(query, page=None, page_size=None):
    headers = copy.deepcopy(HEADERS)
    headers['Accept'] = 'application/vnd.github.v3+json'
    params = {
        'q': query
    }

    if page is not None:
        params['page'] = page
    if page_size is not None:
        params['per_page'] = page_size

    response = http_request(method='GET',
                            url_suffix='/search/code',
                            params=params,
                            headers=headers)
    return response


def search_code_command():
    q = demisto.args().get('query')
    page_number = demisto.args().get('page_number')
    page_size = demisto.args().get('page_size')
    limit = demisto.args().get('limit')

    response = None

    if limit and page_number:
        raise ValueError('Must pass either limit or page_number with page_size')
    elif limit:
        tmp_limit = int(limit)

        page_size = int(page_size or 100)
        while tmp_limit > 0:
            page_number = int(tmp_limit / page_size)
            res = search_code(
                query=q,
                page=page_number,
                page_size=min(page_size, tmp_limit)
            )

            if not response:
                response = res
            else:
                response['items'].extend(res.get('items', []))

            tmp_limit = tmp_limit - page_size

    else:
        page_number = int(page_number or 0)
        page_size = int(page_size or 50)

        response = search_code(
            query=q,
            page=page_number,
            page_size=page_size
        )

    total_count = response.get('total_count') if response else 0
    items = response.get('items', []) if response else []
    outputs = []
    md_table = []
    for item in items:
        outputs.append({
            'name': item.get('name'),
            'path': item.get('path'),
            'html_url': item.get('html_url'),
            'repository': {
                'desrciption': item.get('repository', {}).get('description'),
                'full_name': item.get('repository', {}).get('full_name'),
                'html_url': item.get('repository', {}).get('html_url'),
                'branches_url': item.get('repository', {}).get('branches_url'),
                'releases_url': item.get('repository', {}).get('releases_url'),
                'commits_url': item.get('repository', {}).get('commits_url'),
                'private': item.get('repository', {}).get('private'),
                'id': item.get('repository', {}).get('id')
            }
        })

        md_table.append({
            'Name': f'[{item.get("name")}]({item.get("html_url")})',
            'Path': item.get('path'),
            'Repository Name': item.get('repository', {}).get('full_name'),
            'Repository Description': item.get('repository', {}).get('description'),
            'Is Repository Private': item.get('repository', {}).get('private')
        })
    md = tableToMarkdown(f'Returned {len(md_table)} out of {total_count} total results.', md_table,
                         headers=['Name', 'Path', 'Repository Name', 'Repository Description', 'Is Repository Private'])

    results = CommandResults(
        outputs_prefix='GitHub.CodeSearchResults',
        outputs_key_field='html_url',
        outputs=outputs,
        raw_response=response,
        readable_output=md
    )

    return_results(results)


def search_issue(query, limit, page=1):
    params = {'q': query, 'page': page, 'per_page': MAX_FETCH_PAGE_RESULTS, }
    response = http_request(method='GET',
                            url_suffix='/search/issues',
                            params=params)
    if len(response["items"]) == MAX_FETCH_PAGE_RESULTS:
        next_res = search_issue(query=query, limit=limit, page=page + 1)
        response["items"] = response["items"] + next_res["items"]
        return response
    else:
        return response


def search_command():
    q = demisto.args().get('query')
    limit = int(demisto.args().get('limit'))
    if limit > 1000:
        limit = 1000  # per GitHub limitation.
    response = search_issue(q, limit)
    create_issue_table(response['items'], response, limit)


def get_download_count():
    response = http_request(method='GET',
                            url_suffix=RELEASE_SUFFIX)

    count_per_release = []
    for release in response:
        total_download_count = 0
        for asset in release.get('assets', []):
            total_download_count = total_download_count + asset['download_count']

        release_info = {
            'ID': release.get('id'),
            'Download_count': total_download_count,
            'Name': release.get('name'),
            'Body': release.get('body'),
            'Created_at': release.get('created_at'),
            'Published_at': release.get('published_at')
        }
        count_per_release.append(release_info)

    ec = {
        'GitHub.Release( val.ID == obj.ID )': count_per_release
    }
    return_outputs(tableToMarkdown('Releases:', count_per_release, headers=RELEASE_HEADERS, removeNull=True), ec,
                   response)


def list_owner_repositories(owner_name, repo_type):
    """ List organization repositories.

    Args:
        owner_name (str): repositories owner.
        repo_type (str): repository type, possible values: all, public, private, forks, sources, member, internal.

    Returns:
        list: organization repositories names.
    """
    url_suffix = f"/orgs/{owner_name}/repos"
    params = {'type': repo_type}
    repos_info = http_request(method="GET", url_suffix=url_suffix, params=params)

    return [r.get('name') for r in repos_info]


def list_repository_workflows(owner_name, repository_name):
    """ Lists the workflows in a repository.

    Args:
        owner_name (str): repositories owner.
        repository_name (str): repository name.

    Returns:
        list: list of dictionaries of workflow data.
    """
    url_suffix = f"/repos/{owner_name}/{repository_name}/actions/workflows"
    repository_workflows = http_request(method="GET", url_suffix=url_suffix)

    return [w for w in repository_workflows.get('workflows') if w.get('state') == "active"]


def get_workflow_usage(owner_name, repository_name, workflow_id):
    """ Gets the number of billable minutes used by a specific workflow during the current billing cycle.

    Args:
        owner_name (str): repositories owner.
        repository_name (str): repository name.
        workflow_id (str): workflow id.

    Returns:
        dict: milliseconds usage on ubuntu, macos and windows os.
    """
    url_suffix = f"/repos/{owner_name}/{repository_name}/actions/workflows/{workflow_id}/timing"
    workflow_usage = http_request(method="GET", url_suffix=url_suffix).get('billable', {})

    return workflow_usage


def list_team_members_command():
    args = demisto.args()
    org = args.get('organization')
    team_slug = args.get('team_slug')
    maximum_users = int(args.get('maximum_users'))
    response = get_team_members(org, team_slug, maximum_users)
    members = []
    for member in response:
        context_data = {
            'ID': member.get("id"),
            'Login': member.get("login"),
            'Team': team_slug,
        }
        members.append(context_data)
    if members:
        human_readable = tableToMarkdown(f'Team Member of team {team_slug} in organization {org}', t=members,
                                         removeNull=True)
    else:
        human_readable = f'There is no team members under team {team_slug} in organization {org}'

    return_results(CommandResults(
        readable_output=human_readable,
        outputs_prefix='GitHub.TeamMember',
        outputs_key_field='ID',
        outputs=members if members else None,
        raw_response=response,
    ))


def get_github_actions_usage():
    """ List github actions workflows usage of private repositories.

    """
    command_args = demisto.args()
    owner_name = command_args.get('owner', '')
    usage_result = []

    private_repositories = list_owner_repositories(owner_name=owner_name, repo_type="private")

    for repository_name in private_repositories:
        repository_workflows = list_repository_workflows(owner_name=owner_name, repository_name=repository_name)

        for workflow in repository_workflows:
            workflow_id = workflow.get('id', '')
            workflow_name = workflow.get('name', '')
            workflow_usage = get_workflow_usage(owner_name=owner_name, repository_name=repository_name,
                                                workflow_id=workflow_id)

            if workflow_usage:
                usage_result.append({
                    'WorkflowName': workflow_name,
                    'WorkflowID': workflow_id,
                    'RepositoryName': repository_name,
                    'WorkflowUsage': workflow_usage,
                })

    ec = {
        'GitHub.ActionsUsage': usage_result
    }
    human_readable = tableToMarkdown('Github Actions Usage', usage_result,
                                     headerTransform=string_to_table_header)

    return_outputs(readable_output=human_readable, outputs=ec, raw_response=usage_result)


def get_file_content_from_repo():
    """Gets the content of a file from GitHub.
    """
    args = demisto.args()

    file_path = args.get('file_path')
    branch_name = args.get('branch_name')
    media_type = args.get('media_type', 'raw')
    organization = args.get('organization') or USER
    repository = args.get('repository') or REPOSITORY
    create_file_from_content = argToBoolean(args.get('create_file_from_content', False))

    url_suffix = f'/repos/{organization}/{repository}/contents/{file_path}'
    if branch_name:
        url_suffix += f'?ref={branch_name}'

    headers = {
        'Authorization': "Bearer " + TOKEN,
        'Accept': f'application/vnd.github.VERSION.{media_type}',
    }

    file_data = http_request(method="GET", url_suffix=url_suffix, headers=headers, is_raw_response=True)

    if create_file_from_content:
        file_name = file_path.split('/')[-1]
        demisto.results(fileResult(filename=file_name, data=file_data, file_type=EntryType.ENTRY_INFO_FILE))
        return

    file_processed_data = {
        'Path': file_path,
        'Content': file_data,
        'MediaType': media_type,
    }
    if branch_name:
        file_processed_data['Branch'] = branch_name

    results = CommandResults(
        outputs_prefix='GitHub.FileContent',
        outputs_key_field=['Path', 'Branch', 'MediaType'],
        outputs=file_processed_data,
        readable_output=f'File {file_path} successfully fetched.',
        raw_response=file_data,
    )

    return_results(results)


def list_files_command():
    args = demisto.args()
    path = args.get('path', '')
    organization = args.get('organization')
    repository = args.get('repository')
    branch = args.get('branch')

    if organization and repository:
        suffix = f'/repos/{organization}/{repository}/contents/{path}'
    else:
        suffix = f'{USER_SUFFIX}/contents/{path}'

    params = {}
    if branch:
        params['ref'] = branch

    res = http_request(method='GET', url_suffix=suffix, params=params)

    ec_object = []
    for file in res:
        ec_object.append({
            'Type': file.get('type'),
            'Name': file.get('name'),
            'Size': file.get('size'),
            'Path': file.get('path'),
            'SHA': file.get('sha'),
            'DownloadUrl': file.get('download_url')
        })

    ec = {'GitHub.File(val.Path === obj.Path)': ec_object}
    human_readable = tableToMarkdown(f'Files in path: {path}', ec_object, removeNull=True, headers=FILE_HEADERS)
    return_outputs(readable_output=human_readable, outputs=ec, raw_response=res)


def commit_file_command():
    args = demisto.args()
    commit_message = args.get('commit_message')
    path_to_file = args.get('path_to_file')
    branch = args.get('branch_name')
    entry_id = args.get('entry_id')
    file_text = args.get('file_text')
    file_sha = args.get('file_sha')

    if not entry_id and not file_text:
        raise DemistoException('You must specify either the "file_text" or the "entry_id" of the file.')
    elif entry_id:
        file_path = demisto.getFilePath(entry_id).get('path')
        with open(file_path, 'rb') as f:
            content = f.read()
    else:
        content = bytes(file_text, encoding='utf8')

    data = {
        'message': commit_message,
        'content': base64.b64encode(content).decode("utf-8"),
        'branch': branch,
    }
    if file_sha:
        data['sha'] = file_sha
    res = http_request(method='PUT', url_suffix='{}/{}'.format(FILE_SUFFIX, path_to_file), data=data)

    return_results(CommandResults(
        readable_output=f"The file {path_to_file} committed successfully. Link to the commit:"
                        f" {res['commit'].get('html_url')}",
        raw_response=res
    ))


def list_check_runs(owner_name, repository_name, run_id, commit_id):
    url_suffix = None

    if run_id:
        url_suffix = f"/repos/{owner_name}/{repository_name}/check-runs/{run_id}"
    elif commit_id:
        url_suffix = f"/repos/{owner_name}/{repository_name}/commits/{commit_id}/check-runs"
    else:
        raise DemistoException("You have to specify either the check run id of the head commit reference")

    check_runs = http_request(method="GET", url_suffix=url_suffix)

    return [r for r in check_runs.get('check_runs')]


def get_github_get_check_run():
    """ List github check runs.

    """
    command_args = demisto.args()
    owner_name = command_args.get('owner', '')
    repository_name = command_args.get('repository', '')
    run_id = command_args.get('run_id', '')
    commit_id = command_args.get('commit_id', '')

    check_run_result = []

    check_runs = list_check_runs(owner_name=owner_name, repository_name=repository_name, run_id=run_id,
                                 commit_id=commit_id)

    for check_run in check_runs:
        check_run_id = check_run.get('id', '')
        check_external_id = check_run.get('external_id', '')
        check_run_name = check_run.get('name', '')
        check_run_app_name = check_run['app'].get('name', '')
        check_run_pr = check_run.get('pull_requests')
        check_run_status = check_run.get('status', '')
        check_run_conclusion = check_run.get('conclusion', '')
        check_run_started_at = check_run.get('started_at', '')
        check_run_completed_at = check_run.get('completed_at', '')
        check_run_output = check_run.get('output', '')

        check_run_result.append({
            'CheckRunID': check_run_id,
            'CheckExternalID': check_external_id,
            'CheckRunName': check_run_name,
            'CheckRunAppName': check_run_app_name,
            'CheckRunPR': check_run_pr,
            'CheckRunStatus': check_run_status,
            'CheckRunConclusion': check_run_conclusion,
            'CheckRunStartedAt': check_run_started_at,
            'CheckRunCompletedAt': check_run_completed_at,
            'CheckRunOutPut': check_run_output
        })
    command_results = CommandResults(
        outputs_prefix='GitHub.CheckRuns',
        outputs_key_field='CheckRunID',
        outputs=check_run_result,
        raw_response=check_run_result,
    )
    return_results(command_results)


def create_release_command():
    args = demisto.args()
    tag_name = args.get('tag_name')
    data = {
        'tag_name': tag_name,
        'name': args.get('name'),
        'body': args.get('body'),
        'draft': argToBoolean(args.get('draft')),
    }
    response = http_request('POST', url_suffix=RELEASE_SUFFIX, data=data)
    release_url = response.get('html_url')

    return_results(CommandResults(
        outputs_prefix='GitHub.Release',
        outputs=response,
        outputs_key_field='id',
        readable_output=f'Release {tag_name} created successfully for repo {REPOSITORY}: {release_url}',
        raw_response=response
    ))


def get_issue_events_command():
    args = demisto.args()
    issue_number = args.get('issue_number')
    res = http_request(method='GET', url_suffix=f'{ISSUE_SUFFIX}/{issue_number}/events')
    return_results(CommandResults(outputs_prefix='GitHub.IssueEvent', outputs_key_field='id', outputs=res,
                                  readable_output=tableToMarkdown(f'GitHub Issue Events For Issue {issue_number}',
                                                                  res)))


def fetch_incidents_command_rec(start_time, last_time, page=1):
    incidents = []

    if demisto.params().get('fetch_object') == "Pull_requests":
        pr_list = http_request(method='GET',
                               url_suffix=PULLS_SUFFIX,
                               params={
                                   'state': 'open',
                                   'sort': 'created',
                                   'page': page,
                                   'per_page': MAX_FETCH_PAGE_RESULTS,
                               })
        for pr in pr_list:
            updated_at_str = pr.get('created_at')
            updated_at = datetime.strptime(updated_at_str, '%Y-%m-%dT%H:%M:%SZ')
            if updated_at > start_time:
                inc = {
                    'name': pr.get('url'),
                    'occurred': updated_at_str,
                    'rawJSON': json.dumps(pr)
                }
                incidents.append(inc)
                if updated_at > last_time:
                    last_time = updated_at

        if len(pr_list) == MAX_FETCH_PAGE_RESULTS:
            rec_prs, rec_last_time = fetch_incidents_command_rec(start_time=start_time, last_time=last_time,
                                                                 page=page + 1)
            incidents = incidents + rec_prs
            if rec_last_time > last_time:
                last_time = rec_last_time
    else:
        params = {'page': page, 'per_page': MAX_FETCH_PAGE_RESULTS, 'state': 'all'}
        # params.update({'labels': 'DevOps'})
        issue_list = http_request(method='GET',
                                  url_suffix=ISSUE_SUFFIX,
                                  params=params)

        for issue in issue_list:
            updated_at_str = issue.get('created_at')
            updated_at = datetime.strptime(updated_at_str, '%Y-%m-%dT%H:%M:%SZ')
            if updated_at > start_time:
                inc = {
                    'name': issue.get('url'),
                    'occurred': updated_at_str,
                    'rawJSON': json.dumps(issue)
                }
                incidents.append(inc)
                if updated_at > last_time:
                    last_time = updated_at

        if len(issue_list) == MAX_FETCH_PAGE_RESULTS:
            rec_incidents, rec_last_time = fetch_incidents_command_rec(start_time=start_time, last_time=last_time,
                                                                       page=page + 1)
            incidents = incidents + rec_incidents
            if rec_last_time > last_time:
                last_time = rec_last_time
    return incidents, last_time


def get_path_data():
    """
    Get path data from given relative file path, repository and organization corresponding to branch name if given.
    Returns:
        Outputs to XSOAR.
    """
    args = demisto.args()

    relative_path: str = args.get('relative_path', '')
    repo: str = args.get('repository') or REPOSITORY
    organization: str = args.get('organization') or USER
    branch_name: Optional[str] = args.get('branch_name')

    url_suffix = f'/repos/{organization}/{repo}/contents/{relative_path}'
    url_suffix = f'{url_suffix}?ref={branch_name}' if branch_name else url_suffix

    headers = {
        'Authorization': "Bearer " + TOKEN,
        'Accept': 'application/vnd.github.VERSION.object',
    }
    try:
        raw_response = http_request(method="GET", url_suffix=url_suffix, headers=headers)
    except DemistoException as e:
        if '[404]' in str(e):
            err_msg = 'Could not find path.'
            if branch_name:
                err_msg += f' Make sure branch {branch_name} exists.'
            err_msg += f' Make sure relative path {relative_path} is correct.'
            raise DemistoException(err_msg)
        raise e

    # Content is given as str of base64, need to encode and decode in order to retrieve its human readable content.
    file_data = copy.deepcopy(raw_response)
    if 'content' in file_data:
        file_data['content'] = codecs.decode(file_data.get('content', '').encode(), 'base64').decode('utf-8')
    # Links are duplications of the Git/HTML/URL. Deleting duplicate data from context.
    file_data.pop('_links', None)
    for entry in file_data.get('entries', []):
        entry.pop('_links', None)

    results = CommandResults(
        outputs_prefix='GitHub.PathData',
        outputs_key_field='url',
        outputs=file_data,
        readable_output=tableToMarkdown(f'File Data For File {relative_path}', file_data, removeNull=True),
        raw_response=raw_response,
    )
    return_results(results)


def github_releases_list_command():
    """
    Gets releases data of given repository in given organization.
    Returns:
        CommandResults data.
    """
    args: Dict[str, Any] = demisto.args()

    repo: str = args.get('repository') or REPOSITORY
    organization: str = args.get('organization') or USER
    page_number: Optional[int] = arg_to_number(args.get('page'))
    page_size: Optional[int] = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit'))
    if (page_number or page_size) and limit:
        raise DemistoException('page_number and page_size arguments cannot be given with limit argument.\n'
                               'If limit is given, please do not use page or page_size arguments.')

    results: List[Dict] = []
    if limit:
        page_number = 1
        page_size = 100
        while len(results) < limit:
            url_suffix: str = f'/repos/{organization}/{repo}/releases?per_page={page_size}&page={page_number}'
            response = http_request(method='GET', url_suffix=url_suffix)
            # No more releases to bring from GitHub services.
            if not response:
                break
            results.extend(response)
            page_number += 1

        results = results[:limit]
    else:
        page_size = page_size if page_size else DEFAULT_PAGE_SIZE
        page_number = page_number if page_number else DEFAULT_PAGE_NUMBER
        url_suffix = f'/repos/{organization}/{repo}/releases?per_page={page_size}&page={page_number}'
        results = http_request(method='GET', url_suffix=url_suffix)

    result: CommandResults = CommandResults(
        outputs_prefix='GitHub.Release',
        outputs_key_field='id',
        outputs=results,
        readable_output=tableToMarkdown(f'Releases Data Of {repo}', results, removeNull=True)
    )
    return_results(result)


def update_comment(comment_id: Union[int, str], msg: str) -> dict:
    suffix = f'{ISSUE_SUFFIX}/comments/{comment_id}'
    response = http_request('PATCH', url_suffix=suffix, data={'body': msg})
    return response


def github_update_comment_command():
    args = demisto.args()
    comment_id = args.get('comment_id')
    issue_number = args.get('issue_number')
    body = args.get('body')
    response = update_comment(comment_id, body)

    ec_object = format_comment_outputs(response, issue_number)
    ec = {
        'GitHub.Comment(val.IssueNumber === obj.IssueNumber && val.ID === obj.ID)': ec_object,
    }
    human_readable = tableToMarkdown('Updated Comment', ec_object, removeNull=True)
    return_outputs(readable_output=human_readable, outputs=ec, raw_response=response)


def github_delete_comment_command():
    args = demisto.args()
    comment_id = args.get('comment_id')
    suffix = f'{ISSUE_SUFFIX}/comments/{comment_id}'
    http_request('DELETE', url_suffix=suffix)
    return_results(f'comment with ID {comment_id} was deleted successfully')


def fetch_incidents_command():
    last_run = demisto.getLastRun()
    if last_run and 'start_time' in last_run:
        start_time = datetime.strptime(last_run.get('start_time'), '%Y-%m-%dT%H:%M:%SZ')

    else:
        start_time = datetime.now() - timedelta(days=int(FETCH_TIME))

    incidents, last_time = fetch_incidents_command_rec(start_time=start_time, last_time=start_time)

    demisto.setLastRun({'start_time': datetime.strftime(last_time, '%Y-%m-%dT%H:%M:%SZ')})
    demisto.incidents(incidents)


''' COMMANDS MANAGER / SWITCH PANEL '''

COMMANDS = {
    'test-module': test_module,
    'fetch-incidents': fetch_incidents_command,
    'GitHub-create-issue': create_command,
    'GitHub-close-issue': close_command,
    'GitHub-update-issue': update_command,
    'GitHub-list-all-issues': list_all_command,
    'GitHub-list-all-projects': list_all_projects_command,
    'GitHub-search-issues': search_command,
    'GitHub-get-download-count': get_download_count,
    'GitHub-get-stale-prs': get_stale_prs_command,
    'GitHub-get-branch': get_branch_command,
    'GitHub-create-branch': create_branch_command,
    'GitHub-get-team-membership': get_team_membership_command,
    'GitHub-request-review': request_review_command,
    'GitHub-create-comment': create_comment_command,
    'GitHub-list-issue-comments': list_issue_comments_command,
    'GitHub-list-pr-files': list_pr_files_command,
    'GitHub-list-pr-reviews': list_pr_reviews_command,
    'GitHub-get-commit': get_commit_command,
    'GitHub-add-label': add_label_command,
    'GitHub-get-pull-request': get_pull_request_command,
    'GitHub-list-teams': list_teams_command,
    'GitHub-delete-branch': delete_branch_command,
    'GitHub-list-pr-review-comments': list_pr_review_comments_command,
    'GitHub-update-pull-request': update_pull_request_command,
    'GitHub-is-pr-merged': is_pr_merged_command,
    'GitHub-create-pull-request': create_pull_request_command,
    'Github-get-github-actions-usage': get_github_actions_usage,
    'Github-list-files': list_files_command,
    'GitHub-get-file-content': get_file_content_from_repo,
    'GitHub-search-code': search_code_command,
    'GitHub-list-team-members': list_team_members_command,
    'GitHub-list-branch-pull-requests': list_branch_pull_requests_command,
    'Github-get-check-run': get_github_get_check_run,
    'Github-commit-file': commit_file_command,
    'GitHub-create-release': create_release_command,
    'Github-list-issue-events': get_issue_events_command,
    'GitHub-add-issue-to-project-board': add_issue_to_project_board_command,
    'GitHub-get-path-data': get_path_data,
    'GitHub-releases-list': github_releases_list_command,
    'GitHub-update-comment': github_update_comment_command,
    'GitHub-delete-comment': github_delete_comment_command,
}


def main():
    global BASE_URL
    global USER
    global TOKEN
    global PRIVATE_KEY
    global INTEGRATION_ID
    global INSTALLATION_ID
    global REPOSITORY
    global USE_SSL
    global FETCH_TIME
    global MAX_FETCH_PAGE_RESULTS
    global USER_SUFFIX
    global ISSUE_SUFFIX
    global PROJECT_SUFFIX
    global RELEASE_SUFFIX
    global PULLS_SUFFIX
    global FILE_SUFFIX
    global HEADERS

    params = demisto.params()
    BASE_URL = params.get('url', 'https://api.github.com')
    USER = params.get('user')
    TOKEN = params.get('token') or (params.get('api_token') or {}).get('password', '')
    creds: dict = params.get('credentials', {})
    PRIVATE_KEY = creds.get('sshkey', '') if creds else ''
    INTEGRATION_ID = params.get('integration_id')
    INSTALLATION_ID = params.get('installation_id')
    REPOSITORY = params.get('repository')
    USE_SSL = not params.get('insecure', False)
    FETCH_TIME = params.get('fetch_time', '3')
    MAX_FETCH_PAGE_RESULTS = 100

    USER_SUFFIX = '/repos/{}/{}'.format(USER, REPOSITORY)
    PROJECT_SUFFIX = USER_SUFFIX + '/projects'
    ISSUE_SUFFIX = USER_SUFFIX + '/issues'
    RELEASE_SUFFIX = USER_SUFFIX + '/releases'
    PULLS_SUFFIX = USER_SUFFIX + '/pulls'
    FILE_SUFFIX = USER_SUFFIX + '/contents'

    if TOKEN == '' and PRIVATE_KEY != '':
        try:
            import jwt  # noqa
        except Exception:
            return_error("You need to update the docker image so that the jwt package could be used")

        generated_jwt_token = create_jwt(PRIVATE_KEY, INTEGRATION_ID)
        TOKEN = get_installation_access_token(INSTALLATION_ID, generated_jwt_token)

    if TOKEN == '' and PRIVATE_KEY == '':
        return_error("Insert api token or private key")

    HEADERS = {
        'Authorization': "Bearer " + TOKEN
    }

    handle_proxy()
    cmd = demisto.command()
    LOG(f'command is {cmd}')
    try:
        if cmd in COMMANDS.keys():
            COMMANDS[cmd]()
    except Exception as e:
        return_error(str(e))


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins' or __name__ == '__main__':
    main()

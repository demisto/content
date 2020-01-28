import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import requests
from typing import Union, Any
from datetime import datetime

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

USER = demisto.params().get('user')
TOKEN = demisto.params().get('token', '')
BASE_URL = 'https://api.github.com'
REPOSITORY = demisto.params().get('repository')
USE_SSL = not demisto.params().get('insecure', False)
FETCH_TIME = demisto.params().get('fetch_time', '3')

USER_SUFFIX = '/repos/{}/{}'.format(USER, REPOSITORY)
ISSUE_SUFFIX = USER_SUFFIX + '/issues'
RELEASE_SUFFIX = USER_SUFFIX + '/releases'
PULLS_SUFFIX = USER_SUFFIX + '/pulls'

RELEASE_HEADERS = ['ID', 'Name', 'Download_count', 'Body', 'Created_at', 'Published_at']
ISSUE_HEADERS = ['ID', 'Repository', 'Title', 'State', 'Body', 'Created_at', 'Updated_at', 'Closed_at', 'Closed_by',
                 'Assignees', 'Labels']

# Headers to be sent in requests
HEADERS = {
    'Authorization': "Bearer " + TOKEN
}


''' HELPER FUNCTIONS '''


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


def http_request(method, url_suffix, params=None, data=None):
    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        data=json.dumps(data),
        headers=HEADERS
    )
    if res.status_code >= 400:
        try:
            json_res = res.json()

            if json_res.get('errors') is None:
                return_error('Error in API call to the GitHub Integration [%d] - %s' % (res.status_code, res.reason))

            else:
                error_code = json_res.get('errors')[0].get('code')
                if error_code == 'missing_field':
                    return_error(
                        'Error: the field: "{}" requires a value'.format(json_res.get('errors')[0].get('field')))

                elif error_code == 'invalid':
                    field = json_res.get('errors')[0].get('field')
                    if field == 'q':
                        return_error('Error: invalid query - {}'.format(json_res.get('errors')[0].get('message')))

                    else:
                        return_error('Error: the field: "{}" has an invalid value'.format(field))

                elif error_code == 'missing':
                    return_error('Error: {} does not exist'.format(json_res.get('errors')[0].get('resource')))

                elif error_code == 'already_exists':
                    return_error('Error: the field {} must be unique'.format(json_res.get('errors')[0].get('field')))

                else:
                    return_error(
                        'Error in API call to the GitHub Integration [%d] - %s' % (res.status_code, res.reason))

        except ValueError:
            return_error('Error in API call to GitHub Integration [%d] - %s' % (res.status_code, res.reason))

    try:
        if res.status_code == 204:
            return res
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

    form = {
        'ID': issue.get('number'),
        'Repository': REPOSITORY,
        'Title': issue.get('title'),
        'Body': issue.get('body'),
        'State': issue.get('state'),
        'Labels': list_create(issue, 'labels', 'name'),
        'Assignees': list_create(issue, 'assignees', 'login'),
        'Created_at': issue.get('created_at'),
        'Updated_at': issue.get('updated_at'),
        'Closed_at': issue.get('closed_at'),
        'Closed_by': closed_by
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
    head_or_base_repo_owner = head_or_base_repo.get('owner', {})
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


def get_pull_request(pull_number: Union[int, str]):
    suffix = PULLS_SUFFIX + f'/{pull_number}'
    response = http_request('GET', url_suffix=suffix)
    return response


def get_pull_request_command():
    args = demisto.args()
    pull_number = args.get('pull_number')
    response = get_pull_request(pull_number)

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


def list_pr_files(pull_number: Union[int, str]) -> list:
    suffix = PULLS_SUFFIX + f'/{pull_number}/files'
    response = http_request('GET', url_suffix=suffix)
    return response


def list_pr_files_command():
    args = demisto.args()
    pull_number = args.get('pull_number')
    response = list_pr_files(pull_number)

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


def list_issue_comments(issue_number: Union[int, str]) -> list:
    suffix = ISSUE_SUFFIX + f'/{issue_number}/comments'
    response = http_request('GET', url_suffix=suffix)
    return response


def list_issue_comments_command():
    args = demisto.args()
    issue_number = args.get('issue_number')
    response = list_issue_comments(issue_number)

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

    commit = response.get('commit', {})
    author = commit.get('author', {})
    parents = commit.get('parents', [])
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
    matching_issues = search_issue(query).get('items', [])
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


def list_all_issue(state):
    params = {'state': state}
    response = http_request(method='GET',
                            url_suffix=ISSUE_SUFFIX,
                            params=params)
    return response


def list_all_command():
    state = demisto.args().get('state')
    limit = int(demisto.args().get('limit'))
    if limit > 200:
        limit = 200

    response = list_all_issue(state)
    create_issue_table(response, response, limit)


def search_issue(query):
    response = http_request(method='GET',
                            url_suffix='/search/issues',
                            params={'q': query})
    return response


def search_command():
    q = demisto.args().get('query')
    limit = int(demisto.args().get('limit'))
    if limit > 200:
        limit = 200

    response = search_issue(q)
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


def fetch_incidents_command():
    last_run = demisto.getLastRun()
    if last_run and 'start_time' in last_run:
        start_time = datetime.strptime(last_run.get('start_time'), '%Y-%m-%dT%H:%M:%SZ')

    else:
        start_time = datetime.now() - timedelta(days=int(FETCH_TIME))

    last_time = start_time
    issue_list = http_request(method='GET',
                              url_suffix=ISSUE_SUFFIX,
                              params={'state': 'all'})

    incidents = []
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
    'GitHub-create-pull-request': create_pull_request_command
}


'''EXECUTION'''


def main():
    handle_proxy()
    cmd = demisto.command()
    LOG(f'command is {cmd}')
    try:
        if cmd in COMMANDS.keys():
            COMMANDS[cmd]()
    except Exception as e:
        return_error(str(e))


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()

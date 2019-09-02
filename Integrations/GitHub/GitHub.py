import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import requests
from typing import Union
from datetime import datetime

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

USER = demisto.params().get('user')
TOKEN = demisto.params().get('token', '')
BASE_URL = 'https://api.github.com'
REPOSITORY = demisto.params().get('repository')
CONTRIBUTION_LABEL = demisto.params().get('contribution_label')
BOT_NAME = demisto.params().get('bot_name')
STALE_TIME = demisto.params().get('stale_time', '3 days')
USE_SSL = not demisto.params().get('insecure', False)
FETCH_TIME = demisto.params().get('fetch_time', '30 days')

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

# REVIEWERS = ['Itay4', 'yaakovi', 'yuvalbenshalom', 'ronykoz']
REVIEWERS = ['avidan-H']
CONTENT_TEAM_ID = 3043448

WELCOME_MSG = 'Thank you for your contribution. Your generosity and caring are unrivaled! Rest assured - our content ' \
              'wizard @reviewer will very shortly look over your proposed changes.'
NEEDS_REVIEW_MSG = '@reviewer This PR won\'t review itself and I\'m not going to do it for you (I bet you\'d like ' \
                   'that wouldn\'t you) - look it over, eh?'
LOTR_NUDGE_MSG = '"And some things that should not have been forgotten were lost. History became legend. Legend ' \
                 'became myth. And for two and a half thousand years..." @reviewer had not looked at this ' \
                 'beautiful PR - as they were meant to do.'
NUDGE_AUTHOR_MSG = 'A lengthy period of time has transpired since the PR was reviewed. @author Please address the ' \
                   'reviewer\'s comments and push your committed changes.'
APPROVED_UNMERGED_MSG = 'The PR was approved but doesn\'t seem to have been merged. @author Please verify that there ' \
                        'aren\'t any outstanding requested changes.'
SUGGEST_CLOSE_MSG = 'These reminders don\'t seem to be working and the issue is getting pretty stale - @reviewer - ' \
                    'consider whether this PR is still relevant or should be closed.'
STALE_MSG = 'This PR is starting to get a little stale and possibly even a little moldy and smelly.'
UNIT_TEST_MSG = ' It is very likely that the reviewer will want you to add a unittest for your '\
        'code changes in the `$unittest$` file - please refer to the documentation '\
        'https://github.com/demisto/content/tree/master/docs/tests/unit-testing for more details.'
CHANGELOG_MSG = ' Because of your changes you will also need to update the `$changelog$` file - please refer '\
        'to the documentation https://github.com/demisto/content/tree/master/docs/release_notes for more details.'

''' HELPER FUNCTIONS '''


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


def get_last_event(commit_timestamp: str = '', comment_timestamp: str = '', review_timestamp: str = '') -> str:
    """ Compare dates to determine the last event.

    :param commit_timestamp: timestamp of last pr commit
    :param comment_timestamp: timestamp of last pr comment
    :param review_timestamp:  timestamp of the last pr review
    :return: The last event to occur
    """
    time_fmt = '%Y-%m-%dT%H:%M:%SZ'
    commit_date = datetime.strptime(commit_timestamp, time_fmt) if commit_timestamp else datetime.fromordinal(1)
    comment_date = datetime.strptime(comment_timestamp, time_fmt) if comment_timestamp else datetime.fromordinal(1)
    review_date = datetime.strptime(review_timestamp, time_fmt) if review_timestamp else datetime.fromordinal(1)

    last_event = 'comment' if comment_date >= commit_date else 'commit'
    if last_event == 'comment' and review_date > comment_date:
        last_event = 'review'
    elif last_event == 'commit' and review_date > commit_date:
        last_event = 'review'
    return last_event


def alert_appropriate_party(pr: dict, commit_data: dict, reviews_data: list, comments_data: list):
    requested_reviewers = [requested_reviewer.get('login') for requested_reviewer in pr.get('requested_reviewers', [])]
    reviewers_with_prefix = ' '.join(['@' + reviewer for reviewer in requested_reviewers])

    head_author = pr.get('head', {}).get('user', {}).get('login')
    # commit_author = commit_data.get('author', {}).get('login')
    commit_time = commit_data.get('author', {}).get('date', '')

    demisto.info('REVIEWS: ' + json.dumps(reviews_data, indent=4))
    last_review = reviews_data[-1] if len(reviews_data) >= 1 else {}
    review_time = last_review.get('submitted_at', '')
    review_status = last_review.get('state', '')

    comments = [
        comment for comment in comments_data if not
        (comment.get('body', '').startswith(('Thank', 'Hey')) and comment.get('user', {}).get('login', '') == BOT_NAME)
    ]
    last_comment = comments[-1] if len(comments) >= 1 else {}
    comment_time = last_comment.get('updated_at', '')
    comment_body = last_comment.get('body', '')
    commenter = last_comment.get('user', {}).get('login')

    demisto.info('-----------------------------------')
    demisto.info('commit_time: ' + commit_time + ' comment_time: ' + comment_time + ' review_time: ' + review_time)
    demisto.info('last_comment: ' + json.dumps(last_comment, indent=4))
    demisto.info(f'commenter: {commenter}')
    demisto.info(f'head_author: {head_author}')

    msg = ''
    issue_number = pr.get('number')
    last_event = get_last_event(commit_time, comment_time, review_time)
    if last_event == 'commit':
        msg = NEEDS_REVIEW_MSG.replace('@reviewer', reviewers_with_prefix)
    elif last_event == 'review':
        if review_status != 'APPROVED':
            msg = NUDGE_AUTHOR_MSG.replace('author', head_author)
        else:
            msg = APPROVED_UNMERGED_MSG.replace('author', head_author)
    else:  # last_event == 'comment'
        # Actions if the last comment was by the bot itself
        if commenter == BOT_NAME:
            lotr_nudge = LOTR_NUDGE_MSG.replace('@reviewer', reviewers_with_prefix)
            suggest_close = SUGGEST_CLOSE_MSG.replace('@reviewer', reviewers_with_prefix)
            if review_status in ['PENDING', ''] and (comment_body != lotr_nudge and comment_body != suggest_close):
                msg = lotr_nudge
            elif comment_body == suggest_close:
                # PR already has comment from our bot to consider closing the issue so skip commenting
                return
            else:
                msg = suggest_close
        # Determine who the last commenter was - assume that whichever party was not the commenter needs a reminder
        elif commenter != head_author:
            # The last comment wasn't made by the PR opener (and is probably one of the requested reviewers) assume
            # that the PR opener needs a nudge
            nudge_author = f' @{head_author} are there any changes you wanted to make since @{commenter}\'s last ' \
                f'comment? '
            msg = STALE_MSG + nudge_author
        else:
            # Else assume the person who opened the PR is waiting on the response of one of the reviewers
            nudge_reviewer = ' ' + reviewers_with_prefix + f' what\'s new since @{commenter}\'s last comment?'
            msg = STALE_MSG + nudge_reviewer
    create_issue_comment(issue_number, msg)


def check_pr_files(pull_number, pull_author):
    pr_files = get_pr_files(pull_number)
    filenames = [fileobject.get('filename') for fileobject in pr_files]
    filenames_str = '\n'.join(filenames)
    demisto.info('**********************')
    demisto.info('filenames: ' + json.dumps(filenames, indent=4))
    # accepted_path_prefixes = ['content/Integrations/', 'content/Scripts/']
    py_yml_reg = r"(Integrations|Scripts)/(.*)/(\2\.(?:py|yml))"
    modified_files = re.findall(py_yml_reg, filenames_str)
    demisto.info('######################')
    demisto.info('modified_files: ' + json.dumps(modified_files, indent=4))
    requires = {}
    if modified_files:
        warning = f'Hey @{pull_author}, it appears you made changes ' \
                  f'to {" and ".join(["/".join(mod) for mod in modified_files])}.'
        for modded in modified_files:
            path_prefix, dir_name, file = [modded[0], modded[1], modded[2]]
            test_file = path_prefix + '/' + dir_name + '/' + dir_name + '_test.py'
            changelog_file = path_prefix + '/' + dir_name + '/' + 'CHANGELOG.md'
            if file.endswith('.py') and test_file not in filenames:
                requires['unittest'] = test_file
            if changelog_file not in filenames:
                requires['changelog'] = changelog_file
        if not requires:
            return
        else:
            unit_test = requires.get('unittest')
            changelog = requires.get('changelog')
            warning += UNIT_TEST_MSG.replace('$unittest$', unit_test) if unit_test else ''
            warning += CHANGELOG_MSG.replace('$changelog$', changelog) if changelog else ''
            create_issue_comment(pull_number, warning)


''' REQUESTS FUNCTIONS '''


def get_branch(branch: str) -> dict:
    suffix = USER_SUFFIX + f'/branches/{branch}'
    response = http_request('GET', url_suffix=suffix)
    return response


def create_branch(name: str, sha: str) -> dict:
    suffix = USER_SUFFIX + '/git/refs'
    data = {
        'ref': f'ref/heads/{name}',
        'sha': sha
    }
    response = http_request('POST', url_suffix=suffix, data=data)
    return response


def get_team_membership(team_id: int, user_name: str) -> dict:
    suffix = f'/teams/{team_id}/memberships/{user_name}'
    response = http_request('GET', url_suffix=suffix)
    return response


def assign_reviewer(pull_number: int, reviewers: list) -> dict:
    suffix = PULLS_SUFFIX + f'/{pull_number}/requested_reviewers'
    response = http_request('POST', url_suffix=suffix, data={'reviewers': reviewers})
    return response


def create_issue_comment(issue_number, msg: str) -> dict:
    suffix = ISSUE_SUFFIX + f'/{issue_number}/comments'
    response = http_request('POST', url_suffix=suffix, data={'body': msg})
    return response


def list_issue_comments(issue_number: int) -> list:
    suffix = ISSUE_SUFFIX + f'/{issue_number}/comments'
    response = http_request('GET', url_suffix=suffix)
    return response


def get_pr_files(pull_number: int) -> list:
    suffix = PULLS_SUFFIX + f'/{pull_number}/files'
    response = http_request('GET', url_suffix=suffix)
    return response


def get_pr_reviews(pull_number: int) -> list:
    suffix = PULLS_SUFFIX + f'/{pull_number}/reviews'
    response = http_request('GET', url_suffix=suffix)
    return response


def get_commit(commit_sha: str) -> dict:
    suffix = USER_SUFFIX + f'/git/commits/{commit_sha}'
    response = http_request('GET', url_suffix=suffix)
    return response


def add_label(issue_number, labels: list):
    suffix = ISSUE_SUFFIX + f'/{issue_number}'
    response = http_request('POST', url_suffix=suffix, data={'labels': labels})
    return response


def get_pull_request(pull_number):
    suffix = PULLS_SUFFIX + f'/{pull_number}'
    response = http_request('GET', url_suffix=suffix)
    return response


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


def close_issue(id):
    response = http_request(method='PATCH',
                            url_suffix=ISSUE_SUFFIX + '/{}'.format(str(id)),
                            data={'state': 'closed'})
    return response


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


def list_all_issue(state):
    params = {'state': state}
    response = http_request(method='GET',
                            url_suffix=ISSUE_SUFFIX,
                            params=params)
    return response


def search_issue(query):
    response = http_request(method='GET',
                            url_suffix='/search/issues',
                            params={'q': query})
    return response


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


def get_relevant_prs(time_or_period: Union[str, datetime], label: str, query: str) -> list:
    reg = re.compile("\.\d{6}$")
    try:
        now = datetime.now()
        # try to parse 'time_or_period' into a starting datetime object
        time_range_start, _ = parse_date_range(time_or_period)
        start_delta = now - time_range_start
        start_time = now - start_delta
        time_or_period = start_time
    except Exception:
        # if parse_date_range threw an exception it means that 'time_or_period' was already in the right format
        pass
    timestamp, _ = reg.subn('', time_or_period.isoformat())
    query = query.replace('{USER}', USER).replace('{REPOSITORY}', REPOSITORY).replace('{timestamp}', timestamp)

    # if label was passed then use it in the query otherwise remove that part of the query
    if label:
        query = query.replace('{label}', label)
    elif ' label:{label}' in query:
        query = query.replace(' label:{label}', '')
    elif ' -label:{label}' in query:
        query = query.replace(' -label:{label}', '')

    matching_issues = search_issue(query).get('items', [])
    relevant_prs = [get_pull_request(issue.get('number')) for issue in matching_issues]
    return relevant_prs


def get_stale_prs(args={}):
    stale_time = args.get('stale_time')
    label = args.get('label')
    query = 'repo:{USER}/{REPOSITORY} is:open updated:<{timestamp} is:pr label:{label}'
    return get_relevant_prs(stale_time, label, query)


''' COMMANDS '''


def test_module():
    http_request(method='GET', url_suffix=ISSUE_SUFFIX, params={'state': 'all'})
    demisto.results("ok")


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
        'GitHub.Branch(val.Name === obj.name && val.CommitSHA === obj.CommitSHA)': ec_object
    }
    human_readable = tableToMarkdown('Branch', ec_object, removeNull=True)
    return_outputs(readable_output=human_readable, outputs=ec, raw_response=response)


def create_branch_command():
    args = demisto.args()
    branch_name = args.get('branch_name')
    sha = args.get('sha')
    response = create_branch(branch_name, sha)

    ec_object = {
        'Ref': response.get('ref'),
        'NodeID': response.get('node_id')
    }
    ec = {
        'GitHub.Branch(val.Ref === obj.Ref && val.NodeID === obj.NodeID)': ec_object
    }
    human_readable = tableToMarkdown('Created Branch Details', ec_object, removeNull=True)
    return_outputs(readable_output=human_readable, outputs=ec, raw_response=response)


def get_stale_prs_command():
    args = demisto.args()
    results = get_stale_prs(args)
    if results:
        formatted_results = []
        for pr in results:
            requested_reviewers = [
                requested_reviewer.get('login') for requested_reviewer in pr.get('requested_reviewers', [])
            ]
            formatted_pr = {
                'URL': pr.get('html_url'),
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



def create_command():
    args = demisto.args()
    response = create_issue(args.get('title'), args.get('body'),
                            args.get('labels'), args.get('assignees'))
    issue = issue_format(response)
    context_create_issue(response, issue)


def close_command():
    id = demisto.args().get('ID')
    response = close_issue(id)
    issue = issue_format(response)
    context_create_issue(response, issue)


def update_command():
    args = demisto.args()
    response = update_issue(args.get('ID'), args.get('title'), args.get('body'), args.get('state'),
                            args.get('labels'), args.get('assignees'))
    issue = issue_format(response)
    context_create_issue(response, issue)


def list_all_command():
    state = demisto.args().get('state')
    limit = int(demisto.args().get('limit'))
    if limit > 200:
        limit = 200

    response = list_all_issue(state)
    create_issue_table(response, response, limit)


def search_command():
    q = demisto.args().get('query')
    limit = int(demisto.args().get('limit'))
    if limit > 200:
        limit = 200

    response = search_issue(q)
    create_issue_table(response['items'], response, limit)


def fetch_incidents_command():
    last_run = demisto.getLastRun()
    now = datetime.now()
    if last_run and 'start_time' in last_run:
        start_time = datetime.strptime(last_run.get('start_time'), '%Y-%m-%dT%H:%M:%SZ')

    else:
        time_range_start, _ = parse_date_range(FETCH_TIME)
        start_delta = now - time_range_start
        start_time = now - start_delta

    last_time = start_time

    opened_query = 'repo:{USER}/{REPOSITORY} is:open updated:>{timestamp} is:pr -label:{label}'
    opened_prs = get_relevant_prs(start_time, CONTRIBUTION_LABEL, opened_query)

    time_range_start, _ = parse_date_range(STALE_TIME)
    inactive_query = 'repo:{USER}/{REPOSITORY} is:open updated:<{timestamp} is:pr label:{label}'
    inactive_prs = get_relevant_prs(time_range_start, CONTRIBUTION_LABEL, inactive_query)
    for pr in inactive_prs:
        # demisto.info('PR: ' + json.dumps(pr, indent=4))
        issue_number = pr.get('number')
        sha = pr.get('head', {}).get('sha')
        demisto.info('SHA: ' + sha)
        commit_data = get_commit(sha)
        # demisto.info('COMMIT: ', json.dumps(commit_data, indent=4))
        reviews_data = get_pr_reviews(issue_number)
        comments_data = list_issue_comments(issue_number)
        alert_appropriate_party(pr, commit_data, reviews_data, comments_data)

    # label and assign reviewer to new external PRs
    incidents = []
    for pr in opened_prs:
        updated_at_str = pr.get('created_at')
        updated_at = datetime.strptime(updated_at_str, '%Y-%m-%dT%H:%M:%SZ')
        pr_opener = pr.get('head', {}).get('user', {}).get('login')
        try:
            not_content_member = get_team_membership(CONTENT_TEAM_ID, pr_opener).get('state', '') != 'active'
        except Exception:
            not_content_member = True
        demisto.info(f'not_content_member: {not_content_member}')
        is_fork = pr.get('head', {}).get('repo', {}).get('fork')
        if is_fork or not_content_member:
            issue_number = pr.get('number')
            add_label(issue_number, [CONTRIBUTION_LABEL])
            selected_reviewer = REVIEWERS[issue_number % len(REVIEWERS)]
            create_issue_comment(issue_number, WELCOME_MSG.replace('reviewer', selected_reviewer))
            assign_reviewer(issue_number, [selected_reviewer])
            check_pr_files(issue_number, pr.get('head', {}).get('user', {}).get('login', ''))
        if updated_at > start_time:
            inc = {
                'name': pr.get('url'),
                'occurred': updated_at_str,
                'rawJSON': json.dumps(pr)
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
    'GitHub-create-branch': create_branch_command
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
        # raise e
        return_error(str(e))

# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()

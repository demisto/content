import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
import typing
from datetime import datetime, timedelta

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

USER = demisto.params().get('user')
TOKEN = demisto.params().get('token')
BASE_URL = 'https://api.github.com'
REPOSITORY = demisto.params().get('repository')
CONTRIBUTION_LABEL = demisto.params().get('contribution_label')
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

REVIEWERS = ['Itay4', 'yaakovi', 'yuvalbenshalom', 'ronykoz']

WELCOME_MSG = 'Thank you for your contribution. Your generosity and caring are unrivaled! Rest assured - our content ' \
              'wizard @reviewer will very shortly look over your proposed changes.'
LOTR_NUDGE_MSG = '"And some things that should not have been forgotten were lost. History became legend. Legend ' \
                 'became myth. And for two and a half thousand years", @reviewer had not looked at this beautiful PR ' \
                 '- as they were meant to do.'
NUDGE_AUTHOR_MSG = 'A lengthy period of time has transpired since the PR was reviewed. @author Please address the ' \
                   'reviewer\'s comments and push your committed changes. '
APPROVED_UNMERGED_MSG = 'The PR was approved but doesn\'t seem to have been merged. @author Please verify that there ' \
                        'aren\'t any outstanding requested changes. '


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
                    return_error('Error: the field: "{}" requires a value'.format(json_res.get('errors')[0].get('field')))

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
                    return_error('Error in API call to the GitHub Integration [%d] - %s' % (res.status_code, res.reason))

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
    commit_date = datetime.strptime(commit_timestamp) if commit_timestamp else datetime.fromordinal(1)
    comment_date = datetime.strptime(comment_timestamp) if comment_timestamp else datetime.fromordinal(1)
    review_date = datetime.strptime(review_timestamp) if review_timestamp else datetime.fromordinal(1)

    last_event = 'comment' if comment_date >= commit_date else 'commit'
    if last_event == 'comment' and review_date > comment_date:
        last_event = 'review'
    elif last_event == 'commit' and review_date > commit_date:
        last_event = 'review'
    return last_event


''' REQUESTS FUNCTIONS '''


def create_issue_comment(issue_number: int, msg: str) -> dict:
    suffix = ISSUE_SUFFIX + f'/{issue_number}/comments'
    response = http_request('POST', url_suffix=suffix, data={'body': msg})
    return response


def list_issue_comments(issue_number: int) -> list:
    suffix = ISSUE_SUFFIX + f'/{issue_number}/comments'
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


def add_label(issue_number, labels):
    suffix = ISSUE_SUFFIX + f'/{issue_number}'
    response = http_request('POST', url_suffix=suffix, data=labels)
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


''' COMMANDS MANAGER / SWITCH PANEL '''


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
    if last_run and 'start_time' in last_run:
        start_time = datetime.strptime(last_run.get('start_time'), '%Y-%m-%dT%H:%M:%SZ')

    else:
        time_range_start, _ = date_to_timestamp(parse_date_range(FETCH_TIME))
        start_time = datetime.now() - time_range_start

    last_time = start_time
    # issue_list = http_request(method='GET',
    #                           url_suffix=ISSUE_SUFFIX,
    #                           params={'state': 'all'})
    timestamp = timestamp_to_datestring(str(datetime.now().timestamp()))
    query = f'repo:{USER}/{REPOSITORY} is:open updated:<{timestamp} is:pr'
    external_pr_count = search_issue(query)

    timestamp = timestamp_to_datestring(str(start_time))
    query = f'repo:{USER}/{REPOSITORY} is:open updated:>{timestamp} is:pr -label:{CONTRIBUTION_LABEL}'
    newly_opened_prs = search_issue(query)

    time_range_start, _ = parse_date_range(STALE_TIME)
    timestamp = timestamp_to_datestring(time_range_start)
    query = f'repo:{USER}/{REPOSITORY} is:open updated:<{timestamp} is:pr label:{CONTRIBUTION_LABEL}'
    ongoing_external_prs = search_issue(query)
    inactive_prs = [get_pull_request(issue.get('number')) for issue in ongoing_external_prs]
    for pr in inactive_prs:
        issue_number = pr.get('number')
        requested_reviewers = [requested_reviewer.get('login') for requested_reviewer in pr.get('requested_reviewers')]
        commit_data = get_commit(pr.get('head', {}).get('sha'))
        reviews_data = get_pr_reviews(issue_number)
        comments_data = list_issue_comments(issue_number)

    # label and assign reviewer to new external PRs
    incidents = []
    for issue in newly_opened_prs:
        updated_at_str = issue.get('created_at')
        updated_at = datetime.strptime(updated_at_str, '%Y-%m-%dT%H:%M:%SZ')
        is_fork = issue.get('head', {}).get('repo', {}).get('fork')
        if is_fork:
            add_label(issue.get('number'), CONTRIBUTION_LABEL)
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


'''EXECUTION'''
handle_proxy()
LOG('command is %s' % (demisto.command(),))
try:
    if demisto.command() == 'test-module':
        issue_list = http_request(method='GET',
                                  url_suffix=ISSUE_SUFFIX,
                                  params={'state': 'all'})
        demisto.results("ok")
    elif demisto.command() == 'fetch-incidents':
        fetch_incidents_command()
    elif demisto.command() == 'GitHub-create-issue':
        create_command()
    elif demisto.command() == 'GitHub-close-issue':
        close_command()
    elif demisto.command() == 'GitHub-update-issue':
        update_command()
    elif demisto.command() == 'GitHub-list-all-issues':
        list_all_command()
    elif demisto.command() == 'GitHub-search-issues':
        search_command()
    elif demisto.command() == 'GitHub-get-download-count':
        get_download_count()

except Exception as e:
    LOG(str(e))
    LOG.print_log()
    raise

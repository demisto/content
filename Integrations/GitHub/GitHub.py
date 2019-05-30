import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''
from datetime import datetime, timedelta
import json
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''


API_KEY = demisto.params().get('apikey')
OWNER = demisto.params().get('owner')
REPO = demisto.params().get('repository')
BASE_URL = 'https://api.github.com'
FETCH_INTERVAL = demisto.params()['fetch_interval']
SUFFIX = {'list': '/repos/{}/{}/issues'.format(OWNER, REPO),
          'create': '/repos/{}/{}/issues'.format(OWNER, REPO),
          'close': '/repos/{}/{}/issues/'.format(OWNER, REPO,),
          'update': '/repos/{}/{}/issues/'.format(OWNER, REPO),
          'search': '/repos/{}/{}/issues/'.format(OWNER, REPO),
          'download_count': '/repos/{}/{}/releases'.format(OWNER, REPO)
          }
HEADERS = {'Content-Type': 'application/json',
           'Accept': 'application/vnd.github.v3+json',
           'Authorization': 'Bearer ' + API_KEY
           }

''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, json=None, params=None):
    try:
        res = requests.request(
            method,
            BASE_URL + url_suffix,
            data=json,
            headers=HEADERS,
            params=params
        )

        if res.status_code == 410:
            return_error("Error - this issue was deleted")

        elif res.status_code == 404:
            return_error("Error - this issue doesn't exists ")

        return res.json()

    except Exception as e:
        return_error("Error:\n{}".format(str(e)))


def fetch_incidents():
    now_utc = datetime.utcnow()
    last_run_data = demisto.getLastRun()
    last_run_time = last_run_data.get('time')

    if last_run_time is None:
        last_run_time = now_utc - timedelta(minutes=int(FETCH_INTERVAL))
    else:
        last_run_time = datetime.strptime(last_run_time, '%Y-%m-%dT%H:%M:%SZ')

    all_issues = List_all_issues('false')

    incidents = []

    for issue in all_issues:
        issue_create_time = issue['created_at']
        issue_create_time = datetime.strptime(issue_create_time, "%Y-%m-%dT%H:%M:%SZ")

        if issue_create_time > last_run_time:
            incidents.append({
                'name': str(issue['number']) + " - GitHub integration",
                'occurred': issue['created_at'],
                'rawJSON': json.dumps(issue)
            })

        if issue_create_time > last_run_time:
            last_run_time = issue_create_time

    demisto.incidents(incidents)
    demisto.setLastRun({'time': last_run_time.isoformat().split('.')[0] + 'Z'})


''' COMMANDS + REQUESTS FUNCTIONS '''


def get_issue_context(issue):

    label_context = [label['name'] for label in issue['labels']]
    assignee_context = [assignee['login'] for assignee in issue['assignees']]

    context = {
        'ID': issue['number'],
        'title': issue['title'],
        'state': issue['state'],
        'locked': issue['locked'],
        'body': issue['body'],
        'assignees': assignee_context,
        'labels': label_context
    }
    return context


def List_all_issues(show_all):
    suffix = SUFFIX['list']
    if show_all == 'false':
        res = http_request('GET', suffix)
    else:
        res = http_request('GET', suffix, None, {'state': 'all'})  # include close issues

    return res


def List_all_issues_command():
    show_all = demisto.args()['show-all']
    issues = List_all_issues(show_all)
    issue_list = []  # type: list
    for s in issues:
        context = get_issue_context(s)
        issue_list.insert(0, context)

    header_list = ['ID', 'title', 'state', 'locked', 'body', 'assignees', 'labels']
    human_readable = tableToMarkdown('issue list', issue_list, header_list)
    entry_context = {
        'Git.issue(val.ID && val.ID == obj.ID)': issue_list
    }

    return_outputs(human_readable, entry_context, issues)


def create_or_update_issue(command):
    args = demisto.args()
    for key in args.keys():
        if key == 'labels':
            args['labels'] = args['labels'].split(',')
        if key == 'assignees':
            args['assignees'] = args['assignees'].split(',')
    args = json.dumps(args)
    if command == 'create':
        suffix = SUFFIX['create']
        res = http_request('POST', suffix, json=args)
    else:
        suffix = SUFFIX['update'] + demisto.args()['issue_id']
        res = http_request('PATCH', suffix, args)

    return res


def create_issue_command():
    res = create_or_update_issue('create')
    context = get_issue_context(res)

    header_list = ['ID', 'title', 'state', 'locked', 'body', 'assignees', 'labels']
    human_readable = tableToMarkdown('created issue successfully', context, header_list, removeNull=True)
    entry_context = {
        'Git.issue(val.ID && val.ID == obj.ID)': context
    }
    return_outputs(human_readable, entry_context, res)


def close_issue():
    suffix = SUFFIX['close'] + demisto.args()['issue_id']
    data = {"state": "close"}
    data = json.dumps(data)
    res = http_request('PATCH', suffix, data, params='close')
    return res


def close_issue_command():
    res = close_issue()
    context = get_issue_context(res)

    header_list = ['ID', 'title', 'state', 'locked', 'body', 'assignees', 'labels']
    human_readable = tableToMarkdown('closed issue successfully', context, header_list)
    entry_context = {
        'Git.issue(val.ID && val.ID == obj.ID)': context
    }
    return_outputs(human_readable, entry_context, res)


def update_issue_command():
    res = create_or_update_issue('update')
    context = get_issue_context(res)

    header_list = ['ID', 'title', 'state', 'locked', 'body', 'assignees', 'labels']
    human_readable = tableToMarkdown('updated issue successfully', context, header_list)
    entry_context = {
        'Git.issue(val.ID && val.ID == obj.ID)': context
    }
    return_outputs(human_readable, entry_context, res)


def search_issue():
    suffix = SUFFIX['search'] + demisto.args()['issue_id']
    res = http_request('GET', suffix)
    return res


def search_issue_command():
    res = search_issue()

    context = get_issue_context(res)

    header_list = ['ID', 'title', 'state', 'locked', 'body', 'assignees', 'labels']
    human_readable = tableToMarkdown('issue searched', context, header_list)
    entry_context = {
        'Git.issue(val.ID && val.ID == obj.ID)': context
    }
    return_outputs(human_readable, entry_context, res)


def get_download_count():
    suffix = SUFFIX['download_count']
    res = http_request('GET', suffix)
    return res


def get_download_count_command():
    res = get_download_count()
    header_list = ['ID', 'name', 'download_count']
    download_counts = []  # type: list
    for release in res:
        count = 0
        for asset in release['assets']:
            count = count + asset['download_count']

        insert_release = {
            'ID': release['id'],
            'name': release['name'],
            'download_count': count
        }
        download_counts.insert(0, insert_release)

    human_readable = tableToMarkdown('the download count is:', download_counts, header_list)
    entry_context = {
        'Git.issue(val.ID && val.ID == obj.ID)': res
    }
    return_outputs(human_readable, entry_context, res)


def test_module():
    """
    Performs basic get request to get item samples
    """
    try:
        http_request('GET', '/repos/reutshal/GitHubRepo/issues')
    except Exception as e:
        return_error("Error:\n{}".format(str(e)))

    demisto.results("ok")


''' EXECUTION CODE '''

command = demisto.command()

try:
    if command == 'test-module':
        test_module()
    elif command == 'fetch-incidents':
        fetch_incidents()
    elif command == 'List-all-issues':
        List_all_issues_command()
    elif command == 'create-issue':
        create_issue_command()
    elif command == 'close-issue':
        close_issue_command()
    elif command == 'update-issue':
        update_issue_command()
    elif command == 'search-issue':
        search_issue_command()
    elif command == 'get-download-count':
        get_download_count_command()

except Exception as e:
    raise e

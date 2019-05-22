import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import requests

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

'''Global vars'''

API_KEY = demisto.params().get('api_key')
INSECURE = not demisto.params().get('insecure', False)
BASE_URL = 'https://api.github.com/'

'''Suffixes'''

GET_ISSUES_SUFFIX = 'issues'
REPO_ISSUES_SUFFIX = 'repos/teizenman/Demisto-start/issues'
SEARCH_SUFFIX = 'search/issues?q=repo:teizenman/Demisto-start+'
REPO_SEARCH_SUFFIX = 'search/issues?q=repo:teizenman/Demisto-start'
GET_RELEASES_SUFFIX = 'repos/teizenman/Demisto-start/releases'
FETCH_SUFFIX = SEARCH_SUFFIX + 'updated:>'

'''HELPER FUNCTIONS'''


def http_request(method, URL_SUFFIX, data=None):
    if method == 'GET':
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + API_KEY
        }
    elif method == 'POST':
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Bearer ' + API_KEY
        }
    res = requests.request(
        method,
        BASE_URL + URL_SUFFIX,
        data=data,
        headers=headers,
        verify=INSECURE
    )
    if res.status_code not in [200, 201]:
        return_error('Error in API call [%d] - %s' % (res.status_code, res.reason))
    return res.json()


'''TEST FUNCTION'''


def test_module():
    http_request('GET', GET_ISSUES_SUFFIX)


'''MAIN FUNCTIONS'''


def list_all_issues():
    res = http_request('GET', GET_ISSUES_SUFFIX)
    results = []
    for issue in res:
        issue_details = dict()

        issue_details['number'] = issue['number']
        issue_details['ID'] = str(issue['id'])
        issue_details['title'] = issue['title']
        issue_details['link'] = issue['url']
        issue_details['state'] = issue['state']

        results.append(issue_details)

    return_outputs(tableToMarkdown('Issues list:', results, ['ID', 'number', 'title', 'state', 'link']),
                   {'GitHub.Issues(val.ID==obj.ID)': results}, res)


def create_issue(title='untitled issue', body=None, assignees=None, labels=None):
    query = {'title': title,
             'body': body,
             'assignees': [assignee.strip() for assignee in str(assignees).split(',')],
             'labels': [label.strip() for label in str(labels).split(',')]}
    demisto.results(query)

    res = http_request('POST', REPO_ISSUES_SUFFIX, json.dumps(query))

    new_issue = {'number': res['number'],
                 'ID': str(res['id']),
                 'title': title,
                 'body': body,
                 'state': 'open'}

    return_outputs(tableToMarkdown('Issue #' + str(res['number']) + ' has been created', query),
                   {'GitHub.Issues(val.ID==obj.ID)': new_issue}, res)


def edit_issue(issue_num, title=None, body=None, assignees=None, labels=None):
    if str(issue_num).isdigit():
        res = http_request('GET', SEARCH_SUFFIX + str(issue_num))

        if res['total_count'] > 0:
            query = {}
            if title:
                query['title'] = title
            if body:
                query['body'] = body
            if assignees:
                query['assignees'] = [assignee.strip() for assignee in str(assignees).split(',')]
            if labels:
                query['labels'] = [label.strip() for label in str(labels).split(',')]

            res = http_request('POST', REPO_ISSUES_SUFFIX + '/' + str(issue_num), json.dumps(query))

            human_readable = tableToMarkdown(
                'Issue #' + str(issue_num) + ' has been edited with the following details:', query)

            context_output = {'number': res['number'],
                              'ID': str(res['id']),
                              'title': res['title'],
                              'body': res['body'],
                              'state': res['state']}
            context = {
                'GitHub.Issues(val.ID==obj.ID)': context_output
            }

            return_outputs(human_readable, context, res)

        else:
            return_error('No such issue')
    else:
        return_error('Please enter a valid issue number')


def close_issue(issue_num):
    if str(issue_num).isdigit():
        res = http_request('GET', SEARCH_SUFFIX + str(issue_num))

        if res['total_count'] > 0:
            query = {'state': 'close'}
            res = http_request('POST', REPO_ISSUES_SUFFIX + '/' + str(issue_num),
                               json.dumps(query))
            human_readable = 'Issue #' + str(issue_num) + ' has been closed'
            context = {
                'GitHub.Issues(val.ID==obj.ID)': {'ID': str(res['id']), 'state': 'close'}
            }

            return_outputs(human_readable, context, res)

        else:
            return_error('No such issue')
    else:
        return_error('Please enter a valid issue number')


def assemble_query(search_query, sort, order):
    query = ''
    if search_query:
        query += '+' + search_query
    if sort:
        query += '&sort=' + sort
        if order:
            query += '&order=' + order
    return query


def make_search(search_query=None, sort_by=None, order_by=None):
    query = assemble_query(search_query, sort_by, order_by)
    res = http_request('GET', REPO_SEARCH_SUFFIX + query)

    if res['total_count'] != 0:
        context_output = {'query': query}
        results = []
        for issue in res['items']:
            issue_details = dict()
            issue_details['ID'] = str(issue['id'])
            issue_details['title'] = issue['title']
            issue_details['link'] = issue['url']
            issue_details['state'] = issue['state']

            results.append(issue_details)

            human_readable = tableToMarkdown(
                str(res['total_count']) + ' found issues.\nComplete list of issues: ' + str(
                    not res['incomplete_results']),
                results, ['ID', 'title', 'state', 'link'])

        context_output['results'] = results
        context = {
            'GitHub.Search(val.query==obj.query)': context_output
        }

        return_outputs(human_readable, context, res)

    else:
        return_error('No issues found for this query!')


def count_total_downloads():
    res = http_request('GET', GET_RELEASES_SUFFIX)
    output = []
    if res:
        for asset in res[0]['assets']:
            count = dict()
            count['asset_name'] = asset['name']
            count['download_count'] = asset['download_count']

            output.append(count)

        return_outputs(tableToMarkdown('Download counts:', output, ['asset_name', 'download_count']),
                       {'GitHub.DownloadCount(val.asset_name==obj.asset_name)': output}, res)
    else:
        return_error('No releases found')


def fetch_incidents_command():
    last_run = demisto.getLastRun()

    if last_run and 'start_time' in last_run:
        last_fetch_time = last_run.get('start_time')
    else:
        last_fetch_time = (datetime.now() - timedelta(minutes=60)).isoformat().split('.')[0]

    res = http_request('GET', FETCH_SUFFIX + last_fetch_time)
    if res['total_count'] != 0:
        incs = []
        for issue in res['items']:
            inc = {
                'name': 'Issue #' + str(issue['number']) + ' ID = ' + str(issue['id']) + ' updated',
                'occurred': issue['updated_at'],
                'rawJSON': json.dumps(issue)
            }

            if issue['updated_at'] > last_fetch_time:
                last_fetch_time = issue['updated_at']
            incs.append(inc)
        demisto.incidents(incs)

    demisto.setLastRun({'start_time': last_fetch_time})


''' EXECUTION '''
LOG('command is %s' % (demisto.command(),))
try:
    if demisto.command() == 'test-module':
        test_module()
        demisto.results('ok')

    elif demisto.command() == 'list-all-issues':
        list_all_issues()

    elif demisto.command() == 'create-issue':
        create_issue(**demisto.args())

    elif demisto.command() == 'edit-issue':
        edit_issue(**demisto.args())

    elif demisto.command() == 'close-issue':
        close_issue(**demisto.args())

    elif demisto.command() == 'make-search':
        make_search(**demisto.args())

    elif demisto.command() == 'count-downloads':
        count_total_downloads()

    elif demisto.command() == 'fetch-incidents':
        fetch_incidents_command()

except Exception as e:
    demisto.debug('We are the people')
    LOG(e.message)
    LOG.print_log()
    return_error(e.message)

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import requests
import json
import collections

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

API_KEY = '9a278be9afbedfa23ce6cba1e01cd578e51065d2'
INSECURE = demisto.params().get('insecure')
BASE_URL = 'https://api.github.com/'

'''HELPER FUNCTIONS'''


def http_request(method, URL_SUFFIX, json=None):
    if method is 'GET':
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + API_KEY
        }
    elif method is 'POST':
        if not API_KEY:
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        else:
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': 'Bearer ' + API_KEY
            }
    r = requests.request(
        method,
        BASE_URL + URL_SUFFIX,
        data=json,
        headers=headers,
        verify=INSECURE
    )
    if r.status_code not in [200, 201]:
        return_error('Error in API call [%d] - %s' % (r.status_code, r.reason))
    return r.json()


def filter_issues_by(response):
    issues = {}
    for issue in response:
        issues[issue['number']] = issue['title']
    return issues


# Allows nested keys to be accesible
def makehash():
    return collections.defaultdict(makehash)


'''MAIN FUNCTIONS'''


def list_all_issues():
    r = http_request('GET', 'issues')
    results = []
    for issue in r:
        issue_details = makehash()

        issue_details['number'] = issue['number']
        issue_details['ID'] = str(issue['id'])
        issue_details['title'] = issue['title']
        issue_details['link'] = issue['url']
        issue_details['state'] = issue['state']

        results.append(issue_details)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': r,
        'HumanReadable': tableToMarkdown('Issues list:', results, ['number', 'ID', 'title', 'state', 'link']),
        'EntryContext': {
            'GitHub.Issues(val.ID==obj.ID)': results
        }
    })
    return r


def create_issue(title, body, assignees, labels):
    query = {'title': title, 'body': body, 'assignees': assignees, 'labels': labels}
    search = json.dumps(query)
    r = http_request('POST', 'repos/teizenman/Demisto-start/issues', search)
    new_issue = {'number': r['number'], 'ID': str(r['id']), 'title': title, 'body': body, 'state': 'open'}
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': r,
        'HumanReadable': tableToMarkdown('Issue #' + str(r['number']) + ' has been created', query),
        'EntryContext': {
            'GitHub.Issues(val.ID==obj.ID)': new_issue
        }
    })
    return r


def edit_issue(issue_num, title, body, assignees, labels):
    r = None
    if str.isdigit(str(issue_num)):
        print_results = {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown']
        }
        r = http_request('GET', 'search/issues?q=repo:teizenman/Demisto-start+' + str(issue_num))
        if r['total_count'] > 0:
            query = {}
            if title:
                query['title'] = title
            if body:
                query['body'] = body
            if assignees:
                query['assignees'] = assignees
            if labels:
                query['labels'] = labels
            search = json.dumps(query)
            r = http_request('POST', 'repos/teizenman/Demisto-start/issues/' + str(issue_num), search)
            print_results['HumanReadable'] = tableToMarkdown(
                'Issue #' + str(issue_num) + ' has been edited with the following details:', query)
            print_results['EntryContext'] = {
                'GitHub.Issues(val.ID==obj.ID)': {'number': r['number'], 'ID': str(r['id']), 'title': r['title'],
                                                  'body': r['body'],
                                                  'state': r['state']}}
        else:
            print_results['HumanReadable'] = 'No such issue'
        print_results['Contents'] = r
        demisto.results(print_results)
    else:
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': r,
            'HumanReadable': 'Please enter a valid issue number',
        })
    return r


def close_issue(issue_num, state):
    r = None
    if str.isdigit(str(issue_num)):
        print_results = {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown']
        }
        r = http_request('GET', 'search/issues?q=repo:teizenman/Demisto-start+' + str(issue_num))
        if r['total_count'] > 0:
            query = {'state': state}
            search = json.dumps(query)
            r = http_request('POST', 'repos/teizenman/Demisto-start/issues/' + str(issue_num), search)
            print_results['HumanReadable'] = 'Issue #' + str(issue_num) + ' has been closed'
            print_results['EntryContext'] = {
                'GitHub.Issues(val.ID==obj.ID)': {'ID': str(r['id']), 'state': 'close'}
            }
        else:
            print_results['HumanReadable'] = 'No such issue'
        print_results['Contents'] = r
        demisto.results(print_results)
    else:
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': r,
            'HumanReadable': 'Please enter a valid issue number',
        })
    return r


def make_search(search_query, sort, order):
    query = '?q=repo:teizenman/Demisto-start'
    if search_query:
        query += '+' + search_query
    if sort:
        query += '&sort=' + sort
        if order:
            query += '&order=' + order
    r = http_request('GET', 'search/issues' + query)
    print_results = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': r
    }
    if r['total_count'] != 0:
        results = []
        for issue in r['items']:
            issue_details = makehash()
            issue_details['ID'] = str(issue['id'])
            issue_details['title'] = issue['title']
            issue_details['link'] = issue['url']
            issue_details['state'] = issue['state']
            results.append(issue_details)
            print_results['HumanReadable'] = tableToMarkdown(
                str(r['total_count']) + ' found issues.\nComplete list of issues: ' + str(not r['incomplete_results']),
                results, ['ID', 'title', 'state', 'link'])
        print_results['EntryContext'] = {
            'GitHub.Searches(val.query==obj.query)': {'query': query, 'results': results}
        }
    else:
        print_results['HumanReadable'] = 'No issues found for this query!'
    demisto.results(print_results)
    return r


def count_total_downloads():
    r = http_request('GET', 'repos/teizenman/Demisto-start/releases')
    output = []
    for asset in r[0]['assets']:
        count = makehash()
        count['asset_name'] = asset['name']
        count['download_count'] = asset['download_count']
        output.append(count)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': r,
        'HumanReadable': tableToMarkdown('Download counts:', output, ['asset_name', 'download_count']),
        'EntryContext': {
            'GitHub.Download-counts(val.asset_name==obj.asset_name)': output
        }
    })
    return r


''' EXECUTION '''
LOG('command is %s' % (demisto.command(),))
try:
    if demisto.command() == 'list-all-issues':
        list_all_issues()

    elif demisto.command() == 'create-issue':
        title = demisto.args().get('title')
        body = demisto.args().get('body')
        assignees = argToList(demisto.args().get('assignees'))
        labels = argToList(demisto.args().get('labels'))
        create_issue(title, body, assignees, labels)

    elif demisto.command() == 'edit-issue':
        issue_num = demisto.args().get('issue_num')
        title = demisto.args().get('title')
        body = demisto.args().get('body')
        assignees = argToList(demisto.args().get('assignees'))
        labels = argToList(demisto.args().get('labels'))
        edit_issue(issue_num, title, body, assignees, labels)

    elif demisto.command() == 'close-issue':
        issue_num = demisto.args().get('issue_num')
        close_issue(issue_num, 'close')

    elif demisto.command() == 'make-search':
        search_query = demisto.args().get('search_query')
        sort_by = demisto.args().get('sort_by')
        order_by = demisto.args().get('order_by')
        make_search(search_query, sort_by, order_by)

    elif demisto.command() == 'count-downloads':
        count_total_downloads()

    elif demisto.command() == 'test-module':
        list_all_issues()  # result code 200
        create_issue('From Demisto', 'Right from the integration window', ['teizenman'],
                     ['good first issue'])  # result code 201
        edit_issue(3, 'From Demisto', 'Right from the integration window', ['teizenman'],
                   ['enhancment'])  # result code 200
        close_issue(3, 'close')  # result code 200
        demisto.results('ok')
except Exception, e:
    demisto.debug('The Senate? I am the Senate!')
    LOG(e.message)
    LOG.print_log()
    return_error(e.message)

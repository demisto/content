import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import requests

'''HELPER FUNCITONS'''


def http_request(method, URL_SUFFIX="", data={}, full_url=""):
    if method is 'GET':
        headers = {'Authorization': 'Bearer ' + API_KEY}
    elif method is 'POST':
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + API_KEY
        }
    if (full_url == ""):
        r = requests.request(method,
                             API + URL_SUFFIX,
                             headers=headers,
                             json=data)
    else:
        r = requests.request(method,
                             full_url,
                             headers=headers,
                             json=data)
    if (r.status_code == 404):
        return_error("Issue {} not found.".format(URL_SUFFIX[URL_SUFFIX.rfind("/") + 1:]))
    if (r.status_code == 422):
        return_error("One of the users {} is unassaignable.".format(data['assignees']))
    if r.status_code not in [200, 201]:
        return_error('Error in API call [{}] -{}. headers: {} \n url: {}\ndata: {}'.format(
            r.status_code, r.reason, headers, API + URL_SUFFIX, data))

    return r.json()


'''COMMAND FUNCTIONS'''


def list_all_issues_command():
    LOG("GitHub: Fetching open issues for repository: {}/{}".format(OWNER, REPO))
    context_entries = []
    res = http_request('GET', "/issues")
    for issue in res:
        context_entries.append({
            'ID': issue.get('number'),
            'Title': issue.get('title'),
            'Body': issue.get('body'),
            'Assignees': [assignee.get('login') for assignee in issue.get('assignees')],
            'Labels': [label.get('name') for label in issue.get('labels')]
        })
    HR = tableToMarkdown("Open issues", context_entries)
    EC = {'GitHub.Issue(val.ID && val.ID == obj.ID)': context_entries}
    return_outputs(HR, EC, res)


def create_issue_command():
    title = demisto.args().get('title')
    body = demisto.args().get('body')
    assignees = argToList(demisto.args().get('assignees'))
    labels = argToList(demisto.args().get('labels'))

    LOG("GitHub: Creating a new issue with title %s" % (title))

    create_issue(title, body, assignees, labels)


def create_issue(title, body, assignees, labels):
    data = {'title': title}
    if (body is not None):
        data['body'] = body
    if (len(assignees) > 0):
        ##check assignees
        data['assignees'] = assignees
    if (len(labels) > 0):
        data['labels'] = labels
    res = http_request('POST', "/issues", data)

    context_entries = {
        'ID': res.get('number'),
        'Title': res.get('title'),
        'Body': res.get('body'),
        'Assignees': [assignee.get('login') for assignee in res.get('assignees')],
        'Labels': [label.get('name') for label in res.get('labels')]
    }
    HR = tableToMarkdown("Created issue", context_entries,
                         ["ID", "Title", "Body", "Assignees", "Labels"])
    EC = {'GitHub.Issue(val.ID && val.ID == obj.ID)': context_entries}
    return_outputs(HR, EC, res)


def close_issue_command():
    issues = argToList(str(demisto.args().get('issue_number')))
    s = ""
    for issue in issues:
        close_issue(issue)
        s = s + str(issue) + ", "
    demisto.results("Closed issues number: %s" % s[:-2])


def close_issue(issue_number):
    data = {"state": "closed"}
    http_request("POST", "/issues/" + str(issue_number), data)


def update_issue_command():
    title = demisto.args().get('title')
    body = demisto.args().get('body')
    assignees = argToList(demisto.args().get('assignees'))
    labels = argToList(demisto.args().get('labels'))
    issue_number = str(demisto.args().get('issue_number'))

    LOG("GitHub: Updating issue number {}".format(issue_number))

    return (update_issue(issue_number, title, body, assignees, labels))


def update_issue(issue_number, title, body, assignees, labels):
    data = {}
    if (title is not None):
        data['title'] = title
    if (body is not None):
        data['body'] = body
    if (len(assignees) > 0):
        ##check assignees
        data['assignees'] = assignees
    if (len(labels) > 0):
        data['labels'] = labels
    res = http_request('POST', "/issues/" + str(issue_number), data)

    context_entries = {
        'ID': res.get('number'),
        'Title': res.get('title'),
        'Body': res.get('body'),
        'Assignees': [assignee.get('login') for assignee in res.get('assignees')],
        'Labels': [label.get('name') for label in res.get('labels')]
    }
    HR = tableToMarkdown("Updated issue:", context_entries,
                         ["ID", "Title", "Body", "Assignees", "Labels"])
    EC = {'GitHub.Issue(val.ID && val.ID == obj.ID)': context_entries}
    return_outputs(HR, EC, res)


def download_count_command():
    LOG("GitHub: How many downloads were in repo: %s/%s." % (OWNER, REPO))
    res = http_request("GET", "/releases")
    if (res == []):
        demisto.results("There were no dowloads for the repository %s/%s" % (OWNER, REPO))
    else:
        counter = 0
        for release in res:
            for asset in release.get('assets'):
                counter = counter + asset.get("download_count")
        demisto.results("There were %d dowloads for the repository %s/%s" % (counter, OWNER, REPO))


def search_issues_command():
    query = demisto.args().get('query')
    LOG("Searching for issues with query: {}".format(query))
    search_issues(query)


def search_issues(query):
    url = "https://api.github.com/search/issues?q=repo:{}/{}+{}".format(OWNER, REPO, query)
    res = http_request("GET", full_url=url)
    context = []
    for issue in res['items']:
        context.append({
            'ID': issue.get('number'),
            'Title': issue.get('title'),
            'Body': issue.get('body'),
            'Assignees': [assignee.get('login') for assignee in issue.get('assignees')],
            'Labels': [label.get('name') for label in issue.get('labels')]
        })
    HR = tableToMarkdown("{} issues found.".format(res['total_count']), context,
                         ["ID", "Title", "Body", "Assignees", "Labels"])
    EC = {'GitHub.Issue(val.ID && val.ID == obj.ID)': context}
    return_outputs(HR, EC, res)


def fetch_incidents_command():
    last_run = demisto.getLastRun()

    last_fetch = last_run.get('time')
    if last_fetch is None:
        last_fetch = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
    last_issue = datetime.strptime(last_fetch, '%Y-%m-%dT%H:%M:%SZ')

    incs = []


    url = "https://api.github.com/search/issues?q=repo:{}/{}+state:open+created:>{}".format(OWNER, REPO, last_fetch)
    res = http_request("GET", full_url=url)
    for issue in res.get('items'):
        issue_time = issue.get('created_at')
        issue_time_date = datetime.strptime(issue_time, '%Y-%m-%dT%H:%M:%SZ')
        inc = {
            'name': 'Issue number {}, titled: "{}"'.format(issue.get('number'), issue.get('title')),
            'occured': issue_time,
            'rawJSON': json.dumps(issue)
        }
        if (issue_time_date > last_issue):
            last_issue = issue_time_date
        incs.append(inc)
    demisto.setLastRun({'time': last_issue.strftime('%Y-%m-%dT%H:%M:%SZ')})
    demisto.incidents(incs)


def main():
    ## Global variables declaration
    global REPO, OWNER, API, API_KEY
    REPO = demisto.params().get('repo_name')
    OWNER = demisto.params().get('repo_owner')
    API_KEY = demisto.params().get('api_key')
    API = 'https://api.github.com/repos/' + OWNER + "/" + REPO

    '''EXECUTION CODE'''
    COMMANDS = {
        "list-all-issues": list_all_issues_command,
        'create-issue': create_issue_command,
        'close-issue': close_issue_command,
        'update-issue': update_issue_command,
        'download-count': download_count_command,
        'search-issues': search_issues_command,
        'fetch-incidents': fetch_incidents_command
    }
    command = demisto.command()
    LOG('GitHub command is: %s' % (command,))
    try:
        if command == 'test-module':
            headers = {'Authorization': 'Bearer ' + API_KEY}
            r = requests.request("GET",
                                 API,
                                 headers=headers)
            if (r.status_code == 200):
                demisto.results('ok')
            else:
                demisto.results('Unable to connect with the given credentials.')
            sys.exit(0)
        cmd_func = COMMANDS.get(command)
        if cmd_func is None:
            raise NotImplemented('Command "%s" is not implemented.') % (cmd_func)
        else:
            cmd_func()
    except Exception as e:
        import traceback
        return_error('GitHub: {}'.format(str(e)), traceback.format_exc())


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import requests

'''GLOBAL VARIABLES'''
REPO = demisto.params().get('repo_name')
OWNER = demisto.params().get('repo_owner')
API_KEY = demisto.params().get('api_key')
API = 'https://api.github.com/repos/' + OWNER + "/" + REPO
PROXY = demisto.params().get('proxy')
INSECURE = not demisto.params().get('insecure')
FETCH_TIME = demisto.params().get('first_fetch')
IS_FETCH = demisto.params().get('isFetch')

'''HELPER FUNCITONS'''


def http_request(method, url_suffix="", data={}, full_url=""):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + API_KEY
    }
    if (full_url == ""):
        r = requests.request(method,
                             API + url_suffix,
                             headers=headers,
                             json=data,
                             verify=INSECURE)
    else:
        r = requests.request(method,
                             full_url,
                             headers=headers,
                             json=data,
                             verify=INSECURE)
    if (r.status_code == 404):
        return_error("Issue {} not found.".format(url_suffix[url_suffix.rfind("/") + 1:]))
    if (r.status_code == 422):
        return_error("One of the users {} is unassaignable.".format(data['assignees']))
    if r.status_code not in [200, 201]:
        return_error('Error in API call [{}] -{}. headers: {} \n url: {}\ndata: {}'.format(
            r.status_code, r.reason, headers, API + url_suffix, data))

    return r.json()


'''COMMAND FUNCTIONS'''


def list_all_issues_command():
    LOG("GitHub: Fetching open issues for repository: {}/{}".format(OWNER, REPO))
    context_entries = []
    res = http_request('GET', "/issues")
    demisto.results(len(res))
    for issue in res:
        context_entries.append({
            'ID': issue.get('number'),
            'Title': issue.get('title'),
            'Body': issue.get('body'),
            'Assignees': [assignee.get('login') for assignee in issue.get('assignees')],
            'Labels': [label.get('name') for label in issue.get('labels')]
        })
    open_issues, num_open_issues = search_issues("state:open")
    md = tableToMarkdown("Open issues [{}/{}]".format(len(res), num_open_issues), context_entries,
                         ["ID", "Title", "Body", "Assignees", "Labels"])
    ec = {'GitHub.Issue(val.ID && val.ID == obj.ID)': context_entries}
    return_outputs(md, ec, res)


def create_issue_command():
    title = demisto.args().get('title')
    body = demisto.args().get('body')
    assignees = argToList(demisto.args().get('assignees'))
    labels = argToList(demisto.args().get('labels'))

    LOG("GitHub: Creating a new issue with title {}".format(title))

    res = create_issue(title, body, assignees, labels)

    context_entries = {
        'ID': res.get('number'),
        'Title': res.get('title'),
        'Body': res.get('body'),
        'Assignees': [assignee.get('login') for assignee in res.get('assignees')],
        'Labels': [label.get('name') for label in res.get('labels')]
    }

    md = tableToMarkdown("Created issue", context_entries,
                         ["ID", "Title", "Body", "Assignees", "Labels"])
    ec = {'GitHub.Issue(val.ID && val.ID == obj.ID)': context_entries}
    return_outputs(md, ec, res)


def create_issue(title, body, assignees, labels):
    data = {'title': title}
    if (body is not None):
        data['body'] = body
    if (len(assignees) > 0):
        ##check assignees
        data['assignees'] = assignees
    if (len(labels) > 0):
        data['labels'] = labels
    return http_request('POST', "/issues", data)


def close_issue_command():
    issues = argToList(str(demisto.args().get('issue_number')))
    for issue in issues:
        close_issue(issue)
    demisto.results("Closed issues number: {}".format((",".join(str(x) for x in issues))))


def close_issue(issue_number):
    data = {"state": "closed"}
    http_request("POST", "/issues/" + str(issue_number), data)


def update_issue_command():
    title = demisto.args().get('title')
    body = demisto.args().get('body')
    assignees = argToList(demisto.args().get('assignees'))
    labels = argToList(demisto.args().get('labels'))
    issue_number = demisto.args().get('issue_number')

    LOG("GitHub: Updating issue number {}".format(issue_number))

    res = update_issue(issue_number, title, body, assignees, labels)

    context_entries = {
        'ID': res.get('number'),
        'Title': res.get('title'),
        'Body': res.get('body'),
        'Assignees': [assignee.get('login') for assignee in res.get('assignees')],
        'Labels': [label.get('name') for label in res.get('labels')]
    }
    md = tableToMarkdown("Updated issue:", context_entries,
                         ["ID", "Title", "Body", "Assignees", "Labels"])
    ec = {'GitHub.Issue(val.ID && val.ID == obj.ID)': context_entries}
    return_outputs(md, ec, res)


def update_issue(issue_number, title, body, assignees, labels):
    data = {}
    if (title is not None):
        data['title'] = title
    if (body is not None):
        data['body'] = body
    if (len(assignees) > 0):
        data['assignees'] = assignees
    if (len(labels) > 0):
        data['labels'] = labels
    return http_request('POST', "/issues/" + str(issue_number), data)


def download_count_command():
    LOG("GitHub: How many downloads were in repo: {}/{}.".format(OWNER, REPO))
    res = http_request("GET", "/releases")
    if (res == []):
        demisto.results("There were no dowloads for the repository {}/{}".format(OWNER, REPO))
    else:
        releases=[]
        for release in res:
            counter = 0
            for asset in release.get('assets'):
                counter = counter + asset.get("download_count")
            releases.append({"Release name": release.get('name'),
                            "Download count": counter})
        md = tableToMarkdown("Release downloads:", releases,
                             ["Release name","Download count"])
        demisto.results(md)


def search_issues_command():
    query = argToList(demisto.args().get('query'))
    created_from = demisto.args().get('created_from')
    in_title = argToList(demisto.args().get('in_title'))
    in_body = argToList(demisto.args().get('in_body'))
    max=demisto.args().get('max_results')
    if (query is not None):
        query_str = "+".join(query)
    else:
        query_str = ""
    if (created_from is not None):
        query_str = query_str + "+created:>={}".format(created_from)
    if (in_title is not None):
        for title in in_title:
            query_str = query_str + '+"{}" in:title'.format(title)
    if (in_body is not None):
        for phrase in in_body:
            query_str = query_str + '+"{}" in:body'.format(phrase)
    query_str= query_str+ '&per_page={}'.format(max)

    LOG("Searching for issues with query: {}".format(query_str))

    items, num_items = search_issues(query_str)

    context = []
    for issue in items:
        context.append({
            'ID': issue.get('number'),
            'Title': issue.get('title'),
            'Body': issue.get('body'),
            'Assignees': [assignee.get('login') for assignee in issue.get('assignees')],
            'Labels': [label.get('name') for label in issue.get('labels')]
        })
    md = tableToMarkdown("{} issues found.".format(num_items), context,
                         ["ID", "Title", "Body", "Assignees", "Labels"])
    ec = {'GitHub.Issue(val.ID && val.ID == obj.ID)': context}
    return_outputs(md, ec, items)


def search_issues(query):
    url = "https://api.github.com/search/issues?q=repo:{}/{}+{}".format(OWNER, REPO, query)
    res = http_request("GET", full_url=url)
    return res['items'], res['total_count']


def fetch_incidents_command():
    last_run = demisto.getLastRun()

    last_fetch = last_run.get('time')
    if last_fetch is None:
        last_fetch, _ = parse_date_range(FETCH_TIME, date_format='%Y-%m-%dT%H:%M:%SZ')
    last_issue = datetime.strptime(last_fetch, '%Y-%m-%dT%H:%M:%SZ')
    incs = []
    url = "https://api.github.com/search/issues?q=repo:{}/{}+state:open+created:>{}&sort=created&order=asc&per_page=30".format(
        OWNER, REPO, last_fetch)
    res = http_request("GET", full_url=url)
    for issue in res.get('items'):
        issue_time = issue.get('created_at')
        issue_time_date = datetime.strptime(issue_time, '%Y-%m-%dT%H:%M:%SZ')
        inc = {
            'name': 'Issue number {}, titled: "{}"'.format(issue.get('number'), issue.get('title')),
            'occurred': issue_time,
            'rawJSON': json.dumps(issue)
        }
        last_issue = max(issue_time_date, last_issue)
        incs.append(inc)
    demisto.setLastRun({'time': last_issue.strftime('%Y-%m-%dT%H:%M:%SZ')})
    demisto.incidents(incs)

def test_module_command():
    if IS_FETCH:
        parse_date_range(FETCH_TIME)
    headers = {'Authorization': 'Bearer ' + API_KEY}

    r = requests.request("GET",
                         API,
                         headers=headers)
    if (r.status_code == 200):
        demisto.results('ok')
    else:
        demisto.results('Unable to connect with the given credentials.')
    sys.exit(0)

def main():
    ## Global variables declaration
    # global REPO, OWNER, API, API_KEY

    '''EXECUTION CODE'''
    handle_proxy()
    COMMANDS = {
        "Github-list-all-issues": list_all_issues_command,
        'Github-create-issue': create_issue_command,
        'Github-close-issue': close_issue_command,
        'Github-update-issue': update_issue_command,
        'Github-download-count': download_count_command,
        'Github-search-issues': search_issues_command,
        'fetch-incidents': fetch_incidents_command,
        'test-module': test_module_command()
    }
    command = demisto.command()
    LOG('GitHub command is: {}'.format(command,))
    try:
        cmd_func = COMMANDS.get(command)
        if cmd_func is None:
            raise NotImplemented('Command "{}" is not implemented.').format(cmd_func)
        else:
            cmd_func()
    except Exception as e:
        import traceback
        return_error('GitHub: {}'.format(str(e)), traceback.format_exc())


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()

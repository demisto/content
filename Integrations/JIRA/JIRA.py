import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import json
import requests
from base64 import b64encode

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
BASE_URL = demisto.params().get('url')
API_TOKEN = demisto.params().get('APItoken')
USERNAME = demisto.params().get('username')
PASSWORD = demisto.params().get('password')
IS_OAUTH = demisto.params().get('consumerKey') and demisto.params().get('accessToken') and demisto.params().get(
    'privateKey')

# if not OAuth, check for valid parameters for basic auth, i.e. username & pass, or just APItoken
if not IS_OAUTH and not (USERNAME and PASSWORD or API_TOKEN):
    return_error('Provide Authorization information, Basic(userName & password / API-token) or OAuth1.0')
BASIC_AUTH = 'Basic ' + b64encode(USERNAME + ":" + (API_TOKEN if API_TOKEN else PASSWORD))
OAUTH = {
    "ConsumerKey": demisto.params().get('consumerKey'),
    "AccessToken": demisto.params().get('accessToken'),
    "PrivateKey": demisto.params().get('privateKey')
} if IS_OAUTH else ''

HEADERS = {
    'Content-Type': 'application/json',
}
if not IS_OAUTH:
    HEADERS['Authorization'] = BASIC_AUTH

USE_SSL = not demisto.params().get('insecure', False)

# Remove proxy if not set to true in params
if not demisto.params().get('proxy', False):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


@logger
def jira_req(method, resource_url, body='', link=False):
    url = resource_url if link else (BASE_URL + resource_url)
    result = requests.request(
        method=method,
        url=url,
        data=body,
        headers=HEADERS,
        verify=USE_SSL,
        params=OAUTH
    )
    if not result.ok:
        demisto.debug(result.text)
        try:
            rj = result.json()
            if rj.get('errorMessages'):
                return_error(
                    'Status code: {}\nMessage: {}'.format(result.status_code, ','.join(rj['errorMessages'])))
            elif rj.get('errors'):
                return_error(
                    'Status code: {}\nMessage: {}'.format(result.status_code, ','.join(rj['errors'].values())))
            else:
                return_error('Status code: {}\nError text: {}'.format(result.status_code, result.text))
        except ValueError as ve:
            demisto.debug(str(ve))
            if result.status_code == 401:
                return_error('Unauthorized, please check parameters')
            elif result.status_code == 404:
                return_error("Server is unreachable, please insure the URL is correct")
            else:
                return_error("Failed reaching the server. status code: {}".format(result.status_code))

    return result


@logger
def run_query(query, start_at='', max_results=None):
    # EXAMPLE
    """
    request = {
        "jql": "project = HSP",
        "startAt": 0,
        "maxResults": 15,
        "fields": [    <-- not supported yet, but easily attainable
            "summary",
            "status",
            "assignee"
        ]
    }
    """
    demisto.debug('querying with: {}'.format(query))
    url = BASE_URL + 'rest/api/latest/search/'
    query_params = {
        'jql': query,
        "startAt": start_at,
        "maxResults": max_results,
    }
    query_params.update(OAUTH)

    result = requests.get(
        url=url,
        headers=HEADERS,
        verify=USE_SSL,
        params=query_params
    )
    try:
        return result.json()

    except ValueError as ve:
        demisto.debug(ve.message)
        return_error('Failed to send request, reason: {}'.format(result.reason))


@logger
def get_id_offset():
    query = "ORDER BY created ASC"
    j_res = run_query(query=query, max_results=1)
    first_issue_id = j_res.get('issues')[0].get('id')
    return_outputs(
        readable_output="ID Offset: {}".format(first_issue_id),
        outputs={'Ticket.idOffSet': first_issue_id},
    )


@logger
def expand_urls(data, depth=0):
    if isinstance(data, dict) and depth < 10:
        for key, value in data.items():
            if key in ['_links', 'watchers', 'sla', 'request participants']:
                # dictionary of links
                if isinstance(value, dict):
                    for link_key, link_url in value.items():
                        value[link_key + '_expended'] = json.dumps(
                            jira_req(method='GET', resource_url=link_url, link=True).json())

                # link
                else:
                    data[key + '_expended'] = json.dumps(jira_req(method='GET', resource_url=value, link=True).json())

            # search deeper
            else:
                if isinstance(value, dict):
                    return expand_urls(value, depth + 1)


@logger
def generate_md_context_get_issue(data):
    get_issue_obj = {"md": [], "context": []}
    if not isinstance(data, list):
        data = [data]

    for element in data:
        md_obj, context_obj = {}, {}

        context_obj['Id'] = md_obj['id'] = demisto.get(element, 'id')
        context_obj['Key'] = md_obj['key'] = demisto.get(element, 'key')
        context_obj['Summary'] = md_obj['summary'] = demisto.get(element, 'fields.summary')
        context_obj['Status'] = md_obj['status'] = demisto.get(element, 'fields.status.name')

        assignee = demisto.get(element, 'fields.assignee')
        context_obj['Assignee'] = md_obj['assignee'] = "{name}({email})".format(
            name=assignee.get('displayName', 'null'),
            email=assignee.get('emailAddress', 'null')
        ) if assignee else 'null(null)'

        creator = demisto.get(element, 'fields.creator')
        context_obj['Creator'] = md_obj['creator'] = "{name}({email})".format(
            name=creator.get('displayName', 'null'),
            email=creator.get('emailAddress', 'null')
        ) if creator else 'null(null)'

        reporter = demisto.get(element, 'fields.reporter')
        md_obj['reporter'] = "{name}({email})".format(
            name=reporter.get('displayName', 'null'),
            email=reporter.get('emailAddress', 'null')
        ) if reporter else 'null(null)'

        md_obj.update({
            'issueType': demisto.get(element, 'fields.issuetype.description'),
            'priority': demisto.get(element, 'fields.priority.name'),
            'project': demisto.get(element, 'fields.project.name'),
            'labels': demisto.get(element, 'fields.labels'),
            'description': demisto.get(element, 'fields.description'),
            'duedate': demisto.get(element, 'fields.duedate'),
            'ticket_link': demisto.get(element, 'self'),
            'created': demisto.get(element, 'fields.created'),
        })
        attachments = demisto.get(element, 'fields.attachment')
        if isinstance(attachments, list):
            md_obj['attachment'] = ','.join(attach.get('filename') for attach in attachments)

        get_issue_obj['md'].append(md_obj)
        get_issue_obj['context'].append(context_obj)

    return get_issue_obj


@logger
def generate_md_context_create_issue(data, project_name=None, project_key=None):
    create_issue_obj = {"md": [], "context": {"Ticket": []}}
    if project_name:
        data["projectName"] = project_name

    if project_key:
        data["projectKey"] = project_key

    elif demisto.params().get('projectKey'):
        data["projectKey"] = demisto.params().get('projectKey')

    create_issue_obj['md'].append(data)
    create_issue_obj['context']['Ticket'].append({"Id": demisto.get(data, 'id'), "Key": demisto.get(data, 'key')})
    return create_issue_obj


@logger
def generate_md_upload_issue(data, issue_id):
    upload_md = []
    if not isinstance(data, list):
        data = [data]

    for element in data:
        md_obj = {
            'id': demisto.get(element, 'id'),
            'issueId': issue_id,
            'attachment_name': demisto.get(element, 'filename'),
            'attachment_link': demisto.get(element, 'self')
        }
        upload_md.append(md_obj)

    return upload_md


@logger
def create_incident_from_ticket(issue):
    labels = [
        {'type': 'issue', 'value': json.dumps(issue)}, {'type': 'id', 'value': str(issue.get('id'))},
        {'type': 'lastViewed', 'value': str(demisto.get(issue, 'fields.lastViewed'))},
        {'type': 'priority', 'value': str(demisto.get(issue, 'fields.priority.name'))},
        {'type': 'status', 'value': str(demisto.get(issue, 'fields.status.name'))},
        {'type': 'project', 'value': str(demisto.get(issue, 'fields.project.name'))},
        {'type': 'updated', 'value': str(demisto.get(issue, 'fields.updated'))},
        {'type': 'reportername', 'value': str(demisto.get(issue, 'fields.reporter.displayName'))},
        {'type': 'reporteremail', 'value': str(demisto.get(issue, 'fields.reporter.emailAddress'))},
        {'type': 'created', 'value': str(demisto.get(issue, 'fields.created'))},
        {'type': 'summary', 'value': str(demisto.get(issue, 'fields.summary'))},
        {'type': 'description', 'value': str(demisto.get(issue, 'fields.description'))}
    ]

    name = demisto.get(issue, 'fields.summary')
    if name:
        name = "Jira issue: {}".format(issue.get('id'))

    severity = 0
    if demisto.get(issue, 'fields.priority') and demisto.get(issue, 'fields.priority.name'):
        if demisto.get(issue, 'fields.priority.name') == 'Highest':
            severity = 4
        elif demisto.get(issue, 'fields.priority.name') == 'High':
            severity = 3
        elif demisto.get(issue, 'fields.priority.name') == 'Medium':
            severity = 2
        elif demisto.get(issue, 'fields.priority.name') == 'Low':
            severity = 1

    return {
        "name": name,
        "labels": labels,
        "details": demisto.get(issue, "fields.description"),
        "severity": severity,
        "rawJSON": json.dumps(issue)
    }


@logger
def get_project_id(project_key='', project_name=''):
    result = jira_req('GET', 'rest/api/latest/issue/createmeta')

    for project in result.json().get('projects'):
        if project_key.lower() == project.get('key').lower() or project_name.lower() == project.get('name').lower():
            return project.get('id')
    return_error('Project not found')


@logger
def get_issue_fields(**kwargs):
    issue = {}
    if 'issueJson' in kwargs:
        issue = json.dumps(kwargs['issueJson'])

    if not issue.get('fields'):
        issue['fields'] = {}

    if not issue['fields'].get('issuetype') and demisto.command() == 'jira-create-issue':
        issue['fields']['issuetype'] = {}

    if kwargs.get('summary'):
        issue['fields']['summary'] = kwargs['summary']

    if not issue['fields'].get('project'):
        issue['fields']['project'] = {}

    if kwargs.get('projectKey'):
        issue['fields']['project']['key'] = kwargs.get('projectKey', '')
    if kwargs.get('projectName'):
        issue['fields']['project']['name'] = kwargs.get('projectName', '')

    if demisto.command() == 'jira-create-issue':
        # make sure the key & name are right, and get the corresponding project id & key
        project_id = get_project_id(issue['fields']['project'].get('key', ''),
                                    issue['fields']['project'].get('name', ''))
        issue['fields']['project']['id'] = project_id

    if kwargs.get('issueTypeName'):
        issue['fields']['issuetype']['name'] = kwargs['issueTypeName'].title()

    if kwargs.get('issueTypeId'):
        issue['fields']['issuetype']['id'] = kwargs['issueTypeId']

    if kwargs.get('parentIssueId'):
        if not issue['fields'].get('parent'):
            issue['fields']['parent'] = {}
        issue['fields']['parent']['id'] = kwargs['parentIssueId']

    if kwargs.get('parentIssueKey'):
        if not issue['fields'].get('parent'):
            issue['fields']['parent'] = {}
        issue['fields']['parent']['key'] = kwargs['parentIssueKey']

    if kwargs.get('description'):
        issue['fields']['description'] = kwargs['description']

    if kwargs.get('labels'):
        issue['fields']['labels'] = kwargs['labels'].split(",")

    if kwargs.get('priority'):
        if not issue['fields'].get('priority'):
            issue['fields']['priority'] = {}
        issue['fields']['priority']['name'] = kwargs['priority']

    if kwargs.get('duedate'):
        issue['fields']['duedate'] = kwargs['duedate']

    if kwargs.get('assignee'):
        if not issue['fields'].get('assignee'):
            issue['fields']['assignee'] = {}
        issue['fields']['assignee']['name'] = kwargs['assignee']

    if kwargs.get('reporter'):
        if not issue['fields'].get('reporter'):
            issue['fields']['reporter'] = {}
        issue['fields']['reporter']['name'] = kwargs['reporter']

    return issue


@logger
def get_issue(issue_id, headers=None, expend_links=False, is_update=False, get_attachments=False):
    result = jira_req('GET', 'rest/api/latest/issue/' + issue_id)
    j_res = result.json()
    if expend_links:
        expand_urls(j_res)

    attachments = demisto.get(j_res, 'fields.attachment')  # list of all attachments
    if get_attachments == 'true' and attachments:
        attachments_zip = jira_req(method='GET', resource_url='secure/attachmentzip/{}.zip'.format(issue_id)).content
        demisto.results(fileResult(filename='{}_attachments.zip'.format(j_res.get('id')), data=attachments_zip))

    md_and_context = generate_md_context_get_issue(j_res)
    human_readable = tableToMarkdown(demisto.command(), md_and_context['md'], argToList(headers))
    if is_update:
        human_readable += 'Issue #{} was updated successfully'.format(issue_id)

    contents = j_res
    outputs = {'Ticket(val.Id == obj.Id)': md_and_context['context']}
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=contents)


@logger
def issue_query_command(query, start_at='', max_results=None, headers=''):
    j_res = run_query(query, start_at, max_results)
    issues = demisto.get(j_res, 'issues')
    md_and_context = generate_md_context_get_issue(issues)
    human_readable = tableToMarkdown(demisto.command(), md_and_context['md'], argToList(headers))
    contents = j_res
    outputs = {'Ticket(val.Id == obj.Id)': md_and_context['context']}
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=contents)


@logger
def create_issue_command():
    url = 'rest/api/latest/issue'
    issue = get_issue_fields(**demisto.args())
    result = jira_req('POST', url, json.dumps(issue))
    j_res = result.json()

    md_and_context = generate_md_context_create_issue(j_res, project_key=demisto.args().get('projectKey'),
                                                      project_name=demisto.args().get('issueTypeName'))
    human_readable = tableToMarkdown(demisto.command(), md_and_context['md'], "")
    contents = j_res
    outputs = md_and_context['context']
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=contents)


@logger
def edit_issue_command(issue_id, headers=None, status=None, **kwargs):
    url = 'rest/api/latest/issue/{issue_Id}/'.format(issue_Id=issue_id)
    issue = get_issue_fields(**demisto.args())
    jira_req('PUT', url, json.dumps(issue))
    if status:
        edit_status(issue_id, status)
    return get_issue(issue_id, headers, is_update=True)


@logger
def edit_status(issue_id, status):
    # check for all authorized transitions available for this user
    # if the requested transition is available, execute it.
    url = 'rest/api/2/issue/{issue_Id}/transitions'.format(issue_Id=issue_id)
    result = jira_req('GET', url)
    j_res = result.json()
    transitions = [transition.get('name') for transition in j_res.get('transitions')]
    for i, transition in enumerate(transitions):
        if transition.lower() == status.lower():
            url = 'rest/api/latest/issue/{issue_Id}/transitions?expand=transitions.fields'.format(issue_Id=issue_id)
            json_body = {"transition": {"id": str(j_res.get('transitions')[i].get('id'))}}
            return jira_req('POST', url, json.dumps(json_body))

    return_error('Status "{}" not found. \n'
                 'Valid transitions are: {} \n'.format(status, transitions))


@logger
def get_comments_command(issue_id):
    url = 'rest/api/latest/issue/{issue_Id}/comment'.format(issue_Id=issue_id)
    result = jira_req('GET', url)
    body = result.json()
    comments = []
    if body.get("comments"):
        for comment in body.get("comments"):
            comments.append({
                'Comment': comment.get("body"),
                'User': demisto.get(comment, 'updateAuthor.name'),
                'Created': comment.get("created")
            })

        human_readable = tableToMarkdown("Comments", comments)
        contents = body
        outputs = {'Ticket(val.Id == obj.Id)': {'Id': issue_id, "Comment": comments}}
        return_outputs(readable_output=human_readable, outputs=outputs, raw_response=contents)

    else:
        demisto.results('No comments were found in the ticket')


@logger
def add_comment_command(issue_id, comment, visibility=''):
    url = 'rest/api/latest/issue/{issue_Id}/comment'.format(issue_Id=issue_id)
    comment = {
        "body": comment
    }
    if visibility:
        comment["visibility"] = {
            "type": "role",
            "value": visibility
        }
    result = jira_req('POST', url, json.dumps(comment))
    data = result.json()
    md_list = []
    if not isinstance(data, list):
        data = [data]
    for element in data:
        md_obj = {
            'id': demisto.get(element, 'id'),
            'key': demisto.get(element, 'updateAuthor.key'),
            'comment': demisto.get(element, 'body'),
            'ticket_link': demisto.get(element, 'self')
        }
        md_list.append(md_obj)

    human_readable = tableToMarkdown(demisto.command(), md_list, "")
    contents = data
    return_outputs(readable_output=human_readable, outputs={}, raw_response=contents)


@logger
def issue_upload_command(issue_id, upload):
    j_res = upload_file(upload, issue_id)
    md = generate_md_upload_issue(j_res, issue_id)
    human_readable = tableToMarkdown(demisto.command(), md, "")
    contents = j_res
    return_outputs(readable_output=human_readable, outputs={}, raw_response=contents)


@logger
def upload_file(entry_id, issue_id):
    headers = {
        'X-Atlassian-Token': 'no-check',
    }
    res = requests.post(
        BASE_URL + 'rest/api/latest/issue/{issue_id}/attachments'.format(issue_id=issue_id),
        headers=headers,
        files={'file': get_file(entry_id)},
        auth=(USERNAME, PASSWORD),
        verify=USE_SSL
    )

    if not res.ok:
        return_error('Failed to execute request:{}\nBody: {}'.format(res.status_code, res.text))

    return res.json()


@logger
def get_file(entry_id):
    get_file_path_res = demisto.getFilePath(entry_id)
    file_path = get_file_path_res["path"]
    file_name = get_file_path_res["name"]
    with open(file_path, 'rb') as fopen:
        file_bytes = fopen.read()
    return file_name, file_bytes


@logger
def add_link_command(issue_id, title, url, summary=None, global_id=None, relationship=None):
    req_url = 'rest/api/latest/issue/{issue_Id}/remotelink'.format(issue_Id=issue_id)
    link = {
        "object": {
            "url": url,
            "title": title
        }
    }

    if summary:
        link['summary'] = summary
    if global_id:
        link['globalId'] = global_id
    if relationship:
        link['relationship'] = relationship

    result = jira_req('POST', req_url, json.dumps(link))
    data = result.json()
    md_list = []
    if not isinstance(data, list):
        data = [data]
    for element in data:
        md_obj = {
            'id': demisto.get(element, 'id'),
            'key': demisto.get(element, 'updateAuthor.key'),
            'comment': demisto.get(element, 'body'),
            'ticket_link': demisto.get(element, 'self')
        }
        md_list.append(md_obj)
    human_readable = tableToMarkdown(demisto.command(), md_list, "", removeNull=True)
    contents = data
    return_outputs(readable_output=human_readable, outputs={}, raw_response=contents)


@logger
def delete_issue_command(issue_id_or_key):
    url = 'rest/api/latest/issue/{}'.format(issue_id_or_key)
    issue = get_issue_fields(**demisto.args())
    result = jira_req('DELETE', url, json.dumps(issue))
    if result.status_code == 204:
        demisto.results('Issue deleted successfully.')
    else:
        demisto.results('Failed to delete issue.')


@logger
def test_module():
    """
    Performs basic get request to get item samples
    """
    req_res = jira_req('GET', 'rest/api/latest/myself')
    run_query(demisto.params().get('query'), max_results=1)
    if req_res.ok:
        demisto.results('ok')


@logger
def fetch_incidents(query, id_offset=None, fetch_by_created=None, **kwargs):
    last_run = demisto.getLastRun()
    demisto.debug("last_run: {}".format(last_run) if last_run else 'last_run is empty')
    id_offset = last_run.get("idOffset") if (last_run and last_run.get("idOffset")) else id_offset

    incidents, max_results = [], 50
    if id_offset:
        query += ' AND id >= {idOffset}'.format(idOffset=id_offset)
    if fetch_by_created:
        query += ' and created>-1m'
    res = run_query(query, '', max_results)
    for ticket in res.get('issues'):
        id_offset = max(id_offset, ticket.get("id"))
        incidents.append(create_incident_from_ticket(ticket))

    demisto.setLastRun({"idOffset": id_offset})
    demisto.incidents(incidents)


''' COMMANDS MANAGER / SWITCH PANEL '''
demisto.debug('Command being called is %s' % (demisto.command()))
try:
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module()

    elif demisto.command() == 'fetch-incidents':
        # Set and define the fetch incidents command to run after activated via integration settings.
        fetch_incidents(**snakify(demisto.params()))

    elif demisto.command() == 'jira-get-issue':
        get_issue(**snakify(demisto.args()))

    elif demisto.command() == 'jira-issue-query':
        issue_query_command(**snakify(demisto.args()))

    elif demisto.command() == 'jira-create-issue':
        create_issue_command()

    elif demisto.command() == 'jira-edit-issue':
        edit_issue_command(**snakify(demisto.args()))

    elif demisto.command() == 'jira-get-comments':
        get_comments_command(**snakify(demisto.args()))

    elif demisto.command() == 'jira-issue-add-comment':
        add_comment_command(**snakify(demisto.args()))

    elif demisto.command() == 'jira-issue-upload-file':
        issue_upload_command(**snakify(demisto.args()))

    elif demisto.command() == 'jira-issue-add-link':
        add_link_command(**snakify(demisto.args()))

    elif demisto.command() == 'jira-delete-issue':
        delete_issue_command(**snakify(demisto.args()))

    elif demisto.command() == 'jira-get-id-offset':
        get_id_offset()


except Exception, ex:
    return_error(str(ex))

finally:
    LOG.print_log()

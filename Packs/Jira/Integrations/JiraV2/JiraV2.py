from typing import Union

from requests_oauthlib import OAuth1
from dateparser import parse
from datetime import timedelta
from CommonServerPython import *
# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
BASE_URL = demisto.getParam('url').rstrip('/') + '/'
API_TOKEN = demisto.getParam('APItoken')
USERNAME = demisto.getParam('username')
PASSWORD = demisto.getParam('password')
COMMAND_NOT_IMPELEMENTED_MSG = 'Command not implemented'

HEADERS = {
    'Content-Type': 'application/json',
}
JIRA_INCIDENT_TYPE_NAME = 'Jira Incident'
ISSUE_INCIDENT_FIELDS = {'issueId': 'The ID of the issue to edit',
                         'summary': 'The summary of the issue.',
                         'description': 'The description of the issue.',
                         'labels': 'A CSV list of labels.',
                         'priority': 'A priority name, for example "High" or "Medium".',
                         'dueDate': 'The due date for the issue (in the format 2018-03-11).',
                         'assignee': 'The name of the assignee.',
                         'status': 'The name of the status.',
                         'assignee_id': 'The account ID of the assignee. Use'
                                        ' the jira-get-id-by-attribute command to get the user\'s Account ID.'
                         }
BASIC_AUTH_ERROR_MSG = "For cloud users: As of June 2019, Basic authentication with passwords for Jira is no" \
                       " longer supported, please use an API Token or OAuth 1.0"
JIRA_RESOLVE_REASON = 'Issue was marked as "Done"'
USE_SSL = not demisto.params().get('insecure', False)


def jira_req(
        method: str,
        resource_url: str,
        body: str = '',
        link: bool = False,
        resp_type: str = 'text',
        headers: Optional[dict] = None,
        files: Optional[dict] = None
):
    url = resource_url if link else (BASE_URL + resource_url)
    try:
        result = requests.request(
            method=method,
            url=url,
            data=body,
            headers=headers or HEADERS,
            verify=USE_SSL,
            auth=get_auth(),
            files=files
        )
    except ValueError:
        raise ValueError("Could not deserialize privateKey")

    if not result.ok:
        demisto.debug(result.text)
        try:
            rj = result.json()
            if rj.get('errorMessages'):
                return_error(f'Status code: {result.status_code}\nMessage: {",".join(rj["errorMessages"])}')
            elif rj.get('errors'):
                return_error(f'Status code: {result.status_code}\nMessage: {",".join(rj["errors"].values())}')
            else:
                return_error(f'Status code: {result.status_code}\nError text: {result.text}')
        except ValueError as ve:
            demisto.debug(str(ve))
            if result.status_code == 401:
                return_error('Unauthorized request, please check authentication related parameters.'
                             f'{BASIC_AUTH_ERROR_MSG}')
            elif result.status_code == 404:
                return_error("Could not connect to the Jira server. Verify that the server URL is correct.")
            elif result.status_code == 500 and files:
                return_error(f"Failed to execute request, status code: 500\nBody: {result.text}"
                             f"\nMake sure file name doesn't contain any special characters")
            else:
                return_error(
                    f"Failed reaching the server. status code: {result.status_code}")

    if resp_type == 'json':
        return result.json()
    return result


def generate_oauth1():
    oauth = OAuth1(
        client_key=demisto.getParam('consumerKey'),
        rsa_key=demisto.getParam('privateKey'),
        signature_method='RSA-SHA1',
        resource_owner_key=demisto.getParam('accessToken'),
    )
    return oauth


def generate_basic_oauth():
    return USERNAME, (API_TOKEN or PASSWORD)


def get_auth():
    is_basic = USERNAME and (PASSWORD or API_TOKEN)
    is_oauth1 = demisto.getParam('consumerKey') and demisto.getParam('accessToken') and demisto.getParam('privateKey')

    if is_basic:
        return generate_basic_oauth()

    elif is_oauth1:
        HEADERS.update({'X-Atlassian-Token': 'nocheck'})
        return generate_oauth1()

    return_error(
        'Please provide the required Authorization information:'
        '- Basic Authentication requires user name and password or API token'
        '- OAuth 1.0 requires ConsumerKey, AccessToken and PrivateKey'
    )


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
    demisto.debug(f'querying with: {query}')
    url = BASE_URL + 'rest/api/latest/search/'
    query_params = {
        'jql': query,
        "startAt": start_at,
        "maxResults": max_results,
    }

    try:
        result = requests.get(
            url=url,
            headers=HEADERS,
            verify=USE_SSL,
            params=query_params,
            auth=get_auth(),
        )
    except ValueError:
        raise ValueError("Could not deserialize privateKey")

    try:
        rj = result.json()
        if rj.get('issues'):
            return rj

        errors = ",".join(rj.get("errorMessages", ['could not fetch any issues, please check your query']))
        if 'could not fetch any issues, please check your query' in errors:
            return {}
        raise Exception(f'No issues were found, error message from Jira: {errors}')

    except ValueError as ve:
        demisto.debug(str(ve))
        raise Exception(f'Failed to send request, reason: {result.reason}')


def get_id_offset():
    """
    gets the ID Offset, i.e., the first issue id. used to fetch correctly all issues
    """
    query = "ORDER BY created ASC"
    j_res = run_query(query=query, max_results=1)
    first_issue_id = j_res.get('issues')[0].get('id')
    return_outputs(
        readable_output=f"ID Offset: {first_issue_id}",
        outputs={'Ticket.idOffSet': first_issue_id},
    )


def get_custom_fields():
    """
    This function returns all custom fields.
    :return: dict of custom fields: id as key and description as value.
    """
    custom_id_description_mapping = {}
    HEADERS['Accept'] = "application/json"
    try:
        res = requests.request(
            method='GET',
            url=BASE_URL + 'rest/api/latest/field',
            headers=HEADERS,
            verify=USE_SSL,
            auth=get_auth(),
        )
    except Exception as e:
        demisto.error(f'Could not get custom fields because got the next exception: {e}')
    else:
        if res.status_code == 200:
            custom_fields_list = res.json()
            custom_id_description_mapping = {field.get('id'): field.get('description') for field in custom_fields_list}
        else:
            demisto.error(f'Could not get custom fields. status code: {res.status_code}. reason: {res.reason}')
    finally:
        return custom_id_description_mapping


def expand_urls(data, depth=0):
    if isinstance(data, dict) and depth < 10:
        for key, value in data.items():
            if key in ['_links', 'watchers', 'sla', 'request participants']:
                # dictionary of links
                if isinstance(value, dict):
                    for link_key, link_url in value.items():
                        value[link_key + '_expended'] = json.dumps(
                            jira_req(method='GET', resource_url=link_url, link=True, resp_type='json'))
                # link
                else:
                    data[key + '_expended'] = json.dumps(jira_req(method='GET', resource_url=value,
                                                                  link=True, resp_type='json'))
            # search deeper
            else:
                if isinstance(value, dict):
                    return expand_urls(value, depth + 1)


def search_user(query: str, max_results: str = '50'):
    """
        Search for user by name or email address.
    Args:
        query: A query string that is matched against user attributes ( displayName, and emailAddress) to find relevant users.
        max_results (str): The maximum number of items to return. default by the server: 50

    Returns:
        List of users.
    """
    url = f"rest/api/latest/user/search?query={query}&maxResults={max_results}"
    res = jira_req('GET', url, resp_type='json')
    return res


def get_account_id_from_attribute(attribute: str, max_results: str = '50') -> Union[CommandResults, str]:
    """
    https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-user-search/#api-rest-api-3-user-search-get

    Args:
        attribute (str): Username or Email address of a user.
        max_results (str): The maximum number of items to return. default by the server: 50
    """
    users = search_user(attribute, max_results)
    account_ids = {
        user.get('accountId') for user in users if (attribute.lower() in [user.get('displayName', '').lower(),
                                                                          user.get('emailAddress', '').lower()])}

    if not account_ids:
        return f'No Account ID was found for attribute: {attribute}.'
    if len(account_ids) > 1:
        return f'Multiple account IDs were found for attribute: {attribute}.\n' \
               f'Please try to provide the other attribute available - Email or DisplayName.'

    account_id = next(iter(account_ids))
    outputs = {
        'Attribute': attribute,
        'AccountID': account_id
    }

    return CommandResults(
        outputs_prefix='Jira.User',
        outputs_key_field='AccountID',
        readable_output=f'Account ID for attribute: {attribute} is: {account_id}',
        outputs=outputs,
    )


def generate_md_context_get_issue(data):
    get_issue_obj: dict = {"md": [], "context": []}
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
            context_obj['attachment'] = ','.join(attach.get('filename') for attach in attachments)

        get_issue_obj['md'].append(md_obj)
        get_issue_obj['context'].append(context_obj)

    return get_issue_obj


def generate_md_context_create_issue(data, project_name=None, project_key=None):
    create_issue_obj = {"md": [], "context": {"Ticket": []}}  # type: ignore
    if project_name:
        data["projectName"] = project_name

    if project_key:
        data["projectKey"] = project_key

    elif demisto.getParam('projectKey'):
        data["projectKey"] = demisto.getParam('projectKey')

    create_issue_obj['md'].append(data)  # type: ignore
    create_issue_obj['context']['Ticket'].append(  # type: ignore
        {"Id": demisto.get(data, 'id'), "Key": demisto.get(data, 'key')})  # type: ignore
    return create_issue_obj


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


def get_mirror_type(should_mirror_in, should_mirror_out):
    """
    This function return the type of mirror to perform on a Jira incident.
    NOTE: in order to not mirror an incident, the type should be None.
    :param should_mirror_in: demisto.params().get("incoming_mirror")
    :param should_mirror_out: demisto.params().get('outgoing_mirror')
    :return: The mirror type
    """
    # Adding mirroring details
    mirror_type = None
    if should_mirror_in and should_mirror_out:
        mirror_type = 'Both'
    elif should_mirror_in:
        mirror_type = 'In'
    elif should_mirror_out:
        mirror_type = 'Out'
    return mirror_type


def create_incident_from_ticket(issue, should_get_attachments, should_get_comments, should_mirror_in, should_mirror_out,
                                comment_tag, attachment_tag):
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
        {'type': 'description', 'value': str(demisto.get(issue, 'fields.description'))},

    ]

    name = demisto.get(issue, 'fields.summary')
    if name:
        name = f"Jira issue: {issue.get('id')}"

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

    file_names = []
    if should_get_attachments:
        for file_result in get_entries_for_fetched_incident(issue.get('id'), False, True)['attachments']:
            if file_result['Type'] != entryTypes['error']:
                file_names.append({
                    'path': file_result.get('FileID', ''),
                    'name': file_result.get('File', '')
                })

    if should_get_comments:
        labels.append({'type': 'comments', 'value': str(get_entries_for_fetched_incident(issue.get('id'), True, False)
                                                        ['comments'])})
    else:
        labels.append({'type': 'comments', 'value': '[]'})

    issue['mirror_direction'] = get_mirror_type(should_mirror_in, should_mirror_out)

    issue['mirror_tags'] = [
        comment_tag,
        attachment_tag
    ]
    issue['mirror_instance'] = demisto.integrationInstance()

    return {
        "name": name,
        "labels": labels,
        "details": demisto.get(issue, "fields.description"),
        "severity": severity,
        "attachment": file_names,
        "rawJSON": json.dumps(issue)
    }


def get_project_id(project_key='', project_name=''):
    if not project_key and not project_name:
        return_error('You must provide at least one of the following: project_key or project_name')

    result = jira_req('GET', 'rest/api/latest/issue/createmeta', resp_type='json')

    for project in result.get('projects'):
        if project_key.lower() == project.get('key').lower() or project_name.lower() == project.get('name').lower():
            return project.get('id')
    return_error('Project not found')


def get_issue_fields(issue_creating=False, mirroring=False, **issue_args):
    """
    refactor issues's argument as received from demisto into jira acceptable format, and back.
    :param issue_creating: flag that indicates this function is called when creating an issue
    :param issue_args: issue argument
    """
    issue = {}  # type: dict
    if 'issue_json' in issue_args:
        try:
            issue = json.loads(issue_args['issue_json'])
        except TypeError as te:
            demisto.debug(str(te))
            return_error("issueJson must be in a valid json format")
    elif 'issueJson' in issue_args:
        try:
            issue = json.loads(issue_args['issueJson'])
        except TypeError as te:
            demisto.debug(str(te))
            return_error("issueJson must be in a valid json format")

    if not issue.get('fields'):
        issue['fields'] = {}

    if mirroring:
        for field_name in issue_args:
            if field_name and field_name.startswith('customfield'):
                issue['fields'][field_name] = issue_args[field_name]

    if not issue['fields'].get('issuetype') and issue_creating:
        issue['fields']['issuetype'] = {}

    if issue_args.get('summary'):
        issue['fields']['summary'] = issue_args['summary']

    if not issue['fields'].get('project') and (issue_args.get('projectKey') or issue_args.get('projectName')):
        issue['fields']['project'] = {}

    if issue_args.get('projectKey'):
        issue['fields']['project']['key'] = issue_args.get('projectKey', '')
    if issue_args.get('projectName'):
        issue['fields']['project']['name'] = issue_args.get('projectName', '')

    if issue_creating:
        # make sure the key & name are right, and get the corresponding project id & key
        project_id = get_project_id(issue['fields'].get('project', {}).get('key', ''),
                                    issue['fields'].get('project', {}).get('name', ''))
        issue['fields']['project']['id'] = project_id

    if issue_args.get('issueTypeName'):
        issue['fields']['issuetype']['name'] = issue_args['issueTypeName']

    if issue_args.get('issueTypeId'):
        issue['fields']['issuetype']['id'] = issue_args['issueTypeId']

    if issue_args.get('parentIssueId'):
        if not issue['fields'].get('parent'):
            issue['fields']['parent'] = {}
        issue['fields']['parent']['id'] = issue_args['parentIssueId']

    if issue_args.get('parentIssueKey'):
        if not issue['fields'].get('parent'):
            issue['fields']['parent'] = {}
        issue['fields']['parent']['key'] = issue_args['parentIssueKey']

    if issue_args.get('description'):
        issue['fields']['description'] = issue_args['description']

    if issue_args.get('labels') and isinstance(issue_args.get('labels'), str):
        issue['fields']['labels'] = issue_args['labels'].split(",")

    if issue_args.get('labels') and isinstance(issue_args.get('labels'), list):
        issue['fields']['labels'] = issue_args['labels']

    if issue_args.get('priority'):
        if not issue['fields'].get('priority'):
            issue['fields']['priority'] = {}
        issue['fields']['priority']['name'] = issue_args['priority']

    duedate = issue_args.get('duedate') or issue_args.get('dueDate')
    if duedate:
        issue['fields']['duedate'] = duedate

    if issue_args.get('assignee'):
        if not issue['fields'].get('assignee'):
            issue['fields']['assignee'] = {}
        issue['fields']['assignee']['name'] = issue_args['assignee']

    if issue_args.get('assignee_id'):
        if not issue['fields'].get('assignee'):
            issue['fields']['assignee'] = {}
        issue['fields']['assignee']['accountId'] = issue_args['assignee_id']

    if issue_args.get('reporter_id'):
        if not issue['fields'].get('reporter'):
            issue['fields']['reporter'] = {}
        issue['fields']['reporter']['accountId'] = issue_args['reporter_id']

    if issue_args.get('reporter'):
        if not issue['fields'].get('reporter'):
            issue['fields']['reporter'] = {}
        issue['fields']['reporter']['name'] = issue_args['reporter']

    return issue


def get_issue(issue_id, headers=None, expand_links=False, is_update=False, get_attachments=False):
    j_res = jira_req('GET', f'rest/api/latest/issue/{issue_id}', resp_type='json')
    if expand_links == "true":
        expand_urls(j_res)

    attachments = demisto.get(j_res, 'fields.attachment')  # list of all attachments
    # handle issues were we allowed incorrect values of true
    if get_attachments == "true" or get_attachments == "\"true\"":
        get_attachments = True
    if get_attachments and attachments:
        attachment_urls = [attachment['content'] for attachment in attachments]
        for attachment_url in attachment_urls:
            attachment = f"secure{attachment_url.split('/secure')[-1]}"
            filename = attachment.split("/")[-1]
            attachments_zip = jira_req(method='GET', resource_url=attachment).content
            demisto.results(fileResult(filename=filename, data=attachments_zip))

    md_and_context = generate_md_context_get_issue(j_res)
    human_readable = tableToMarkdown(demisto.command(), md_and_context['md'], argToList(headers))
    if is_update:
        human_readable += f'Issue #{issue_id} was updated successfully'

    contents = j_res
    outputs = {'Ticket(val.Id == obj.Id)': md_and_context['context']}

    return human_readable, outputs, contents


def issue_query_command(query, start_at='', max_results=None, headers=''):
    j_res = run_query(query, start_at, max_results)
    if not j_res:
        outputs = contents = {}
        human_readable = 'No issues matched the query.'
    else:
        issues = demisto.get(j_res, 'issues')
        md_and_context = generate_md_context_get_issue(issues)
        human_readable = tableToMarkdown(demisto.command(), t=md_and_context['md'], headers=argToList(headers))
        contents = j_res
        outputs = {'Ticket(val.Id == obj.Id)': md_and_context['context']}

    return human_readable, outputs, contents


def create_issue_command():
    url = 'rest/api/latest/issue'
    issue = get_issue_fields(issue_creating=True, **demisto.args())
    j_res = jira_req('POST', url, json.dumps(issue), resp_type='json')

    md_and_context = generate_md_context_create_issue(j_res, project_key=demisto.getArg('projectKey'),
                                                      project_name=demisto.getArg('projectName'))
    human_readable = tableToMarkdown(demisto.command(), md_and_context['md'], "")
    contents = j_res
    outputs = md_and_context['context']
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=contents)


def edit_issue_command(issue_id, mirroring=False, headers=None, status=None, transition=None, **kwargs):
    url = f'rest/api/latest/issue/{issue_id}/'
    issue = get_issue_fields(mirroring=mirroring, **kwargs)
    jira_req('PUT', url, json.dumps(issue))
    if status and transition:
        return_error("Please provide only status or transition, but not both.")
    elif status:
        edit_status(issue_id, status)
    elif transition:
        edit_transition(issue_id, transition)

    return get_issue(issue_id, headers, is_update=True)


def edit_status(issue_id, status):
    # check for all authorized transitions available for this user
    # if the requested transition is available, execute it.
    j_res = list_transitions_data_for_issue(issue_id)
    transitions = [transition.get('name') for transition in j_res.get('transitions')]
    for i, transition in enumerate(transitions):
        if transition.lower() == status.lower():
            url = f'rest/api/latest/issue/{issue_id}/transitions?expand=transitions.fields'
            json_body = {"transition": {"id": str(j_res.get('transitions')[i].get('id'))}}
            return jira_req('POST', url, json.dumps(json_body))

    return_error(f'Status "{status}" not found. \nValid transitions are: {transitions} \n')


def list_transitions_data_for_issue(issue_id):
    """
    This function performs the API call for getting a list of all possible transitions for a given issue.
    :param issue_id: The ID of the issue.
    :return: API raw response.
    """
    url = f'rest/api/2/issue/{issue_id}/transitions'
    return jira_req('GET', url, resp_type='json')


def edit_transition(issue_id, transition_name):
    """
    This function changes a transition for a given issue.
    :param issue_id: The ID of the issue.
    :param transition_name: The name of the new transition.
    :return: None
    """
    j_res = list_transitions_data_for_issue(issue_id)
    transitions_data = j_res.get('transitions')
    for transition in transitions_data:
        if transition.get('name') == transition_name:
            url = f'rest/api/latest/issue/{issue_id}/transitions?expand=transitions.fields'
            json_body = {"transition": {"id": transition.get("id")}}
            return jira_req('POST', url, json.dumps(json_body))

    return_error(f'Transitions "{transition_name}" not found. \nValid transitions are: {transitions_data} \n')


def list_transitions_command(args):
    """
    This command list all possible transitions for a given issue.
    :param args: args['issueId']: The ID of the issue.
    :return: CommandResults object with the list of transitions
    """
    issue_id = args.get('issueId')
    transitions_data_list = list_transitions_data_for_issue(issue_id)
    transitions_names = [transition.get('name') for transition in transitions_data_list.get('transitions')]
    readable_output = tableToMarkdown(
        'List Transitions:', transitions_names, headers=['Transition Name']
    )
    outputs = {'ticketId': issue_id,
               'transitions': transitions_names
               }
    return CommandResults(raw_response=transitions_names, readable_output=readable_output,
                          outputs_prefix="Ticket.Transitions", outputs_key_field="ticketId", outputs=outputs)


def get_comments_command(issue_id):
    url = f'rest/api/latest/issue/{issue_id}/comment'
    body = jira_req('GET', url, resp_type='json')
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
        return human_readable, outputs, contents

    else:
        return 'No comments were found in the ticket', None, None


def add_comment(issue_id, comment, visibility=''):
    url = f'rest/api/latest/issue/{issue_id}/comment'
    comment = {
        "body": comment
    }
    if visibility:
        comment["visibility"] = {
            "type": "role",
            "value": visibility
        }
    return jira_req('POST', url, json.dumps(comment), resp_type='json')


def add_comment_command(issue_id, comment, visibility=''):
    data = add_comment(issue_id, comment, visibility)
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


def issue_upload_command(issue_id, upload, attachment_name=None):
    j_res = upload_file(upload, issue_id, attachment_name)
    md = generate_md_upload_issue(j_res, issue_id)
    human_readable = tableToMarkdown(demisto.command(), md, "")
    contents = j_res
    return_outputs(readable_output=human_readable, outputs={}, raw_response=contents)


def upload_file(entry_id, issue_id, attachment_name=None):
    file_name, file_bytes = get_file(entry_id)
    return jira_req(
        method='POST',
        resource_url=f'rest/api/latest/issue/{issue_id}/attachments',
        headers={
            'X-Atlassian-Token': 'no-check'
        },
        files={'file': (attachment_name or file_name, file_bytes)},
        resp_type='json'
    )


def get_file(entry_id):
    get_file_path_res = demisto.getFilePath(entry_id)
    file_path = get_file_path_res["path"]
    file_name = get_file_path_res["name"]
    with open(file_path, 'rb') as f:
        file_bytes = f.read()
    return file_name, file_bytes


def add_link_command(issue_id, title, url, summary=None, global_id=None, relationship=None,
                     application_type=None, application_name=None):
    req_url = f'rest/api/latest/issue/{issue_id}/remotelink'
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
    if application_type or application_name:
        link['application'] = {}
    if application_type:
        link['application']['type'] = application_type
    if application_type:
        link['application']['name'] = application_name

    data = jira_req('POST', req_url, json.dumps(link), resp_type='json')
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

    return_outputs(readable_output=human_readable, outputs={}, raw_response=data)


def delete_issue_command(issue_id_or_key):
    url = f'rest/api/latest/issue/{issue_id_or_key}'
    issue = get_issue_fields(**demisto.args())
    result = jira_req('DELETE', url, json.dumps(issue))
    if result.status_code == 204:
        demisto.results('Issue deleted successfully.')
    else:
        demisto.results('Failed to delete issue.')


def test_module() -> str:
    """
    Performs basic get request to get item samples
    """
    user_data = jira_req('GET', 'rest/api/latest/myself', resp_type='json')
    if demisto.params().get('isFetch'):
        run_query(demisto.getParam('query'), '', max_results=1)

    if not user_data.get('active'):
        raise Exception(f'Test module for Jira failed for the configured parameters.'
                        f'please Validate that the user is active. Response: {str(user_data)}')
    outgoing_mirror = demisto.params().get('outgoing_mirror')
    if outgoing_mirror:
        try:
            custom_fields = get_custom_fields()
            if custom_fields is None:
                return_warning("Test module has finished successfully!."
                               "Please Note: There was a problem getting the list of custom fields for mirror "
                               "outgoing incidents.")
        except Exception as e:
            return_warning("Test module has finished successfully!."
                           f" Please Note: There was a problem getting the list of custom fields for mirror outgoing "
                           f"incidents.\n The error is:{e}.")

    return 'ok'


def get_entries_for_fetched_incident(ticket_id, should_get_comments, should_get_attachments):
    """
    Get entries for incident
    :param ticket_id: the remote system id of the ticket
    :param should_get_comments: if 'True', return ticket's comments
    :param should_get_attachments: if 'True', return ticket's attachments
    :return: incident's entries.
    """
    entries: dict = {'comments': [], 'attachments': []}
    try:
        _, _, raw_response = get_issue(issue_id=ticket_id)
        entries = get_incident_entries(raw_response, '', False, should_get_comments, should_get_attachments)
    except Exception as e:
        demisto.debug(f'could not get attachments for {ticket_id} while fetch this incident because: {str(e)}')
    finally:
        return entries


def fetch_incidents(query, id_offset, should_get_attachments, should_get_comments, should_mirror_in, should_mirror_out,
                    comment_tag, attachment_tag, fetch_by_created=None):
    last_run = demisto.getLastRun()
    demisto.debug(f'last_run: {last_run}' if last_run else 'last_run is empty')
    last_created_time = ''
    if last_run:
        id_offset = last_run.get('idOffset') or ''
        last_created_time = last_run.get('lastCreatedTime') or ''
    if not id_offset:
        id_offset = 0

    incidents, max_results = [], 50
    if fetch_by_created and last_created_time:
        last_issue_time = parse(last_created_time)
        minute_to_fetch = last_issue_time - timedelta(minutes=2)
        formatted_minute_to_fetch = minute_to_fetch.strftime('%Y-%m-%d %H:%M')
        query = f'{query} AND created>=\"{formatted_minute_to_fetch}\"'
    else:
        if id_offset:
            query = f'{query} AND id >= {id_offset}'
        if fetch_by_created:
            query = f'{query} AND created>-1m'

    res = run_query(query, '', max_results)
    if res:
        curr_id = int(id_offset)
        for ticket in res.get('issues'):
            ticket_id = int(ticket.get('id'))
            ticket_created = ticket.get('fields', {}).get('created', '')
            if ticket_id <= curr_id:
                continue
            if ticket_id > int(id_offset):
                id_offset = ticket_id
                last_created_time = ticket_created
            incidents.append(create_incident_from_ticket(ticket, should_get_attachments, should_get_comments,
                                                         should_mirror_in, should_mirror_out, comment_tag,
                                                         attachment_tag))

    demisto.setLastRun({'idOffset': id_offset, 'lastCreatedTime': last_created_time})
    return incidents


def get_attachment_data(attachment):
    """
    Get attachments content
    :param attachment: attachment metadata
    :return: attachment name and content
    """
    attachment_url = f"secure{attachment['content'].split('/secure')[-1]}"
    filename = attachment_url.split("/")[-1]
    attachments_zip = jira_req(method='GET', resource_url=attachment_url).content
    return filename, attachments_zip


def get_attachments(attachments, incident_modified_date, only_new=True):
    """
    Get incident attachments as fileResults objects
    :param attachments: the issue's attachments
    :param incident_modified_date: the date the incident was last updated
    :param only_new: if 'True', getting only attachments that was added after the incident_modified_date
    :return: a list of fileResults
    """
    file_results = []
    # list of all attachments
    if attachments:
        if not only_new:
            for attachment in attachments:
                filename, attachments_zip = get_attachment_data(attachment)
                file_results.append(fileResult(filename=filename, data=attachments_zip))
        else:
            for attachment in attachments:
                attachment_modified_date: datetime = parse(dict_safe_get(attachment, ['created'], "", str))
                if incident_modified_date < attachment_modified_date:
                    filename, attachments_zip = get_attachment_data(attachment)
                    file_results.append(fileResult(filename=filename, data=attachments_zip))
    return file_results


def get_comments(comments, incident_modified_date, only_new=True):
    """
    Get issue's comments
    :param comments: the issue's comments
    :param incident_modified_date: the date the incident was last updated
    :param only_new: if 'True', getting only comments that was added after the incident_modified_date
    :return: a list of comments
    """
    if not only_new:
        return comments
    else:
        returned_comments = []
        for comment in comments:
            comment_modified_date: datetime = parse(dict_safe_get(comment, ['updated'], "", str))
            if incident_modified_date < comment_modified_date:
                returned_comments.append(comment)
        return returned_comments


def get_incident_entries(issue, incident_modified_date, only_new=True, should_get_comments=True,
                         should_get_attachments=True):
    """
    This function get comments and attachments from Jira Ticket, if specified, for a Jira incident.
    :param issue: the incident to get its entries
    :param incident_modified_date: when the incident was last modified
    :param only_new: if 'True' it gets only entries that were added after the incident was last modified
    :param should_get_comments: if 'True', the returned entries will contain comments
    :param should_get_attachments: if 'True' the returned entries will contain attachments
    :return: the incident's comments and attachments
    """
    entries: dict = {'comments': [], 'attachments': []}
    if should_get_comments:
        _, _, comments_content = get_comments_command(issue['id'])
        if comments_content:
            raw_comments_content = comments_content
            commands = get_comments(raw_comments_content.get('comments', []), incident_modified_date, only_new)
            entries['comments'] = commands
    if should_get_attachments:
        attachments = demisto.get(issue, 'fields.attachment')
        if attachments:
            file_results = get_attachments(attachments, incident_modified_date, only_new)
            if file_results:
                entries['attachments'] = file_results
    return entries


def get_mapping_fields_command() -> GetMappingFieldsResponse:
    """
     this command pulls the remote schema for the different incident types, and their associated incident fields,
     from the remote system.
    :return: A list of keys you want to map
    """
    jira_incident_type_scheme = SchemeTypeMapping(type_name=JIRA_INCIDENT_TYPE_NAME)
    custom_fields = get_custom_fields()
    ISSUE_INCIDENT_FIELDS.update(custom_fields)
    for argument, description in ISSUE_INCIDENT_FIELDS.items():
        jira_incident_type_scheme.add_field(name=argument, description=description)

    mapping_response = GetMappingFieldsResponse()
    mapping_response.add_scheme_type(jira_incident_type_scheme)

    return mapping_response


def handle_incoming_closing_incident(incident_data):
    """
    This function creates an object for issues with status 'Done' in order to close its incident when getting remote
     data
    :param incident_data: the data of an incident
    :return: the object using to close the incident in Demito
    """
    closing_entry: dict = {}
    if incident_data.get('fields').get('status').get('name') == 'Done':
        demisto.debug(f"Closing Jira issue {incident_data.get('id')}")
        closing_entry = {
            'Type': EntryType.NOTE,
            'Contents': {
                'dbotIncidentClose': True,
                'closeReason': JIRA_RESOLVE_REASON,
            },
            'ContentsFormat': EntryFormat.JSON
        }
    return closing_entry


def update_remote_system_command(args):
    """ Mirror-out data that is in Demito into Jira issue

    Notes:
        1. Documentation on mirroring - https://xsoar.pan.dev/docs/integrations/mirroring_integration

    Args:
        args: A dictionary contains the next data regarding a modified incident: data, entries, incident_changed,
         remote_incident_id, inc_status, delta

    Returns: The incident id that was modified.
    """
    remote_args = UpdateRemoteSystemArgs(args)
    entries = remote_args.entries
    remote_id = remote_args.remote_incident_id
    demisto.debug(
        f'Update remote system check if need to update: remoteId: {remote_id}, incidentChanged: '
        f'{remote_args.incident_changed}, data:'
        f' {remote_args.data}, entries: {entries}')
    try:
        if remote_args.delta and remote_args.incident_changed:
            demisto.debug(f'Got the following delta keys {str(list(remote_args.delta.keys()))} to update Jira '
                          f'incident {remote_id}')
            edit_issue_command(remote_id, mirroring=True, **remote_args.delta)

        else:
            demisto.debug(f'Skipping updating remote incident fields [{remote_id}] '
                          f'as it is not new nor changed')

        if entries:
            for entry in entries:
                demisto.debug(f'Sending entry {entry.get("id")}, type: {entry.get("type")}')
                if entry.get('type') == 3:
                    demisto.debug('Add new file\n')
                    path_res = demisto.getFilePath(entry.get('id'))
                    file_name = path_res.get('name')
                    upload_file(entry.get('id'), remote_id, file_name)
                else:  # handle comments
                    demisto.debug('Add new comment\n')
                    add_comment(remote_id, str(entry.get('contents', '')))
    except Exception as e:
        demisto.error(f"Error in Jira outgoing mirror for incident {remote_args.remote_incident_id} \n"
                      f"Error message: {str(e)}")
    finally:
        return remote_id


def get_user_info_data():
    """
    This function returns details for a current user in order to get timezone.
    :return: API response
    """
    HEADERS['Accept'] = "application/json"
    return requests.request(method='GET', url=BASE_URL + 'rest/api/latest/myself', headers=HEADERS, verify=USE_SSL,
                            auth=get_auth())


def get_modified_remote_data_command(args):
    """
    available from Cortex XSOAR version 6.1.0. This command queries for incidents that were modified since the last
    update. If the command is implemented in the integration, the get-remote-data command will only be performed on
    incidents returned from this command, rather than on all existing incidents.
    :param args: args['last_update']: Date string represents the last time we retrieved modified incidents for this
     integration.
    :return: GetModifiedRemoteDataResponse: this is the object that maintains a list of incident ids to run
     'get-remote-data' on.
    """
    remote_args = GetModifiedRemoteDataArgs(args)
    modified_issues_ids = []
    HEADERS['Accept'] = "application/json"
    try:
        res = get_user_info_data()
    except Exception as e:
        demisto.error(f'Could not get Jira\'s timezone for get-modified-remote-data. failed because: {e}')
    else:
        if res.status_code == 200:
            timezone_name = res.json().get('timeZone')
            if not timezone_name:
                demisto.error(f'Could not get Jira\'s time zone for get-modified-remote-data.Got unexpected reason:'
                              f' {res.json()}')
            last_update: datetime = parse(remote_args.last_update, settings={'TIMEZONE': timezone_name})\
                .strftime('%Y-%m-%d %H:%M')
            demisto.debug(f'Performing get-modified-remote-data command. Last update is: {last_update}')
            _, _, context = issue_query_command(f'updated > "{last_update}"', max_results=100)
            modified_issues = context.get('issues', [])
            modified_issues_ids = [issue.get('id') for issue in modified_issues if issue.get('id')]
            demisto.debug(f'Performing get-modified-remote-data command. Issue IDs to update in XSOAR:'
                          f' {modified_issues_ids}')
        else:
            demisto.error(f'Could not get Jira\'s time zone for get-modified-remote-data. status code:'
                          f' {res.status_code}.'
                          f' reason: {res.reason}')
    finally:
        return GetModifiedRemoteDataResponse(modified_issues_ids)


def get_remote_data_command(args) -> GetRemoteDataResponse:
    """ Mirror-in data to incident from Jira into XSOAR 'jira issue' incident.

    Notes:
        1. Documentation on mirroring - https://xsoar.pan.dev/docs/integrations/mirroring_integration

    Args:
        args:
            id: Remote incident id.
            lastUpdate: Server last sync time with remote server.

    Returns:
        GetRemoteDataResponse: Structured incident response.
    """
    incident_update = {}
    parsed_entries = []
    parsed_args = GetRemoteDataArgs(args)
    try:
        # Get raw response on issue ID
        _, _, issue_raw_response = get_issue(issue_id=parsed_args.remote_incident_id)
        demisto.info('get remote data')
        # Timestamp - Issue last modified in jira server side
        jira_modified_date: datetime = parse(dict_safe_get(issue_raw_response, ['fields', 'updated'], "", str))
        # Timestamp - Issue last sync in demisto server side
        incident_modified_date: datetime = parse(parsed_args.last_update)
        # Update incident only if issue modified in Jira server-side after the last sync
        demisto.info(f"jira_modified_date{jira_modified_date}")
        demisto.info(f"incident_modified_date{incident_modified_date}")
        if jira_modified_date > incident_modified_date:
            demisto.info('updating remote data')
            incident_update = issue_raw_response

            demisto.info(f"\nUpdate incident:\n\tIncident name: Jira issue {issue_raw_response.get('id')}\n\t"
                         f"Reason: Issue modified in remote.\n\tIncident Last update time: {incident_modified_date}"
                         f"\n\tRemote last updated time: {jira_modified_date}\n")
            demisto.info(f"\n raw incident: {issue_raw_response}\n")

            closed_issue = handle_incoming_closing_incident(incident_update)
            if closed_issue:
                demisto.info(
                    f'Close incident with ID: {parsed_args.remote_incident_id} this issue was marked as "Done"')
                incident_update['in_mirror_error'] = ''
                return GetRemoteDataResponse(incident_update, [closed_issue])

            entries = get_incident_entries(issue_raw_response, incident_modified_date)

            for comment in entries['comments']:
                parsed_entries.append({
                    'Type': EntryType.NOTE,
                    'Contents': comment.get('body', ''),
                    'ContentsFormat': EntryFormat.TEXT,
                    # 'Tags': ['comment'],  # the list of tags to add to the entry
                    'Note': True
                })
            for attachment in entries['attachments']:
                parsed_entries.append(attachment)
        if parsed_entries:
            demisto.info(f'Update the next entries: {parsed_entries}')

        incident_update['in_mirror_error'] = ''
        return GetRemoteDataResponse(incident_update, parsed_entries)

    except Exception as e:
        demisto.info(f"Error in Jira incoming mirror for incident {parsed_args.remote_incident_id} \n"
                     f"Error message: {str(e)}")

        if "Rate limit exceeded" in str(e):
            return_error("API rate limit")

        if incident_update:
            incident_update['in_mirror_error'] = str(e)
        else:
            incident_update = {
                'id': parsed_args.remote_incident_id,
                'in_mirror_error': str(e)
            }
        return GetRemoteDataResponse(
            mirrored_object=incident_update,
            entries=[]
        )


def main():
    demisto.debug(f'Command being called is {demisto.command()}')
    fetch_query = demisto.params().get('query')
    id_offset = demisto.params().get('idOffset')
    fetch_attachments = demisto.params().get('fetch_attachments')
    fetch_comments = demisto.params().get('fetch_comments')
    incoming_mirror = demisto.params().get("incoming_mirror")
    outgoing_mirror = demisto.params().get('outgoing_mirror')
    comment_tag = demisto.params().get('comment_tag')
    attachment_tag = demisto.params().get('file_tag')
    fetch_by_created = demisto.params().get('fetchByCreated')
    try:
        # Remove proxy if not set to true in params
        handle_proxy()

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            demisto.results(test_module())

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            incidents = fetch_incidents(fetch_query, id_offset, fetch_attachments, fetch_comments, incoming_mirror,
                                        outgoing_mirror, comment_tag, attachment_tag, fetch_by_created)
            demisto.incidents(incidents)
        elif demisto.command() == 'jira-get-issue':
            human_readable, outputs, raw_response = get_issue(**snakify(demisto.args()))
            return_outputs(human_readable, outputs, raw_response)

        elif demisto.command() == 'jira-issue-query':
            human_readable, outputs, raw_response = issue_query_command(**snakify(demisto.args()))
            return_outputs(human_readable, outputs, raw_response)

        elif demisto.command() == 'jira-create-issue':
            create_issue_command()

        elif demisto.command() == 'jira-edit-issue':
            human_readable, outputs, raw_response = edit_issue_command(**snakify(demisto.args()))
            return_outputs(human_readable, outputs, raw_response)

        elif demisto.command() == 'jira-get-comments':
            human_readable, outputs, raw_response = get_comments_command(**snakify(demisto.args()))
            return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)

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

        elif demisto.command() == 'get-mapping-fields':
            return_results(get_mapping_fields_command())

        elif demisto.command() == 'update-remote-system':
            return_results(update_remote_system_command(demisto.args()))

        elif demisto.command() == 'get-remote-data':
            return_results(get_remote_data_command(demisto.args()))

        elif demisto.command() == 'jira-get-id-by-attribute':
            return_results(get_account_id_from_attribute(**demisto.args()))

        elif demisto.command() == 'jira-list-transitions':
            return_results(list_transitions_command(demisto.args()))
        elif demisto.command() == 'get-modified-remote-data':
            return_results(get_modified_remote_data_command(demisto.args()))
        else:
            raise NotImplementedError(f'{COMMAND_NOT_IMPELEMENTED_MSG}: {demisto.command()}')

    except Exception as err:
        if isinstance(err, NotImplementedError) and COMMAND_NOT_IMPELEMENTED_MSG in str(err):
            raise
        return_error(str(err))

    finally:
        LOG.print_log()


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()

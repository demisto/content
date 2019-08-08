from distutils.util import strtobool
from typing import Dict

import demistomock as demisto
from CommonServerPython import *
''' IMPORTS '''

import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

USERNAME = demisto.params().get('credentials').get('identifier')
PASSWORD = demisto.params().get('credentials').get('password')
TOKEN = None
# # Remove trailing slash to prevent wrong URL path to service
# SERVER = demisto.params()['url'][:-1] \
#     if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)
# How many time before the first fetch to retrieve incidents
FETCH_TIME = demisto.params().get('fetch_time', '3 days')
# Service base URL
BASE_URL = 'https://api.zerofox.com/1.0' # disable-secrets-detection
# Headers to be sent in requests
HEADERS = None
# Remove proxy if not set to true in params
if not demisto.params().get('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


''' HELPER FUNCTIONS '''


def get_alert_contents(alert):
    return {
        'AlertType': alert.get('alert_type'),
        'OffendingContentURL': alert.get('off'),
        'AssetTermID': alert.get('asset_term', {}).get('id'),
        'AssetTermName': alert.get('asset_term', {}).get('name'),
        'AssetTermDeleted': alert.get('asset_term', {}).get('deleted'),
        'Assignee': alert.get('assignee'),
        'EntityID': alert.get('entity', {}).get('id'),
        'EntityName': alert.get('entity', {}).get('name'),
        'EntityImage': alert.get('entity', {}).get('image'),
        'EntityTermID': alert.get('entity_term', {}).get('id'),
        'EntityTermName': alert.get('entity_term', {}).get('name'),
        'EntityTermDeleted': alert.get('entity_term', {}).get('deleted'),
        'ContentCreatedAt': alert.get('content_created_at'),
        'ID': alert.get('id'),
        'ProtectedAccount': alert.get('protected_account'),
        'Severity': alert.get('severity'),
        'PerpetratorName': alert.get('perpetrator', {}).get('name'),
        'PerpetratorURL': alert.get('perpetrator', {}).get('url'),
        'PerpetratorTimeStamp': alert.get('perpetrator', {}).get('timestamp'),
        'PerpetratorType': alert.get('perpetrator', {}).get('type'),
        'PerpetratorID': alert.get('perpetrator', {}).get('id'),
        'PerpetratorNetwork': alert.get('perpetrator', {}).get('network'),
        'RuleGroupID': alert.get('rule_group_id'),
        'AssetID': alert.get('asset', {}).get('id'),
        'AssetName': alert.get('asset', {}).get('name'),
        'AssetImage': alert.get('asset', {}).get('image'),
        'Status': alert.get('status'),
        'Timestamp': alert.get('timestamp'),
        'RuleName': alert.get('rule_name'),
        'LastModified': alert.get('last_modified'),
        'ProtectedLocations': alert.get('protected_locations'),
        'DarkwebTerm': alert.get('darkweb_Term'),
        'Reviewed': alert.get('reviewed'),
        'Escalated': alert.get('escalated'),
        'Network': alert.get('network'),
        'ProtectedSocialObject': alert.get('protected_social_object'),
        'Notes': alert.get('notes'),
        'RuleID': alert.get('rule_id'),
        'EntityAccount': alert.get('entity_account'),
        'Tags': alert.get('tags'),
        'Notes': alert.get('notes')
    }


def get_alert_contents_war_room(contents):
    return {
        'ID': contents.get('ID'),
        'Protected Entity': contents.get('EntityName').title(),
        'Content Type': contents.get('AlertType').title(),
        'Alert Date': contents.get('Timestamp'),
        'Status': contents.get('Status').title(),
        'Source': contents.get('Network').title(),
        'Rule': contents.get('RuleName'),
        'Severity': contents.get('Severity'),
        'Notes': contents.get('Notes') if contents.get('Notes') != '' else None,
        'Tags': contents.get('Tags')
    }

def clear_integration_context():
    demisto.setIntegrationContext({})
    demisto.info(demisto.getIntegrationContext())


def get_authorization_token():
    # context: Dict = demisto.getIntegrationContext()
    # if context is a dict so it must have a token inside - because token is the first thing added to the context
    # if context.get('auth_token'):
    #     return
    endpoint: str = '/api-token-auth/'
    data_for_request: Dict = {
        'username': USERNAME,
        'password': PASSWORD
    }
    request_response = http_request('POST', endpoint, data=data_for_request)
    global TOKEN, HEADERS
    TOKEN = request_response.get('token')
    HEADERS = {
        'Authorization': f'Token {TOKEN}',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    demisto.setIntegrationContext({'auth_token': TOKEN})


def http_request(method: str, url_suffix: str, params=None, data=None):
    # A wrapper for requests lib to send our requests and handle requests and responses better
    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        data=data,
        headers=HEADERS
    )
    # Handle error responses gracefully
    if res.status_code not in {200, 201}:
        err_msg: str = f'Error in ZeroFox Integration API call [{res.status_code}] - {res.reason}\n'
        try:
            res_json = res.json()
            if 'error' in res_json:
                err_msg += res_json.get('error')
            else:
                err_msg += res_json
        except ValueError:
            pass
        finally:
            return_error(err_msg)
    else:
        try:
            res_json = res.json()
            return res_json
        except ValueError:
            return 'Success Message'


def item_to_incident(item):
    incident = {}
    # Incident Title
    incident['name'] = 'Example Incident: ' + item.get('name')
    # Incident occurrence time, usually item creation date in service
    incident['occurred'] = item.get('createdDate')
    # The raw response from the service, providing full info regarding the item
    incident['rawJSON'] = json.dumps(item)
    return incident


''' COMMANDS + REQUESTS FUNCTIONS '''


def close_alert(alert_id):
    url_suffix: str = f'/alerts/{alert_id}/close/'
    response_content = http_request('POST', url_suffix)
    return response_content


def close_alert_command():
    alert_id: int = demisto.args().get('alert_id')
    close_alert(alert_id)
    return_outputs(f'Alert: {alert_id} has been closed successfully.', outputs={})


def alert_request_takedown(alert_id):
    url_suffix: str = f'/alerts/{alert_id}/request_takedown/'
    response_content = http_request('POST', url_suffix)
    return response_content


def alert_request_takedown_command():
    alert_id: int = demisto.args().get('alert_id')
    alert_request_takedown(alert_id)
    return_outputs(f'Alert: {alert_id} has been taken down successfully.', outputs={})


def alert_user_assignment(alert_id, subject_email, subject_name):
    url_suffix: str = f'/alerts/{alert_id}/assign/'
    request_body: Dict = {
        'subject_email': subject_email,
        'subject': subject_name
    }
    response_content = http_request('POST', url_suffix, data=json.dumps(request_body))
    return response_content


def alert_user_assignment_command():
    alert_id: int = demisto.args().get('alert_id')
    subject_name: str = demisto.args().get('subject_name')
    subject_email: str = demisto.args().get('subject_email')
    alert_user_assignment(alert_id, subject_email, subject_name)
    return_outputs(f'User: {subject_email} has been assigned to Alert: {alert_id} successfully.', outputs={})


def modify_alert_tags(alert_id, addition, tags_list_string):
    url_suffix: str = '/alerttagchangeset/'
    tags_list_name: str = 'added' if addition else 'removed'
    tags_list: list = tags_list_string.split(',')
    request_body: Dict = {
        'changes': [
            {
                f'{tags_list_name}': tags_list,
                'alert': alert_id
            }
        ]
    }
    response_content = http_request('POST', url_suffix, data=json.dumps(request_body))
    return response_content


def modify_alert_tags_command():
    alert_id = demisto.args().get('alert_id')
    addition_string = demisto.args().get('addition')
    addition = True if addition_string == 'true' else False
    tags_list_string = demisto.args().get('tags')
    response_content = modify_alert_tags(alert_id, addition, tags_list_string)
    alert_tags_change_uuid: str = response_content.get('uuid')
    return_outputs('Changes were successfully made.', outputs={})


def get_alert(alert_id):
    url_suffix: str = f'/alerts/{alert_id}/'
    response_content = http_request('GET', url_suffix)
    return response_content


def get_alert_command():
    alert_id = demisto.args().get('alert_id')
    response_content = get_alert(alert_id)
    response_json_fields = response_content.get('alert', {})
    contents = get_alert_contents(response_json_fields)
    contents_war_room = get_alert_contents_war_room(contents)
    context = {'ZeroFox.Alert(val.ID && val.ID === obj.ID)': contents}
    return_outputs(
        tableToMarkdown(f'Alert: {alert_id}', contents_war_room, removeNull=True),
        context,
        response_content
    )


def list_alerts():
    pass


def list_alerts_command():
    pass


def create_entity(name, strict_name_matching=None, image=None, labels=None, policy=None, organization=None):
    url_suffix: str = '/entities/'
    request_body = {
        'name': name,
        'strict_name_matching': strict_name_matching,
        'image': image,
        'labels': labels,
        'policy': policy,
        'organization': organization
    }
    request_body = {key: value for key, value in request_body.items() if value is not None}
    response_content = http_request('POST', url_suffix, data=json.dumps(request_body))
    return response_content


def create_entity_command():
    name = demisto.args().get('name')
    strict_name_matching = demisto.args().get('strict_name_matching')
    image = demisto.args().get('image')
    labels = demisto.args().get('args')
    policy = demisto.args().get('policy')
    organization = demisto.args().get('organization')
    response_content = create_entity(name, strict_name_matching, image, labels, policy, organization)
    entity_id = response_content.get('id')
    return_outputs(
        f'Entity has been created successfully. ID: {entity_id}',
        {'ZeroFox.Entity(val.ID && val.ID === obj.ID)': {'ID': entity_id}},
        response_content
    )


def get_entities():
    pass


def get_entities_command():
    pass



def test_module():
    """
    Performs basic get request to get item samples
    """
    samples = http_request('GET', 'items/samples')


def get_items_command():
    """
    Gets details about a items using IDs or some other filters
    """
    # Init main vars
    headers = []
    contents = []
    context = {}
    context_entries = []
    title = ''
    # Get arguments from user
    item_ids = argToList(demisto.args().get('item_ids', []))
    is_active = bool(strtobool(demisto.args().get('is_active', 'false')))
    limit = int(demisto.args().get('limit', 10))
    # Make request and get raw response
    items = get_items_request(item_ids, is_active)
    # Parse response into context & content entries
    if items:
        if limit:
            items = items[:limit]
        title = 'Example - Getting Items Details'

        for item in items:
            contents.append({
                'ID': item.get('id'),
                'Description': item.get('description'),
                'Name': item.get('name'),
                'Created Date': item.get('createdDate')
            })
            context_entries.append({
                'ID': item.get('id'),
                'Description': item.get('description'),
                'Name': item.get('name'),
                'CreatedDate': item.get('createdDate')
            })

        context['Example.Item(val.ID && val.ID === obj.ID)'] = context_entries

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, contents, removeNull=True),
        'EntryContext': context
    })


def get_items_request(item_ids, is_active):
    # The service endpoint to request from
    endpoint_url = 'items'
    # Dictionary of params for the request
    params = {
        'ids': item_ids,
        'isActive': is_active
    }
    # Send a request using our http_request wrapper
    response = http_request('GET', endpoint_url, params)
    # Check if response contains errors
    if response.get('errors'):
        return_error(response.get('errors'))
    # Check if response contains any data to parse
    if 'data' in response:
        return response.get('data')
    # If neither was found, return back empty results
    return {}


def fetch_incidents():
    last_run = demisto.getLastRun()
    # Get the last fetch time, if exists
    last_fetch = last_run.get('time')

    # Handle first time fetch, fetch incidents retroactively
    if last_fetch is None:
        last_fetch, _ = parse_date_range(FETCH_TIME, to_timestamp=True)

    incidents = []
    items = get_items_request()
    for item in items:
        incident = item_to_incident(item)
        incident_date = date_to_timestamp(incident['occurred'], '%Y-%m-%dT%H:%M:%S.%fZ')
        # Update last run and add incident if the incident is newer than last fetch
        if incident_date > last_fetch:
            last_fetch = incident_date
            incidents.append(incident)

    demisto.setLastRun({'time' : last_fetch})
    demisto.incidents(incidents)


''' COMMANDS MANAGER / SWITCH PANEL '''

''' EXECUTION '''


def main():
    LOG('Command being called is %s' % (demisto.command()))
    try:
        get_authorization_token()
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module()
            demisto.results('ok')
        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            fetch_incidents()
        elif demisto.command() == 'example-get-items':
            # An example command
            get_items_command()
        elif demisto.command() == 'zerofox-get-alert':
            get_alert_command()
        elif demisto.command() == 'zerofox-alert-user-assignment':
            alert_user_assignment_command()
        elif demisto.command() == 'zerofox-close-alert':
            close_alert_command()
        elif demisto.command() == 'zerofox-alert-request-takedown':
            alert_request_takedown_command()
        elif demisto.command() == 'zerofox-modify-alert-tags':
            modify_alert_tags_command()
        elif demisto.command() == 'zerofox-create-entity':
            create_entity_command()

    # Log exceptions
    except Exception as e:
        return_error(str(e))


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()

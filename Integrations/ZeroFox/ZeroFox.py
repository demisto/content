from distutils.util import strtobool
from typing import Dict

import demistomock as demisto
from CommonServerPython import *
''' IMPORTS '''

import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

USERNAME = None
PASSWORD = None
TOKEN = None
# # Remove trailing slash to prevent wrong URL path to service
# SERVER = demisto.params()['url'][:-1] \
#     if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
# Should we use SSL
USE_SSL = None
# How many time before the first fetch to retrieve incidents
# Service base URL
BASE_URL = None
# Headers to be sent in requests
HEADERS = None


''' HELPER FUNCTIONS '''


def remove_none_dict(input_dict):
    return {key: value for key, value in input_dict.items() if value is not None}


def initialize_preset():
    global USERNAME, PASSWORD, USE_SSL, BASE_URL
    USERNAME = demisto.params().get('credentials').get('identifier')
    PASSWORD = demisto.params().get('credentials').get('password')
    USE_SSL = not demisto.params().get('insecure', False)
    BASE_URL = demisto.params()['url'][:-1] if demisto.params()['url'].endswith('/') else demisto.params()['url']
    # Remove proxy if not set to true in params
    handle_proxy()



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
        'Tags': alert.get('tags')
    }


def get_alert_contents_war_room(contents):
    return {
        'ID': contents.get('ID'),
        'Protected Entity': contents.get('EntityName', '').title(),
        'Content Type': contents.get('AlertType', '').title(),
        'Alert Date': contents.get('Timestamp', ''),
        'Status': contents.get('Status', '').title(),
        'Source': contents.get('Network', '').title(),
        'Rule': contents.get('RuleName'),
        'Severity': contents.get('Severity'),
        'Notes': contents.get('Notes') if contents.get('Notes') != '' else None,
        'Tags': contents.get('Tags')
    }


def clear_integration_context():
    demisto.setIntegrationContext({})
    demisto.info(demisto.getIntegrationContext())


def get_authorization_token():
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


''' COMMANDS + REQUESTS FUNCTIONS '''


def close_alert(alert_id):
    url_suffix: str = f'/alerts/{alert_id}/close/'
    response_content = http_request('POST', url_suffix)
    return response_content


def close_alert_command():
    alert_id: int = demisto.args().get('alert_id')
    close_alert(alert_id)
    return_outputs(f'Alert: {alert_id} has been closed successfully.', outputs={})


def open_alert(alert_id):
    url_suffix: str = f'/alerts/{alert_id}/open/'
    response_content = http_request('POST', url_suffix)
    return response_content


def open_alert_command():
    alert_id: int = demisto.args().get('alert_id')
    open_alert(alert_id)
    return_outputs(f'Alert: {alert_id} has been opened successfully.', outputs={})


def alert_request_takedown(alert_id):
    url_suffix: str = f'/alerts/{alert_id}/request_takedown/'
    response_content = http_request('POST', url_suffix)
    return response_content


def alert_request_takedown_command():
    alert_id: int = demisto.args().get('alert_id')
    alert_request_takedown(alert_id)
    return_outputs(f'Alert: {alert_id} has been taken down successfully.', outputs={})


def alert_cancel_takedown(alert_id):
    url_suffix: str = f'/alerts/{alert_id}/cancel_takedown/'
    response_content = http_request('POST', url_suffix)
    return response_content


def alert_cancel_takedown_command():
    alert_id: int = demisto.args().get('alert_id')
    alert_cancel_takedown(alert_id)
    return_outputs(f'Alert: {alert_id} has canceled takedown successfully.', outputs={})


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
    modify_alert_tags(alert_id, addition, tags_list_string)
    return_outputs('Changes were successfully made.', outputs={})


def get_alert(alert_id):
    url_suffix: str = f'/alerts/{alert_id}/'
    response_content = http_request('GET', url_suffix)
    return response_content


def get_alert_command():
    alert_id = demisto.args().get('alert_id')
    response_content = get_alert(alert_id)
    response_json_fields = response_content.get('alert')
    if not isinstance(response_json_fields, dict) or len(response_json_fields) <= 0:
        demisto.results("NO RESULTS FOUND")
    contents = get_alert_contents(response_json_fields)
    contents_war_room = get_alert_contents_war_room(contents)
    context = {'ZeroFox.Alert(val.ID && val.ID === obj.ID)': contents}
    return_outputs(
        tableToMarkdown(f'Alert: {alert_id}', contents_war_room, removeNull=True),
        context,
        response_content
    )


def list_alerts(params):  # not fully implemented
    url_suffix: str = '/alerts/'
    response_content = http_request('GET', url_suffix, params=params)
    return response_content


def list_alerts_command():  # not fully implemented
    params = remove_none_dict(demisto.args())
    response_content = list_alerts(params).get('alerts')
    if not response_content:
        return_outputs('No alerts found.', outputs={})
    else:
        contents = [get_alert_contents(alert) for alert in response_content]
        contents_war_room = [get_alert_contents_war_room(content) for content in contents]
        context = {'ZeroFox.Alert(val.ID && val.ID === obj.ID)': contents}
        return_outputs(
            tableToMarkdown('Alerts', contents_war_room, removeNull=True),
            context,
            response_content
    )


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
    request_body = remove_none_dict(request_body)
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


''' COMMANDS MANAGER / SWITCH PANEL '''

''' EXECUTION '''


def main():
    LOG('Command being called is %s' % (demisto.command()))
    try:
        if USERNAME is None or PASSWORD is None or BASE_URL is None or USE_SSL is None:
            initialize_preset()
        if TOKEN is None:
            get_authorization_token()
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module()
            demisto.results('ok')
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
        elif demisto.command() == 'zerofox-list-alerts':
            list_alerts_command()
        elif demisto.command() == 'zerofox-open-alert':
            open_alert_command()
        elif demisto.command() == 'zerofox-alert-cancel-takedown':
            alert_cancel_takedown_command()

    # Log exceptions
    except Exception as e:
        return_error(str(e))


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import requests
from typing import Dict, List, Any, cast
from datetime import datetime, timedelta
# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

USERNAME: str = demisto.params().get('credentials').get('identifier')
PASSWORD: str = demisto.params().get('credentials').get('password')
USE_SSL: str = not demisto.params().get('insecure', False)
BASE_URL: str = demisto.params()['url'][:-1] if demisto.params()['url'].endswith('/') else demisto.params()['url']
FETCH_TIME_DEFAULT = '3 days'
FETCH_TIME: str = demisto.params().get('fetch_time', FETCH_TIME_DEFAULT)
# Remove proxy if not set to true in params
handle_proxy()

''' HELPER FUNCTIONS '''


# transforms severity number to string representation
def severity_num_to_string(severity_num: int):
    if severity_num == 1:
        return 'Info'
    elif severity_num == 2:
        return 'Low'
    elif severity_num == 3:
        return 'Medium'
    elif severity_num == 4:
        return 'High'
    elif severity_num == 5:
        return 'Critical'


# transforms an alert to incident convention
def alert_to_incident(alert: Dict):
    incident: Dict = {
        'rawJSON': json.dumps(alert),
        'name': 'ZeroFox Alert ' + str(alert.get('id')),  # not sure if it's the right name
        'occurred': alert.get('timestamp')  # not sure if it's the right field
    }
    return incident


# return updated contents of an alert
def get_updated_contents(alert_id: int):
    response_content: Dict = get_alert(alert_id)
    if not response_content or not isinstance(response_content, Dict):
        return {}
    alert: Dict = response_content.get('alert')
    if not alert or not isinstance(alert, Dict):
        return {}
    contents: Dict = get_alert_contents(alert)
    return contents


# removes all none values from a dict
def remove_none_dict(input_dict: Dict):
    return {key: value for key, value in input_dict.items() if value is not None}


def get_alert_contents(alert: Dict):
    return {
        'AlertType': alert.get('alert_type'),
        'OffendingContentURL': alert.get('offending_content_url'),
        'AssetTermID': alert.get('asset_term').get('id') if alert.get('asset_term') else None,
        'AssetTermName': alert.get('asset_term').get('name') if alert.get('asset_term') else None,
        'AssetTermDeleted': alert.get('asset_term').get('deleted') if alert.get('asset_term') else None,
        'Assignee': alert.get('assignee'),
        'EntityID': alert.get('entity').get('id') if alert.get('entity') else None,
        'EntityName': alert.get('entity').get('name') if alert.get('entity') else None,
        'EntityImage': alert.get('entity').get('image') if alert.get('entity') else None,
        'EntityTermID': alert.get('entity_term').get('id') if alert.get('entity_term') else None,
        'EntityTermName': alert.get('entity_term').get('name') if alert.get('entity_term') else None,
        'EntityTermDeleted': alert.get('entity_term').get('deleted') if alert.get('entity_term') else None,
        'ContentCreatedAt': alert.get('content_created_at'),
        'ID': alert.get('id'),
        'ProtectedAccount': alert.get('protected_account'),
        'RiskRating': severity_num_to_string(alert.get('severity')),
        'PerpetratorName': alert.get('perpetrator').get('name') if alert.get('perpetrator') else None,
        'PerpetratorURL': alert.get('perpetrator').get('url') if alert.get('perpetrator') else None,
        'PerpetratorTimeStamp': alert.get('perpetrator').get('timestamp') if alert.get('perpetrator') else None,
        'PerpetratorType': alert.get('perpetrator').get('type') if alert.get('perpetrator') else None,
        'PerpetratorID': alert.get('perpetrator').get('id') if alert.get('perpetrator') else None,
        'PerpetratorNetwork': alert.get('perpetrator').get('network') if alert.get('perpetrator') else None,
        'RuleGroupID': alert.get('rule_group_id'),
        'AssetID': alert.get('asset').get('id') if alert.get('asset') else None,
        'AssetName': alert.get('asset').get('name') if alert.get('asset') else None,
        'AssetImage': alert.get('asset').get('image') if alert.get('asset') else None,
        'Status': alert.get('status'),
        'Timestamp': alert.get('timestamp'),
        'RuleName': alert.get('rule_name'),
        'LastModified': alert.get('last_modified'),
        'ProtectedLocations': alert.get('protected_locations'),
        'DarkwebTerm': alert.get('darkweb_term'),
        'Reviewed': alert.get('reviewed'),
        'Escalated': alert.get('escalated'),
        'Network': alert.get('network'),
        'ProtectedSocialObject': alert.get('protected_social_object'),
        'Notes': alert.get('notes'),
        'RuleID': alert.get('rule_id'),
        'EntityAccount': alert.get('entity_account'),
        'Tags': alert.get('tags')
    }


# returns the convention for the war room
def get_alert_contents_war_room(contents: Dict):
    return {
        'ID': contents.get('ID'),
        'Protected Entity': contents.get('EntityName', '').title(),
        'Content Type': contents.get('AlertType', '').title(),
        'Alert Date': contents.get('Timestamp', ''),
        'Status': contents.get('Status', '').title(),
        'Source': contents.get('Network', '').title(),
        'Rule': contents.get('RuleName'),
        'Risk Rating': contents.get('RiskRating'),
        'Notes': contents.get('Notes') if contents.get('Notes') else None,
        'Tags': contents.get('Tags')
    }


def get_entity_contents(entity: Dict):
    return {
        'ID': entity.get('id'),
        'Name': entity.get('name'),
        'EmailAddress': entity.get('email_address'),
        'Organization': entity.get('organization'),
        'Labels': entity.get('labels'),
        'StrictNameMatching': entity.get('strict_name_matching'),
        'PolicyID': entity.get('policy_id'),
        'Profile': entity.get('profile'),
        'EntityGroupID': entity.get('entity_group').get('id') if entity.get('entity_group') else None,
        'EntityGroupName': entity.get('entity_group').get('name') if entity.get('entity_group') else None,
        'TypeID': entity.get('type').get('id') if entity.get('type') else None,
        'TypeName': entity.get('type').get('name') if entity.get('type') else None
    }


def get_entity_contents_war_room(contents: Dict):
    return {
        'Name': contents.get('Name'),
        'Type': contents.get('Type'),
        'Policy': contents.get('Policy'),
        'Email': contents.get('EmailAddress'),
        'Tags': contents.get('Labels'),
        'ID': contents.get('ID')
    }


def get_authorization_token():
    integration_context: Dict = demisto.getIntegrationContext()
    token: str = integration_context.get('token')
    if token:
        return token
    url_suffix: str = '/api-token-auth/'
    data_for_request: Dict = {
        'username': USERNAME,
        'password': PASSWORD
    }
    response_content: Dict = http_request('POST', url_suffix, data=data_for_request, continue_err=True,
                                          regular_request=False)
    if not response_content or not isinstance(response_content, Dict):
        raise Exception('Unexpected outputs from API call.')
    token: str = response_content.get('token')
    if not token:
        x: List = response_content.get('non_field_errors')
        if not x or not isinstance(x, List):
            raise Exception('Unexpected outputs from API call.')
        else:
            raise Exception(x[0])
    demisto.setIntegrationContext({'token': token})
    return token


def http_request(method: str, url_suffix: str, params: Dict = None, data: Dict = None, continue_err: bool = False,
                 regular_request: bool = True):
    # A wrapper for requests lib to send our requests and handle requests and responses better
    headers: Dict = {}
    try:
        if regular_request:
            token: str = get_authorization_token()
            headers: Dict = {
                'Authorization': f'Token {token}',
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        res = requests.request(
            method,
            BASE_URL + url_suffix,
            verify=USE_SSL,
            params=params,
            data=data,
            headers=headers
        )
        # Handle error responses gracefully
        if res.status_code not in {200, 201} and not continue_err:
            err_msg: str = f'Error in ZeroFox Integration API call [{res.status_code}] - {res.reason}\n'
            try:
                res_json = res.json()
                if 'error' in res_json:
                    err_msg += res_json.get('error')
            except ValueError:
                err_msg += res.content
            finally:
                raise ValueError(err_msg)
        else:
            try:
                return res.json()
            except ValueError:
                return res.content
    except requests.exceptions.ConnectTimeout:
        err_msg: str = 'Connection Timeout Error - potential reasons may be that the Server URL parameter' \
                  ' is incorrect or that the Server is not accessible from your host.'
        raise Exception(err_msg)
    except requests.exceptions.SSLError:
        err_msg: str = 'SSL Certificate Verification Failed - try selecting \'Trust any certificate\' in' \
                  ' the integration configuration.'
        raise Exception(err_msg)
    except requests.exceptions.ProxyError:
        err_msg: str = 'Proxy Error - if \'Use system proxy\' in the integration configuration has been' \
                  ' selected, try deselecting it.'
        raise Exception(err_msg)
    except requests.exceptions.ConnectionError as e:
        # Get originating Exception in Exception chain
        while '__context__' in dir(e) and e.__context__:
            e = cast(Any, e.__context__)
        error_class: str = str(e.__class__)
        err_type: str = '<' + error_class[error_class.find('\'') + 1: error_class.rfind('\'')] + '>'
        err_msg: str = f'\nERRTYPE: {err_type}\nERRNO: [{e.errno}]\nMESSAGE: {e.strerror}\n' \
                  f'ADVICE: Check that the Server URL parameter is correct and that you' \
                  f' have access to the Server from your host.'
        return_error(err_msg)


''' COMMANDS + REQUESTS FUNCTIONS '''


def close_alert(alert_id: int):
    url_suffix: str = f'/alerts/{alert_id}/close/'
    response_content: Dict = http_request('POST', url_suffix)
    return response_content


def close_alert_command():
    alert_id: int = int(demisto.args().get('alert_id'))
    close_alert(alert_id)
    contents: Dict = get_updated_contents(alert_id)
    context: Dict = {'ZeroFox.Alert(val.ID && val.ID === obj.ID)': {'ID': alert_id, 'Status': 'Closed'}}
    return_outputs(
        f'Alert: {alert_id} has been closed successfully.',
        context,
        raw_response=contents
    )


def open_alert(alert_id: int):
    url_suffix: str = f'/alerts/{alert_id}/open/'
    response_content: Dict = http_request('POST', url_suffix)
    return response_content


def open_alert_command():
    alert_id: int = int(demisto.args().get('alert_id'))
    open_alert(alert_id)
    contents: Dict = get_updated_contents(alert_id)
    context: Dict = {'ZeroFox.Alert(val.ID && val.ID === obj.ID)': {'ID': alert_id, 'Status': 'Open'}}
    return_outputs(
        f'Alert: {alert_id} has been opened successfully.',
        context,
        raw_response=contents
    )


def alert_request_takedown(alert_id: int):
    url_suffix: str = f'/alerts/{alert_id}/request_takedown/'
    response_content: Dict = http_request('POST', url_suffix)
    return response_content


def alert_request_takedown_command():
    alert_id: int = int(demisto.args().get('alert_id'))
    alert_request_takedown(alert_id)
    contents: Dict = get_updated_contents(alert_id)
    context: Dict = {'ZeroFox.Alert(val.ID && val.ID === obj.ID)': {'ID': alert_id, 'Status': 'Takedown:Requested'}}
    return_outputs(
        f'Alert: {alert_id} has been requested to be taken down successfully.',
        context,
        raw_response=contents
    )


def alert_cancel_takedown(alert_id: int):
    url_suffix: str = f'/alerts/{alert_id}/cancel_takedown/'
    response_content: Dict = http_request('POST', url_suffix)
    return response_content


def alert_cancel_takedown_command():
    alert_id: int = int(demisto.args().get('alert_id'))
    alert_cancel_takedown(alert_id)
    contents: Dict = get_updated_contents(alert_id)
    context: Dict = {'ZeroFox.Alert(val.ID && val.ID === obj.ID)': {'ID': alert_id, 'Status': 'Open'}}
    return_outputs(
        f'Alert: {alert_id} has canceled takedown successfully.',
        context,
        raw_response=contents
    )


def alert_user_assignment(alert_id: int, username: str):
    url_suffix: str = f'/alerts/{alert_id}/assign/'
    request_body: Dict = {
        'subject': username
    }
    response_content: Dict = http_request('POST', url_suffix, data=json.dumps(request_body))
    return response_content


def alert_user_assignment_command():
    alert_id: int = int(demisto.args().get('alert_id'))
    username: str = demisto.args().get('username')
    alert_user_assignment(alert_id, username)
    contents: Dict = get_updated_contents(alert_id)
    context: Dict = {'ZeroFox.Alert(val.ID && val.ID === obj.ID)': {'ID': alert_id, 'Assignee': username}}
    return_outputs(
        f'{username} has been assigned to alert {alert_id} successfully.',
        context,
        raw_response=contents
    )


def modify_alert_tags(alert_id: int, action: str, tags_list_string: str):
    url_suffix: str = '/alerttagchangeset/'
    tags_list: list = argToList(tags_list_string, separator=',')
    request_body: Dict = {
        'changes': [
            {
                f'{action}': tags_list,
                'alert': alert_id
            }
        ]
    }
    response_content: Dict = http_request('POST', url_suffix, data=json.dumps(request_body))
    return response_content


def modify_alert_tags_command():
    alert_id: int = int(demisto.args().get('alert_id'))
    action_string: str = demisto.args().get('action')
    action: str = 'added' if action_string == 'add' else 'removed'
    tags_list_string: str = demisto.args().get('tags')
    response_content: Dict = modify_alert_tags(alert_id, action, tags_list_string)
    if not response_content or not isinstance(response_content, Dict):
        raise Exception('Unexpected outputs from API call.')
    if not response_content.get('changes'):
        raise Exception(f'Alert with ID `{alert_id}` does not exist')
    contents: Dict = get_updated_contents(alert_id)
    context: Dict = {'ZeroFox.Alert(val.ID && val.ID === obj.ID)': contents}
    return_outputs(
        'Tags were modified successfully.',
        context,
        raw_response=contents
    )


def get_alert(alert_id: int):
    url_suffix: str = f'/alerts/{alert_id}/'
    response_content: Dict = http_request('GET', url_suffix, continue_err=True)
    return response_content


def get_alert_command():
    alert_id: int = int(demisto.args().get('alert_id'))
    response_content: Dict = get_alert(alert_id)
    if not response_content or not isinstance(response_content, Dict):
        raise Exception('Unexpected outputs from API call.')
    alert: Dict = response_content.get('alert')
    if not alert or not isinstance(alert, Dict):
        raise Exception(f'Alert with ID `{alert_id}` does not exist')
    contents: Dict = get_alert_contents(alert)
    contents_war_room: Dict = get_alert_contents_war_room(contents)
    context: Dict = {'ZeroFox.Alert(val.ID && val.ID === obj.ID)': contents}
    return_outputs(
        tableToMarkdown(f'ZeroFox Alert {alert_id}', contents_war_room, removeNull=True),
        context,
        response_content
    )


def create_entity(name: str, strict_name_matching: bool = None, image: str = None, labels: list = None,
                  policy: int = None, organization: str = None):
    url_suffix: str = '/entities/'
    request_body: Dict = {
        'name': name,
        'strict_name_matching': strict_name_matching,
        'image': image,
        'labels': labels,
        'policy': policy,
        'organization': organization
    }
    request_body: Dict = remove_none_dict(request_body)
    response_content: Dict = http_request('POST', url_suffix, data=json.dumps(request_body))
    return response_content


def create_entity_command():
    name: str = demisto.args().get('name')
    strict_name_matching: bool = bool(demisto.args().get('strict_name_matching'))
    image: str = demisto.args().get('image')
    labels: str = demisto.args().get('args')
    labels: List = argToList(labels, ',')
    policy: int = int(demisto.args().get('policy'))
    organization: str = demisto.args().get('organization')
    response_content: Dict = create_entity(name, strict_name_matching, image, labels, policy, organization)
    if not response_content or not isinstance(response_content, Dict):
        raise Exception('Unexpected outputs from API call.')
    entity_id: int = response_content.get('id')
    return_outputs(
        f'Entity has been created successfully. ID: {entity_id}',
        {'ZeroFox.Entity(val.ID && val.ID === obj.ID)': {'ID': entity_id}},
        response_content
    )


def list_alerts(params: Dict):  # not fully implemented
    url_suffix: str = '/alerts/'
    response_content: Dict = http_request('GET', url_suffix, params=params)
    return response_content


def list_alerts_command():  # not fully implemented
    params: Dict = remove_none_dict(demisto.args())
    response_content: Dict = list_alerts(params)
    if not response_content:
        return_outputs('No alerts found.', outputs={})
    elif isinstance(response_content, Dict):
        alerts: List = response_content.get('alerts')
        contents: Dict = [get_alert_contents(alert) for alert in alerts]
        contents_war_room: Dict = [get_alert_contents_war_room(content) for content in contents]
        context: Dict = {'ZeroFox.Alert(val.ID && val.ID === obj.ID)': contents}
        return_outputs(
            tableToMarkdown('ZeroFox Alerts', contents_war_room, removeNull=True),
            context,
            response_content
        )
    else:
        return_outputs('Unexpected outputs from API call.', outputs={})


def list_entities(params: Dict):
    url_suffix: str = '/entities/'
    response_content: Dict = http_request('GET', url_suffix, params=params)
    return response_content


def list_entities_command():
    params: Dict = remove_none_dict(demisto.args())
    response_content: Dict = list_entities(params)
    if not response_content:
        return_outputs('No entities found.', outputs={})
    elif isinstance(response_content, Dict):
        entities: List = response_content.get('entities')
        contents: Dict = [get_entity_contents(entity) for entity in entities]
        contents_war_room: Dict = [get_entity_contents_war_room(content) for content in contents]
        context: Dict = {'ZeroFox.Entity(val.ID && val.ID === obj.ID)': contents}
        return_outputs(
            tableToMarkdown('ZeroFox Entities', contents_war_room, removeNull=True),
            context,
            response_content
        )
    else:
        raise Exception('Unexpected outputs from API call.')


# REMEMBER TO DELETE
def fetch_incidents_command():
    return_outputs('fetch 1', outputs={})
    fetch_incidents()
    return_outputs('fetch 2', outputs={})
    fetch_incidents()


def fetch_incidents():
    date_format = '%Y-%m-%dT%H:%M:%S'
    last_run = demisto.getLastRun()
    if last_run and last_run.get('last_fetched_event_timestamp'):
        last_update_time = last_run['last_fetched_event_timestamp']
    else:
        last_update_time = parse_date_range(FETCH_TIME, date_format=date_format)[0]
    incidents = []
    limit = demisto.params().get('fetch_limit')
    response_content = list_alerts({'sort_direction': 'asc', 'limit': limit, 'min_timestamp': last_update_time})
    alerts = response_content.get('alerts')
    if not alerts:
        return
    for alert in alerts:
        alert_id = alert.get('id')
        ts = alert.get('timestamp')
        # REMEMBER TO DELETE
        return_outputs(f'Alert: {alert_id}, TS: {ts}', outputs={})
        incident = alert_to_incident(alert)
        incidents.append(incident)
    # max_update_time is the timestamp of the last alert in alerts (alerts is a sorted list)
    last_alert_timestamp = str(alerts[len(alerts) - 1].get('timestamp'))
    if '+' in last_alert_timestamp:
        max_update_time = last_alert_timestamp.split('+')[0]
    else:
        max_update_time = last_alert_timestamp.split('-')[0]
    # add 1 second to last alert timestamp, in order to prevent duplicated alerts
    max_update_time = (datetime.strptime(max_update_time, date_format) + timedelta(0, 1)).isoformat()
    demisto.setLastRun({'last_fetched_event_timestamp': max_update_time})  # check whether max_update_time is a string?
    demisto.incidents(incidents)


def test_module():
    """
    Performs basic get request to get item samples
    """
    get_authorization_token()


''' COMMANDS MANAGER / SWITCH PANEL '''

''' EXECUTION '''


def main():
    LOG('Command being called is %s' % (demisto.command()))
    try:
        if demisto.command() == 'test-module':
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
        elif demisto.command() == 'zerofox-list-entities':
            list_entities_command()
        elif demisto.command() == 'fetch-incidents':
            fetch_incidents()
        elif demisto.command() == 'zerofox-fetch-incidents':
            fetch_incidents_command()

    # Log exceptions
    except Exception as e:
        error_msg: str = str(e)
        if demisto.command() == 'fetch-incidents':
            LOG(error_msg)
            LOG.print_log()
            raise
        else:
            return_error(error_msg)


if __name__ == 'builtins':
    main()

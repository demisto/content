from json import JSONDecodeError

import demistomock as demisto
from CommonServerPython import *

import traceback
import json
import requests

# disable unsecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS '''
INPUT_SCIM_EXTENSION_KEY = "urn:scim:schemas:extension:custom:1.0:user"
SLACK_SCIM_EXTENSION_KEY = "urn:scim:schemas:extension:enterprise:1.0"
SLACK_SCIM_CORE_SCHEMA_KEY = "urn:scim:schemas:core:1.0"
base_url = 'https://api.slack.com/scim/v1/'


'''CLIENT CLASS'''


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """
    def __init__(self, base_url, verify=True, proxy=False, headers=None):
        self.base_url = base_url
        self.verify = verify
        self.headers = headers

    def http_request(self, method, url_suffix, params=None, data=None, headers=None):
        if headers is None:
            headers = self.headers
        full_url = self.base_url + url_suffix
        res = requests.request(
            method,
            full_url,
            verify=self.verify,
            headers=headers,
            params=params,
            json=data
        )

        return res

    def get_user(self, user_id):
        user = None
        uri = f'/Users/{user_id}'
        res = self.http_request(
            method='GET',
            url_suffix=uri
        )
        if res.status_code == 200:
            user = res.json()

        return res, res.status_code, user

    def search_user(self, search_filter):
        user = None
        status_code = None

        uri = '/Users'
        params = {'filter': search_filter}
        res = self.http_request(
            method='GET',
            url_suffix=uri,
            params=params
        )
        if res.status_code == 200:
            response_json = res.json()
            totalResults = response_json.get('totalResults')
            if totalResults == 0:
                status_code = 404
            else:
                status_code = res.status_code
                user = response_json['Resources'][0]
        return res, status_code, user

    def create_user(self, data):
        uri = '/Users'
        return self.http_request(
            method='POST',
            url_suffix=uri,
            data=data)

    def update_user(self, user_id, data):
        uri = f'/Users/{user_id}'
        return self.http_request(
            method='PATCH',
            url_suffix=uri,
            data=data
        )

    def get_group_by_id(self, group_id):
        uri = f'/Groups/{group_id}'
        return self.http_request(
            method="GET",
            url_suffix=uri
        )

        # Getting Group Id with a given group name

    def get_group_id(self, group_name):
        uri = '/Groups'
        query_params = {
            'filter': f'displayName eq "{group_name}"'
        }
        res = self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params
        )
        res_json = res.json()

        if res.status_code != 200:
            raise Exception(f"Error in API call. Status Code: [{res.status_code}]. Error Response: {res_json}")
        elif res_json and res_json.get('totalResults') < 1:
            raise Exception(f'Group "{group_name}" Not Found')

        id = res_json['Resources'][0].get('id')

        return id

    def create_group(self, data):
        uri = '/Groups'
        return self.http_request(
            method="POST",
            url_suffix=uri,
            data=data
        )

    def update_group(self, group_id, data):
        uri = f'/Groups/{group_id}'
        return self.http_request(
            method="PATCH",
            url_suffix=uri,
            data=data
        )

    def replace_group(self, group_id, data):
        uri = f'/Groups/{group_id}'
        return self.http_request(
            method="PUT",
            url_suffix=uri,
            data=data
        )

    def delete_group(self, group_id):
        uri = f'/Groups/{group_id}'
        return self.http_request(
            method="DELETE",
            url_suffix=uri
        )

    def build_slack_user_profile(self, args, scim, custom_mapping):
        if args.get('customMapping'):
            custom_mapping = json.loads(args.get('customMapping'))
        elif custom_mapping:
            custom_mapping = json.loads(custom_mapping)

        extension_schema = scim.get(INPUT_SCIM_EXTENSION_KEY, {})

        if extension_schema:
            if custom_mapping:
                new_extension_schema = {}
                for key, value in custom_mapping.items():
                    # key is the attribute name in input scim. value is the attribute name of slack profile
                    try:
                        new_extension_schema[value] = extension_schema.get(key)
                    except Exception:
                        pass
                scim[SLACK_SCIM_EXTENSION_KEY] = new_extension_schema
            else:
                scim[SLACK_SCIM_EXTENSION_KEY] = extension_schema

        return scim


class OutputContext:
    """
        Class to build a generic output and context.
    """
    def __init__(self, success=None, active=None, iden=None, username=None, email=None, errorCode=None,
                 errorMessage=None, details=None):
        self.instanceName = demisto.callingContext['context']['IntegrationInstance']
        self.brand = demisto.callingContext['context']['IntegrationBrand']
        self.command = demisto.command().replace('-', '_').title().replace('_', '')
        self.success = success
        self.active = active
        self.iden = iden
        self.username = username
        self.email = email
        self.errorCode = errorCode
        self.errorMessage = errorMessage
        self.details = details
        self.data = {
            "brand": self.brand,
            "instanceName": self.instanceName,
            "success": success,
            "active": active,
            "id": iden,
            "username": username,
            "email": email,
            "errorCode": errorCode,
            "errorMessage": errorMessage,
            "details": details
        }


''' HELPER FUNCTIONS '''


def map_scim(client_data):
    try:
        client_data = json.loads(client_data)
    except Exception:
        pass
    if type(client_data) != dict:
        raise Exception('Provided client data is not JSON compatible')

    mapping = {
        "active": "active",
        "email": "emails(val.primary && val.primary==true).[0].value",
        "id": "id",
        "nameFamilyName": "name.familyName",
        "nameGivenName": "name.givenName",
        "userName": "userName",
        "userType": "userType"
    }
    ret = dict()
    for k, v in mapping.items():
        try:
            ret[k] = demisto.dt(client_data, v)
        except Exception:
            ret[k] = None
    return ret


def verify_and_load_scim_data(scim):
    try:
        scim = json.loads(scim)
    except Exception:
        pass
    if type(scim) != dict:
        raise Exception('SCIM data is not a valid JSON')
    return scim


def get_primary(arr, val):
    value = None
    for x in arr:
        try:
            if x.get('primary', None):
                value = x[val]
                break
        except Exception:
            pass
        if not value:
            try:
                value = arr[0][val]
            except Exception:
                value = ""
        return value


'''COMMAND FUNCTIONS'''


def test_module(client, args):
    """
    Attempts to get a user to verify authentication
    """
    uri = '/Users?count=1'
    res = client.http_request(
        method='GET',
        url_suffix=uri
    )
    if res.status_code == 200:
        return 'ok', None, None
    else:
        return_error(f'Failed: Error Code: {res.status_code}. Error Response: {res.json()}')


def get_user_command(client, args):
    scim = verify_and_load_scim_data(args.get('scim'))
    scim_flat_data = map_scim(scim)
    user_id = scim_flat_data.get('id')
    username = scim_flat_data.get('userName')
    email = scim_flat_data.get('email')

    if not (user_id or username or email):
        return_error('You must provide either id, username or email of the user')
    elif user_id:
        res, status_code, user = client.get_user(user_id)
    elif username:
        search_filter = "{} eq {}".format("username", username)
        res, status_code, user = client.search_user(search_filter)
    elif email:
        search_filter = "{} eq {}".format("email", email)
        res, status_code, user = client.search_user(search_filter)
    else:
        return

    if status_code == 200:
        email = get_primary(user.get('emails', []), 'value') if len(user.get('emails', [])) > 0 else ""
        generic_iam_context = OutputContext(success=True, iden=user.get('id'), email=email,
                                            username=user.get('userName'), details=user, active=user.get('active'))
    elif status_code == 404:
        generic_iam_context = OutputContext(success=False, iden=user_id, username=username, email=email, errorCode=404,
                                            errorMessage="User not found")
    else:
        error_payload = res.json()
        generic_iam_context = OutputContext(success=False, username=username, email=email,
                                            errorCode=error_payload['Errors']['code'],
                                            errorMessage=error_payload['Errors']['description'])

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(name='Get Slack User:',
                                      t=generic_iam_context.data,
                                      headers=["brand", "instanceName", "success", "active", "id", "username", "email",
                                               "errorCode", "errorMessage", "details"],
                                      removeNull=True)
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def create_user_command(client, args):
    scim = verify_and_load_scim_data(args.get('scim'))
    scim_flat_data = map_scim(scim)
    email = scim_flat_data['email']
    username = scim_flat_data['userName']

    custom_mapping = demisto.params().get('customMappingCreateUser')
    slack_scim = client.build_slack_user_profile(args, scim, custom_mapping)

    if not slack_scim.get('schemas'):
        slack_scim['schemas'] = [SLACK_SCIM_CORE_SCHEMA_KEY, SLACK_SCIM_EXTENSION_KEY]
    res = client.create_user(slack_scim)
    res_json = res.json()
    if res.status_code in [200, 201]:
        generic_iam_context = OutputContext(success=True, iden=res_json['id'], email=email,
                                            username=res_json['userName'], details=res_json, active=res_json['active'])
    else:
        generic_iam_context = OutputContext(success=False, username=username, email=email,
                                            errorCode=res_json['Errors']['code'],
                                            errorMessage=res_json['Errors']['description'])

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(name='Create Slack User:',
                                      t=generic_iam_context.data,
                                      headers=["brand", "instanceName", "success", "active", "id", "username", "email",
                                               "errorCode", "errorMessage", "details"],
                                      removeNull=True)
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def update_user_command(client, args):
    old_scim = verify_and_load_scim_data(args.get('oldScim'))
    new_scim = verify_and_load_scim_data(args.get('newScim'))

    user_id = old_scim.get('id')

    if not (user_id):
        return_error('You must provide id of the user')

    custom_mapping = demisto.params().get('customMappingUpdateUser')
    slack_scim = client.build_slack_user_profile(args, new_scim, custom_mapping)

    res = client.update_user(user_id, slack_scim)
    res_json = res.json()

    if res.status_code == 200:
        email = get_primary(res_json.get('emails', []), 'value') if len(res_json.get('emails', [])) > 0 else ""
        generic_iam_context = OutputContext(success=True, iden=res_json['id'], username=res_json['userName'],
                                            email=email, active=res_json['active'], details=res_json)
    elif res.status_code == 404:
        generic_iam_context = OutputContext(success=False, iden=user_id, errorCode=404,
                                            errorMessage=res_json['Errors']['description'])
    else:
        generic_iam_context = OutputContext(success=False, iden=user_id, errorCode=res_json['Errors']['code'],
                                            errorMessage=res_json['Errors']['description'])

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(name='Update Slack User:',
                                      t=generic_iam_context.data,
                                      headers=["brand", "instanceName", "success", "active", "id", "username", "email",
                                               "errorCode", "errorMessage", "details"],
                                      removeNull=True)
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def enable_disable_user_command(client, args):
    scim = verify_and_load_scim_data(args.get('scim'))
    parsed_scim = map_scim(scim)
    user_id = parsed_scim.get('id')

    if not (user_id):
        return_error('You must provide id of the user')

    if demisto.command() == 'enable-user':
        format_pre_text = 'Enable'
        custom_mapping = demisto.params().get('customMappingUpdateUser')
        slack_scim = client.build_slack_user_profile(args, scim, custom_mapping)
        slack_scim['active'] = True
        res = client.update_user(user_id, slack_scim)
    elif demisto.command() == 'disable-user':
        format_pre_text = 'Disable'
        slack_scim = {'active': False}
        res = client.update_user(user_id, slack_scim)

    res_json = res.json()

    if res.status_code == 200:
        email = get_primary(res_json.get('emails', []), 'value') if len(res_json.get('emails', [])) > 0 else ""
        generic_iam_context = OutputContext(success=True, iden=user_id, username=res_json.get('userName'), email=email,
                                            active=res_json.get('active'), details=res_json)
    elif res.status_code == 404:
        generic_iam_context = OutputContext(success=False, iden=user_id, errorCode=404,
                                            errorMessage=res_json.get('errorSummary'), details=res_json)
    else:
        generic_iam_context = OutputContext(success=False, iden=user_id, errorCode=res_json.get('errorCode'),
                                            errorMessage=res_json.get('errorSummary'), details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(name=f'{format_pre_text} Slack User:',
                                      t=generic_iam_context.data,
                                      headers=["brand", "instanceName", "success", "active", "id", "username", "email",
                                               "errorCode", "errorMessage", "details"],
                                      removeNull=True)
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def get_group(client, args):
    group_id = args.get('groupId')
    group_name = args.get('groupName')

    if not (group_id or group_name):
        return_error("You must supply either 'groupId' or 'groupName")
    if not group_id:
        group_id = client.get_group_id(group_name)

    res = client.get_group_by_id(group_id)
    res_json = res.json()

    if res.status_code != 200:
        return_error(f"Error in API call. Status Code: [{res.status_code}]. Error Response: {res_json}")

    members = res_json.get('members')

    outputs = {
        'Slack.Group(val.Id && val.Id === obj.Id)': {
            'Id': group_id,
            'DisplayName': res_json.get('displayName'),
            'Members': members
        }
    }

    readable_output = tableToMarkdown(name=f"Slack Group {group_id} Members: {res_json.get('displayName')}",
                                      t=members)

    return (
        readable_output,
        outputs,
        res_json
    )


def delete_group_command(client, args):
    group_id = args.get('groupId')
    group_name = args.get('groupName')

    if not (group_id or group_name):
        return_error("You must supply either 'groupId' or 'groupName'")
    if not group_id:
        group_id = client.get_group_id(group_name)

    res = client.delete_group(group_id)

    if res.status_code != 204:
        error_json = res.json()
        return_error(f"Error in API call. Status Code: [{res.status_code}]. Error Response: {error_json}")

    readable_output = f'Slack Group ID: {group_id} was deleted successfully'
    return (
        readable_output,
        {},
        None)


def create_group_command(client, args):

    group_data = {'schemas': [SLACK_SCIM_CORE_SCHEMA_KEY], 'displayName': args.get('groupName')}
    members = []
    member_ids = args.get('memberIds')
    if member_ids:
        if type(member_ids) is not list:
            try:
                member_ids = json.loads(member_ids)
            except JSONDecodeError:
                return_error("memberIds is not a valid list")
            for member_id in member_ids:
                members.append({"value": member_id})

            group_data['members'] = members
            res = client.create_group(group_data)
            res_json = res.json()

            if res.status_code not in [200, 201]:
                return_error(f"Error in API call. Status Code: [{res.status_code}]. Error Response: {res_json}")

            readable_output = f'Slack Group ID: {res_json.get("id")} created successfully'
            return (
                readable_output,
                {},
                res_json)


def update_group_members_command(client, args):
    group_id = args.get('groupId')
    group_name = args.get('groupName')

    if not (group_id or group_name):
        return_error("You must supply either 'groupId' or 'groupName")
    if not group_id:
        group_id = client.get_group_id(group_name)

    member_ids_to_add = args.get('memberIdsToAdd')
    member_ids_to_delete = args.get('memberIdsToDelete')

    member_ids_json_list = []
    if member_ids_to_add:
        if type(member_ids_to_add) is not list:
            member_ids_to_add = json.loads(member_ids_to_add)
        for member_id in member_ids_to_add:
            member_ids_json_list.append(
                {
                    "value": member_id
                }
            )
    if member_ids_to_delete:
        if type(member_ids_to_delete) is not list:
            member_ids_to_delete = json.loads(member_ids_to_delete)
        for member_id in member_ids_to_delete:
            member_ids_json_list.append(
                {
                    "value": member_id,
                    "operation": "delete"
                }
            )

    group_input = {'schemas': [SLACK_SCIM_CORE_SCHEMA_KEY], 'members': member_ids_json_list}

    res = client.update_group(group_id, group_input)

    if res.status_code != 204:
        error_json = res.json()
        return_error(f"Error in API call. Status Code: [{res.status_code}]. Error Response: {error_json}")

    readable_output = f"Updated Slack Group Members for group : {group_id}"

    return (
        readable_output,
        {},
        None
    )


def replace_group_command(client, args):
    group_id = args.get('groupId')
    group_name = args.get('groupName')

    if not (group_id or group_name):
        return_error("You must supply either 'groupId' or 'groupName")
    if not group_id:
        group_id = client.get_group_id(group_name)

    group_input = {'schemas': [SLACK_SCIM_CORE_SCHEMA_KEY], 'displayName': args.get('newGroupName')}
    members = []
    member_ids = args.get('memberIds')
    if member_ids:
        if type(member_ids) is not list:
            try:
                member_ids = json.loads(member_ids)
            except JSONDecodeError:
                return_error("memberIds is not a valid list")
            for member_id in member_ids:
                members.append({"value": member_id})

    group_input['members'] = members
    res = client.replace_group(group_id, group_input)
    res_json = res.json()

    if res.status_code not in [200, 201]:
        return_error(f"Error in API call. Status Code: [{res.status_code}]. Error Response: {res_json}")

    readable_output = tableToMarkdown(name=f"Slack Group replaced: {group_id}",
                                      t=res_json)

    return (
        readable_output,
        {},
        res_json)


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    access_token = params.get('access_token')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()

    LOG(f'Command being called is {command}')
    commands = {
        'test-module': test_module,
        'get-user': get_user_command,
        'create-user': create_user_command,
        'update-user': update_user_command,
        'disable-user': enable_disable_user_command,
        'enable-user': enable_disable_user_command,
        'slack-get-group': get_group,
        'slack-create-group': create_group_command,
        'slack-delete-group': delete_group_command,
        'slack-update-group-members': update_group_members_command,
        'slack-replace-group': replace_group_command

    }
    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}'
        },
        proxy=proxy
    )

    try:
        if command in commands:
            human_readable, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)

    # Log exceptions
    except Exception:
        return_error(f'Failed to execute {demisto.command()} command. Traceback: {traceback.format_exc()}')


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()

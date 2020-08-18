import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''

import json
import requests
import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
SCIM_EXTENSION_SCHEMA = "urn:scim:schemas:extension:custom:1.0:user"
USER_NOT_FOUND = "User not found"
USER_DISABLED = "User disabled"
USER_ENABLED = "User enabled"
CUSTOM_MAPPING_CREATE = demisto.params().get('customMappingCreateUser')
CUSTOM_MAPPING_UPDATE = demisto.params().get('customMappingUpdateUser')


class Client(BaseClient):
    """
    Client will implement the service API,
    and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url, token, directory_id, headers, verify=True, proxy=False):
        self.base_url = base_url
        self.token = token
        self.directory_id = directory_id
        self.verify = verify
        self.headers = headers
        self.session = requests.Session()
        if not proxy:
            self.session.trust_env = False
        self.headers['Authorization'] = 'Bearer ' + self.token

    def http_request(self, method, url_suffix, params=None, data=None, headers=None):

        if not headers:
            headers = self.headers
        full_url = self.base_url + url_suffix
        res = requests.request(
            method,
            full_url,
            verify=self.verify,
            params=params,
            json=data,
            headers=headers
        )

        return res

    def get_user(self, input_type, user_term):
        if input_type == 'id':
            uri = f'/scim/directory/{encode_string_results(self.directory_id)}/Users/{encode_string_results(user_term)}'
        else:
            user_term = "\"" + user_term + "\""
            uri = f'/scim/directory/{encode_string_results(self.directory_id)}' \
                  f'/Users?filter={encode_string_results(input_type)} eq {encode_string_results(user_term)}'
        return self.http_request(
            method='GET',
            url_suffix=uri,
        )

    def create_user(self, data):
        uri = f'/scim/directory/{encode_string_results(self.directory_id)}/Users/'
        return self.http_request(
            method='POST',
            url_suffix=uri,
            data=data
        )

    def update_user(self, user_term, data):
        uri = f'/scim/directory/{encode_string_results(self.directory_id)}/Users/{encode_string_results(user_term)}'
        return self.http_request(
            method='PUT',
            url_suffix=uri,
            data=data,
        )

    def enable_disable_user(self, user_term, data):
        uri = f'/scim/directory/{encode_string_results(self.directory_id)}/Users/{encode_string_results(user_term)}'
        return self.http_request(
            method='PATCH',
            url_suffix=uri,
            data=data,
        )

    # Builds a new user atlassian_user dict with pre-defined keys and custom mapping (for user)
    def build_atlassian_user(self, args, atlassian_user, scim, fn):
        extension_schema = scim.get(SCIM_EXTENSION_SCHEMA)
        custom_mapping = None

        if fn == 'create':
            custom_mapping_fromparams = CUSTOM_MAPPING_CREATE
        else:
            custom_mapping_fromparams = CUSTOM_MAPPING_UPDATE

        if args.get('customMapping'):
            custom_mapping = json.loads(args.get('customMapping'))
        elif custom_mapping_fromparams:
            custom_mapping = json.loads(custom_mapping_fromparams)

        if custom_mapping and extension_schema:
            for key, value in custom_mapping.items():
                # key is the attribute name in input scim. value is the attribute name of app profile
                user_extension_data = extension_schema.get(key)
                if user_extension_data:
                    atlassian_user[value] = user_extension_data

        return atlassian_user


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


def verify_and_load_scim_data(scim):
    try:
        scim = json.loads(scim)
    except Exception:
        pass
    if type(scim) != dict:
        raise Exception("SCIM data is not a valid JSON ")
    return scim


def map_scim(scim):
    mapping = {
        "userName": "userName",
        "email": "emails(val.primary && val.primary==true).value",
        "first_name": "name.givenName",
        "last_name": "name.familyName",
        "active": "active",
        "id": "id",
    }

    parsed_scim = dict()
    for k, v in mapping.items():
        try:
            value = demisto.dt(scim, v)
            if type(value) == list:
                parsed_scim[k] = value[0]
            else:
                parsed_scim[k] = value
        except Exception:
            parsed_scim[k] = None
    return parsed_scim


def map_changes_to_existing_user(existing_user, new_json):
    for key, value in new_json.items():
        if type(value) == list:
            # handle in specific way
            # as of now only emails needs to be handled
            if key == 'emails':
                existing_email_list = existing_user.get(key)

                # update
                for new_json_item in value:
                    for existing_json_item in existing_email_list:
                        if existing_json_item.get('type') == new_json_item.get('type'):
                            if existing_json_item.get('value') != new_json_item.get('value'):
                                existing_json_item['value'] = new_json_item.get('value')
                            if new_json_item.get('primary', None) is not None:
                                existing_json_item['primary'] = new_json_item.get('primary')
                            else:
                                if existing_json_item.get('primary', None) is not None:
                                    existing_json_item['primary'] = existing_json_item.get('primary')
                            break

                # add
                new_email_list = []
                for new_json_item in value:
                    exist = False
                    for existing_json_item in existing_email_list:
                        if new_json_item.get('type') == existing_json_item.get('type', ''):
                            exist = True
                            break
                    if not exist:
                        new_email = {'type': new_json_item.get('type'),
                                     'value': new_json_item.get('value')}
                        if new_json_item.get('primary', None) is not None:
                            new_email.update({'primary': new_json_item.get('primary')})
                        new_email_list.append(new_email)
                existing_email_list.extend(new_email_list)

        elif type(value) == dict:
            if key != SCIM_EXTENSION_SCHEMA:
                map_changes_to_existing_user(existing_user.get(key), value)
        else:
            existing_user[key] = value


''' COMMAND FUNCTIONS '''


def test_module(client, args):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: Atlassian client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    """result = client.http_request('DBot')
    if res.status_code == 200:
        return 'ok'
    else:
        raise Exception"""

    uri = f'/scim/directory/{encode_string_results(client.directory_id)}/Users/1234'
    res = client.http_request(method='GET', url_suffix=uri)
    if res.status_code == 403:
        err_msg = 'Invalid url: ' + client.base_url + f'/scim/directory/{encode_string_results(client.directory_id)}'
        raise Exception(f"{res.status_code} - {err_msg}")
    elif res.status_code == 401:
        raise Exception(f"{res.status_code} - {res.json().get('message')}")
    else:
        return 'ok', None, None


def get_user_command(client, args):
    """
        Returning user GET details and status of response.

        Args:   demisto command line argument
        client: Atlassian

        Returns:
            success : success=True, id, email, login as username, details, active status
            fail : success=False, id, login as username, errorCode, errorMessage, details
    """

    scim = verify_and_load_scim_data(args.get('scim'))
    scim_flat_data = map_scim(scim)
    user_id = scim_flat_data.get('id')
    username = scim_flat_data.get('userName')

    input_type = None
    if not (user_id or username):
        raise Exception('You must provide either the id or userName of the user')

    if user_id:
        user_term = user_id
        input_type = 'id'
    else:
        user_term = username
        input_type = 'userName'

    res = client.get_user(input_type, user_term)

    res_json = res.json()
    generic_iam_context_data_list = []

    if res.status_code == 404 or res_json.get('totalResults', '') == 0:
        if input_type == 'userName':
            generic_iam_context = OutputContext(success=False, iden=user_id, username=user_term,
                                                errorCode=404,
                                                errorMessage=USER_NOT_FOUND, details=res_json)
        else:
            generic_iam_context = OutputContext(success=False, iden=user_id,
                                                errorCode=404,
                                                errorMessage=USER_NOT_FOUND, details=res_json)
        generic_iam_context_data_list.append(generic_iam_context.data)

    elif res.status_code == 200:
        if input_type == 'id':
            id = res_json.get('id')
            emails = res_json.get('emails')
            email = None
            for each in emails:
                if each.get('primary'):
                    email = each.get('value')
            active = res_json.get('active')
            username = res_json.get('userName')
            generic_iam_context = OutputContext(success=True, iden=id, username=username, email=email, details=res_json,
                                                active=active)
        else:
            username = res_json.get("Resources")[0].get("userName")
            id = res_json.get("Resources")[0].get("id")
            emails = res_json.get("Resources")[0].get("emails")
            email = None
            for each in emails:
                if each.get('primary'):
                    email = each.get('value')
            active = res_json.get("Resources")[0].get("active")
            generic_iam_context = OutputContext(success=True, iden=id, username=username, email=email, details=res_json,
                                                active=active)
        generic_iam_context_data_list.append(generic_iam_context.data)
    else:
        generic_iam_context = OutputContext(success=False, iden=user_id, username=username,
                                            errorCode=res.status_code,
                                            errorMessage=res.headers.get('status'), details=res_json)
        generic_iam_context_data_list.append(generic_iam_context.data)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context_data_list
    }

    readable_output = tableToMarkdown(name='Get Atlassian User:',
                                      t=generic_iam_context_data_list,
                                      headers=["brand", "instanceName", "success", "active", "id",
                                               "username", "email",
                                               "errorCode", "errorMessage", "details"],
                                      removeNull=True)
    return (
        readable_output,
        outputs,
        generic_iam_context_data_list
    )


def create_user_command(client, args):
    """
        Create user using POST to Atlassian  API, if Connection to the service is successful.

        Args: demisto command line argument
        client: Atlassian

        Returns:
            success : success=True, id, email, login as username, details, active status
            fail : success=False, id, login as username, errorCode, errorMessage, details
    """

    scim = verify_and_load_scim_data(args.get('scim'))
    parsed_scim = map_scim(scim)
    atlassian_user = scim
    atlassian_user = client.build_atlassian_user(args, atlassian_user, scim, 'create')

    # Removing Elements from atlassian_user dictionary which was not sent as part of scim
    atlassian_user = {key: value for key, value in atlassian_user.items() if value is not None}

    res = client.create_user(atlassian_user)
    res_json = res.json()

    if res.status_code == 201:
        generic_iam_context = OutputContext(success=True,
                                            iden=res_json.get('id', None),
                                            email=parsed_scim.get('email'),
                                            details=res_json,
                                            username=parsed_scim.get('userName'),
                                            active=True)

    else:
        generic_iam_context = OutputContext(success=False,
                                            iden=parsed_scim.get('id'),
                                            email=parsed_scim.get('email'),
                                            errorCode=res.status_code,
                                            errorMessage=res_json.get('detail'),
                                            username=parsed_scim.get('userName'),
                                            details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(name='Create Atlassian User:',
                                      t=generic_iam_context.data,
                                      headers=["brand", "instanceName", "success", "active", "id",
                                               "username", "email",
                                               "errorCode", "errorMessage", "details"],
                                      removeNull=True)

    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def update_user_command(client, args):
    """
        Update user using PUT to Atlassian API , if Connection to the service is successful.

        Args:   demisto command line argument
        client: Atlassian

        Returns:
            success : success=True, id, email, login as username, details, active status
            fail : success=False, id, login as username, errorCod, errorMessage, details
    """

    old_scim = verify_and_load_scim_data(args.get('oldScim'))
    new_scim = verify_and_load_scim_data(args.get('newScim'))

    parsed_old_scim = map_scim(old_scim)
    user_id = parsed_old_scim.get('id')
    userName = parsed_old_scim.get('userName')

    if not (user_id or userName):
        raise Exception('You must provide id or userName of the user')

    if user_id:
        input_type = 'id'
        user_term = user_id
    else:
        input_type = 'userName'
        user_term = userName

    res = client.get_user(input_type, user_term)
    existing_user = res.json()

    if (res.status_code == 200 and input_type == 'id') or \
            (existing_user.get('totalResults') != 0 and input_type == 'userName'):
        if input_type == 'userName':
            existing_user = existing_user.get('Resources')[0]
        map_changes_to_existing_user(existing_user, new_scim)
        # custom mapping
        atlassian_user = client.build_atlassian_user(args, existing_user, new_scim, 'update')
        # Removing Elements from github_user dictionary which was not sent as part of scim
        atlassian_user = {key: value for key, value in atlassian_user.items() if value is not None}
        res_update = client.update_user(user_term=existing_user.get('id'), data=atlassian_user)
        res_json_update = res_update.json()

        if res_update.status_code == 200:
            generic_iam_context = OutputContext(success=True,
                                                iden=res_json_update.get('id'),
                                                username=res_json_update.get('userName'),
                                                email=res_json_update.get('emails')[0].get('value'),
                                                details=res_json_update,
                                                active=True)
        else:
            generic_iam_context = OutputContext(success=False,
                                                iden=user_id,
                                                username=userName,
                                                errorCode=res_update.status_code,
                                                errorMessage=res_json_update.get('detail'),
                                                details=res_json_update)
    elif existing_user.get('totalResults') == 0:
        generic_iam_context = OutputContext(success=False, iden=user_id, username=userName,
                                            errorCode=404,
                                            errorMessage=USER_NOT_FOUND, details=existing_user)
    elif res.status_code != 200:
        # api returns 404, not found for user not found case.
        generic_iam_context = OutputContext(success=False, iden=user_id, username=userName,
                                            errorCode=res.status_code,
                                            errorMessage=res.headers.get('status'), details=existing_user)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(name='Updated Atlassian User:',
                                      t=generic_iam_context.data,
                                      headers=["brand", "instanceName", "success", "active", "id",
                                               "username", "email",
                                               "errorCode", "errorMessage", "details"],
                                      removeNull=True)

    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def disable_user_command(client, args):
    return enablee_disable_user_command(client, args, False)


def enable_user_command(client, args):
    return enablee_disable_user_command(client, args, True)


def enablee_disable_user_command(client, args, is_active):
    """
        Enable user by setting active = true in Atlassian API , if Connection to the service is successful.

        Args:   demisto command line argument
        client: Atlassian API

        Returns:
            success : success=True, id as iden, active status
            fail : success=False, id as iden, errorCod, errorMessage, details
    """
    scim = verify_and_load_scim_data(args.get('scim'))
    scim_flat_data = map_scim(scim)
    user_id = scim_flat_data.get('id')

    if not user_id:
        raise Exception('You must provide either the id of the user')

    data = {"Operations": [{"op": "replace", "value": {"active": is_active}}]}

    res = client.enable_disable_user(user_id, data)

    if res.status_code == 200:
        msg = USER_ENABLED if is_active else USER_DISABLED
        generic_iam_context = OutputContext(success=True,
                                            iden=user_id,
                                            details=msg,
                                            active=is_active)
    else:
        generic_iam_context = OutputContext(success=False,
                                            iden=user_id,
                                            errorCode=res.status_code,
                                            errorMessage=res.json().get('detail'),
                                            details=res.json())

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    name = 'Enable Atlassian User:' if is_active else 'Disable Atlassian User:'
    readable_output = tableToMarkdown(name=name,
                                      t=generic_iam_context.data,
                                      headers=["brand", "instanceName", "success", "active", "id",
                                               "username", "email",
                                               "errorCode", "errorMessage", "details"],
                                      removeNull=True)

    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """

    params = demisto.params()

    base_url = params.get('url')
    # checks for '/' at the end url, if it is not available add it
    if base_url[-1] != '/':
        base_url += '/'
    token = params.get('token')
    directory_id = params.get('directoryId')

    headers = {
        'accept': 'application/json',
        'content-type': 'application/json',
    }

    proxy = demisto.params().get('proxy', False)
    verify_certificate = not demisto.params().get('insecure', False)
    command = demisto.command()

    demisto.debug(f'Command being called is {demisto.command()}')

    # Commands supported for Atlassian API for user
    commands = {
        'test-module': test_module,
        'get-user': get_user_command,
        'create-user': create_user_command,
        'update-user': update_user_command,
        'enable-user': enable_user_command,
        'disable-user': disable_user_command
    }

    try:
        client = Client(
            base_url=base_url,
            token=token,
            directory_id=directory_id,
            verify=verify_certificate,
            proxy=proxy,
            headers=headers)

        if command in commands:
            human_readable, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)

    # Log exceptions
    except Exception:
        demisto.error(f'Failed to execute {demisto.command()} command. Traceback: {traceback.format_exc()}')
        return_error(f'Failed to execute {demisto.command()} command. Traceback: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

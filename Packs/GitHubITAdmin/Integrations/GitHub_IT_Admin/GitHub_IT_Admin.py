''' IMPORTS '''
import demistomock as demisto
from CommonServerPython import *
import json
import traceback
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
USER_NOT_FOUND = "User not found"
SCIM_EXTENSION_SCHEMA = "urn:scim:schemas:extension:custom:1.0:user"
CUSTOM_MAPPING_CREATE = demisto.params().get('customMappingCreateUser')
CUSTOM_MAPPING_UPDATE = demisto.params().get('customMappingUpdateUser')


class Client(BaseClient):
    """
    Client will implement the service API,
    and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url, token, org, headers, verify=True, proxy=False):
        self.base_url = base_url
        self.token = token
        self.org = org
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
            uri = f'scim/v2/organizations/{encode_string_results(self.org)}/Users/{encode_string_results(user_term)}'

        else:
            user_term = "\"" + user_term + "\""
            uri = f'scim/v2/organizations/{encode_string_results(self.org)}/' \
                  f'Users?filter={encode_string_results(input_type)} eq {encode_string_results(user_term)}'
        return self.http_request(
            method='GET',
            url_suffix=uri,
        )

    def create_user(self, data):
        uri = f'scim/v2/organizations/{encode_string_results(self.org)}/Users'
        return self.http_request(
            method='POST',
            url_suffix=uri,
            data=data,
        )

    def update_user(self, user_term, data):
        uri = f'scim/v2/organizations/{encode_string_results(self.org)}/Users/{encode_string_results(user_term)}'
        return self.http_request(
            method='PUT',
            url_suffix=uri,
            data=data,
        )

    def disable_user(self, data):

        uri = f'scim/v2/organizations/{encode_string_results(self.org)}/Users/{encode_string_results(data)}'
        return self.http_request(
            method='DELETE',
            url_suffix=uri
        )

    # Builds a new user github_user dict with pre-defined keys and custom mapping (for user)
    def build_github_create_user(self, args, scim):
        extension_schema = scim.get(SCIM_EXTENSION_SCHEMA)

        github_user = scim

        custom_mapping = None
        if args.get('customMapping'):
            custom_mapping = json.loads(args.get('customMapping'))
        elif CUSTOM_MAPPING_CREATE:
            custom_mapping = json.loads(CUSTOM_MAPPING_CREATE)

        if custom_mapping and extension_schema:
            for key, value in custom_mapping.items():
                # key is the attribute name in input scim. value is the attribute name of app profile
                user_extension_data = extension_schema.get(key)
                if user_extension_data:
                    github_user[value] = user_extension_data

        return github_user

    # Builds a new user github profile dict with pre-defined keys and custom mapping (for user)
    def build_github_update_user(self, args, github_user, scim):
        extension_schema = scim.get(SCIM_EXTENSION_SCHEMA)
        custom_mapping = None
        if args.get('customMapping'):
            custom_mapping = json.loads(args.get('customMapping'))
        elif CUSTOM_MAPPING_UPDATE:
            custom_mapping = json.loads(CUSTOM_MAPPING_UPDATE)

        if custom_mapping and extension_schema:
            for key, value in custom_mapping.items():
                # key is the attribute name in input scim. value is the attribute name of app profile
                user_extension_data = extension_schema.get(key)
                if user_extension_data:
                    github_user[value] = user_extension_data

        return github_user


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
    try:
        scim = json.loads(scim)
    except Exception:
        pass
    if type(scim) != dict:
        raise Exception('Provided client data is not JSON compatible')

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
            if(type(value) == list):
                parsed_scim[k] = value[0]
            else:
                parsed_scim[k] = value
        except Exception:
            parsed_scim[k] = None
    return parsed_scim


def map_changes_to_existing_user(existing_user, new_json):
    # if existing_user is not None:
    for k, v in new_json.items():
        if type(v) == list:
            # handle in specific way
            # as of now only emails needs to be handled
            if k == 'emails':
                existing_email_list = existing_user.get(k)

                # update
                for i in v:
                    for j in existing_email_list:
                        if j.get('type') == i.get('type'):
                            if j.get('value') != i.get('value'):
                                j['value'] = i.get('value')
                            if i.get('primary', None) is not None:
                                j['primary'] = i.get('primary')
                            else:
                                if j.get('primary', None) is not None:
                                    j['primary'] = j.get('primary')
                            break

                # add
                new_email_list = []
                for i in v:
                    exist = False
                    for j in existing_email_list:
                        if i.get('type') == j.get('type', ''):
                            exist = True
                            break
                    if not exist:
                        new_email = {'type': i.get('type'),
                                     'value': i.get('value')}
                        if i.get('primary', None) is not None:
                            new_email.update({'primary': i.get('primary')})
                        new_email_list.append(new_email)
                existing_email_list.extend(new_email_list)

        elif type(v) == dict:
            if k != SCIM_EXTENSION_SCHEMA:
                map_changes_to_existing_user(existing_user.get(k), v)
        else:
            existing_user[k] = v


''' COMMAND FUNCTIONS '''


def test_module(client, args):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: GitHub client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    """result = client.http_request(method,url_suffix)
    if res.status_code == 200:
        return 'ok'
    else:
        raise Exception"""

    uri = ""
    res = client.http_request(method='GET', url_suffix=uri)
    if res.status_code == 200:
        return 'ok', None, None
    else:
        raise Exception(f"{res.status_code} - {res.text}")


def get_user_command(client, args):
    """
        Returning user GET details and status of response.

        Args:   demisto command line argument
        client: GitHub

        Returns:
            success : success=True, id, email, login as username, details, active status
            fail : success=False, id, login as username, errorCode, errorMessage, details
    """

    scim = verify_and_load_scim_data(args.get('scim'))
    scim_flat_data = map_scim(scim)
    user_id = scim_flat_data.get('id')
    username = scim_flat_data.get('userName')
    email = scim_flat_data.get('email')

    input_type = None
    if not (user_id or username or email):
        raise Exception('You must provide either the id, email or login as userName of the user')

    if user_id:
        user_term = user_id
        input_type = 'id'
    else:
        if email:
            user_term = email
            input_type = 'emails'
        else:
            user_term = username
            input_type = 'userName'

    res = client.get_user(input_type, user_term)
    res_json = res.json()
    generic_iam_context_data_list = []

    if res.status_code == 200:
        if input_type == 'id':  # if search is using the id
            id = res_json.get('id', None)
            active = res_json.get('active', False)
            username = res_json.get('userName', None)
            for item in res_json.get('emails', None):
                email = item['value']
                if "primary" in item:
                    break
            generic_iam_context = OutputContext(success=True, iden=id, email=email,
                                                username=username, details=res_json, active=active)
            generic_iam_context_data_list.append(generic_iam_context.data)

        else:  # if search is using the email or userName
            if res_json.get('totalResults', 0) == 0:
                generic_iam_context = OutputContext(success=False, iden=user_id, username=username, errorCode=404, email=email,
                                                    errorMessage=USER_NOT_FOUND, details=res_json)
                generic_iam_context_data_list.append(generic_iam_context.data)

            else:
                for item in res_json.get('Resources'):
                    active = item.get('active', None)
                    id = item.get('id', None)
                    username = item.get('userName', None)
                    for email_item in item.get('emails', []):
                        email = email_item['value']
                        if "primary" in email_item:
                            break

                    generic_iam_context = OutputContext(success=True, iden=id, email=email,
                                                        username=username, details=item, active=active)
                    generic_iam_context_data_list.append(generic_iam_context.data)

    else:  # api returns 404, not found for user not found case.
        generic_iam_context = OutputContext(success=False, iden=user_id, username=username, email=email,
                                            errorCode=res.status_code,
                                            errorMessage=res.headers.get('status'), details=res_json)
        generic_iam_context_data_list.append(generic_iam_context.data)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context_data_list
    }

    readable_output = tableToMarkdown(name='Get GitHub User:',
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
        Create user using POST to GitHub  API, if Connection to the service is successful.

        Args: demisto command line argument
        client: GitHub

        Returns:
            success : success=True, id, email, login as username, details, active status
            fail : success=False, id, login as username, errorCode, errorMessage, details
    """

    scim = verify_and_load_scim_data(args.get('scim'))
    parsed_scim = map_scim(scim)

    github_user = client.build_github_create_user(args, scim)

    # Removing Elements from github_user dictionary which was not sent as part of scim
    github_user = {key: value for key, value in github_user.items() if value is not None}
    res = client.create_user(github_user)
    res_json = res.json()

    if res.status_code == 201:
        id = res_json.get('id', None)
        generic_iam_context = OutputContext(success=True,
                                            iden=id,
                                            email=parsed_scim.get('email'),
                                            details=res_json,
                                            username=parsed_scim.get('userName'),
                                            active=True)

    else:
        generic_iam_context = OutputContext(success=False,
                                            iden=parsed_scim.get('id'),
                                            email=parsed_scim.get('email'),
                                            errorCode=res.status_code,
                                            errorMessage=res.headers.get('status'),
                                            username=parsed_scim.get('userName'),
                                            details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(name='Create GitHub User:',
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
        Update user using PUT to GitHub API , if Connection to the service is successful.

        Args:   demisto command line argument
        client: GitHub

        Returns:
            success : success=True, id, email, login as username, details, active status
            fail : success=False, id, login as username, errorCod, errorMessage, details
    """

    old_scim = verify_and_load_scim_data(args.get('oldScim'))
    new_scim = verify_and_load_scim_data(args.get('newScim'))

    parsed_old_scim = map_scim(old_scim)
    user_id = parsed_old_scim.get('id')

    if not (user_id):
        raise Exception('You must provide id of the user')

    res = client.get_user('id', user_id)
    existing_user = res.json()
    if res.status_code == 200:
        map_changes_to_existing_user(existing_user, new_scim)

        # custom mapping
        github_user = client.build_github_update_user(args, existing_user, new_scim)
        # Removing Elements from github_user dictionary which was not sent as part of scim
        github_user = {key: value for key, value in github_user.items() if value is not None}
        res_update = client.update_user(user_term=user_id, data=github_user)

        if res_update.status_code == 200:
            res_json = res_update.json()
            generic_iam_context = OutputContext(success=True,
                                                iden=user_id,
                                                details=res_json,
                                                active=True)
        elif res_update.status_code == 404:
            generic_iam_context = OutputContext(success=False,
                                                iden=user_id,
                                                errorCode=res_update.status_code,
                                                errorMessage=USER_NOT_FOUND,
                                                details=res_update.headers.get('status'))
        else:
            generic_iam_context = OutputContext(success=False,
                                                iden=user_id,
                                                errorCode=res_update.status_code,
                                                errorMessage=res_update.headers.get('status'),
                                                details=res_update.headers.get('status'))

    else:  # api returns 404, not found for user not found case.
        generic_iam_context = OutputContext(success=False, iden=user_id,
                                            errorCode=res.status_code,
                                            errorMessage=res.headers.get('status'), details=existing_user)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(name='Updated GitHub User:',
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
    """
        Deactivate user by using 'DELETE' to Github API , if Connection to the service is successful.

        Args:   demisto command line argument
        client: Github API

        Returns:
            success : success=True, id as iden, active status
            fail : success=False, id as iden, errorCod, errorMessage, details
    """
    scim = verify_and_load_scim_data(args.get('scim'))
    scim_flat_data = map_scim(scim)
    user_id = scim_flat_data.get('id')

    if not (user_id):
        raise Exception('You must provide either the id of the user')

    res = client.disable_user(user_id)

    if res.status_code == 204:
        generic_iam_context = OutputContext(active=False, success=True, iden=user_id)

    elif res.status_code == 404:
        generic_iam_context = OutputContext(success=False, iden=user_id, errorCode=404,
                                            errorMessage=USER_NOT_FOUND, details=res.json())
    else:
        generic_iam_context = OutputContext(success=False, iden=user_id, errorCode=res.status_code,
                                            errorMessage=res.json().get('detail'), details=res.json())

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(name='Disable GitHub User:',
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

    # get the service API url
    base_url = params.get('url')
    # get the service token  which is mendatory
    token = params.get('token')
    # get the org(organization name)
    org = params.get('org')

    verify_certificate = not demisto.params().get('insecure', False)

    headers = {
        'accept': 'application/json',
        'content-type': 'application/json',
    }

    proxy = demisto.params().get('proxy', False)
    command = demisto.command()

    demisto.debug(f'Command being called is {demisto.command()}')

    # Commands supported for GitHub API for user
    commands = {
        'test-module': test_module,
        'get-user': get_user_command,
        'create-user': create_user_command,
        'update-user': update_user_command,
        'enable-user': create_user_command,
        'disable-user': disable_user_command
    }

    try:
        client = Client(
            base_url=base_url,
            token=token,
            org=org,
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

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

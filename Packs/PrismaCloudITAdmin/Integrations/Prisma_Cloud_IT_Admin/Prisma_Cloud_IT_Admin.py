import json
import traceback

import requests

import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
SCIM_EXTENSION_SCHEMA = "urn:scim:schemas:extension:custom:1.0:user"


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url, conn_username, conn_password, headers, conn_customer_name='',
                 verify=True, proxy=False):
        self.base_url = base_url
        self.conn_username = conn_username
        self.conn_password = conn_password
        self.conn_customer_name = conn_customer_name
        self.verify = verify
        self.headers = headers
        self.session = requests.Session()
        if not proxy:
            self.session.trust_env = False
        res = self.create_login()
        res_json = res.json()
        self.headers['x-redlock-auth'] = res_json.get('token')

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

    def create_login(self):
        uri = 'login/'
        body = {
            "username": self.conn_username,
            "password": self.conn_password,
            "customerName": self.conn_customer_name
        }
        return self.http_request(
            method='POST',
            url_suffix=uri,
            data=body
        )

    def get_user_profile(self, user_term):
        uri = f'user/{encode_string_results(user_term)}'
        return self.http_request(
            method='GET',
            url_suffix=uri
        )

    def create_user_profile(self, data):
        uri = 'user/'
        return self.http_request(
            method='POST',
            url_suffix=uri,
            data=data
        )

    def update_user_profile(self, user_term, data):
        uri = f'user/{encode_string_results(user_term)}'
        return self.http_request(
            method='PUT',
            url_suffix=uri,
            data=data
        )

    def disable_user_profile(self, user_term):
        uri = f'user/{encode_string_results(user_term)}/status/false'
        return self.http_request(
            method='PATCH',
            url_suffix=uri
        )

    def enable_user_profile(self, user_term):
        uri = f'user/{encode_string_results(user_term)}/status/true'
        return self.http_request(
            method='PATCH',
            url_suffix=uri
        )

    # Builds a new user prisma profile dict with pre-defined keys and custom mapping (for user)
    def build_prisma_profile_create_user(self, args, scim, custom_mapping):
        parsed_scim_data = map_scim(scim)
        prisma_user = {
            "email": parsed_scim_data.get('email'),
            "firstName": parsed_scim_data.get('first_name'),
            "lastName": parsed_scim_data.get('last_name'),
            "timeZone": parsed_scim_data.get('timezone'),
        }

        if args.get('customMapping'):
            custom_mapping = json.loads(args.get('customMapping'))
        elif custom_mapping:
            custom_mapping = json.loads(custom_mapping)

        extension_schema = scim.get(SCIM_EXTENSION_SCHEMA)
        if custom_mapping and extension_schema:
            for key, value in custom_mapping.items():
                # key is the attribute name in input scim. value is the attribute name of app profile
                user_extension_data = extension_schema.get(key)
                if user_extension_data:
                    prisma_user[value] = user_extension_data
        return prisma_user

    # Builds a new user prisma profile dict with pre-defined keys and custom mapping (for user)

    def build_prisma_profile_update_user(self, args, scim, custom_mapping):
        parsed_scim_data = map_scim(scim)
        prisma_user = {
            "email": parsed_scim_data.get('email'),
            "firstName": parsed_scim_data.get('first_name'),
            "lastName": parsed_scim_data.get('last_name'),
            "timeZone": parsed_scim_data.get('timezone'),
        }

        if args.get('customMapping'):
            custom_mapping = json.loads(args.get('customMapping'))
        elif custom_mapping:
            custom_mapping = json.loads(custom_mapping)

        extension_schema = scim.get(SCIM_EXTENSION_SCHEMA)
        if custom_mapping and extension_schema:
            for key, value in custom_mapping.items():
                # key is the attribute name in input scim. value is the attribute name of app profile
                user_extension_data = extension_schema.get(key)
                if user_extension_data:
                    prisma_user[value] = user_extension_data

        return prisma_user


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


def verify_and_load_scim_data(scim):
    try:
        scim = json.loads(scim)
    except Exception:
        pass
    if type(scim) != dict:
        raise Exception("SCIM data is not a valid JSON")
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
        "email": "emails(val.primary && val.primary==true).[0].value",
        "first_name": "name.givenName",
        "last_name": "name.familyName",
        "id": "id",
        "timezone": "timezone",
    }
    parsed_scim = dict()
    for k, v in mapping.items():
        try:
            parsed_scim[k] = demisto.dt(scim, v)
        except Exception:
            parsed_scim[k] = None
    return parsed_scim


''' COMMAND FUNCTIONS '''


def test_module(client, args):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: PrismaCloudAdmin client
        args  : PrismaCloudAdmin arguments passed

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    args
    uri = 'user/id'
    res = client.http_request(method='GET', url_suffix=uri)
    if res.status_code == 200 or res.status_code == 400:
        return 'ok', None, None
    else:
        error_response = str(res.headers.get('x-redlock-status'))
        raise Exception(f"Failed to execuete test_module. Error Code: {res.status_code}. Error Response: {error_response}")


def get_user_command(client, args):

    scim = verify_and_load_scim_data(args.get('scim'))
    scim_flat_data = map_scim(scim)
    user_id = scim_flat_data.get('id')
    username = scim_flat_data.get('userName')
    email = scim_flat_data.get('email')

    if not (user_id or username or email):
        raise Exception('You must provide either the id, email or username of the user')

    if user_id:
        user_term = user_id
    else:
        user_term = username if username else email

    user_term = user_term.lower()
    res = client.get_user_profile(user_term)

    if res.status_code == 200:
        res_json = res.json()
        active = res_json['enabled']
        generic_iam_context = OutputContext(success=True, iden=user_id, email=email,
                                            username=username, details=res_json, active=active)
    elif res.status_code == 400:
        generic_iam_context = OutputContext(success=False, iden=user_id, username=username, email=email, errorCode=404,
                                            errorMessage="User Not Found", details=res.headers.get('x-redlock-status'))
    else:
        generic_iam_context = OutputContext(success=False, iden=user_id, username=username, email=email,
                                            errorCode=res.status_code,
                                            errorMessage=res.headers.get('x-redlock-status'))

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(name='Get PrismaCloud User:',
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

    custom_mapping = demisto.params().get('customMappingCreateUser')
    scim = verify_and_load_scim_data(args.get('scim'))
    parsed_scim = map_scim(scim)

    prisma_user = client.build_prisma_profile_create_user(args, scim, custom_mapping)

    # Removing Elements from prisma_user dictionary which was not sent as part of scim
    prisma_user = {key: value for key, value in prisma_user.items() if value is not None}

    res = client.create_user_profile(prisma_user)

    if res.status_code == 200:
        generic_iam_context = OutputContext(success=True,
                                            iden=parsed_scim.get('email'),
                                            email=parsed_scim.get('email'),
                                            active=True)
    elif res.status_code == 409:
        generic_iam_context = OutputContext(success=False,
                                            iden=parsed_scim.get('email'),
                                            email=parsed_scim.get('email'),
                                            errorCode=res.status_code,
                                            errorMessage=res.headers.get('x-redlock-status'))
    else:
        generic_iam_context = OutputContext(success=False,
                                            iden=parsed_scim.get('email'),
                                            email=parsed_scim.get('email'),
                                            errorCode=res.status_code,
                                            errorMessage=res.headers.get('x-redlock-status'))

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(name='Create Prisma User:',
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
    custom_mapping = demisto.params().get('customMappingUpdateUser')

    old_scim = verify_and_load_scim_data(args.get('oldScim'))
    new_scim = verify_and_load_scim_data(args.get('newScim'))

    parsed_old_scim = map_scim(old_scim)
    user_id = parsed_old_scim.get('id')
    username = parsed_old_scim.get('userName')
    email = parsed_old_scim.get('email')

    if not (user_id or username or email):
        raise Exception('You must provide either the id, email or username of the user')

    if user_id:
        user_term = user_id
    else:
        user_term = username if username else email

    prisma_user = client.build_prisma_profile_update_user(args, new_scim, custom_mapping)

    # Removing Elements from prisma_user dictionary which was not sent as part of scim
    prisma_user = {key: value for key, value in prisma_user.items() if value is not None}

    res = client.update_user_profile(user_term=user_term, data=prisma_user)

    if res.status_code == 200:
        generic_iam_context = OutputContext(success=True,
                                            iden=user_id,
                                            email=email,
                                            username=username,
                                            active=True)
    elif res.status_code == 400:
        error_mesaage = str(res.headers.get('x-redlock-status'))
        if 'user_inactive_or_not_exist' in error_mesaage:
            error_code = 404
        else:
            error_code = res.status_code
        generic_iam_context = OutputContext(success=False,
                                            iden=user_id,
                                            email=email,
                                            username=username,
                                            errorCode=error_code,
                                            errorMessage=res.headers.get('x-redlock-status'))

    else:
        generic_iam_context = OutputContext(success=False,
                                            iden=user_id,
                                            email=email,
                                            username=username,
                                            errorCode=res.status_code,
                                            errorMessage=res.headers.get('x-redlock-status'))

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(name='Update Prisma User:',
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
    scim_flat_data = map_scim(scim)
    user_id = scim_flat_data.get('id')
    username = scim_flat_data.get('userName')
    email = scim_flat_data.get('email')

    if not (user_id or username or email):
        raise Exception('You must provide either the id, email or username of the user')

    if user_id:
        user_term = user_id
    else:
        user_term = username if username else email

    user_term = user_term.lower()

    if demisto.command() == 'enable-user':
        format_pre_text = 'Enable'
        active = True
        res = client.enable_user_profile(user_term)
    elif demisto.command() == 'disable-user':
        format_pre_text = 'Disable'
        active = False
        res = client.disable_user_profile(user_term)

    if res.status_code == 200:
        generic_iam_context = OutputContext(success=True, iden=user_id, username=username, email=email, active=active)
    elif res.status_code == 404:
        generic_iam_context = OutputContext(success=False, iden=user_id, email=email,
                                            username=username, errorCode=res.status_code,
                                            errorMessage="User Not Found",
                                            details=res.headers.get('x-redlock-status'))
    else:
        generic_iam_context = OutputContext(success=False, iden=user_term, username=username,
                                            email=email, errorCode=res.status_code,
                                            errorMessage=res.headers.get('x-redlock-status'))

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(name=f'{format_pre_text} Prisma User:',
                                      t=generic_iam_context.data,
                                      headers=["brand", "instanceName", "success", "active", "id", "username", "email",
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

    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    customer_name = params.get('customerName')
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
        'enable-user': enable_disable_user_command
    }

    try:
        client = Client(
            base_url=base_url,
            conn_username=username,
            conn_password=password,
            conn_customer_name=customer_name,
            verify=verify_certificate,
            headers={
                'accept': 'application/json',
                'content-type': 'application/json',
                'x-redlock-auth': ''
            },
            proxy=proxy)

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

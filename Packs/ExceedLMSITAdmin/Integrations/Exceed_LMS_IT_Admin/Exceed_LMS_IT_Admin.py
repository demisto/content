import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''

import json
import traceback

import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
SCIM_EXTENSION_SCHEMA = "urn:scim:schemas:extension:custom:1.0:user"
USER_NOT_FOUND = "User not found"
CUSTOM_MAPPING_CREATE = demisto.params().get('customMappingCreateUser')
CUSTOM_MAPPING_UPDATE = demisto.params().get('customMappingUpdateUser')


class Client(BaseClient):
    """
    Client will implement the service API,
    and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url, api_key, headers, verify=True, proxy=False):
        self.base_url = base_url
        self.api_key = api_key
        self.verify = verify
        self.headers = headers
        self.session = requests.Session()
        if not proxy:
            self.session.trust_env = False

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

        uri = '/api/v2/users.json/'
        params = {
            'user[' + input_type + ']': user_term,
            'api_key': self.api_key
        }

        return self.http_request(
            method='GET',
            url_suffix=uri,
            params=params
        )

    def create_user(self, data):
        uri = '/api/v2/users.json'
        params = {
            'api_key': self.api_key
        }

        return self.http_request(
            method='POST',
            url_suffix=uri,
            data=data,
            params=params
        )

    def update_user(self, user_term, data):
        uri = f'/api/v2/users/{encode_string_results(user_term)}'
        params = {
            'api_key': self.api_key
        }

        return self.http_request(
            method='PUT',
            url_suffix=uri,
            data=data,
            params=params
        )

    # Builds a new user exceedlms_user dict with pre-defined keys and custom mapping (for user)
    def build_exceedlms_create_user(self, args, scim):
        parsed_scim_data = map_scim(scim)
        extension_schema = scim.get(SCIM_EXTENSION_SCHEMA)

        manager_id = ''
        manageremail = ''
        if extension_schema and extension_schema.get('manager_id') is not None:
            manager_id = extension_schema.get('manager_id')

        if extension_schema and extension_schema.get('manageremail') is not None:
            manageremail = extension_schema.get('manageremail')

        manager_term = None

        if manager_id:
            manager_term = manager_id
        elif manageremail:
            input_type = 'email'
            res = self.get_user(input_type, manageremail)
            res_json = res.json()
            if len(res_json) > 0:
                manager_term = res_json[0].get('id', '')

        exceedlms_user = {
            "login": parsed_scim_data.get('userName'),
            "first_name": parsed_scim_data.get('first_name'),
            "last_name": parsed_scim_data.get('last_name'),
            "email": parsed_scim_data.get('email'),
            "is_active": parsed_scim_data.get('active'),
            "manager_id": manager_term,
            "address_one": parsed_scim_data.get('address_one'),
            "address_two": parsed_scim_data.get('address_two'),
            "city": parsed_scim_data.get('city'),
            "country": parsed_scim_data.get('country'),
            "phone_home": parsed_scim_data.get('phone_home'),
            "phone_mobile": parsed_scim_data.get('phone_mobile'),
            "phone_work": parsed_scim_data.get('phone_work'),
            "state": parsed_scim_data.get('state'),
            "zip": parsed_scim_data.get('zip'),
        }

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
                    exceedlms_user[value] = user_extension_data

        return exceedlms_user

    # Builds a new user ExceedLMS profile dict with pre-defined keys and custom mapping (for user)

    def build_exceedlms_update_user(self, args, scim):
        parsed_scim_data = map_scim(scim)
        extension_schema = scim.get(SCIM_EXTENSION_SCHEMA)

        manager_id = ''
        manageremail = ''
        if extension_schema and extension_schema.get('manager_id') is not None:
            manager_id = extension_schema.get('manager_id')

        if extension_schema and extension_schema.get('manageremail') is not None:
            manageremail = extension_schema.get('manageremail')

        manager_term = None

        if manager_id:
            manager_term = manager_id
        elif manageremail:
            input_type = 'email'
            res = self.get_user(input_type, manageremail)
            res_json = res.json()
            if len(res_json) > 0:
                manager_term = res_json[0].get('id', '')

        exceedlms_user = {
            "email": parsed_scim_data.get('email'),
            "first_name": parsed_scim_data.get('first_name'),
            "last_name": parsed_scim_data.get('last_name'),
            "login": parsed_scim_data.get('userName'),
            "manager_id": manager_term,
            "address_one": parsed_scim_data.get('address_one'),
            "address_two": parsed_scim_data.get('address_two'),
            "city": parsed_scim_data.get('city'),
            "country": parsed_scim_data.get('country'),
            "phone_home": parsed_scim_data.get('phone_home'),
            "phone_mobile": parsed_scim_data.get('phone_mobile'),
            "phone_work": parsed_scim_data.get('phone_work'),
            "state": parsed_scim_data.get('state'),
            "zip": parsed_scim_data.get('zip'),
        }

        custom_mapping = None
        if args.get('customMapping'):
            custom_mapping = json.loads(args.get('customMapping'))
        elif CUSTOM_MAPPING_UPDATE:
            custom_mapping = json.loads(CUSTOM_MAPPING_UPDATE)

        extension_schema = scim.get(SCIM_EXTENSION_SCHEMA)
        if custom_mapping and extension_schema:
            for key, value in custom_mapping.items():
                # key is the attribute name in input scim. value is the attribute name of app profile
                user_extension_data = extension_schema.get(key)
                if user_extension_data:
                    exceedlms_user[value] = user_extension_data

        return exceedlms_user

    def enable_disable_user(self, user_id, params):
        uri = f'/api/v2/users/{encode_string_results(user_id)}'
        return self.http_request(
            method='PUT',
            url_suffix=uri,
            params=params
        )

    # Builds a set of params to enable or diable user
    def build_enable_disable_user_param(self, active_status):
        params = {
            'api_key': self.api_key,
            'user[is_active]': str(active_status).lower()
        }
        return params


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
        "address_one": "addresses(val.primary && val.primary==true).formatted",
        "address_two": "addresses( !val.primary ).formatted",
        "city": "addresses(val.primary && val.primary==true).locality",
        "country": "addresses(val.primary && val.primary==true).country",
        "phone_home": "phoneNumbers(val.type && val.type=='home').value",
        "phone_mobile": "phoneNumbers(val.type && val.type=='mobile').value",
        "phone_work": "phoneNumbers(val.type && val.type=='work').value",
        "state": "addresses(val.primary && val.primary==true).region",
        "zip": "addresses(val.primary && val.primary==true).postalCode",
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


''' COMMAND FUNCTIONS '''


def test_module(client, args):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: ExceedLMSITAdmin client
        args  : ExceedLMSITAdmin arguments passed

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    """res = client.http_request(method, url, param)
    if res.status_code ==200:
        return 'ok'
    else:
        raise Exception"""
    args
    uri = '/api/v2/users.json/'
    params = {
        'user[login]': 123,
        'api_key': client.api_key
    }
    res = client.http_request(method='GET', url_suffix=uri, params=params)
    if res.status_code == 200:
        return 'ok', None, None
    else:
        raise Exception(f"{res.status_code} - {res.text}")


def get_user_command(client, args):
    """
        Returning user GET details and status of response.

        Args:   demisto command line argument
        client: Exceed LMS

        Returns:
            success : success=True, id, email, login as username, details, active status
            fail : success=False, id, login as username, errorCod, errorMessage, details
    """

    scim = verify_and_load_scim_data(args.get('scim'))
    scim_flat_data = map_scim(scim)
    user_id = scim_flat_data.get('id')
    username = scim_flat_data.get('userName')
    email = scim_flat_data.get('email')

    if not (user_id or username or email):
        raise Exception('You must provide either the id, email or login as userName of the user')

    if user_id:
        user_term = user_id
        input_type = 'id'
    else:
        if email:
            user_term = email
            input_type = 'email'
        else:
            user_term = username
            input_type = 'login'

    res = client.get_user(input_type, user_term)
    res_json = res.json()
    generic_iam_context_data_list = []
    if res.status_code == 200:
        if len(res_json) > 0:

            for item in res_json:
                active = item['is_active']
                id = item['id']
                email = item['email']
                username = item['login']

                generic_iam_context = OutputContext(success=True, iden=id, email=email,
                                                    username=username, details=item, active=active)
                generic_iam_context_data_list.append(generic_iam_context.data)
        else:
            generic_iam_context = OutputContext(success=False, iden=user_id, username=username, errorCode=404, email=email,
                                                errorMessage=USER_NOT_FOUND, details=res_json)
            generic_iam_context_data_list.append(generic_iam_context.data)
    else:
        generic_iam_context = OutputContext(success=False, iden=user_id, username=username, email=email,
                                            errorCode=res.status_code,
                                            errorMessage=res.headers.get('status'), details=res_json)
        generic_iam_context_data_list.append(generic_iam_context.data)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context_data_list
    }

    readable_output = tableToMarkdown(name='Get EXCEED LMS User:',
                                      t=generic_iam_context_data_list,
                                      headers=["brand", "instanceName", "success", "active", "id", "username", "email",
                                               "errorCode", "errorMessage", "details"],
                                      removeNull=True)

    return (
        readable_output,
        outputs,
        generic_iam_context_data_list
    )


def create_user_command(client, args):
    """
        Create user using POST to Exceed LMS API, if Connection to the service is successful.

        Args: demisto command line argument
        client: Exceed LMS

        Returns:
            success : success=True, id, email, login as username, details, active status
            fail : success=False, id, login as username, errorCode, errorMessage, details
    """

    scim = verify_and_load_scim_data(args.get('scim'))
    parsed_scim = map_scim(scim)

    exceedlms_user = client.build_exceedlms_create_user(args, scim)

    # Removing Elements from exceed lms dictionary which was not sent as part of scim
    exceedlms_user = {key: value for key, value in exceedlms_user.items() if value is not None}

    res = client.create_user(exceedlms_user)
    res_json = res.json()

    if res.status_code == 201:
        id_val = res_json['id']
        email = res_json['email']
        generic_iam_context = OutputContext(success=True,
                                            iden=id_val,
                                            email=email,
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

    readable_output = tableToMarkdown(name='Create Exceed LMS User:',
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
    """
        Update user using PUT to Exceed LMS API , if Connection to the service is successful.

        Args:   demisto command line argument
        client: Exceed LMS

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

    exceedlms_user = client.build_exceedlms_update_user(args, new_scim)

    # Removing Elements from Exceedlms user dictionary which was not sent as part of scim
    exceedlms_user = {key: value for key, value in exceedlms_user.items() if value is not None}

    res = client.update_user(user_term=user_id, data=exceedlms_user)

    if res.status_code == 200:
        generic_iam_context = OutputContext(success=True,
                                            iden=user_id,
                                            active=True)
    elif res.status_code == 404:
        generic_iam_context = OutputContext(success=False,
                                            iden=user_id,
                                            errorCode=res.status_code,
                                            errorMessage=USER_NOT_FOUND,
                                            details=res.headers.get('status'))
    else:
        generic_iam_context = OutputContext(success=False,
                                            iden=user_id,
                                            errorCode=res.status_code,
                                            errorMessage=res.headers.get('status'),
                                            details=res.headers.get('status'))

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(name='Updated ExceedLMS User:',
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
    """
        Activates or Deactivate user by using 'PUT' to Exceed LMS API , if Connection to the service is successful.

        Args:   demisto command line argument
        client: Exceed LMS

        Returns:
            success : success=True, id as iden, active status
            fail : success=False, id as iden, errorCod, errorMessage, details
    """
    if demisto.command() == 'enable-user':
        active_status = True
        format_pre_text = 'Enable'
    else:
        active_status = False
        format_pre_text = 'Disable'
    scim = verify_and_load_scim_data(args.get('scim'))
    scim_flat_data = map_scim(scim)

    user_id = scim_flat_data.get('id')

    if not (user_id):
        raise Exception('You must provide id of the user')

    params = client.build_enable_disable_user_param(active_status)
    res = client.enable_disable_user(user_id, params)
    demisto.debug(f'response received for id: {str(user_id)}')
    if res.status_code == 200:
        generic_iam_context = OutputContext(success=True,
                                            iden=user_id,
                                            active=active_status)
    elif res.status_code == 404:
        generic_iam_context = OutputContext(success=False,
                                            iden=user_id,
                                            errorCode=res.status_code,
                                            errorMessage=USER_NOT_FOUND,
                                            details=res.json())
    else:
        generic_iam_context = OutputContext(success=False,
                                            iden=user_id,
                                            errorCode=res.status_code,
                                            errorMessage=res.headers.get('status'),
                                            details=res.json())

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(name=f'{format_pre_text} ExceedLMS User:',
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
    # get the service API key which is mendatory
    api_key = params.get('api_key')

    verify_certificate = not demisto.params().get('insecure', False)

    headers = {
        'accept': 'application/json',
        'content-type': 'application/json',
    }

    proxy = demisto.params().get('proxy', False)
    command = demisto.command()

    demisto.debug(f'Command being called is {demisto.command()}')

    # Commands supported for Exceed LMS API for user
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
            api_key=api_key,
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

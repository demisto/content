import json
import traceback

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
URI_PREFIX = 'scim/v2/'
SCIM_EXTENSION_SCHEMA = "urn:scim:schemas:extension:custom:1.0:user"
TWIC_EXTENSION_SCHEMA = "urn:ietf:params:scim:schemas:extension:twic:2.0:User"
CUSTOM_MAPPING_CREATE = None
CUSTOM_MAPPING_UPDATE = None


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url, auth_token, headers, verify=True, proxy=False):
        self.base_url = base_url
        self.verify = verify
        self.headers = headers
        self.headers['Authorization'] = "Bearer " + auth_token
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

    def get_user_profile(self, user_term):
        uri = URI_PREFIX + f'Users/{encode_string_results(user_term)}'
        return self.http_request(
            method='GET',
            url_suffix=uri
        )

    def search_user_profile(self, user_param, user_term):
        uri = URI_PREFIX + 'Users'
        params = {
            "filter": f'{encode_string_results(user_param)} eq "{encode_string_results(user_term)}"'
        }
        return self.http_request(
            method='GET',
            url_suffix=uri,
            params=params
        )

    def create_user_profile(self, data):
        uri = URI_PREFIX + 'Users'
        return self.http_request(
            method='POST',
            url_suffix=uri,
            data=data
        )

    def update_user_profile(self, user_term, data):
        uri = URI_PREFIX + f'Users/{encode_string_results(user_term)}'
        return self.http_request(
            method='PUT',
            url_suffix=uri,
            data=data
        )

    def enable_disable_user_profile(self, user_term, data):
        uri = URI_PREFIX + f'Users/{encode_string_results(user_term)}'
        return self.http_request(
            method='PATCH',
            url_suffix=uri,
            data=data
        )

    def build_twic_extension(self, args, scim, custom_mapping_parameter, office_country):
        twic_extension = {}
        custom_mapping = {}

        if args.get('customMapping'):
            custom_mapping = json.loads(args.get('customMapping'))
        elif custom_mapping_parameter:
            custom_mapping = json.loads(custom_mapping_parameter)

        extension_schema = scim.get(SCIM_EXTENSION_SCHEMA)
        if custom_mapping and extension_schema:
            for key, value in custom_mapping.items():
                # key is the attribute name in input scim. value is the attribute name of app profile
                user_extension_data = extension_schema.get(key)
                if user_extension_data:
                    twic_extension[value] = user_extension_data
        elif office_country:
            twic_extension['office_country'] = office_country
        return twic_extension


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
        "id": "id",
        "office_country": "addresses(val.primary && val.primary==true).country",
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
        client: TwicITAdmin client
        args  : TwicITAdmin arguments passed

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    args
    uri = URI_PREFIX + 'Users'
    res = client.http_request(method='GET', url_suffix=uri)
    if res.status_code == 200:
        return 'ok', None, None
    else:
        res_json = res.json()
        error_response = res_json.get('detail')
        raise Exception(f"Failed to execute test_module. Error Code: {res.status_code}.Error "
                        f"Response: {error_response}")


def get_user_command(client, args):

    scim = verify_and_load_scim_data(args.get('scim'))
    scim_flat_data = map_scim(scim)
    user_id = scim_flat_data.get('id')
    username = scim_flat_data.get('userName')
    email = scim_flat_data.get('email')

    if not (user_id or username or email):
        raise Exception('You must provide either the id, email or username of the user')

    if user_id:
        res = client.get_user_profile(user_id)
    else:
        if username:
            user_term = username
            user_param = "userName"
        else:
            user_term = email
            user_param = "emails"
        res = client.search_user_profile(user_param, user_term)
        if res.status_code == 200:
            res_json = res.json()
            resources = res_json.get('Resources')
            if len(resources) > 0:
                resource = resources[0]
                user_id = resource.get('id')
                res = client.get_user_profile(user_id)
            else:
                res.status_code = 404
                res_json['detail'] = "User Not Found"

    if res.status_code == 200:
        res_json = res.json()

        emails = res_json.get('emails')
        for email_dict in emails:
            if email_dict.get("primary") is True:
                email = email_dict.get("value")
                break

        generic_iam_context = OutputContext(success=True, iden=res_json.get('id'), email=email,
                                            username=res_json.get('userName'), details=res_json,
                                            active=res_json.get('active'))
    elif res.status_code == 404:
        res_json = res.json()
        generic_iam_context = OutputContext(success=False, iden=user_id, email=email, username=username,
                                            errorCode=404, errorMessage="User Not Found",
                                            details=res_json.get('detail'))
    else:
        res_json = res.json()
        generic_iam_context = OutputContext(success=False, iden=user_id, email=email, username=username,
                                            errorCode=res.status_code,
                                            errorMessage=res_json.get('detail'),
                                            details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(name='Get Twic User:',
                                      t=generic_iam_context.data,
                                      headers=["brand", "instanceName", "success", "active", "id", "username", "email",
                                               "errorCode", "errorMessage", "details"],
                                      removeNull=True
                                      )
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def create_user_command(client, args):

    scim = verify_and_load_scim_data(args.get('scim'))
    parsed_scim = map_scim(scim)

    twic_extension = client.build_twic_extension(args, scim, CUSTOM_MAPPING_CREATE, parsed_scim.get('office_country'))

    # building twic extension schema
    if twic_extension:
        scim[TWIC_EXTENSION_SCHEMA] = twic_extension

    if SCIM_EXTENSION_SCHEMA in scim:
        scim.pop(SCIM_EXTENSION_SCHEMA)

    # Setting User's active status to True by default
    scim['active'] = True

    res = client.create_user_profile(scim)

    if res.status_code == 201:
        res_json = res.json()
        generic_iam_context = OutputContext(success=True,
                                            iden=res_json.get('id'),
                                            email=parsed_scim.get('email'),
                                            username=res_json.get('userName'),
                                            details=res_json,
                                            active=res_json.get('active'))
    else:
        res_json = res.json()
        generic_iam_context = OutputContext(success=False,
                                            email=parsed_scim.get('email'),
                                            username=parsed_scim.get('userName'),
                                            errorCode=res.status_code,
                                            errorMessage=res_json.get('detail'),
                                            details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(name='Create Twic User:',
                                      t=generic_iam_context.data,
                                      headers=["brand", "instanceName", "success", "active", "id", "username",
                                               "email", "errorCode", "errorMessage", "details"],
                                      removeNull=True)
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def update_user_command(client, args):

    old_scim = verify_and_load_scim_data(args.get('oldScim'))
    new_scim = verify_and_load_scim_data(args.get('newScim'))

    parsed_old_scim = map_scim(old_scim)
    parsed_new_scim = map_scim(new_scim)
    user_id = parsed_old_scim.get('id')

    if not user_id:
        raise Exception('You must provide id of the user')

    twic_extension = client.build_twic_extension(args, new_scim, CUSTOM_MAPPING_UPDATE,
                                                 parsed_new_scim.get('office_country'))

    # building twic extension schema
    if twic_extension:
        new_scim[TWIC_EXTENSION_SCHEMA] = twic_extension

    if SCIM_EXTENSION_SCHEMA in new_scim:
        new_scim.pop(SCIM_EXTENSION_SCHEMA)

    # Removing userName and emails from new_scim
    if "userName" in new_scim:
        new_scim.pop("userName")
    if "emails" in new_scim:
        new_scim.pop("emails")

    res = client.update_user_profile(user_term=user_id, data=new_scim)

    if res.status_code == 200:
        res_json = res.json()
        generic_iam_context = OutputContext(success=True,
                                            iden=res_json.get('id'),
                                            details=res_json,
                                            active=res_json.get('active'))
    else:
        res_json = res.json()
        generic_iam_context = OutputContext(success=False,
                                            iden=user_id,
                                            errorCode=res.status_code,
                                            errorMessage=res_json.get('detail'),
                                            details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(name='Update Twic User:',
                                      t=generic_iam_context.data,
                                      headers=["brand", "instanceName", "success", "active", "id", "username",
                                               "email", "errorCode", "errorMessage", "details"],
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

    if not user_id:
        raise Exception('You must provide id of the user')

    if demisto.command() == 'enable-user':
        format_pre_text = 'Enable'
        active = True
    elif demisto.command() == 'disable-user':
        format_pre_text = 'Disable'
        active = False

    twic_user = {
        "Operations": [
            {
                "op": "replace",
                "value": {
                    "active": active
                }
            }
        ]
    }

    res = client.enable_disable_user_profile(user_term=user_id, data=twic_user)

    if res.status_code == 200:
        res_json = res.json()
        generic_iam_context = OutputContext(success=True,
                                            iden=user_id,
                                            active=active,
                                            details=res_json)
    else:
        res_json = res.json()
        generic_iam_context = OutputContext(success=False,
                                            iden=user_id,
                                            errorCode=res.status_code,
                                            errorMessage=res_json.get('detail'),
                                            details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(name=f'{format_pre_text} Twic User:',
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

    # checks for '/' at the end url, if it is not available add it
    if base_url[-1] != '/':
        base_url += '/'

    # Resetting global variable
    global CUSTOM_MAPPING_CREATE
    CUSTOM_MAPPING_CREATE = demisto.params().get('customMappingCreateUser')
    global CUSTOM_MAPPING_UPDATE
    CUSTOM_MAPPING_UPDATE = demisto.params().get('customMappingUpdateUser')

    auth_token = params.get('authorization_token')
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
            auth_token=auth_token,
            verify=verify_certificate,
            headers={'Content-Type': 'application/json'},
            proxy=proxy)

        if command in commands:
            human_readable, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)

    # Log exceptions
    except Exception:
        return_error(f'Failed to execute {demisto.command()} command. Traceback: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

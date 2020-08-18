import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''
import traceback
import jwt
import requests


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
BASE_URL = 'https://api.zoom.us/v2/'
SCIM_EXTENSION_SCHEMA = "urn:scim:schemas:extension:custom:1.0:user"

'''CLIENT CLASS'''


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url, api_key, api_secret, verify=True, proxy=False, headers=None):
        self.base_url = base_url
        self.access_token = get_jwt(api_key, api_secret)
        self.verify = verify
        self.params = {'access_token': self.access_token}
        self.headers = headers
        self.session = requests.Session()
        if not proxy:
            self.session.trust_env = False

    def http_request(self, method, url_suffix, params=None, data=None, headers=None):
        if not params:
            params = self.params
        if not params.get('access_token', None):
            params['access_token'] = self.access_token
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

    # Getting User Id with a given username
    def get_user_id(self, username):
        uri = 'users'
        query_params = {
            'filter': encode_string_results(f'profile.login eq "{username}"')
        }

        res = self.http_request(
            method='GET',
            url_suffix=uri,
            params=query_params

        )
        return res

    def deactivate_user(self, user_id):
        uri = f'users/{user_id}/status'
        body = {
            "action": "deactivate"
        }
        return self.http_request(
            method="PUT",
            url_suffix=uri,
            data=body
        )

    def activate_user(self, user_id):
        uri = f'users/{user_id}/status'
        body = {
            "action": "activate"
        }
        return self.http_request(
            method="PUT",
            url_suffix=uri,
            data=body
        )

    def get_user(self, user_term):
        uri = f'users/{encode_string_results(user_term)}'
        return self.http_request(
            method='GET',
            url_suffix=uri
        )

    def create_user(self, data):
        uri = 'users'
        return self.http_request(
            method='POST',
            url_suffix=uri,
            data=data
        )

    def update_user(self, user_id, data):
        uri = f"users/{user_id}"
        return self.http_request(
            method='PATCH',
            url_suffix=uri,
            data=data
        )

    # Builds a new user zoom profile dict with pre-defined keys and custom mapping (for user)
    def build_zoom_profile_create_user(self, args, scim, custom_mapping):
        zoom_user = {}
        parsed_scim_data = map_scim(scim)
        user_info = {
            "email": parsed_scim_data.get('email'),
            "first_name": parsed_scim_data.get('first_name'),
            "last_name": parsed_scim_data.get('last_name'),
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
                    if value == "action":
                        zoom_user['action'] = user_extension_data
                    else:
                        user_info[value] = user_extension_data

        zoom_user['user_info'] = user_info
        return zoom_user

    # Builds a new user zoom profile dict with pre-defined keys and custom mapping (for user)
    def build_zoom_profile_update_user(self, args, scim, custom_mapping):
        parsed_scim_data = map_scim(scim)
        zoom_user = {
            "email": parsed_scim_data.get('email'),
            "first_name": parsed_scim_data.get('first_name'),
            "last_name": parsed_scim_data.get('last_name'),
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
                    zoom_user[value] = user_extension_data

        return zoom_user


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

    scim_extension = SCIM_EXTENSION_SCHEMA.replace('.', '\.')

    mapping = {
        "userName": "userName",
        "email": "emails(val.primary && val.primary==true).[0].value",
        "emailType": "emails(val.primary && val.primary==true).[0].type",
        "first_name": "name.givenName",
        "last_name": "name.familyName",
        "dept": scim_extension + ".department",
        "job_title": "title",
        "active": "active",
        "id": "id",
        "externalId": "externalId",
        "nameFormatted": "name.formatted",
        "nameHonorificPrefix": "name.honorificPrefix",
        "nameHonorificSuffix": "name.honorificSuffix",
        "nameMiddleName": "name.middleName",
        "nickName": "nickName",
        "organization": scim_extension + ".organization",
        "password": "password",
        "photo": "photos(val.type && val.type=='photo').[0].value",
        "preferredLanguage": "preferredLanguage",
        "timezone": "timezone",
        "userType": "userType"
    }
    parsed_scim = dict()
    for k, v in mapping.items():
        try:
            parsed_scim[k] = demisto.dt(scim, v)
        except Exception:
            parsed_scim[k] = None
    return parsed_scim


def get_jwt(api_key, api_secret):
    """
    Encode the JWT token given the api ket and secret
    """
    tt = datetime.now()
    expire_time = int(tt.strftime('%s')) + 5000
    payload = {
        'iss': api_key,
        'exp': expire_time
    }
    encoded = jwt.encode(payload, api_secret, algorithm='HS256')
    return encoded


''' COMMAND FUNCTIONS '''


def test_module(client, args):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    params = {
        'access_token': client.access_token,
        'status': 'active',
        'page_size': 1,
        'page_number': 1
    }
    res = client.http_request('get', 'users', params=params)
    if res.status_code == 200:
        return 'ok', None, None
    else:
        raise Exception(f"{res.status_code} - {res.text}")


def enable_disable_user_command(client, args):
    scim = verify_and_load_scim_data(args.get('scim'))
    parsed_scim = map_scim(scim)
    user_id = parsed_scim.get('id')
    username = parsed_scim.get('userName')
    email = parsed_scim.get('email')

    if not (user_id or username or email):
        raise Exception('You must provide either the id,, email or username of the user')

    if user_id:
        user_term = user_id
    else:
        user_term = email if email else username

    if demisto.command() == 'enable-user':
        format_pre_text = 'Enable'
        active = True
        res = client.activate_user(user_term)
    elif demisto.command() == 'disable-user':
        format_pre_text = 'Disable'
        active = False
        res = client.deactivate_user(user_term)

    if res.status_code == 204:
        generic_iam_context = OutputContext(success=True, iden=user_id, username=username, active=active)
    elif res.status_code == 404:
        res_json = res.json()
        generic_iam_context = OutputContext(success=False, iden=user_id, username=username, errorCode=404,
                                            errorMessage=res_json.get('message'), details=res_json)
    else:
        res_json = res.json()
        generic_iam_context = OutputContext(success=False, iden=user_id, username=username,
                                            errorCode=res_json.get('code'),
                                            errorMessage=res_json.get('message'), details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(f'{format_pre_text} Zoom User:', generic_iam_context.data)
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def get_user_command(client, args):
    scim = verify_and_load_scim_data(args.get('scim'))
    scim_flat_data = map_scim(scim)
    user_id = scim_flat_data.get('id')
    username = scim_flat_data.get('userName')
    email = scim_flat_data.get('email')

    if not (user_id or username or email):
        raise Exception('You must provide either the id,, email or username of the user')

    if user_id:
        user_term = user_id
    else:
        user_term = email if email else username

    res = client.get_user(user_term)
    res_json = res.json()

    if res.status_code == 200:
        active = True if res_json['status'] == "active" else False
        generic_iam_context = OutputContext(success=True, iden=res_json.get('id'), email=res_json.get('email'),
                                            username=username, details=res_json, active=active)
    elif res.status_code == 404:
        generic_iam_context = OutputContext(success=False, iden=user_id, username=username, errorCode=404,
                                            errorMessage=res_json.get('message'), details=res_json)
    else:
        generic_iam_context = OutputContext(success=False, iden=user_id, username=username,
                                            errorCode=res_json.get('code'),
                                            errorMessage=res_json.get('message'), details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown('Get Zoom User:', generic_iam_context.data)
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def create_user_command(client, args):
    custom_mapping = demisto.params().get('customMappingCreateUser')
    scim = verify_and_load_scim_data(args.get('scim'))
    parsed_scim = map_scim(scim)

    zoom_user = client.build_zoom_profile_create_user(args, scim, custom_mapping)
    res = client.create_user(zoom_user)
    res_json = res.json()
    demisto.log(str(res_json))

    if res.status_code == 201:
        generic_iam_context = OutputContext(success=True, iden=res_json.get('id'), email=res_json.get('email'),
                                            details=res_json, active=True)
    else:
        generic_iam_context = OutputContext(success=False, username=scim.get('userName'),
                                            email=parsed_scim.get('email'),
                                            errorCode=res_json.get('code'),
                                            errorMessage=res_json.get('message'), details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown('Create Zoom User:', generic_iam_context.data)
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
        raise Exception('You must provide either the id,, email or username of the user')

    if user_id:
        user_term = user_id
    else:
        user_term = email if email else username

    zoom_user_profile = client.build_zoom_profile_update_user(args, new_scim, custom_mapping)
    res = client.update_user(user_id=user_term, data=zoom_user_profile)

    if res.status_code == 204:
        generic_iam_context = OutputContext(success=True, iden=user_id, email=email,
                                            username=username)
    else:
        res_json = res.json()
        generic_iam_context = OutputContext(success=False, username=username,
                                            email=email,
                                            errorCode=res_json.get('code'),
                                            errorMessage=res_json.get('message'), details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown('Update Zoom User:', generic_iam_context.data)
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

    api_key = params.get('apiKey')
    api_secret = params.get('apiSecret')
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

    client = Client(
        base_url=BASE_URL,
        api_key=api_key,
        api_secret=api_secret,
        verify=verify_certificate,
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        proxy=proxy)

    try:
        if command in commands:
            human_readable, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)
    # Log exceptions
    except Exception:
        return_error(f'Failed to execute {demisto.command()} command. Traceback: {traceback.format_exc()}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

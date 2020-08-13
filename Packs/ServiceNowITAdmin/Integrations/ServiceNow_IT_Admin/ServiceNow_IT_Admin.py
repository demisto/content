import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''
import traceback
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
BASE_URI = "/api/now/"
SCIM_EXTENSION_SCHEMA = "urn:scim:schemas:extension:custom:1.0:user"
USER_NOT_FOUND = "User not found"

'''CLIENT CLASS'''


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url, username, password, verify=True, proxy=False, headers=None, auth=None):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.verify = verify
        self.headers = headers
        self.auth = auth
        self.session = requests.Session()
        if not proxy:
            self.session.trust_env = False

    def http_request(self, method, url_suffix, params=None, data=None):
        full_url = self.base_url + url_suffix
        res = requests.request(
            method,
            full_url,
            verify=self.verify,
            params=params,
            json=data,
            auth=(self.username, self.password)
        )
        return res

    def get_user(self, input_type, user_term):
        uri = '/table/sys_user'
        params = {
            input_type: user_term
        }
        return self.http_request(
            method='GET',
            url_suffix=uri,
            params=params
        )

    def create_user(self, data):
        uri = '/table/sys_user'
        return self.http_request(
            method='POST',
            url_suffix=uri,
            data=data
        )

    def update_user(self, sys_id, data):
        uri = f'/table/sys_user/{sys_id}'
        return self.http_request(
            method='PATCH',
            url_suffix=uri,
            data=data
        )

    def build_servicenow_user_profile(self, args, scim, custom_mapping):
        parsed_scim_data = map_scim(scim)
        servicenow_user = {
            "user_name": parsed_scim_data.get('userName'),
            "first_name": parsed_scim_data.get('first_name'),
            "last_name": parsed_scim_data.get('last_name'),
            "active": parsed_scim_data.get('active'),
            "email": parsed_scim_data.get('email')
        }
        if args.get('customMapping'):
            custom_mapping = json.loads(args.get('customMapping'))
        elif custom_mapping:
            custom_mapping = json.loads(custom_mapping)

        extension_schema = scim.get(SCIM_EXTENSION_SCHEMA)
        if custom_mapping and extension_schema:
            for key, value in custom_mapping.items():
                # key is the attribute name in input scim. value is the attribute name of app profile
                if extension_schema.get(key):
                    servicenow_user[value] = extension_schema.get(key)

        return servicenow_user


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


'''HELPER FUNCTIONS'''


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
            parsed_scim[k] = demisto.dt(scim, v)
        except Exception:
            parsed_scim[k] = None
    return parsed_scim


'''COMMAND FUNCTIONS'''


def test_module(client, args):
    uri = '/table/sys_user?sysparm_limit=1'
    res = client.http_request('get', uri)
    if res.status_code == 200:
        demisto.results('ok')
    else:
        return_error('Error testing [%d] - %s' % (res.status_code, res.text))


def get_user_command(client, args):
    """
        Returning user GET details and status of response.

        Args:   demisto command line argument
        client: Service client

        Returns:
            success : success=True, id, email, login as username, details, active status
            fail : success=False, id, login as username, errorCode, errorMessage, details
    """
    scim = verify_and_load_scim_data(args.get('scim'))
    parsed_scim_data = map_scim(scim)
    user_id = parsed_scim_data.get('id')
    username = parsed_scim_data.get('userName')
    email = parsed_scim_data.get('email')

    if not (user_id or username or email):
        raise Exception('You must provide either the id, username or of the user')

    if user_id:
        user_term = user_id
        input_type = 'sys_id'
    else:
        if username:
            user_term = username
            input_type = 'user_name'
        else:
            user_term = email
            input_type = 'email'

    res = client.get_user(input_type, user_term)
    res_json = res.json()
    generic_iam_context_data_list = []
    if res.status_code == 200:
        result = res_json['result']
        if len(result) > 0:
            for item in result:
                active = True if item['active'] == 'true' else False
                generic_iam_context = OutputContext(success=True, iden=item['sys_id'], email=item['email'],
                                                    username=item['user_name'], details=item, active=active)
                generic_iam_context_data_list.append(generic_iam_context.data)
        else:
            generic_iam_context = OutputContext(success=False, iden=user_id, username=username, errorCode=404, email=email,
                                                errorMessage=USER_NOT_FOUND)
            generic_iam_context_data_list.append(generic_iam_context.data)
    else:
        generic_iam_context = OutputContext(success=False, iden=user_id, username=username, email=email,
                                            errorCode=res.status_code,
                                            errorMessage=res_json.get('error', {}).get('message'), details=res_json)
        generic_iam_context_data_list.append(generic_iam_context.data)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context_data_list
    }
    readable_output = tableToMarkdown(name='Get ServiceNow User:',
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
        Create user using POST to Servicenow API , if Connection to the service is successful.

        Args:   demisto command line argument
        client: Service Client

        Returns:
            success : success=True, id, email, login as username, details, active status
            fail : success=False, id, login as username, errorCod, errorMessage, details
    """
    scim = verify_and_load_scim_data(args.get('scim'))
    custom_mapping = demisto.params().get('customMappingCreateUser')

    servicenow_user = client.build_servicenow_user_profile(args, scim, custom_mapping)
    res = client.create_user(servicenow_user)

    res_json = res.json()
    if res.status_code == 201:
        result = res_json['result']
        active = True if result['active'] == 'true' else False
        id = result['sys_id']
        email = result['email']
        username = result['user_name']

        generic_iam_context = OutputContext(success=True, iden=id, email=email,
                                            username=username, details=result, active=active)
    else:
        generic_iam_context = OutputContext(success=False, errorCode=res.status_code,
                                            errorMessage=res_json.get('error', {}).get('message'), details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }
    readable_output = tableToMarkdown('Create ServiceNow User:', t=generic_iam_context.data,
                                      headers=["brand", "instanceName", "success", "active", "id", "username", "email",
                                               "errorCode", "errorMessage", "details"],
                                      removeNull=True
                                      )
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def update_user_command(client, args):
    """
        Update user using PATCH to Servicenow API , if Connection to the service is successful.

        Args:   demisto command line argument
        client: Service Client

        Returns:
            success : success=True, id, email, login as username, details, active status
            fail : success=False, id, login as username, errorCod, errorMessage, details
    """
    old_scim = verify_and_load_scim_data(args.get('oldScim'))
    new_scim = verify_and_load_scim_data(args.get('newScim'))
    custom_mapping = demisto.params().get('customMappingUpdateUser')

    parsed_old_scim = map_scim(old_scim)
    user_id = parsed_old_scim.get('id')

    if not (user_id):
        raise Exception('You must provide id of the user')

    servicenow_user = client.build_servicenow_user_profile(args, new_scim, custom_mapping)
    res = client.update_user(user_id, servicenow_user)
    res_json = res.json()

    if res.status_code == 200:
        result = res_json['result']
        active = True if result['active'] == 'true' else False
        id = result['sys_id']
        email = result['email']
        username = result['user_name']

        generic_iam_context = OutputContext(success=True, iden=id, email=email,
                                            username=username, details=result, active=active)
    else:
        generic_iam_context = OutputContext(success=False, iden=user_id, errorCode=res.status_code,
                                            errorMessage=res_json.get('error', {}).get('message'), details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }
    readable_output = tableToMarkdown('Update ServiceNow User:', t=generic_iam_context.data,
                                      headers=["brand", "instanceName", "success", "active", "id", "username", "email",
                                               "errorCode", "errorMessage", "details"],
                                      removeNull=True
                                      )
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def disable_user_command(client, args):
    """
        Disable user using PATCH to Servicenow API , if Connection to the service is successful.

        Args:   demisto command line argument
        client: Service Client

        Returns:
            success : success=True, id, email, login as username, details, active status
            fail : success=False, id, login as username, errorCod, errorMessage, details
    """
    scim = verify_and_load_scim_data(args.get('scim'))
    parsed_scim_data = map_scim(scim)
    user_id = parsed_scim_data.get('id')

    if not (user_id):
        raise Exception('You must provide sys id of the user')

    servicenow_user = {'active': False}
    res = client.update_user(user_id, servicenow_user)
    res_json = res.json()

    if res.status_code == 200:
        result = res_json['result']
        active = True if result['active'] == 'true' else False
        id = result['sys_id']
        email = result['email']
        username = result['user_name']

        generic_iam_context = OutputContext(success=True, iden=id, email=email,
                                            username=username, details=result, active=active)
    else:
        generic_iam_context = OutputContext(success=False, iden=user_id, errorCode=res.status_code,
                                            errorMessage=res_json.get('error', {}).get('message'), details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }
    readable_output = tableToMarkdown('Disable ServiceNow User:', t=generic_iam_context.data,
                                      headers=["brand", "instanceName", "success", "active", "id", "username", "email",
                                               "errorCode", "errorMessage", "details"],
                                      removeNull=True
                                      )
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def enable_user_command(client, args):
    """
        Enable user using PATCH to Servicenow API , if Connection to the service is successful.

        Args:   demisto command line argument
        client: Service Client

        Returns:
            success : success=True, id, email, login as username, details, active status
            fail : success=False, id, login as username, errorCod, errorMessage, details
    """
    scim = verify_and_load_scim_data(args.get('scim'))
    parsed_scim_data = map_scim(scim)
    user_id = parsed_scim_data.get('id')

    if not (user_id):
        raise Exception('You must provide sys id of the user')

    custom_mapping = demisto.params().get('customMappingUpdateUser')
    servicenow_user = client.build_servicenow_user_profile(args, scim, custom_mapping)
    servicenow_user['active'] = True
    servicenow_user['locked_out'] = False
    res = client.update_user(user_id, servicenow_user)
    res_json = res.json()

    if res.status_code == 200:
        result = res_json['result']
        active = True if result['active'] == 'true' else False
        id = result['sys_id']
        email = result['email']
        username = result['user_name']

        generic_iam_context = OutputContext(success=True, iden=id, email=email,
                                            username=username, details=result, active=active)
    else:
        generic_iam_context = OutputContext(success=False, iden=user_id, errorCode=res.status_code,
                                            errorMessage=res_json.get('error', {}).get('message'), details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }
    readable_output = tableToMarkdown('Enable ServiceNow User:', t=generic_iam_context.data,
                                      headers=["brand", "instanceName", "success", "active", "id", "username", "email",
                                               "errorCode", "errorMessage", "details"],
                                      removeNull=True
                                      )
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
    api_version = params.get('api_version', None)

    # get the service API url
    base_url = urljoin(params.get('url').strip('/'), BASE_URI)
    if api_version:
        base_url += api_version

    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    command = demisto.command()

    LOG(f'Command being called is {command}')
    commands = {
        'test-module': test_module,
        'get-user': get_user_command,
        'create-user': create_user_command,
        'update-user': update_user_command,
        'disable-user': disable_user_command,
        'enable-user': enable_user_command
    }

    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        username=username,
        password=password,
        proxy=proxy)

    try:
        if command in commands:
            human_readable, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)
    # Log exceptions
    except Exception:
        demisto.error(f'Failed to execute {demisto.command()} command. Traceback: {traceback.format_exc()}')
        return_error(f'Failed to execute {demisto.command()} command. Traceback: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

import demistomock as demisto
from CommonServerPython import *

import json
import traceback

import requests

''' IMPORTS '''

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
URI_PREFIX = '/services/data/v51.0/'
SCIM_EXTENSION_SCHEMA = "urn:scim:schemas:extension:custom:1.0:user"
CUSTOM_MAPPING_CREATE = demisto.params().get('customMappingCreateUser')
CUSTOM_MAPPING_UPDATE = demisto.params().get('customMappingUpdateUser')
USER_DELETED = "User deleted"
ENTITY_IS_ALREADY_DELETED = "Entity is already deleted"
USER_EXIST = "User already exist"
USER_NOT_FOUND = "User not found"
USER_ENABLED = "User is enabled"


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url, conn_client_id, conn_client_secret, conn_username,
                 conn_password, headers, verify=True, proxy=False):
        self.base_url = base_url
        self.conn_client_id = conn_client_id
        self.conn_client_secret = conn_client_secret
        self.conn_username = conn_username
        self.conn_password = conn_password
        self.verify = verify
        self.headers = headers
        self.session = requests.Session()
        if not proxy:
            self.session.trust_env = False
        res = self.create_login()
        res_json = res.json()
        self.headers['content-type'] = 'application/json'
        if res_json.get('access_token') is not None:
            self.headers['Authorization'] = "Bearer " + res_json.get('access_token')
        else:
            self.headers['Authorization'] = None

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
        uri = '/services/oauth2/token'
        params = {
            "client_id": self.conn_client_id,
            "client_secret": self.conn_client_secret,
            "username": self.conn_username,
            "password": self.conn_password,
            "grant_type": "password"
        }
        return self.http_request(
            method='POST',
            url_suffix=uri,
            params=params
        )

    def get_user_profile(self, user_term):
        uri = URI_PREFIX + f'sobjects/FF__Key_Contact__c/{encode_string_results(user_term)}'
        return self.http_request(
            method='GET',
            url_suffix=uri
        )

    def search_user_profile(self, user_term, user_where):
        uri = URI_PREFIX + 'parameterizedSearch/'
        params = {
            "q": user_term,
            "sobject": "FF__Key_Contact__c",
            "FF__Key_Contact__c.where": user_where,
            "FF__Key_Contact__c.fields": "Id, FF__First_Name__c, FF__Last_Name__c,Work_Email__c,Name"
        }

        return self.http_request(
            method='GET',
            url_suffix=uri,
            params=params
        )

    def create_user_profile(self, data):
        uri = URI_PREFIX + 'sobjects/FF__Key_Contact__c'
        return self.http_request(
            method='POST',
            url_suffix=uri,
            data=data
        )

    def update_user_profile(self, user_term, data):
        uri = URI_PREFIX + f'sobjects/FF__Key_Contact__c/{encode_string_results(user_term)}'
        params = {"_HttpMethod": "PATCH"}
        return self.http_request(
            method='POST',
            url_suffix=uri,
            params=params,
            data=data
        )

    def delete_user(self, id):
        uri = URI_PREFIX + f'sobjects/FF__Key_Contact__c/{encode_string_results(id)}'
        return self.http_request(
            method='DELETE',
            url_suffix=uri
        )

    def build_salesforce_profile_update_user(self, args, scim):
        parsed_scim_data = map_scim(scim)

        salesforce_user = {
            "FF__First_Name__c": parsed_scim_data.get('first_name'),
            "FF__Last_Name__c": parsed_scim_data.get('last_name'),
            "FF__Mobile_Phone__c": parsed_scim_data.get('mobile_phone'),
            "Work_Mobile_SMS__c": parsed_scim_data.get('phone'),
            "Facility_Location__c": parsed_scim_data.get('city'),
            "FF__Title__c": parsed_scim_data.get('title'),
            "Work_Email__c": parsed_scim_data.get('email')

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
                    salesforce_user[value] = user_extension_data

        return salesforce_user

        # Builds a new user salesforce profile dict with pre-defined keys and custom mapping (for user)

    def build_salesforce_profile_create_user(self, args, scim):
        parsed_scim_data = map_scim(scim)
        salesforce_user = {
            "FF__First_Name__c": parsed_scim_data.get('first_name'),
            "FF__Last_Name__c": parsed_scim_data.get('last_name'),
            "FF__Mobile_Phone__c": parsed_scim_data.get('mobile_phone'),
            "Work_Mobile_SMS__c": parsed_scim_data.get('phone'),
            "Facility_Location__c": parsed_scim_data.get('city'),
            "FF__Title__c": parsed_scim_data.get('title'),
            "Work_Email__c": parsed_scim_data.get('email'),
            "Name": parsed_scim_data.get('first_name') + " " + parsed_scim_data.get('last_name')
        }

        custom_mapping = None
        if args.get('customMapping'):
            custom_mapping = json.loads(args.get('customMapping'))
        elif CUSTOM_MAPPING_CREATE:
            custom_mapping = json.loads(CUSTOM_MAPPING_CREATE)

        extension_schema = scim.get(SCIM_EXTENSION_SCHEMA)
        if custom_mapping and extension_schema:

            for key, value in custom_mapping.items():
                # key is the attribute name in input scim. value is the attribute name of app profile

                user_extension_data = extension_schema.get(key)
                if user_extension_data:
                    salesforce_user[value] = user_extension_data
        return salesforce_user


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
        "name": "displayName",
        "nick_name": "nickName",
        "id": "id",
        "active": "active",
        "address": "addresses(val.primary && val.primary==true).formatted",
        "street": "addresses(val.primary && val.primary==true).streetAddress",
        "city": "addresses(val.primary && val.primary==true).locality",
        "country": "addresses(val.primary && val.primary==true).country",
        "state": "addresses(val.primary && val.primary==true).region",
        "zip": "addresses(val.primary && val.primary==true).postalCode",
        "timezone": "timezone",
        "locale": "locale",
        "mobile_phone": "phoneNumbers(val.type && val.type=='mobile').value",
        "phone": "phoneNumbers(val.type && val.type=='work').value",
        "title": "title",
        "user_type": "userType",
        "full_photo_url": "photos(val.type && val.type=='photo').value",
        "small_photo_url": "photos(val.type && val.type=='thumbnail').value",
    }
    parsed_scim = dict()
    for k, v in mapping.items():
        try:
            value = demisto.dt(scim, v)
            if (type(value) == list):
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
        client: SalesforceFusion client
        args  : SalesforceFusion arguments passed

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    args
    uri = URI_PREFIX + 'sobjects/User/testid'
    res = client.http_request(method='GET', url_suffix=uri)
    if res.status_code == 200 or res.status_code == 404:
        return 'ok', None, None
    else:
        res_json = res.json()[0]
        error_response = res_json.get('message')
        raise Exception(f"Failed to execute test_module. Error Code: {res.status_code}.Error "
                        f"Response: {error_response}")


def get_user_command(client, args):
    """
           Returning user GET details and status of response.

           Args:   demisto command line argument
           client: Salesforce Fusion

           Returns:
               success : success=True, id, email, login as username, details, active status
               fail : success=False, id, login as username, errorCode, errorMessage, details
       """

    scim = verify_and_load_scim_data(args.get('scim'))
    scim_flat_data = map_scim(scim)
    user_id = scim_flat_data.get('id')
    username = scim_flat_data.get('userName')
    email = scim_flat_data.get('email')
    get_json = True
    generic_iam_context_data_list = []
    res_json_list = []

    if not (user_id or username or email):
        raise Exception('You must provide either the id, email or username of the user')

    if user_id:
        res = client.get_user_profile(user_id)
    else:
        if username:
            user_term = username
            user_where = f"Work_Email__c='{username}'"
            # user_where = f"Name='{username}'"
        else:
            user_term = email
            user_where = f"Work_Email__c='{email}'"
        res = client.search_user_profile(user_term, user_where)
        if res.status_code == 200:
            get_json = False
            res_json = res.json()
            search_records = res_json.get('searchRecords')
            if len(search_records) > 0:
                for search_record in search_records:
                    user_id = search_record.get('Id')
                    res = client.get_user_profile(user_id)
                    res_json_list.append(res.json())
            elif len(search_records) == 0:
                res.status_code = 404

    if res.status_code == 200:
        if get_json is True:
            res_json_list.append(res.json())
        for res_json in res_json_list:
            generic_iam_context = OutputContext(success=True, iden=res_json.get('Id'),
                                                email=res_json.get('Work_Email__c'),
                                                username=res_json.get('Work_Email__c'), details=res_json,
                                                active=True)
            generic_iam_context_data_list.append(generic_iam_context.data)
    elif res.status_code == 404:
        generic_iam_context = OutputContext(success=False, iden=user_id,
                                            errorCode=404, errorMessage=USER_NOT_FOUND,
                                            details=USER_NOT_FOUND,
                                            email=email, username=username)
        generic_iam_context_data_list.append(generic_iam_context.data)
    else:
        if get_json is True:
            res_json = res.json()[0]
        generic_iam_context = OutputContext(success=False, iden=user_id,
                                            errorCode=res.status_code,
                                            errorMessage=res_json.get('message'),
                                            details=res.json())
        generic_iam_context_data_list.append(generic_iam_context.data)

    # Sending outputs as list only if get-user needs to return more than 1 row
    generic_iam_context_data = generic_iam_context_data_list if len(generic_iam_context_data_list) > 1 else \
        generic_iam_context_data_list[0]

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context_data
    }

    readable_output = tableToMarkdown(name='Get Salesforce User:',
                                      t=generic_iam_context_data,
                                      headers=["brand", "instanceName", "success", "active", "id", "username", "email",
                                               "errorCode", "errorMessage", "details"],
                                      removeNull=True
                                      )
    return (
        readable_output,
        outputs,
        generic_iam_context_data
    )


def update_user_command(client, args):
    """
            Update user using PUT to Salesforce Fusion API , if Connection to the service is successful.

            Args:   demisto command line argument
            client: Salesforce Fusion

            Returns:
                success : success=True, id, details, active status
                fail : success=False, id, login as username, errorCod, errorMessage, details
        """

    old_scim = verify_and_load_scim_data(args.get('oldScim'))
    new_scim = verify_and_load_scim_data(args.get('newScim'))

    parsed_old_scim = map_scim(old_scim)
    user_id = parsed_old_scim.get('id')

    if not user_id:
        raise Exception('You must provide id of the user')

    salesforce_user = client.build_salesforce_profile_update_user(args, new_scim)

    # Removing Elements from salesforce user dictionary which was not sent as part of scim
    salesforce_user = {key: value for key, value in salesforce_user.items() if value is not None}

    res = client.update_user_profile(user_term=user_id, data=salesforce_user)

    if res.status_code == 204:
        generic_iam_context = OutputContext(success=True,
                                            iden=user_id,
                                            active=True)
    elif res.status_code == 404:
        res_json = res.json()[0]
        generic_iam_context = OutputContext(success=False, iden=user_id,
                                            errorCode=404, errorMessage=USER_NOT_FOUND,
                                            details=res_json.get('message'))
    else:
        res_json = res.json()[0]
        generic_iam_context = OutputContext(success=False,
                                            iden=user_id,
                                            errorCode=res.status_code,
                                            errorMessage=res_json.get('message'),
                                            details=res.json())

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(name='Update Salesforce Fusion  User:',
                                      t=generic_iam_context.data,
                                      headers=["brand", "instanceName", "success", "active", "id", "username",
                                               "email", "errorCode", "errorMessage", "details"],
                                      removeNull=True)
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def create_user_command(client, args):
    """
            Create user using POST to Salesforce Fusion  API, if Connection to the service is successful.

            Args: demisto command line argument
            client: Salesforce Fusion

            Returns:
                success : success=True, id, email, login as username, details, active status
                fail : success=False, id, login as username, errorCode, errorMessage, details
        """
    scim = verify_and_load_scim_data(args.get('scim'))
    parsed_scim = map_scim(scim)

    salesforce_user = client.build_salesforce_profile_create_user(args, scim)

    # Removing Elements from salesforce_user dictionary which was not sent as part of scim
    salesforce_user = {key: value for key, value in salesforce_user.items() if value is not None}

    res = client.create_user_profile(salesforce_user)

    if res.status_code == 201:
        res_json = res.json()
        generic_iam_context = OutputContext(success=True,
                                            iden=res_json.get('id'),
                                            email=parsed_scim.get('email'),
                                            username=parsed_scim.get('userName'),
                                            details=res_json,
                                            active=True)
    elif res.status_code == 400:
        res_json = res.json()[0]
        generic_iam_context = OutputContext(success=False, iden=res_json.get('id'),
                                            email=parsed_scim.get('email'),
                                            username=parsed_scim.get('userName'),
                                            errorCode=400, errorMessage=USER_EXIST,
                                            details=res_json.get('message'))
    else:
        res_json = res.json()[0]
        generic_iam_context = OutputContext(success=False,
                                            email=parsed_scim.get('email'),
                                            username=parsed_scim.get('userName'),
                                            errorCode=res.status_code,
                                            errorMessage=res_json.get('message'),
                                            details=res.json())

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(name='Create Salesforce Fusion User:',
                                      t=generic_iam_context.data,
                                      headers=["brand", "instanceName", "success", "active", "id", "username",
                                               "email", "errorCode", "errorMessage", "details"],
                                      removeNull=True)
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def enable_user_command(client, args):
    """
            There is no action on the user for Salesforce Fusion instance needs to be taken.
            Args:   demisto command line argument
            client: Salesforce Fusion API

            Returns:
                success : success=True, id as iden, active status
                fail : success=False, id as iden, errorCod, errorMessage, details
        """

    scim = verify_and_load_scim_data(args.get('scim'))
    user_id = scim.get('id')

    if not user_id:
        raise Exception('You must provide the id of the user')

    if user_id:
        res = client.get_user_profile(user_id)

    if res.status_code == 200:
        generic_iam_context = OutputContext(success=True, iden=user_id,
                                            details=USER_ENABLED,
                                            active=True)
    elif res.status_code == 404:
        generic_iam_context = OutputContext(success=False, iden=user_id,
                                            errorCode=404, errorMessage=USER_NOT_FOUND,
                                            details=USER_NOT_FOUND, active=False)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(name="Enable Salesforce Fusion User",
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
        Delete user from Salesforce Fusion instance , if Connection to the service is successful.

        Args:   demisto command line argument
        client: Salesforce Fusion API

        Returns:
            success : success=True, id as iden, active status
            fail : success=False, id as iden, errorCod, errorMessage, details
    """
    scim = verify_and_load_scim_data(args.get('scim'))
    user_id = scim.get('id')

    if not user_id:
        raise Exception('You must provide the id of the user')

    res = client.delete_user(user_id)

    if res.status_code == 204:
        generic_iam_context = OutputContext(success=True,
                                            iden=user_id,
                                            details=USER_DELETED,
                                            active=False)
    elif res.status_code == 404:
        res_json = res.json()[0]
        generic_iam_context = OutputContext(success=True,
                                            iden=user_id,
                                            errorCode=res.status_code,
                                            errorMessage=res_json.get('message'),
                                            details=ENTITY_IS_ALREADY_DELETED)
    else:
        res_json = res.json()[0]
        generic_iam_context = OutputContext(success=False,
                                            iden=user_id,
                                            errorCode=res.status_code,
                                            errorMessage=res_json.get('message'),
                                            details=res.json())

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(name="Delete Salesforce Fusion User",
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
    client_id = params.get('client_id')
    client_secret = params.get('client_secret')
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    secret_token = params.get('secret_token')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
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

    try:
        client = Client(
            base_url=base_url,
            conn_client_id=client_id,
            conn_client_secret=client_secret,
            conn_username=username,
            conn_password=password + secret_token,
            verify=verify_certificate,
            headers={},
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

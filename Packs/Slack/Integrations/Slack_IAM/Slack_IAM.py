import demistomock as demisto
from CommonServerPython import *
from json import JSONDecodeError
import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS '''
INPUT_SCIM_EXTENSION_KEY = "urn:scim:schemas:extension:custom:1.0:user"
SLACK_SCIM_EXTENSION_KEY = "urn:scim:schemas:extension:enterprise:1.0"
SLACK_SCIM_CORE_SCHEMA_KEY = "urn:scim:schemas:core:1.0"

'''CLIENT CLASSES'''


class Client(BaseClient):
    """
    Slack IAM Client class that implements logic to authenticate with Slack.
    """

    def test(self):
        uri = '/Users?count=1'
        res = self._http_request(method='GET', url_suffix=uri)
        return res

    def get_user(self, email):
        uri = '/Users'
        query_params = {
            'filter': f'email eq {email}'
        }

        res = self._http_request(
            method='GET',
            url_suffix=uri,
            params=query_params
        )
        if res and res.get('totalResults') == 1:
            user_app_data = res.get('Resources')[0]
            user_id = user_app_data.get('id')
            is_active = user_app_data.get('active')
            username = user_app_data.get('userName')
            return IAMUserAppData(user_id, username, is_active, user_app_data)
        return None

    def create_user(self, user_data):
        uri = '/Users'
        user_data["schemas"] = ["urn:scim:schemas:core:1.0"]  # Mandatory user profile field.
        res = self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=user_data
        )
        user_app_data = res
        user_id = user_app_data.get('id')
        is_active = user_app_data.get('active')
        username = user_app_data.get('userName')

        return IAMUserAppData(user_id, username, is_active, user_app_data)

    def update_user(self, user_id, user_data):
        uri = f'/Users/{user_id}'
        res = self._http_request(
            method='PATCH',
            url_suffix=uri,
            json_data=user_data
        )
        user_app_data = res
        user_id = user_app_data.get('id')
        is_active = user_app_data.get('active')
        username = user_app_data.get('userName')

        return IAMUserAppData(user_id, username, is_active, user_app_data)

    def disable_user(self, user_id):
        user_data = {'active': False}
        return self.update_user(user_id, user_data)

    def get_app_fields(self):
        app_fields = {}
        uri = '/Schemas/Users'
        res = self._http_request(
            method='GET',
            url_suffix=uri
        )

        elements = res.get('attributes', [])
        for elem in elements:
            if elem.get('name'):
                field_name = elem.get('name')
                description = elem.get('description')
                app_fields[field_name] = description

        return app_fields

    @staticmethod
    def handle_exception(user_profile, e, action):
        """ Handles failed responses from the application API by setting the User Profile object with the results.

        Args:
            user_profile (IAMUserProfile): The User Profile object.
            e (Exception): The exception error. If DemistoException, holds the response json.
            action (IAMActions): An enum represents the current action (get, update, create, etc).
        """
        if e.__class__ is DemistoException and hasattr(e, 'res') and e.res is not None:
            error_code = e.res.status_code
            try:
                resp = e.res.json()
                error_message = resp.get('Errors', {}).get('description')
            except ValueError:
                error_message = str(e)
        else:
            error_code = ''
            error_message = str(e)

        user_profile.set_result(action=action,
                                success=False,
                                error_code=error_code,
                                error_message=error_message)

        demisto.error(traceback.format_exc())


class GroupClient(BaseClient):
    """
    GroupClient will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """
    def __init__(self, base_url, verify=True, proxy=False, headers=None):
        self.base_url = base_url
        self.verify = verify
        self.headers = headers
        self.session = requests.Session()
        if not proxy:
            self.session.trust_env = False

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

    def get_group_by_id(self, group_id):
        uri = f'/Groups/{group_id}'
        return self.http_request(
            method="GET",
            url_suffix=uri
        )

    def search_group(self, group_name):
        uri = '/Groups'
        query_params = {
            'filter': f'displayName eq "{group_name}"'
        }
        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params
        )

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

    def get_group_by_id(self, group_id):
        uri = f'groups/{group_id}'
        return self.http_request(
            method='GET',
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

        scim['schemas'] = [SLACK_SCIM_CORE_SCHEMA_KEY, SLACK_SCIM_EXTENSION_KEY]

        return scim


'''COMMAND FUNCTIONS'''


def test_module(client):
    client.test()
    return_results('ok')


def get_mapping_fields(client: Client) -> GetMappingFieldsResponse:
    """ Creates and returns a GetMappingFieldsResponse object of the user schema in the application

    :param client: (Client) The integration Client object that implements a get_app_fields() method
    :return: (GetMappingFieldsResponse) An object that represents the user schema
    """
    app_fields = client.get_app_fields()
    incident_type_scheme = SchemeTypeMapping(type_name=IAMUserProfile.INDICATOR_TYPE)

    for field, description in app_fields.items():
        incident_type_scheme.add_field(field, description)

    return GetMappingFieldsResponse([incident_type_scheme])


class OutputContext:
    """
        Class to build a generic output and context.
    """
    def __init__(self, success=None, active=None, id=None, username=None, email=None, errorCode=None,
                 errorMessage=None, details=None, displayName=None, members=None):
        self.instanceName = demisto.callingContext['context']['IntegrationInstance']
        self.brand = demisto.callingContext['context']['IntegrationBrand']
        self.command = demisto.command().replace('-', '_').title().replace('_','')
        self.success = success
        self.active = active
        self.id = id
        self.username = username
        self.email = email
        self.errorCode = errorCode
        self.errorMessage = errorMessage
        self.details = details
        self.displayName = displayName  # Used in group
        self.members = members  # Used in group
        self.data = {
            "brand": self.brand,
            "instanceName": self.instanceName,
            "success": success,
            "active": active,
            "id": id,
            "username": username,
            "email": email,
            "errorCode": errorCode,
            "errorMessage": errorMessage,
            "details": details,
            "displayName": displayName,
            "members": members
        }
        # Remoove empty values
        self.data = {
            k: v
            for k, v in self.data.items()
            if v is not None
        }


def map_scim(clientData):
    try:
        clientData = json.loads(clientData)
    except:
        pass
    if type(clientData) != dict:
        raise Exception('Provided client data is not JSON compatible')

    scim_extension = INPUT_SCIM_EXTENSION_KEY.replace('.','\.')
    mapping = {
        "active": "active",
        "addressCountry": "addresses(val.primary && val.primary==true).[0].country",
        "addressFormatted": "addresses(val.primary && val.primary==true).[0].formatted",
        "addressLocailty": "addresses(val.primary && val.primary==true).[0].locality",
        "addressPostalCode": "addresses(val.primary && val.primary==true).[0].postalCode",
        "addressRegion": "addresses(val.primary && val.primary==true).[0].region",
        "addressStreeetAddress": "addresses(val.primary && val.primary==true).[0].streetAddress",
        "addressType": "addresses(val.primary && val.primary==true).[0].type",
        "costCenter": scim_extension + ".costCenter",
        "department": scim_extension + ".department",
        #"displayName": "displayName",
        "division": scim_extension + ".division",
        "email": "emails(val.primary && val.primary==true).[0].value",
        "emailType": "emails(val.primary && val.primary==true).[0].type",
        "employeeNumber": scim_extension + ".employeeNumber",
        "groups": "groups(val.display).display",
        "id": "id",
        "externalId": "externalId",
        "locale": "locale",
        "manager": scim_extension + ".manager.value",
        "nameFormatted": "name.formatted",
        "nameFamilyName": "name.familyName",
        "nameGivenName": "name.givenName",
        "nameHonorificPrefix": "name.honorificPrefix",
        "nameHonorificSuffix": "name.honorificSuffix",
        "nameMiddleName": "name.middleName",
        "nickName": "nickName",
        "organization": scim_extension + ".organization",
        "password": "password",
        "photo": "photos(val.type && val.type=='photo').[0].value",
        "preferredLanguage": "preferredLanguage",
        "profileUrl": "profileUrl",
        "thumbnnail": "photos(val.type && val.type=='thumbnail').[0].value",
        "timezone": "timezone",
        "title": "title",
        "userName": "userName",
        "userType": "userType",
    }
    ret = dict()
    for k,v in mapping.items():
        try:
            ret[k] = demisto.dt(clientData, v)
        except Exception as err:
            ret[k] = None
    return ret


def verify_and_load_scim_data(scim):
    try:
        scim = json.loads(scim)
    except:
        pass
    if type(scim) != dict:
        raise Exception('SCIM data is not a valid JSON')
    return scim


def get_group_command(client, args):
    scim = verify_and_load_scim_data(args.get('scim'))

    group_id = scim.get('id')
    group_name = scim.get('displayName')

    if not (group_id or group_name):
        return_error("You must supply either 'id' or 'displayName' in the scim data")
    if not group_id:
        res = client.search_group(group_name)
        res = client.search_group(group_name)
        res_json = res.json()
        if res.status_code == 200:
            if res_json.get('totalResults') < 1:
                generic_iam_context = OutputContext(success=False, displayName=group_name, errorCode=404,
                                                    errorMessage="Group Not Found", details=res_json)
                generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
                outputs = {
                    generic_iam_context_dt: generic_iam_context.data
                }

                readable_output = tableToMarkdown(f'Slack Get Group:', generic_iam_context.data, removeNull=True)
                return (
                    readable_output,
                    outputs,
                    generic_iam_context.data
                )
            else:
                group_id = res_json['Resources'][0].get('id')
        else:
            generic_iam_context = OutputContext(success=False, displayName=group_name, id=group_id,
                                                errorCode=res_json['Errors']['code'],
                                                errorMessage=res_json['Errors']['description'], details=res_json)
            generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
            outputs = {
                generic_iam_context_dt: generic_iam_context.data
            }

            readable_output = tableToMarkdown(f'Slack Get Group:', generic_iam_context.data, removeNull=True)
            return (
                readable_output,
                outputs,
                generic_iam_context.data
            )

    res = client.get_group_by_id(group_id)
    res_json = res.json()

    if res.status_code == 200:
        include_members = args.get('includeMembers')
        if include_members.lower() == 'false' and 'members' in res_json:
            del res_json['members']
        generic_iam_context = OutputContext(success=True, id=res_json.get('id'),
                                            displayName=res_json.get('displayName'),
                                            members=res_json.get('members'))
    elif res.status_code == 404:
        generic_iam_context = OutputContext(success=False, displayName=group_name, id=group_id, errorCode=404,
                                            errorMessage="Group Not Found", details=res_json)
    else:
        generic_iam_context = OutputContext(success=False, displayName=group_name, id=group_id, errorCode=res_json['Errors']['code'],
                                            errorMessage=res_json['Errors']['description'], details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(f'Slack Get Group:', generic_iam_context.data, removeNull=True)
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def delete_group_command(client, args):
    scim = verify_and_load_scim_data(args.get('scim'))
    group_id = scim.get('id')
    group_name = scim.get('displayName')

    if not (group_id):
        return_error("You must supply 'id' in the scim data")

    res = client.delete_group(group_id)

    if res.status_code == 204:
        generic_iam_context = OutputContext(success=True, id=group_id, displayName=group_name)
    elif res.status_code == 404:
        generic_iam_context = OutputContext(success=False, id=group_id, displayName=group_name, errorCode=404,
                                            errorMessage="Group Not Found", details=res.json())
    else:
        res_json = res.json()
        generic_iam_context = OutputContext(success=False, displayName=group_name, id=group_id,
                                            errorCode=res_json['Errors']['code'],
                                            errorMessage=res_json['Errors']['description'], details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(f'Slack Delete Group:', generic_iam_context.data, removeNull=True)
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def create_group_command(client, args):
    scim = verify_and_load_scim_data(args.get('scim'))
    group_name = scim.get('displayName')

    if not (group_name):
        return_error("You must supply 'displayName' of the group in the scim data")

    group_data = {}
    group_data['schemas'] = [SLACK_SCIM_CORE_SCHEMA_KEY]
    group_data['displayName'] = group_name
    res = client.create_group(group_data)
    res_json = res.json()

    if res.status_code == 201:
        generic_iam_context = OutputContext(success=True, id=res_json.get('id'),
                                            displayName=res_json.get('displayName'))
    else:
        res_json = res.json()
        generic_iam_context = OutputContext(success=False, displayName=group_name,
                                            errorCode=res_json['Errors']['code'],
                                            errorMessage=res_json['Errors']['description'], details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(f'Slack Create Group:', generic_iam_context.data, removeNull=True)
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def update_group_command(client, args):
    scim = verify_and_load_scim_data(args.get('scim'))

    group_id = scim.get('id')
    group_name = scim.get('displayName')

    if not (group_id):
        return_error("You must supply 'id' in the scim data")

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

    group_input = {}
    group_input['schemas'] = [SLACK_SCIM_CORE_SCHEMA_KEY]
    group_input['members'] = member_ids_json_list

    res = client.update_group(group_id, group_input)

    if res.status_code == 204:
        generic_iam_context = OutputContext(success=True, id=group_id, displayName=group_name)
    elif res.status_code == 404:
        generic_iam_context = OutputContext(success=False, id=group_id, displayName=group_name, errorCode=404,
                                            errorMessage="Group Not Found", details=res.json())
    else:
        res_json = res.json()
        generic_iam_context = OutputContext(success=False, displayName=group_name, id=group_id, errorCode=res_json['Errors']['code'],
                                            errorMessage=res_json['Errors']['description'], details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(f'Slack Update Group:', generic_iam_context.data, removeNull=True)
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def replace_group_command(client, args):
    group_id = args.get('groupId')
    group_name = args.get('groupName')

    if not (group_id or group_name):
        return_error("You must supply either 'groupId' or 'groupName")
    if not group_id:
        group_id = client.get_group_id(group_name)

    group_input = {}
    group_input['schemas'] = [SLACK_SCIM_CORE_SCHEMA_KEY]
    group_input['displayName'] = args.get('newGroupName')
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

    readable_output = tableToMarkdown(f"Slack Group replaced: {group_id}", res_json)

    return (
        readable_output,
        {},
        res_json)


def main():
    user_profile = None
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    access_token = params.get('access_token')

    mapper_in = params.get('mapper_in')
    mapper_out = params.get('mapper_out')
    is_create_enabled = params.get("create_user_enabled")
    is_disable_enabled = params.get("disable_user_enabled")
    is_update_enabled = demisto.params().get("update_user_enabled")
    create_if_not_exists = demisto.params().get("create_if_not_exists")

    iam_command = IAMCommand(is_create_enabled, is_disable_enabled, is_update_enabled,
                             create_if_not_exists, mapper_in, mapper_out)

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': f'Bearer {access_token}'
    }

    client = Client(
        base_url='https://api.slack.com/scim/v1/',
        verify=verify_certificate,
        proxy=proxy,
        headers=headers,
        ok_codes=(200, 201)
    )

    group_client = GroupClient(
        base_url='https://api.slack.com/scim/v1/',
        verify=verify_certificate,
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}'
        },
        proxy=proxy
    )

    demisto.debug(f'Command being called is {command}')

    if command == 'iam-get-user':
        user_profile = iam_command.get_user(client, args)

    elif command == 'iam-create-user':
        user_profile = iam_command.create_user(client, args)

    elif command == 'iam-update-user':
        user_profile = iam_command.update_user(client, args)

    elif command == 'iam-disable-user':
        user_profile = iam_command.disable_user(client, args)

    if user_profile:
        # user_profile.return_outputs()
        return_results(user_profile)

    try:
        if command == 'test-module':
            test_module(client)

        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields(client))

    except Exception:
        # For any other integration command exception, return an error
        return_error(f'Failed to execute {command} command. Traceback: {traceback.format_exc()}')

    if command == 'get-group':
        human_readable, outputs, raw_response = get_group_command(group_client, args)
        return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)

    elif command == 'create-group':
        human_readable, outputs, raw_response = create_group_command(group_client, args)
        return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)

    elif command == 'update-group':
        human_readable, outputs, raw_response = update_group_command(group_client, args)
        return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)

    elif command == 'delete-group':
        human_readable, outputs, raw_response = delete_group_command(group_client, args)
        return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)

    elif command == 'slack-replace-group':
        human_readable, outputs, raw_response = replace_group_command(group_client, args)
        return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


from IAMApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

import demistomock as demisto
from CommonServerPython import *
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

    def get_user(self, filter_name: str, filter_value: str):
        uri = f'/Users/{filter_value}' if filter_name == 'id' else '/Users'
        query_params = {
            'filter': f'{filter_name} eq {filter_value}'
        } if filter_name != 'id' else {}
        res = self._http_request(
            method='GET',
            url_suffix=uri,
            params=query_params
        )
        if res and res.get('totalResults') != 0:
            user_app_data = res.get('Resources')[0] if 'totalResults' in res and res.get('totalResults') == 1 else res
            user_id = user_app_data.get('id')
            is_active = user_app_data.get('active')
            username = user_app_data.get('userName')
            email = get_first_primary_email_by_scim_schema(user_app_data)

            return IAMUserAppData(user_id, username, is_active, user_app_data, email)
        return None

    def create_user(self, user_data):
        uri = '/Users'
        user_data["schemas"] = ["urn:scim:schemas:core:1.0"]  # Mandatory user profile field.
        if user_data.get("emails") and not isinstance(user_data["emails"], list):
            user_data["emails"] = [user_data["emails"]]
        if user_data.get("phoneNumbers") and not isinstance(user_data["phoneNumbers"], list):
            user_data["phoneNumbers"] = [user_data["phoneNumbers"]]
        res = self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=user_data
        )
        user_app_data = res
        user_id = user_app_data.get('id')
        is_active = user_app_data.get('active')
        username = user_app_data.get('userName')
        email = get_first_primary_email_by_scim_schema(user_app_data)

        return IAMUserAppData(user_id, username, is_active, user_app_data, email)

    def update_user(self, user_id, user_data):
        uri = f'/Users/{user_id}'
        if user_data.get("emails") and not isinstance(user_data["emails"], list):
            user_data["emails"] = [user_data["emails"]]
        if user_data.get("phoneNumbers") and not isinstance(user_data["phoneNumbers"], list):
            user_data["phoneNumbers"] = [user_data["phoneNumbers"]]

        res = self._http_request(
            method='PATCH',
            url_suffix=uri,
            json_data=user_data
        )
        user_app_data = res
        user_id = user_app_data.get('id')
        is_active = user_app_data.get('active')
        username = user_app_data.get('userName')
        email = get_first_primary_email_by_scim_schema(user_app_data)

        return IAMUserAppData(user_id, username, is_active, user_app_data, email)

    def disable_user(self, user_id):
        user_data = {'active': False}
        return self.update_user(user_id, user_data)

    def enable_user(self, user_id):
        user_data = {'active': True}
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
                                error_message=f'{error_message}\n{traceback.format_exc()}')

        demisto.error(traceback.format_exc())


class GroupClient(BaseClient):
    """
    GroupClient will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """
    def __init__(self, base_url, verify=True, proxy=False, headers=None):
        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy)

    def http_request(self, method, url_suffix, params=None, data=None, headers=None):
        if headers is None:
            headers = self._headers
        full_url = self._base_url + url_suffix
        res = requests.request(
            method,
            full_url,
            verify=self._verify,
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
                    new_extension_schema[value] = extension_schema.get(key)
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
    incident_type_scheme = SchemeTypeMapping(type_name=IAMUserProfile.DEFAULT_INCIDENT_TYPE)

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
        self.command = demisto.command().replace('-', '_').title().replace('_', '')
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


def get_group_id_by_name(client, group_name):
    res = client.search_group(group_name)

    if res.get('totalResults') >= 1:
        return res['Resources'][0].get('id')
    return None


def get_group_command(client, args):
    scim = safe_load_json(args.get('scim'))

    group_id = scim.get('id')
    group_name = scim.get('displayName')

    if not (group_id or group_name):
        return_error("You must supply either 'id' or 'displayName' in the scim data")
    if not group_id:
        res = client.search_group(group_name)
        res_json = res.json()

        if res.status_code == 200:
            if res_json.get('totalResults') < 1:
                generic_iam_context = OutputContext(success=False, displayName=group_name, errorCode=404,
                                                    errorMessage="Group Not Found", details=res_json)
                return CommandResults(
                    raw_response=generic_iam_context.data,
                    outputs_prefix=generic_iam_context.command,
                    outputs_key_field='id',
                    outputs=generic_iam_context.data,
                    readable_output=tableToMarkdown('Slack Get Group:', generic_iam_context.data, removeNull=True)
                )
            else:
                group_id = res_json['Resources'][0].get('id')
        else:
            generic_iam_context = OutputContext(success=False, displayName=group_name, id=group_id,
                                                errorCode=res_json['Errors']['code'],
                                                errorMessage=res_json['Errors']['description'], details=res_json)
            return CommandResults(
                raw_response=generic_iam_context.data,
                outputs_prefix=generic_iam_context.command,
                outputs_key_field='id',
                outputs=generic_iam_context.data,
                readable_output=tableToMarkdown('Slack Get Group:', generic_iam_context.data, removeNull=True)
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
        generic_iam_context = OutputContext(success=False, displayName=group_name, id=group_id,
                                            errorCode=res_json['Errors']['code'],
                                            errorMessage=res_json['Errors']['description'], details=res_json)

    return CommandResults(
        raw_response=generic_iam_context.data,
        outputs_prefix=generic_iam_context.command,
        outputs_key_field='id',
        outputs=generic_iam_context.data,
        readable_output=tableToMarkdown('Slack Get Group:', generic_iam_context.data, removeNull=True)
    )


def delete_group_command(client, args):
    scim = safe_load_json(args.get('scim'))
    group_id = scim.get('id')
    group_name = scim.get('displayName')

    if not group_id:
        group_id = get_group_id_by_name(client, group_name)
        if not group_id:
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
    return CommandResults(
        raw_response=generic_iam_context.data,
        outputs_prefix=generic_iam_context.command,
        outputs_key_field='id',
        outputs=generic_iam_context.data,
        readable_output=tableToMarkdown('Slack Delete Group:', generic_iam_context.data, removeNull=True)
    )


def create_group_command(client, args):
    scim = safe_load_json(args.get('scim'))
    group_name = scim.get('displayName')

    if not group_name:
        return_error("You must supply 'displayName' of the group in the scim data")

    group_data = {'schemas': [SLACK_SCIM_CORE_SCHEMA_KEY], 'displayName': group_name}
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

    return CommandResults(
        raw_response=generic_iam_context.data,
        outputs_prefix=generic_iam_context.command,
        outputs_key_field='id',
        outputs=generic_iam_context.data,
        readable_output=tableToMarkdown('Slack Create Group:', generic_iam_context.data, removeNull=True)
    )


def update_group_command(client, args):
    scim = safe_load_json(args.get('scim'))

    group_id = scim.get('id')
    group_name = scim.get('displayName')

    if not group_id:
        group_id = get_group_id_by_name(client, group_name)
        if not group_id:
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

    group_input = {'schemas': [SLACK_SCIM_CORE_SCHEMA_KEY], 'members': member_ids_json_list}

    res = client.update_group(group_id, group_input)

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
    return CommandResults(
        raw_response=generic_iam_context.data,
        outputs_prefix=generic_iam_context.command,
        outputs_key_field='id',
        outputs=generic_iam_context.data,
        readable_output=tableToMarkdown('Slack Update Group:', generic_iam_context.data, removeNull=True)
    )


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
    is_enable_enabled = demisto.params().get("enable_user_enabled")
    is_disable_enabled = params.get("disable_user_enabled")
    is_update_enabled = demisto.params().get("update_user_enabled")
    create_if_not_exists = demisto.params().get("create_if_not_exists")

    iam_command = IAMCommand(is_create_enabled, is_enable_enabled, is_disable_enabled, is_update_enabled,
                             create_if_not_exists, mapper_in, mapper_out,
                             get_user_iam_attrs=['id', 'userName', 'emails'])

    base_url = 'https://api.slack.com/scim/v1/'
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': f'Bearer {access_token}'
    }

    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        proxy=proxy,
        headers=headers,
        ok_codes=(200, 201),
    )

    group_client = GroupClient(
        base_url=base_url,
        verify=verify_certificate,
        proxy=proxy,
        headers=headers,
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

    if command == 'iam-get-group':
        return_results(get_group_command(group_client, args))

    elif command == 'iam-create-group':
        return_results(create_group_command(group_client, args))

    elif command == 'iam-update-group':
        return_results(update_group_command(group_client, args))

    elif command == 'iam-delete-group':
        return_results(delete_group_command(group_client, args))


from IAMApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

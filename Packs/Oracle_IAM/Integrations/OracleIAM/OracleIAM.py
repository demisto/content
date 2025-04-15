import demistomock as demisto
from CommonServerPython import *
import traceback
import base64
import urllib3
# Disable insecure warnings
urllib3.disable_warnings()


ERROR_CODES_TO_SKIP = [
    404
]

'''CLIENT CLASS'''


def build_body_request_for_update_user(old_user_data, new_user_data):
    operations = []
    for key, value in new_user_data.items():
        operation = {
            'op': 'replace' if key in old_user_data else 'add',
            'path': key,
            'value': [value] if key in ('emails', 'phoneNumbers') and not isinstance(value, list) else value,
        }
        operations.append(operation)

    data = {
        'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations': operations,
    }

    return data


class Client(BaseClient):
    """ A client class that implements logic to authenticate with the application. """

    def __init__(self, base_url, verify=True, proxy=False, ok_codes=(), headers=None, client_id=None,
                 client_secret=None):
        super().__init__(base_url, verify, proxy, ok_codes, headers)
        self.base_url = base_url
        self.verify = verify
        self.client_id = client_id
        self.client_secret = client_secret
        self.headers = headers
        self.headers['Authorization'] = f'Bearer {self.get_access_token()}'

    def get_access_token(self):
        client_id_and_secret = f'{self.client_id}:{self.client_secret}'

        # Standard Base64 Encoding
        encodedBytes = base64.b64encode(client_id_and_secret.encode('utf-8'))
        encodedStr = str(encodedBytes, 'utf-8')

        headers = {
            'Authorization': f'Basic {encodedStr}',
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        }

        data = {
            'grant_type': 'client_credentials',
            'scope': 'urn:opc:idm:__myscopes__',
        }

        token = self._http_request('POST', url_suffix='/oauth2/v1/token', headers=headers, data=data)
        return token.get('access_token')

    def test(self):
        """ Tests connectivity with the application. """

        return self.get_access_token()

    def get_user_by_id(self, user_id):
        """ Queries the user in the application using REST API by its email, and returns an IAMUserAppData object
        that holds the user_id, username, is_active and app_data attributes given in the query response.

        :type user_id: ``str``
        :param user_id: ID of the user

        :return: An IAMUserAppData object if user exists, None otherwise.
        :rtype: ``IAMUserAppData``
        """
        user_app_data = self._http_request(
            'GET',
            url_suffix=f'/admin/v1/Users/{user_id}',
        )

        if user_app_data:
            user_name = user_app_data.get('userName')
            is_active = user_app_data.get('active')
            email = get_first_primary_email_by_scim_schema(user_app_data)

            return IAMUserAppData(user_id, user_name, is_active, user_app_data, email)
        return None

    def get_user(self, filter_name: str, filter_value: str) -> Optional['IAMUserAppData']:
        """ Queries the user in the application using REST API by its email, and returns an IAMUserAppData object
        that holds the user_id, username, is_active and app_data attributes given in the query response.

        :type filter_name: ``str``
        :param filter_name: Attribute name to filter by.

        :type filter_value: ``str``
        :param filter_value: The filter attribute value.

        :return: An IAMUserAppData object if user exists, None otherwise.
        :rtype: ``Optional[IAMUserAppData]``
        """
        query_params = {'filter': f'{filter_name} eq "{filter_value}"'}

        res = self._http_request(
            method='GET',
            url_suffix='/admin/v1/Users',
            params=query_params,
        )

        if res and res.get('Resources'):
            user_app_data = res.get('Resources')[0]

            user_id = user_app_data.get('id')

            return self.get_user_by_id(user_id)
        return None

    def create_user(self, user_data: Dict[str, Any]) -> 'IAMUserAppData':
        """ Creates a user in the application using REST API.

        :type user_data: ``Dict[str, Any]``
        :param user_data: User data in the application format

        :return: An IAMUserAppData object that contains the data of the created user in the application.
        :rtype: ``IAMUserAppData``
        """
        user_data['schemas'] = ['urn:ietf:params:scim:schemas:core:2.0:User']
        if not isinstance(user_data.get('emails'), list):
            user_data['emails'] = [user_data.get('emails')]
        if not isinstance(user_data.get('phoneNumbers'), list):
            user_data['phoneNumbers'] = [user_data.get('phoneNumbers')]

        user_app_data = self._http_request(
            method='POST',
            url_suffix='/admin/v1/Users',
            json_data=user_data,
        )

        user_id = user_app_data.get('id')
        is_active = user_app_data.get('active')
        username = user_app_data.get('userName')
        email = get_first_primary_email_by_scim_schema(user_app_data)

        return IAMUserAppData(user_id, username, is_active, user_app_data, email)

    def update_user(self, user_id, new_user_data):
        old_user_data = self._http_request(
            'GET',
            url_suffix=f'/admin/v1/Users/{user_id}',
        )

        user_app_data = self._http_request(
            'PATCH',
            url_suffix=f'/admin/v1/Users/{user_id}',
            json_data=build_body_request_for_update_user(old_user_data, new_user_data),
        )

        is_active = user_app_data.get('active')
        username = user_app_data.get('userName')
        email = get_first_primary_email_by_scim_schema(user_app_data)

        return IAMUserAppData(user_id, username, is_active, user_app_data, email)

    def enable_user(self, user_id: str):
        """ Enables a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """

        user_data = {
            'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations': [
                {
                    'op': 'replace',
                    'path': 'active',
                    'value': True,
                }
            ]
        }

        user_app_data = self._http_request(
            'PATCH',
            url_suffix=f'/admin/v1/Users/{user_id}',
            json_data=user_data,
        )

        if user_app_data:
            user_name = user_app_data.get('userName')
            is_active = user_app_data.get('active')
            email = get_first_primary_email_by_scim_schema(user_app_data)

            return IAMUserAppData(user_id, user_name, is_active, user_app_data, email)
        return None

    def disable_user(self, user_id: str):
        """ Disables a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """

        user_data = {
            'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations': [
                {
                    'op': 'replace',
                    'path': 'active',
                    'value': False,
                }
            ]
        }

        user_app_data = self._http_request(
            'PATCH',
            url_suffix=f'/admin/v1/Users/{user_id}',
            json_data=user_data,
        )

        if user_app_data:
            user_name = user_app_data.get('userName')
            is_active = user_app_data.get('active')
            email = get_first_primary_email_by_scim_schema(user_app_data)

            return IAMUserAppData(user_id, user_name, is_active, user_app_data, email)
        return None

    def get_group_by_id(self, group_id: str):
        """ Retrieves the group information by ID.

        :type group_id: ``str``
        :param group_id: ID of the group in the application.

        :return: The group data.
        :rtype: ``dict``
        """

        return self._http_request(
            method='GET',
            url_suffix=f'admin/v1/Groups/{group_id}?attributes=id,displayName,members',
            resp_type='response',
        )

    def get_group_by_name(self, group_name):
        """ Retrieves the group information by display name.

        :type group_name: ``str``
        :param group_name: Display name of the group in the application.

        :return: The group data.
        :rtype: ``dict``
        """

        query_params = {
            'filter': f'displayName eq "{group_name}"'
        }
        return self._http_request(
            method='GET',
            url_suffix='admin/v1/Groups?attributes=id,displayName,members',
            params=query_params,
            resp_type='response',
        )

    def create_group(self, group_data: dict):
        """ Creates an empty group with a given name.

        :type group_data: ``str``
        :param group_data: Display name of the group to be created.

        :return: The group data.
        :rtype: ``dict``
        """

        return self._http_request(
            method='POST',
            url_suffix='admin/v1/Groups',
            json_data=group_data,
            resp_type='response',
        )

    def update_group(self, group_id: str, group_data: dict):
        """ Updates a group in the application.

        :type group_id: ``str``
        :param group_id: ID of the group in the application.

        :type group_data: ``str``
        :param group_data: The data that needs to be updated.

        :return: The group data.
        :rtype: ``dict``
        """

        return self._http_request(
            method='PATCH',
            url_suffix=f'admin/v1/Groups/{group_id}',
            json_data=group_data,
            resp_type='response',
        )

    def delete_group(self, group_id: str):
        """ Deletes a group in the application.

        :type group_id: ``str``
        :param group_id: ID of the group in the application.
        """

        return self._http_request(
            method='DELETE',
            url_suffix=f'admin/v1/Groups/{group_id}',
            resp_type='response',
        )

    def get_app_fields(self) -> Dict[str, Any]:
        """ Gets a dictionary of the user schema fields in the application and their description.

        :return: The user schema fields dictionary
        :rtype: ``Dict[str, str]``
        """

        res = self._http_request(
            method='GET',
            url_suffix='admin/v1/Schemas/urn:ietf:params:scim:schemas:core:2.0:User'
        )

        fields = res.get('attributes', [])
        return {field.get('name'): field.get('description') for field in fields}

    @staticmethod
    def handle_exception(user_profile: 'IAMUserProfile',
                         e: Union[DemistoException, Exception],
                         action: 'IAMActions'):
        """ Handles failed responses from the application API by setting the User Profile object with the result.
            The result entity should contain the following data:
            1. action        (``IAMActions``)       The failed action                       Required
            2. success       (``bool``)             The success status                      Optional (by default, True)
            3. skip          (``bool``)             Whether or not the command was skipped  Optional (by default, False)
            3. skip_reason   (``str``)              Skip reason                             Optional (by default, None)
            4. error_code    (``Union[str, int]``)  HTTP error code                         Optional (by default, None)
            5. error_message (``str``)              The error description                   Optional (by default, None)

            Note: This is the place to determine how to handle specific edge cases from the API, e.g.,
            when a DISABLE action was made on a user which is already disabled and therefore we can't
            perform another DISABLE action.

        :type user_profile: ``IAMUserProfile``
        :param user_profile: The user profile object

        :type e: ``Union[DemistoException, Exception]``
        :param e: The exception object - if type is DemistoException, holds the response json object (`res` attribute)

        :type action: ``IAMActions``
        :param action: An enum represents the current action (GET, UPDATE, CREATE, DISABLE or ENABLE)
        """
        if isinstance(e, DemistoException) and e.res is not None:
            error_code = e.res.status_code

            if action == IAMActions.DISABLE_USER and error_code in ERROR_CODES_TO_SKIP:
                skip_message = 'Users is already disabled or does not exist in the system.'
                user_profile.set_result(action=action,
                                        skip=True,
                                        skip_reason=skip_message)

            try:
                resp = e.res.json()
                error_message = get_error_details(resp)
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


class OutputContext:
    """
        Class to build a generic output and context.
    """

    def __init__(self, success=None, active=None, id=None, username=None, email=None, errorCode=None,
                 errorMessage=None, details=None, displayName=None, members=None):
        self.instanceName = demisto.callingContext.get('context', {}).get('IntegrationInstance')
        self.brand = demisto.callingContext.get('context', {}).get('IntegrationBrand')
        self.command = demisto.command().replace('-', '_').title().replace('_', '').replace('Iam', '')
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
            'brand': self.brand,
            'instanceName': self.instanceName,
            'success': success,
            'active': active,
            'id': id,
            'username': username,
            'email': email,
            'errorCode': errorCode,
            'errorMessage': errorMessage,
            'details': details,
            'displayName': displayName,
            'members': members,
        }

        # Remove empty values
        self.data = {
            k: v
            for k, v in self.data.items()
            if v is not None
        }


'''HELPER FUNCTIONS'''


def get_error_details(res: Dict[str, Any]) -> str:
    """ Parses the error details retrieved from the application and outputs the resulted string.

    :type res: ``Dict[str, Any]``
    :param res: The error data retrieved from the application.

    :return: The parsed error details.
    :rtype: ``str``
    """
    details = str(res.get('detail'))
    return details


'''COMMAND FUNCTIONS'''


def test_module(client: Client):
    """ Tests connectivity with the client. """
    res = client.test()
    if isinstance(res, DemistoException):
        if 'Unauthorized' in str(res):
            return 'Authorization Error: Make sure "Client ID" and "Client Secret" is correctly set'
        else:
            return str(res)
    return 'ok'


def get_group_command(client, args):
    scim = safe_load_json(args.get('scim'))

    group_id = scim.get('id')
    group_name = scim.get('displayName')

    if not (group_id or group_name):
        raise Exception('You must supply either "id" or "displayName" in the scim data')

    if group_id:
        try:
            res = client.get_group_by_id(group_id)
            res_json = res.json()
            if res.status_code == 200:
                generic_iam_context = OutputContext(success=True, id=group_id, displayName=res_json.get('displayName'),
                                                    members=res_json.get('members'))
        except DemistoException as exc:
            if exc.res.status_code == 404:
                generic_iam_context = OutputContext(success=False, displayName=group_name, id=group_id,
                                                    errorCode=404, errorMessage='Group Not Found', details=str(exc))
            else:
                generic_iam_context = OutputContext(success=False, displayName=group_name, id=group_id,
                                                    errorCode=exc.res.status_code,
                                                    errorMessage=exc.message, details=str(exc))
    else:
        try:
            res = client.get_group_by_name(group_name)
            res_json = res.json()
            if res.status_code == 200 and res_json.get('totalResults') > 0:
                res_json = res_json['Resources'][0]
                generic_iam_context = OutputContext(success=True, id=res_json.get('id'), displayName=group_name,
                                                    members=res_json.get('members'))
        except DemistoException as exc:
            if exc.res.status_code == 404:
                generic_iam_context = OutputContext(success=False, displayName=group_name, id=group_id, errorCode=404,
                                                    errorMessage='Group Not Found', details=str(exc))
            else:
                generic_iam_context = OutputContext(success=False, displayName=group_name, id=group_id,
                                                    errorCode=exc.res.status_code, errorMessage=exc.message,
                                                    details=str(exc))

    readable_output = tableToMarkdown('Oracle Cloud Get Group:', generic_iam_context.data, removeNull=True)

    return CommandResults(
        raw_response=generic_iam_context.data,
        outputs_prefix=generic_iam_context.command,
        outputs_key_field='id',
        outputs=generic_iam_context.data,
        readable_output=readable_output,
    )


def create_group_command(client, args):
    scim = safe_load_json(args.get('scim'))
    group_name = scim.get('displayName')

    if not group_name:
        raise Exception('You must supply "displayName" of the group in the scim data')

    group_data = scim
    group_data['schemas'] = ['urn:ietf:params:scim:schemas:core:2.0:Group']
    try:
        res = client.create_group(group_data)
        res_json = res.json()

        if res.status_code == 201:
            generic_iam_context = OutputContext(success=True, id=res_json.get('id'), displayName=group_name)
        else:
            res_json = res.json()
            generic_iam_context = OutputContext(success=False, displayName=group_name, errorCode=res_json.get('code'),
                                                errorMessage=res_json.get('message'), details=res_json)
    except DemistoException as e:
        res_json = e.res.json()
        generic_iam_context = OutputContext(success=False, displayName=group_name, errorCode=res_json.get('status'),
                                            errorMessage=res_json.get('detail'), details=res_json)

    readable_output = tableToMarkdown('Oracle Cloud Create Group:', generic_iam_context.data, removeNull=True)

    return CommandResults(
        raw_response=generic_iam_context.data,
        outputs_prefix=generic_iam_context.command,
        outputs_key_field='id',
        outputs=generic_iam_context.data,
        readable_output=readable_output,
    )


def update_group_command(client, args):
    scim = safe_load_json(args.get('scim'))

    group_id = scim.get('id')
    group_name = scim.get('displayName')

    if not group_id:
        raise Exception('You must supply "id" in the scim data')

    member_ids_to_add = args.get('memberIdsToAdd')
    member_ids_to_delete = args.get('memberIdsToDelete')

    if member_ids_to_add is member_ids_to_delete is None:
        raise Exception('You must supply either "memberIdsToAdd" or "memberIdsToDelete" in the scim data')

    operations = []
    member_ids_json_list = []
    if member_ids_to_add:
        if not isinstance(member_ids_to_add, list):
            member_ids_to_add = safe_load_json(member_ids_to_add)

        for member_id in member_ids_to_add:
            member_ids_json_list.append(
                {
                    'value': member_id,
                    'type': 'User',
                }
            )

        if member_ids_json_list:
            operation = {
                'op': 'add',
                'path': 'members',
                'value': member_ids_json_list,
            }
            operations.append(operation)

    if member_ids_to_delete:
        if not isinstance(member_ids_to_delete, list):
            member_ids_to_delete = safe_load_json(member_ids_to_delete)

        for member_id in member_ids_to_delete:
            operation = {
                'op': 'remove',
                'path': f'members[value eq "{member_id}"]',
            }
            operations.append(operation)

    group_input = {'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], 'Operations': operations}

    try:
        res = client.update_group(group_id, group_input)
        res_json = res.json()
        if res.status_code == 200:
            generic_iam_context = OutputContext(success=True, id=group_id, displayName=group_name, details=res_json)
        else:
            generic_iam_context = OutputContext()
            demisto.debug(f"{res.status_code=} , not 200. Initializing generic_iam_context.")
    except DemistoException as exc:
        if exc.res.status_code == 404:
            generic_iam_context = OutputContext(success=False, id=group_id, displayName=group_name, errorCode=404,
                                                errorMessage='Group/User Not Found or User not a member of group',
                                                details=str(exc))
        else:
            generic_iam_context = OutputContext(success=False, id=group_id, displayName=group_name,
                                                errorCode=exc.res.status_code, errorMessage=exc.message,
                                                details=str(exc))

    readable_output = tableToMarkdown('Oracle Cloud Update Group:', generic_iam_context.data, removeNull=True)

    return CommandResults(
        raw_response=generic_iam_context.data,
        outputs_prefix=generic_iam_context.command,
        outputs_key_field='id',
        outputs=generic_iam_context.data,
        readable_output=readable_output,
    )


def delete_group_command(client, args):
    scim = safe_load_json(args.get('scim'))
    group_id = scim.get('id')
    group_name = scim.get('displayName')

    if not group_id:
        raise Exception('You must supply "id" in the scim data')

    res = client.delete_group(group_id)

    try:
        if res.status_code == 204:
            generic_iam_context = OutputContext(success=True, id=group_id, displayName=group_name)
        else:
            generic_iam_context = OutputContext()
            demisto.debug(f"{res.status_code=} , not 204. Initializing generic_iam_context.")
    except DemistoException as exc:
        if exc.res.status_code == 404:
            generic_iam_context = OutputContext(success=False, id=group_id, displayName=group_name, errorCode=404,
                                                errorMessage='Group Not Found', details=str(exc))
        else:
            generic_iam_context = OutputContext(success=False, id=group_id, displayName=group_name,
                                                errorCode=exc.res.status_code, errorMessage=exc.message,
                                                details=str(exc))

    readable_output = tableToMarkdown('Oracle Cloud Delete Group:', generic_iam_context.data, removeNull=True)

    return CommandResults(
        raw_response=generic_iam_context.data,
        outputs_prefix=generic_iam_context.command,
        outputs_key_field='id',
        outputs=generic_iam_context.data,
        readable_output=readable_output,
    )


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


def main():
    user_profile = None
    params = demisto.params()
    base_url = params['url'].strip('/')
    client_id = params.get('credentials', {}).get('identifier')
    client_secret = params.get('credentials', {}).get('password')
    mapper_in = params.get('mapper_in')
    mapper_out = params.get('mapper_out')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()
    args = demisto.args()

    is_create_enabled = params.get('create_user_enabled')
    is_enable_enabled = params.get('enable_user_enabled')
    is_disable_enabled = params.get('disable_user_enabled')
    is_update_enabled = params.get('update_user_enabled')
    create_if_not_exists = params.get('create_if_not_exists')

    iam_command = IAMCommand(is_create_enabled, is_enable_enabled, is_disable_enabled, is_update_enabled,
                             create_if_not_exists, mapper_in, mapper_out,
                             get_user_iam_attrs=['id', 'userName', 'emails'])

    headers = {
        'Content-Type': 'application/scim+json',
        'Accept': 'application/scim+json',
    }

    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        proxy=proxy,
        headers=headers,
        ok_codes=(200, 201, 204),
        client_id=client_id,
        client_secret=client_secret,
    )

    demisto.debug(f'Command being called is {command}')

    '''CRUD commands'''

    if command == 'iam-get-user':
        user_profile = iam_command.get_user(client, args)

    elif command == 'iam-create-user':
        user_profile = iam_command.create_user(client, args)

    elif command == 'iam-update-user':
        user_profile = iam_command.update_user(client, args)

    elif command == 'iam-disable-user':
        user_profile = iam_command.disable_user(client, args)

    if user_profile:
        return_results(user_profile)

    '''non-CRUD commands'''

    try:
        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'iam-get-group':
            return_results(get_group_command(client, args))

        elif command == 'iam-create-group':
            return_results(create_group_command(client, args))

        elif command == 'iam-update-group':
            return_results(update_group_command(client, args))

        elif command == 'iam-delete-group':
            return_results(delete_group_command(client, args))

        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields(client))

    except Exception as exc:
        # For any other integration command exception, return an error
        return_error(f'Failed to execute {command} command. Error:\n{exc}', error=exc)


from IAMApiModule import *  # noqa E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

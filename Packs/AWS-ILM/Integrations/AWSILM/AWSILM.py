import traceback

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

register_module_line('AWS-ILM', 'start', __line__())


# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
userUri = '/scim/v2/Users/'
groupUri = '/scim/v2/Groups/'
patchSchema = 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
ERROR_CODES_TO_SKIP = [
    404
]
SUPPORTED_GET_USER_IAM_ATTRIBUTES = ['id', 'userName']
# contrib to integration
AWS_DEFAULT_SCHEMA_MAPPING = {
    'id': 'id',
    'userName': 'userName',
    'name': {
        'formatted': 'formatted',
        'familyName': 'familyName',
        'givenName': 'givenName',
        'middleName': 'middleName',
        'honorificPrefix': 'honorificPrefix',
        'honorificSuffix': 'honorificSuffix'
    },
    'displayName': 'displayName',
    'nickName': 'nickName',
    'profileUrl': 'profileUrl',
    'title': 'title',
    'userType': 'userType',
    'preferredLanguage': 'preferredLanguage',
    'locale': 'locale',
    'timezone': 'timezone',
    'active': 'active',
    'password': 'password',
    'emails': [{
        'type': 'type',
        'value': 'value',
        'primary': 'primary'
    }],
    'phoneNumbers': [{
        'type': 'type',
        'value': 'value'
    }],
    'addresses': [{
        'formatted': 'formatted',
        'streetAddress': 'streetAddress',
        'locality': 'locality',
        'region': 'region',
        'postalCode': 'postalCode',
        'Country': 'Country'
    }],
    'groups': ['group'],
    'roles': ['role']
}


def build_body_request_for_update_user(old_user_data, new_user_data):
    operations = []
    for key, value in new_user_data.items():
        operation = {
            'op': 'replace' if key in old_user_data.keys() else 'add',
            'path': key,
            'value': [value] if key in ('emails', 'phoneNumbers') and not isinstance(value, list) else value,
        }
        operations.append(operation)

    data = {
        'schemas': [patchSchema],
        'Operations': operations,
    }

    return data


'''CLIENT CLASS'''


class Client(BaseClient):
    """ A client class that implements logic to authenticate with the application. """

    def test(self):
        """ Tests connectivity with the application. """

        self._http_request(method='GET', url_suffix=userUri)

    def get_user(self, iam_attribute: str, iam_attribute_val: str) -> Optional['IAMUserAppData']:
        """ Queries the user in the application using REST API by its email, and returns an IAMUserAppData object
        that holds the user_id, username, is_active and app_data attributes given in the query response.

        :type iam_attribute: ``str``
        :param iam_attribute: The IAM attribute.

        :type iam_attribute_val: ``str``
        :param iam_attribute_val: Value of the given IAM attribute.

        :return: An IAMUserAppData object if user exists, None otherwise.
        :rtype: ``Optional[IAMUserAppData]``
        """
        params = {'filter': f'userName eq "{iam_attribute_val}"'} if iam_attribute == 'userName' else None
        url_suffix: str = f'{userUri}{iam_attribute_val}' if iam_attribute == 'id' else userUri

        res = self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params=params
        )
        user_app_data = None
        if res.get('totalResults', 0) > 0:
            user_app_data = res.get('Resources')[0]
        elif iam_attribute == 'id':
            user_app_data = res

        if user_app_data:
            user_id = user_app_data.get('id')
            username = user_app_data.get('userName')
            is_active = user_app_data.get('active')
            return IAMUserAppData(user_id, username, is_active, user_app_data,
                                  email=get_first_primary_email_by_scim_schema(user_app_data))
        return None

    def create_user(self, user_data: Dict[str, Any]) -> 'IAMUserAppData':
        """ Creates a user in the application using REST API.

        :type user_data: ``Dict[str, Any]``
        :param user_data: User data in the application format

        :return: An IAMUserAppData object that contains the data of the created user in the application.
        :rtype: ``IAMUserAppData``
        """
        if not isinstance(user_data.get('emails'), list):
            user_data['emails'] = [user_data.get('emails')]
        if not isinstance(user_data.get('phoneNumbers'), list):
            user_data['phoneNumbers'] = [user_data.get('phoneNumbers')]
        user_data['active'] = True

        res = self._http_request(
            method='POST',
            url_suffix=userUri,
            json_data=user_data,
        )

        user_id = res.get('id')
        is_active = res.get('active')
        username = res.get('userName')

        return IAMUserAppData(user_id, username, is_active, res, email=get_first_primary_email_by_scim_schema(res))

    def update_user(self, user_id: str, new_user_data: Dict[str, Any]) -> 'IAMUserAppData':
        """ Updates a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :type new_user_data: ``Dict[str, Any]``
        :param new_user_data: New user data in the application format

        :return: An IAMUserAppData object that contains the data of the updated user in the application.
        :rtype: ``IAMUserAppData``
        """
        old_user_data = self._http_request(
            method='GET',
            url_suffix=userUri + user_id,
        )

        res = self._http_request(
            method='PATCH',
            url_suffix=userUri + user_id,
            json_data=build_body_request_for_update_user(old_user_data, new_user_data),
        )

        is_active = res.get('active')
        username = res.get('userName')

        return IAMUserAppData(user_id, username, is_active, res, email=get_first_primary_email_by_scim_schema(res))

    def enable_user(self, user_id: str) -> 'IAMUserAppData':
        """ Enables a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """

        user_data = {
            'schemas': [
                patchSchema
            ],
            'Operations': [
                {
                    'op': 'replace',
                    'path': 'active',
                    'value': 'true',
                }
            ]
        }

        res = self._http_request(
            method='PATCH',
            url_suffix=userUri + user_id,
            json_data=user_data,
        )

        user_id = res.get('id')
        is_active = res.get('active')
        username = res.get('userName')

        return IAMUserAppData(user_id, username, is_active, res, email=get_first_primary_email_by_scim_schema(res))

    def disable_user(self, user_id: str) -> 'IAMUserAppData':
        """ Disables a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """

        user_data = {
            'schemas': [
                patchSchema
            ],
            'Operations': [
                {
                    'op': 'replace',
                    'path': 'active',
                    'value': 'false',
                }
            ]
        }

        res = self._http_request(
            method='PATCH',
            url_suffix=userUri + user_id,
            json_data=user_data,
        )

        user_id = res.get('id')
        is_active = res.get('active')
        username = res.get('userName')

        return IAMUserAppData(user_id, username, is_active, res, email=get_first_primary_email_by_scim_schema(res))

    def get_group_by_id(self, group_id):
        return self._http_request(
            method='GET',
            url_suffix=groupUri + group_id,
            resp_type='response',
        )

    def search_group(self, group_name):
        params = {
            'filter': f'displayName eq "{group_name}"'
        }
        return self._http_request(
            method='GET',
            url_suffix=groupUri,
            params=params,
            resp_type='response',
        )

    def create_group(self, data):
        return self._http_request(
            method='POST',
            url_suffix=groupUri,
            json_data=data,
            resp_type='response',
            ok_codes=(200, 201, 409)
        )

    def update_group(self, group_id, data):
        return self._http_request(
            method='PATCH',
            url_suffix=groupUri + group_id,
            json_data=data,
            resp_type='response',
        )

    def delete_group(self, group_id):
        return self._http_request(
            method='DELETE',
            url_suffix=groupUri + group_id,
            resp_type='response',
        )

    @staticmethod
    def handle_exception(user_profile, e, action):
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


class OutputContext:
    """
        Class to build a generic output and context.
    """

    def __init__(self, success=None, active=None, id=None, iden=None, username=None, email=None, errorCode=None,
                 errorMessage=None, details=None, displayName=None, members=None):
        self.instanceName = demisto.callingContext.get('context', {}).get('IntegrationInstance')
        self.brand = demisto.callingContext.get('context', {}).get('IntegrationBrand')
        self.command = demisto.command().replace('-', '_').title().replace('_', '').replace('Iam', '')
        self.success = success
        self.active = active
        self.id = id
        self.iden = iden
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
            'id': iden,
            'username': username,
            'email': email,
            'errorCode': errorCode,
            'errorMessage': errorMessage,
            'details': details,
            'displayName': displayName,
            'members': members,
        }


'''COMMAND FUNCTIONS'''


def test_module(client: Client):
    """ Tests connectivity with the client. """

    client.test()
    return_results('ok')


def get_group_command(client, args):
    scim = safe_load_json(args.get('scim'))

    group_id = scim.get('id')
    group_name = scim.get('displayName')

    if not (group_id or group_name):
        raise Exception('You must supply either "id" or "displayName" in the scim data')

    if not group_id:
        try:
            res = client.search_group(group_name)
            res_json = res.json()

            if res.status_code == 200:
                if res_json.get('totalResults') == 0:
                    generic_iam_context = OutputContext(success=False, displayName=group_name, errorCode=404,
                                                        errorMessage='Group Not Found', details=res_json)

                else:
                    group_id = res_json['Resources'][0].get('id')
                    group_name = res_json['Resources'][0].get('displayName')
                    generic_iam_context = OutputContext(success=True, iden=group_id, displayName=group_name,
                                                        details=res_json['Resources'][0])

        except DemistoException as exc:
            generic_iam_context = OutputContext(success=False, displayName=group_name, iden=group_id,
                                                errorCode=exc.res.status_code, errorMessage=exc.message,
                                                details=str(exc))
    else:
        try:
            res = client.get_group_by_id(group_id)
            res_json = res.json()

            if res.status_code == 200:
                generic_iam_context = OutputContext(success=True, iden=res_json.get('id'),
                                                    displayName=res_json.get('displayName'), details=res_json)
        except DemistoException as exc:
            if exc.res.status_code == 404:
                generic_iam_context = OutputContext(success=False, iden=group_id, displayName=group_name, errorCode=404,
                                                    errorMessage='Group Not Found', details=str(exc))
            else:
                generic_iam_context = OutputContext(success=False, iden=group_id, displayName=group_name,
                                                    errorCode=exc.res.status_code, errorMessage=exc.message,
                                                    details=str(exc))

    readable_output = tableToMarkdown('AWS Get Group:', generic_iam_context.data, removeNull=True)

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

    res = client.create_group(scim)
    res_json = res.json()

    if res.status_code == 201:

        generic_iam_context = OutputContext(success=True, iden=res_json.get('id'),
                                            displayName=res_json.get('displayName'), details=res_json)
    else:
        res_json = res.json()
        generic_iam_context = OutputContext(success=False, displayName=group_name,
                                            errorCode=res_json.get('code'), errorMessage=res_json.get('message'),
                                            details=res_json)

    readable_output = tableToMarkdown('AWS Create Group:', generic_iam_context.data, removeNull=True)

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
        raise Exception('You must supply either "memberIdsToAdd" or "memberIdsToDelete" in the arguments')

    if member_ids_to_add:
        if not isinstance(member_ids_to_add, list):
            member_ids_to_add = safe_load_json(member_ids_to_add)

        for member_id in member_ids_to_add:
            operation = {
                'op': 'add',
                'path': 'members',
                'value': [{'value': member_id}]
            }
            group_input = {'schemas': [patchSchema], 'Operations': [operation]}
            try:
                res = client.update_group(group_id, group_input)
            except DemistoException as exc:
                generic_iam_context = OutputContext(success=False, displayName=group_name, iden=member_id,
                                                    errorCode=exc.res.status_code, errorMessage=exc.message,
                                                    details=str(exc))

                readable_output = tableToMarkdown('AWS Update Group:', generic_iam_context.data, removeNull=True)

                return CommandResults(
                    raw_response=generic_iam_context.data,
                    outputs_prefix=generic_iam_context.command,
                    outputs_key_field='id',
                    outputs=generic_iam_context.data,
                    readable_output=readable_output,
                )

    if member_ids_to_delete:
        if not isinstance(member_ids_to_delete, list):
            member_ids_to_delete = safe_load_json(member_ids_to_delete)

        for member_id in member_ids_to_delete:
            operation = {
                'op': 'remove',
                'path': 'members',
                'value': [{'value': member_id}]
            }
            group_input = {'schemas': [patchSchema], 'Operations': [operation]}
            try:
                res = client.update_group(group_id, group_input)
            except DemistoException as exc:
                generic_iam_context = OutputContext(success=False, iden=member_id, displayName=group_name,
                                                    errorCode=exc.res.status_code, errorMessage=exc.message,
                                                    details=str(exc))

                readable_output = tableToMarkdown('AWS Update Group:', generic_iam_context.data, removeNull=True)

                return CommandResults(
                    raw_response=generic_iam_context.data,
                    outputs_prefix=generic_iam_context.command,
                    outputs_key_field='id',
                    outputs=generic_iam_context.data,
                    readable_output=readable_output,
                )

    if res.status_code == 204:
        res_json = res.headers
        generic_iam_context = OutputContext(success=True, iden=group_id, displayName=group_name, details=str(res_json))

    readable_output = tableToMarkdown('AWS Update Group:', generic_iam_context.data, removeNull=True)

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
        raise Exception('The group id needs to be provided.')

    try:
        res = client.delete_group(group_id)
        res_json = res.headers
        generic_iam_context = OutputContext(success=True, iden=group_id, displayName=group_name, details=str(res_json))
    except DemistoException as exc:
        if exc.res.status_code == 404:
            generic_iam_context = OutputContext(success=False, iden=group_id, displayName=group_name, errorCode=404,
                                                errorMessage='Group Not Found', details=str(exc))
        else:
            generic_iam_context = OutputContext(success=False, iden=group_id, displayName=group_name,
                                                errorCode=exc.res.status_code, errorMessage=exc.message,
                                                details=str(exc))

    readable_output = tableToMarkdown('AWS Delete Group:', generic_iam_context.data, removeNull=True)

    return CommandResults(
        raw_response=generic_iam_context.data,
        outputs_prefix=generic_iam_context.command,
        outputs_key_field='id',
        outputs=generic_iam_context.data,
        readable_output=readable_output,
    )


def get_mapping_fields() -> GetMappingFieldsResponse:
    """ Creates and returns a GetMappingFieldsResponse object of the user schema in the application

    :return: (GetMappingFieldsResponse) An object that represents the user schema
    """
    incident_type_scheme = SchemeTypeMapping(type_name=IAMUserProfile.DEFAULT_INCIDENT_TYPE,
                                             fields=AWS_DEFAULT_SCHEMA_MAPPING)
    return GetMappingFieldsResponse([incident_type_scheme])


def main():
    user_profile = None
    params = demisto.params()
    base_url = params['url'].strip('/')
    tenant_id = params.get('tenant_id')
    url_with_tenant = f'{base_url}/{tenant_id}'
    authentication_token = params.get('authentication_token')
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
                             get_user_iam_attrs=SUPPORTED_GET_USER_IAM_ATTRIBUTES)

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': f'Bearer {authentication_token}'
    }

    client = Client(
        base_url=url_with_tenant,
        verify=verify_certificate,
        proxy=proxy,
        headers=headers,
        ok_codes=(200, 201, 204),
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

    '''non-CRUD commands'''

    if user_profile:
        return_results(user_profile)

    try:
        if command == 'test-module':
            test_module(client)

        elif command == 'iam-get-group':
            return_results(get_group_command(client, args))

        elif command == 'iam-create-group':
            return_results(create_group_command(client, args))

        elif command == 'iam-update-group':
            return_results(update_group_command(client, args))

        elif command == 'iam-delete-group':
            return_results(delete_group_command(client, args))

        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields())

    except Exception as exc:
        # For any other integration command exception, return an error
        return_error(f'Failed to execute {command} command. Error:\n{exc}', error=exc)


# GENERATED CODE ###: from IAMApiModule import *
# This code was inserted in place of an API module.
register_module_line('IAMApiModule', 'start', __line__(), wrapper=-3)


# contrib to api module
class IAMErrors(object):
    """
    An enum class to manually handle errors in IAM integrations
    :return: None
    :rtype: ``None``
    """
    BAD_REQUEST = 400, 'Bad request - failed to perform operation'
    USER_DOES_NOT_EXIST = 404, 'User does not exist'
    USER_ALREADY_EXISTS = 409, 'User already exists'


class IAMActions(object):
    """
    Enum: contains all the IAM actions (e.g. get, update, create, etc.)
    :return: None
    :rtype: ``None``
    """
    GET_USER = 'get'
    UPDATE_USER = 'update'
    CREATE_USER = 'create'
    DISABLE_USER = 'disable'
    ENABLE_USER = 'enable'


class IAMVendorActionResult:
    """ This class is used in IAMUserProfile class to represent actions data.
    :return: None
    :rtype: ``None``
    """

    def __init__(self, success=True, active=None, iden=None, username=None, email=None, error_code=None,
                 error_message=None, details=None, skip=False, skip_reason=None, action=None, return_error=False):
        """ Sets the outputs and readable outputs attributes according to the given arguments.

        :param success: (bool) whether or not the command succeeded.
        :param active:  (bool) whether or not the user status is active.
        :param iden: (str) the user ID.
        :param username: (str) the username of the user.
        :param email:  (str) the email of the user.
        :param error_code: (str or int) the error code of the response, if exists.
        :param error_message: (str) the error details of the response, if exists.
        :param details: (dict) the full response.
        :param skip: (bool) whether or not the command is skipped.
        :param skip_reason: (str) If the command is skipped, describes the reason.
        :param action: (IAMActions) An enum object represents the action taken (get, update, create, etc).
        :param return_error: (bool) Whether or not to return an error entry.
        """
        self._brand = demisto.callingContext.get('context', {}).get('IntegrationBrand')
        self._instance_name = demisto.callingContext.get('context', {}).get('IntegrationInstance')
        self._success = success
        self._active = active
        self._iden = iden
        self._username = username
        self._email = email
        self._error_code = error_code
        self._error_message = error_message
        self._details = details
        self._skip = skip
        self._skip_reason = skip_reason
        self._action = action
        self._return_error = return_error

    def should_return_error(self):
        return self._return_error

    def create_outputs(self):
        """ Sets the outputs in `_outputs` attribute.
        """
        outputs = {
            'brand': self._brand,
            'instanceName': self._instance_name,
            'action': self._action,
            'success': self._success,
            'active': self._active,
            'id': self._iden,
            'username': self._username,
            'email': self._email,
            'errorCode': self._error_code,
            'errorMessage': self._error_message,
            'details': self._details,
            'skipped': self._skip,
            'reason': self._skip_reason
        }
        return outputs

    def create_readable_outputs(self, outputs):
        """ Sets the human readable output in `_readable_output` attribute.

        :param outputs: (dict) the command outputs.
        """
        title = self._action.title() + ' User Results ({})'.format(self._brand)

        if not self._skip:
            headers = ["brand", "instanceName", "success", "active", "id", "username",
                       "email", "errorCode", "errorMessage", "details"]
        else:
            headers = ["brand", "instanceName", "skipped", "reason"]

        readable_output = tableToMarkdown(
            name=title,
            t=outputs,
            headers=headers,
            removeNull=True
        )

        return readable_output


class IAMUserProfile:
    """ A User Profile object class for IAM integrations.

    :type _user_profile: ``str``
    :param _user_profile: The user profile information.

    :type _user_profile_delta: ``str``
    :param _user_profile_delta: The user profile delta.

    :type _vendor_action_results: ``list``
    :param _vendor_action_results: A List of data returned from the vendor.

    :return: None
    :rtype: ``None``
    """

    DEFAULT_INCIDENT_TYPE = 'User Profile'
    CREATE_INCIDENT_TYPE = 'User Profile - Create'
    UPDATE_INCIDENT_TYPE = 'User Profile - Update'
    DISABLE_INCIDENT_TYPE = 'User Profile - Disable'

    def __init__(self, user_profile, mapper: str, incident_type: str, user_profile_delta=None):
        self._user_profile = safe_load_json(user_profile)
        # Mapping is added here for GET USER commands, where we need to map Cortex XSOAR fields to the given app fields.
        self.mapped_user_profile = None
        self.mapped_user_profile = self.map_object(mapper, incident_type, map_old_data=True) if \
            mapper else self._user_profile
        self._user_profile_delta = safe_load_json(user_profile_delta) if user_profile_delta else {}
        self._vendor_action_results: List = []

    def get_attribute(self, item, use_old_user_data=False, user_profile_data: Optional[Dict] = None):
        user_profile = user_profile_data if user_profile_data else self._user_profile
        if use_old_user_data and user_profile.get('olduserdata', {}).get(item):
            return user_profile.get('olduserdata', {}).get(item)
        return user_profile.get(item)

    def to_entry(self):
        """ Generates a XSOAR IAM entry from the data in _vendor_action_results.
        Note: Currently we are using only the first element of the list, in the future we will support multiple results.

        :return: A XSOAR entry.
        :rtype: ``dict``
        """

        outputs = self._vendor_action_results[0].create_outputs()
        readable_output = self._vendor_action_results[0].create_readable_outputs(outputs)

        entry_context = {
            'IAM.UserProfile(val.email && val.email == obj.email)': self._user_profile,
            'IAM.Vendor(val.instanceName && val.instanceName == obj.instanceName && '
            'val.email && val.email == obj.email)': outputs
        }

        return_entry = {
            'ContentsFormat': EntryFormat.JSON,
            'Contents': outputs,
            'EntryContext': entry_context
        }

        if self._vendor_action_results[0].should_return_error():
            return_entry['Type'] = EntryType.ERROR
        else:
            return_entry['Type'] = EntryType.NOTE
            return_entry['HumanReadable'] = readable_output

        return return_entry

    def return_outputs(self):
        return_results(self.to_entry())

    def set_result(self, success=True, active=None, iden=None, username=None, email=None, error_code=None,
                   error_message=None, details=None, skip=False, skip_reason=None, action=None, return_error=False):
        """ Sets the outputs and readable outputs attributes according to the given arguments.

        :param success: (bool) whether or not the command succeeded.
        :param active:  (bool) whether or not the user status is active.
        :param iden: (str) the user ID.
        :param username: (str) the username of the user.
        :param email:  (str) the email of the user.
        :param error_code: (str or int) the error code of the response, if exists.
        :param error_message: (str) the error details of the response, if exists.
        :param details: (dict) the full response.
        :param skip: (bool) whether or not the command is skipped.
        :param skip_reason: (str) If the command is skipped, describes the reason.
        :param action: (IAMActions) An enum object represents the action taken (get, update, create, etc).
        :param return_error: (bool) Whether or not to return an error entry.
        """
        if not email:
            email = self.get_attribute('email')

        if not details:
            details = self.mapped_user_profile

        vendor_action_result = IAMVendorActionResult(
            success=success,
            active=active,
            iden=iden,
            username=username,
            email=email,
            error_code=error_code,
            error_message=error_message if error_message else '',
            details=details,
            skip=skip,
            skip_reason=skip_reason if skip_reason else '',
            action=action,
            return_error=return_error
        )

        self._vendor_action_results.append(vendor_action_result)

    def map_object(self, mapper_name, incident_type, map_old_data: bool = False):
        """ Returns the user data, in an application data format.

        :type mapper_name: ``str``
        :param mapper_name: The outgoing mapper from XSOAR to the application.

        :type incident_type: ``str``
        :param incident_type: The incident type used.

        :type map_old_data ``bool``
        :param map_old_data: Whether to map old data as well.

        :return: the user data, in the app data format.
        :rtype: ``dict``
        """
        if self.mapped_user_profile:
            if not map_old_data:
                return {k: v for k, v in self.mapped_user_profile.items() if k != 'olduserdata'}
            return self.mapped_user_profile
        if incident_type not in [IAMUserProfile.CREATE_INCIDENT_TYPE, IAMUserProfile.UPDATE_INCIDENT_TYPE,
                                 IAMUserProfile.DISABLE_INCIDENT_TYPE]:
            raise DemistoException('You must provide a valid incident type to the map_object function.')
        if not self._user_profile:
            raise DemistoException('You must provide the user profile data.')
        app_data = demisto.mapObject(self._user_profile, mapper_name, incident_type)
        if map_old_data and 'olduserdata' in self._user_profile:
            app_data['olduserdata'] = demisto.mapObject(self._user_profile.get('olduserdata', {}), mapper_name,
                                                        incident_type)
        return app_data

    def update_with_app_data(self, app_data, mapper_name, incident_type=None):
        """ updates the user_profile attribute according to the given app_data

        :type app_data: ``dict``
        :param app_data: The user data in app

        :type mapper_name: ``str``
        :param mapper_name: Incoming mapper name

        :type incident_type: ``str``
        :param incident_type: Optional - incident type
        """
        if not incident_type:
            incident_type = IAMUserProfile.DEFAULT_INCIDENT_TYPE
        if not isinstance(app_data, dict):
            app_data = safe_load_json(app_data)
        self._user_profile = demisto.mapObject(app_data, mapper_name, incident_type)

    def get_first_available_iam_user_attr(self, iam_attrs: List[str], use_old_user_data: bool = False):
        # Special treatment for ID field, because he is not included in outgoing mappers.
        for iam_attr in iam_attrs:
            # Special treatment for ID field, because he is not included in outgoing mappers.
            if iam_attr == 'id':
                if attr_value := self.get_attribute(iam_attr, use_old_user_data):
                    return iam_attr, attr_value
            if attr_value := self.get_attribute(iam_attr, use_old_user_data, self.mapped_user_profile):
                # Special treatment for emails, as mapper maps it to a list object.
                if iam_attr == 'emails' and not isinstance(attr_value, str):
                    if isinstance(attr_value, dict):
                        attr_value = attr_value.get('value')
                    elif isinstance(attr_value, list):
                        if not attr_value:
                            continue
                        attr_value = next((email.get('value') for email in attr_value if email.get('primary', False)),
                                          attr_value[0].get('value', ''))
                return iam_attr, attr_value

        raise DemistoException('Your user profile argument must contain at least one attribute that is mapped into one'
                               f' of the following attributes in the outgoing mapper: {iam_attrs}')

    def set_user_is_already_disabled(self, details):
        self.set_result(
            action=IAMActions.DISABLE_USER,
            skip=True,
            skip_reason='User is already disabled.',
            details=details
        )


class IAMUserAppData:
    """ Holds user attributes retrieved from an application.

    :type id: ``str``
    :param id: The ID of the user.

    :type username: ``str``
    :param username: The username of the user.

    :type is_active: ``bool``
    :param is_active: Whether or not the user is active in the application.

    :type full_data: ``dict``
    :param full_data: The full data of the user in the application.

    :return: None
    :rtype: ``None``
    """

    def __init__(self, user_id, username, is_active, app_data, email=None):
        self.id = user_id
        self.username = username
        self.is_active = is_active
        self.full_data = app_data
        self.email = email


class IAMCommand:
    """ A class that implements the IAM CRUD commands - should be used.

    :type id: ``str``
    :param id: The ID of the user.

    :type username: ``str``
    :param username: The username of the user.

    :type is_active: ``bool``
    :param is_active: Whether or not the user is active in the application.

    :type full_data: ``dict``
    :param full_data: The full data of the user in the application.

    :return: None
    :rtype: ``None``
    """

    def __init__(self, is_create_enabled=True, is_enable_enabled=True, is_disable_enabled=True, is_update_enabled=True,
                 create_if_not_exists=True, mapper_in=None, mapper_out=None, get_user_iam_attrs=None):
        """ The IAMCommand c'tor

        :param is_create_enabled: (bool) Whether or not to allow creating users in the application.
        :param is_enable_enabled: (bool) Whether or not to allow enabling users in the application.
        :param is_disable_enabled: (bool) Whether or not to allow disabling users in the application.
        :param is_update_enabled: (bool) Whether or not to allow updating users in the application.
        :param create_if_not_exists: (bool) Whether or not to create a user if does not exist in the application.
        :param mapper_in: (str) Incoming mapper from the application to Cortex XSOAR
        :param mapper_out: (str) Outgoing mapper from the Cortex XSOAR to the application
        :param get_user_iam_attrs (List[str]): List of IAM attributes supported by integration by precedence
                                                        order to get user details.
        """
        if get_user_iam_attrs is None:
            get_user_iam_attrs = ['email']
        self.is_create_enabled = is_create_enabled
        self.is_enable_enabled = is_enable_enabled
        self.is_disable_enabled = is_disable_enabled
        self.is_update_enabled = is_update_enabled
        self.create_if_not_exists = create_if_not_exists
        self.mapper_in = mapper_in
        self.mapper_out = mapper_out
        self.get_user_iam_attrs = get_user_iam_attrs

    def get_user(self, client, args):
        """ Searches a user in the application and updates the user profile object with the data.
            If not found, the error details will be resulted instead.
        :param client: (Client) The integration Client object that implements a get_user() method
        :param args: (dict) The `iam-get-user` command arguments
        :return: (IAMUserProfile) The user profile object.
        """
        user_profile = IAMUserProfile(user_profile=args.get('user-profile'), mapper=self.mapper_out,
                                      incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE)
        try:
            iam_attribute, iam_attribute_val = user_profile.get_first_available_iam_user_attr(self.get_user_iam_attrs)
            user_app_data = client.get_user(iam_attribute, iam_attribute_val)
            if not user_app_data:
                error_code, error_message = IAMErrors.USER_DOES_NOT_EXIST
                user_profile.set_result(action=IAMActions.GET_USER,
                                        success=False,
                                        error_code=error_code,
                                        error_message=error_message)
            else:
                user_profile.update_with_app_data(user_app_data.full_data, self.mapper_in)
                user_profile.set_result(
                    action=IAMActions.GET_USER,
                    active=user_app_data.is_active,
                    iden=user_app_data.id,
                    email=user_profile.get_attribute('email') or user_app_data.email,
                    username=user_app_data.username,
                    details=user_app_data.full_data
                )

        except Exception as e:
            client.handle_exception(user_profile, e, IAMActions.GET_USER)

        return user_profile

    def disable_user(self, client, args):
        """ Disables a user in the application and updates the user profile object with the updated data.
            If not found, the command will be skipped.

        :param client: (Client) The integration Client object that implements get_user() and disable_user() methods
        :param args: (dict) The `iam-disable-user` command arguments
        :return: (IAMUserProfile) The user profile object.
        """
        user_profile = IAMUserProfile(user_profile=args.get('user-profile'), mapper=self.mapper_out,
                                      incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE)
        if not self.is_disable_enabled:
            user_profile.set_result(action=IAMActions.DISABLE_USER,
                                    skip=True,
                                    skip_reason='Command is disabled.')
        else:
            try:
                iam_attribute, iam_attribute_val = user_profile.get_first_available_iam_user_attr(
                    self.get_user_iam_attrs)
                user_app_data = client.get_user(iam_attribute, iam_attribute_val)
                if not user_app_data:
                    _, error_message = IAMErrors.USER_DOES_NOT_EXIST
                    user_profile.set_result(action=IAMActions.DISABLE_USER,
                                            skip=True,
                                            skip_reason=error_message)
                else:
                    if user_app_data.is_active:
                        disabled_user = client.disable_user(user_app_data.id)
                        user_profile.set_result(
                            action=IAMActions.DISABLE_USER,
                            active=False,
                            iden=disabled_user.id,
                            email=user_profile.get_attribute('email') or user_app_data.email,
                            username=disabled_user.username,
                            details=disabled_user.full_data
                        )
                    else:
                        user_profile.set_user_is_already_disabled(user_app_data.full_data)

            except Exception as e:
                client.handle_exception(user_profile, e, IAMActions.DISABLE_USER)

        return user_profile

    def create_user(self, client, args):
        """ Creates a user in the application and updates the user profile object with the data.
            If a user in the app already holds the email in the given user profile, updates
            its data with the given data.

        :param client: (Client) A Client object that implements get_user(), create_user() and update_user() methods
        :param args: (dict) The `iam-create-user` command arguments
        :return: (IAMUserProfile) The user profile object.
        """
        user_profile = IAMUserProfile(user_profile=args.get('user-profile'), mapper=self.mapper_out,
                                      incident_type=IAMUserProfile.CREATE_INCIDENT_TYPE)
        if not self.is_create_enabled:
            user_profile.set_result(action=IAMActions.CREATE_USER,
                                    skip=True,
                                    skip_reason='Command is disabled.')
        else:
            try:
                iam_attribute, iam_attribute_val = user_profile.get_first_available_iam_user_attr(
                    self.get_user_iam_attrs)
                user_app_data = client.get_user(iam_attribute, iam_attribute_val)
                if user_app_data:
                    # if user exists, update it
                    user_profile = self.update_user(client, args)

                else:
                    app_profile = user_profile.map_object(self.mapper_out, IAMUserProfile.CREATE_INCIDENT_TYPE)
                    created_user = client.create_user(app_profile)
                    user_profile.set_result(
                        action=IAMActions.CREATE_USER,
                        active=created_user.is_active,
                        iden=created_user.id,
                        email=user_profile.get_attribute('email') or created_user.email,
                        username=created_user.username,
                        details=created_user.full_data
                    )

            except Exception as e:
                client.handle_exception(user_profile, e, IAMActions.CREATE_USER)

        return user_profile

    def update_user(self, client, args):
        """ Creates a user in the application and updates the user profile object with the data.
            If the user is disabled and `allow-enable` argument is `true`, also enables the user.
            If the user does not exist in the app and the `create-if-not-exist` parameter is checked, creates the user.

        :param client: (Client) A Client object that implements get_user(), create_user() and update_user() methods
        :param args: (dict) The `iam-update-user` command arguments
        :return: (IAMUserProfile) The user profile object.
        """
        user_profile = IAMUserProfile(user_profile=args.get('user-profile'), mapper=self.mapper_out,
                                      incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE)
        allow_enable = args.get('allow-enable') == 'true' and self.is_enable_enabled
        if not self.is_update_enabled:
            user_profile.set_result(action=IAMActions.UPDATE_USER,
                                    skip=True,
                                    skip_reason='Command is disabled.')
        else:
            try:
                iam_attribute, iam_attribute_val = user_profile.get_first_available_iam_user_attr(
                    self.get_user_iam_attrs, use_old_user_data=True)
                user_app_data = client.get_user(iam_attribute, iam_attribute_val)
                if user_app_data:
                    app_profile = user_profile.map_object(self.mapper_out, IAMUserProfile.UPDATE_INCIDENT_TYPE)

                    if allow_enable and not user_app_data.is_active:
                        client.enable_user(user_app_data.id)

                    updated_user = client.update_user(user_app_data.id, app_profile)

                    if updated_user.is_active is None:
                        updated_user.is_active = True if allow_enable else user_app_data.is_active

                    user_profile.set_result(
                        action=IAMActions.UPDATE_USER,
                        active=updated_user.is_active,
                        iden=updated_user.id,
                        email=user_profile.get_attribute('email') or updated_user.email or user_app_data.email,
                        username=updated_user.username,
                        details=updated_user.full_data
                    )
                else:
                    if self.create_if_not_exists:
                        user_profile = self.create_user(client, args)
                    else:
                        _, error_message = IAMErrors.USER_DOES_NOT_EXIST
                        user_profile.set_result(action=IAMActions.UPDATE_USER,
                                                skip=True,
                                                skip_reason=error_message)

            except Exception as e:
                client.handle_exception(user_profile, e, IAMActions.UPDATE_USER)

        return user_profile


def get_first_primary_email_by_scim_schema(res: Dict):
    return next((email.get('value') for email in res.get('emails', []) if email.get('primary')), None)


register_module_line('IAMApiModule', 'end', __line__(), wrapper=1)
### END GENERATED CODE ###  # noqa E402

if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()

register_module_line('AWS-ILM', 'end', __line__())

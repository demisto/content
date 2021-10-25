import demistomock as demisto
from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


DEFAULT_OUTGOING_MAPPER = "User Profile - Salesforce (Outgoing)"
DEFAULT_INCOMING_MAPPER = "User Profile - Salesforce (Incoming)"
URI_PREFIX = '/services/data/v44.0/'
GET_USER_ATTRIBUTES = ['id', 'Username', 'Email']

# setting defaults for mandatory fields
DEFAULT_FIELDS = [
    "localesidkey",
    "emailencodingkey",
    "languagelocalekey"
]

ERROR_CODES_TO_RETURN_ERROR = [
    408
]


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, demisto_params, base_url, conn_client_id, conn_client_secret, conn_username, conn_password,
                 ok_codes, verify=True, proxy=False):
        super().__init__(base_url, verify=verify, proxy=proxy, ok_codes=ok_codes,
                         headers={'content-type': 'application/json'})
        self._conn_client_id = conn_client_id
        self._conn_client_secret = conn_client_secret
        self._conn_username = conn_username
        self._conn_password = conn_password
        self.token = self.get_access_token_()
        self.demisto_params = demisto_params

        # used in non-CRUD commands, to allow collecting their result at the end of `IAM - Sync User` flow
        self.command_details = {
            'instanceName': demisto.callingContext.get('context', {}).get('IntegrationInstance'),
            'brand': demisto.callingContext.get('context', {}).get('IntegrationBrand'),
            'action': demisto.command().replace('-', '_').title().replace('_', '')
        }

    def get_access_token_(self):
        params = {
            "client_id": self._conn_client_id,
            "client_secret": self._conn_client_secret,
            "username": self._conn_username,
            "password": self._conn_password,
            "grant_type": "password"
        }
        res = self._http_request(
            method='POST',
            url_suffix='/services/oauth2/token',
            params=params
        )
        token = res.get('access_token')

        headers = {
            'content-type': 'application/json',
            'Authorization': f'Bearer {token}'
        }

        self._headers = headers
        return token

    def get_user(self, iam_attr, iam_attr_value):
        if iam_attr != 'id':
            term = f"{iam_attr}='{iam_attr_value}'"
            user_id, _ = self.get_user_id_and_activity(iam_attr_value, term)
        else:
            user_id = iam_attr_value

        if user_id:
            uri = URI_PREFIX + f'sobjects/User/{user_id}'
            return self._http_request(
                method='GET',
                url_suffix=uri
            )
        return None

    def search_user_profile(self, user_term, user_where):
        uri = URI_PREFIX + 'parameterizedSearch/'
        params = {
            "q": user_term,
            "sobject": "User",
            "User.where": user_where,
            "User.fields": "Id, IsActive, FirstName, LastName, Email, Username"
        }
        return self._http_request(
            method='GET',
            url_suffix=uri,
            params=params
        )

    def get_user_id_and_activity(self, attribute, term):
        user_id = ""
        active = ""
        res = self.search_user_profile(attribute, term)

        search_records = res.get('searchRecords')
        if len(search_records) > 0:
            for search_record in search_records:
                user_id = search_record.get('Id')
                active = search_record.get('IsActive')

        return user_id, active

    def create_user(self, data):
        uri = URI_PREFIX + 'sobjects/User'
        return self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=data
        )

    def update_user(self, user_term, data):
        uri = URI_PREFIX + f'sobjects/User/{user_term}'
        params = {"_HttpMethod": "PATCH"}
        return self._http_request(
            method='POST',
            url_suffix=uri,
            params=params,
            json_data=data,
            resp_type='text'
        )

    def get_all_users(self):
        uri = URI_PREFIX + 'parameterizedSearch/'
        params = {
            "q": "User",
            "sobject": "User",
        }
        return self._http_request(
            method='GET',
            url_suffix=uri,
            params=params
        )

    def assign_permission_set(self, data):
        uri = URI_PREFIX + 'sobjects/PermissionSetAssignment'
        return self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=data,
            ok_codes=(201,)
        )

    def get_assigned_permission_set(self, assignee_id):
        uri = URI_PREFIX + f"query?q=SELECT+AssigneeId,Id,PermissionSetId+FROM+PermissionSetAssignment+WHERE+" \
                           f"AssigneeId='{assignee_id}'"
        return self._http_request(
            method='GET',
            url_suffix=uri,
            ok_codes=(200,)
        )

    def delete_assigned_permission_set(self, permission_set_assignment_id):
        uri = URI_PREFIX + f'sobjects/PermissionSetAssignment/{permission_set_assignment_id}'
        return self._http_request(
            method='DELETE',
            url_suffix=uri,
            ok_codes=(204,),
            resp_type='response'
        )

    def assign_permission_set_license(self, data):
        uri = URI_PREFIX + 'sobjects/PermissionSetLicenseAssign'
        return self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=data,
            ok_codes=(201,)
        )

    def get_assigned_permission_set_license(self, assignee_id):
        uri = URI_PREFIX + f"query?q=SELECT+AssigneeId,Id+FROM+PermissionSetLicenseAssign+WHERE+" \
                           f"AssigneeId='{assignee_id}'"
        return self._http_request(
            method='GET',
            url_suffix=uri,
            ok_codes=(200,)
        )

    def delete_assigned_permission_set_license(self, permission_set_assignment_license_id):
        uri = URI_PREFIX + f'sobjects/PermissionSetLicenseAssign/{permission_set_assignment_license_id}'
        return self._http_request(
            method='DELETE',
            url_suffix=uri,
            ok_codes=(204,),
            resp_type='response'
        )

    def assign_package_license(self, data):
        uri = URI_PREFIX + 'sobjects/UserPackageLicense'
        return self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=data,
            ok_codes=(201,)
        )

    def get_assigned_package_license(self, user_id):
        uri = URI_PREFIX + f"query?q=SELECT+Id,UserId+FROM+UserPackageLicense+WHERE+UserId='{user_id}'"
        return self._http_request(
            method='GET',
            url_suffix=uri,
            ok_codes=(200,)
        )

    def delete_assigned_package_license(self, user_package_license_id):
        uri = URI_PREFIX + f'sobjects/UserPackageLicense/{user_package_license_id}'
        return self._http_request(
            method='DELETE',
            url_suffix=uri,
            ok_codes=(204,)
        )

    def freeze_unfreeze_user_account(self, user_login_id, data):
        uri = URI_PREFIX + f'sobjects/UserLogin/{user_login_id}'
        params = {"_HttpMethod": "PATCH"}
        return self._http_request(
            method='POST',
            url_suffix=uri,
            params=params,
            json_data=data,
            ok_codes=(204,),
            resp_type='response'
        )

    def get_user_isfrozen_status(self, user_id):
        uri = URI_PREFIX + f"query/?q=SELECT+Id,+IsFrozen+FROM+UserLogin+WHERE+UserId+='{user_id}'"
        return self._http_request(
            method='GET',
            url_suffix=uri,
            ok_codes=(200,)
        )


def handle_exception(e, is_crud_command=True):
    if e.__class__ is DemistoException and hasattr(e, 'res') and e.res is not None:
        if is_crud_command:
            error_code = e.res.status_code
            error_message = e.res.text

        else:
            try:
                res_json = e.res.json()
                if res_json and isinstance(res_json, list):
                    res_json = res_json[0]
                error_code = res_json.get('errorCode')
                error_message = res_json.get('message')

            except ValueError:
                error_code = ''
                error_message = e.res.text
    else:
        error_code = ''
        error_message = str(e)

    if 'Read timed out' in error_message:
        error_code = 408

    demisto.error(traceback.format_exc())
    return error_message, error_code


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: SalesforceITAdmin client
        args  : SalesforceITAdmin arguments passed

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    client.get_user_id_and_activity('test@test.com', 'Email=\'test@test.com\'')
    return 'ok'


def get_user_command(client, args, mapper_in, mapper_out):
    try:
        user_profile = args.get("user-profile")
        iam_user_profile = IAMUserProfile(user_profile=user_profile, mapper=mapper_out,
                                          incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE)
        iam_attr, iam_attr_value = user_profile.get_first_available_iam_user_attr(GET_USER_ATTRIBUTES)
        salesforce_user = client.get_user(iam_attr, iam_attr_value)
        if not salesforce_user:
            error_code, error_message = IAMErrors.USER_DOES_NOT_EXIST
            iam_user_profile.set_result(success=False,
                                        error_message=error_message,
                                        error_code=error_code,
                                        action=IAMActions.GET_USER)
        else:
            # unlike query with email, getting a user by id will bring back all the attributes
            iam_user_profile.update_with_app_data(salesforce_user, mapper_in)

            iam_user_profile.set_result(success=True,
                                        iden=salesforce_user.get('Id'),
                                        email=salesforce_user.get('Email'),
                                        username=salesforce_user.get('Username'),
                                        action=IAMActions.GET_USER,
                                        details=salesforce_user,
                                        active=salesforce_user.get('IsActive'))

        return iam_user_profile

    except Exception as e:
        message, code = handle_exception(e)
        iam_user_profile.set_result(success=False,
                                    error_message=message,
                                    error_code=code,
                                    return_error=code in ERROR_CODES_TO_RETURN_ERROR,
                                    action=IAMActions.GET_USER
                                    )
        return iam_user_profile


def create_user_command(client, args, mapper_out, is_create_enabled, is_update_enabled, is_enable_enabled):
    try:
        user_profile = args.get("user-profile")
        iam_user_profile = IAMUserProfile(user_profile=user_profile, mapper=mapper_out,
                                          incident_type=IAMUserProfile.CREATE_INCIDENT_TYPE)

        if not is_create_enabled:
            iam_user_profile.set_result(action=IAMActions.CREATE_USER,
                                        skip=True,
                                        skip_reason='Command is disabled.')

        else:
            iam_attr, iam_attr_value = user_profile.get_first_available_iam_user_attr(GET_USER_ATTRIBUTES)
            salesforce_user = client.get_user(iam_attr, iam_attr_value)
            if salesforce_user:
                create_if_not_exists = False
                iam_user_profile = update_user_command(client, args, mapper_out, is_update_enabled, is_enable_enabled,
                                                       is_create_enabled, create_if_not_exists)

            else:
                salesforce_user = iam_user_profile.map_object(mapper_name=mapper_out,
                                                              incident_type=IAMUserProfile.CREATE_INCIDENT_TYPE)
                # Removing empty elements from salesforce_user
                salesforce_user = {key: value for key, value in salesforce_user.items() if value is not None}
                res = client.create_user(salesforce_user)
                iam_user_profile.set_result(success=True,
                                            iden=res.get('id'),
                                            email=salesforce_user.get('Email'),
                                            username=salesforce_user.get('Username'),
                                            action=IAMActions.CREATE_USER,
                                            details=res,
                                            active=True)

        return iam_user_profile

    except Exception as e:
        message, code = handle_exception(e)
        iam_user_profile.set_result(success=False,
                                    error_message=message,
                                    error_code=code,
                                    return_error=code in ERROR_CODES_TO_RETURN_ERROR,
                                    action=IAMActions.CREATE_USER
                                    )
        return iam_user_profile


def update_user_command(client, args, mapper_out, is_command_enabled, is_enable_enabled,
                        is_create_user_enabled, create_if_not_exists):
    try:
        iam_user_profile = IAMUserProfile(user_profile=args.get('user-profile'), mapper=mapper_out,
                                          incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE)
        allow_enable = args.get('allow-enable') == 'true'

        if not is_command_enabled:
            iam_user_profile.set_result(action=IAMActions.UPDATE_USER,
                                        skip=True,
                                        skip_reason='Command is disabled.')
        else:
            iam_attr, iam_attr_value = iam_user_profile.get_first_available_iam_user_attr(GET_USER_ATTRIBUTES)
            salesforce_user = client.get_user(iam_attr, iam_attr_value)
            user_id = salesforce_user.get('Id') if salesforce_user else None

            if not user_id:
                # user doesn't exists
                if create_if_not_exists:
                    iam_user_profile = create_user_command(client, args, mapper_out, is_create_user_enabled,
                                                           False, False)
                else:
                    error_code, error_message = IAMErrors.USER_DOES_NOT_EXIST
                    iam_user_profile.set_result(action=IAMActions.UPDATE_USER,
                                                error_code=error_code,
                                                skip=True,
                                                skip_reason=error_message)
            else:
                salesforce_user = iam_user_profile.map_object(mapper_name=mapper_out,
                                                              incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE)
                salesforce_user = {key: value for key, value in salesforce_user.items() if value is not None}
                if allow_enable and is_enable_enabled:
                    salesforce_user['IsActive'] = True
                    action = IAMActions.ENABLE_USER
                else:
                    action = IAMActions.UPDATE_USER

                res = client.update_user(user_term=user_id, data=salesforce_user)

                iam_user_profile.set_result(success=True,
                                            iden=user_id,
                                            active=True,
                                            email=salesforce_user.get('Email'),
                                            username=salesforce_user.get('Username'),
                                            action=action,
                                            details=res
                                            )

        return iam_user_profile

    except Exception as e:
        message, code = handle_exception(e)
        iam_user_profile.set_result(success=False,
                                    error_message=message,
                                    error_code=code,
                                    return_error=code in ERROR_CODES_TO_RETURN_ERROR,
                                    action=IAMActions.UPDATE_USER
                                    )
        return iam_user_profile


def disable_user_command(client, args, mapper_out, is_command_enabled):
    try:
        user_profile = args.get("user-profile")
        iam_user_profile = IAMUserProfile(user_profile=user_profile, mapper=mapper_out,
                                          incident_type=IAMUserProfile.DISABLE_INCIDENT_TYPE)

        if not is_command_enabled:
            user_profile.set_result(action=IAMActions.DISABLE_USER,
                                    skip=True,
                                    skip_reason='Command is disabled.')

        else:
            iam_attr, iam_attr_value = iam_user_profile.get_first_available_iam_user_attr(GET_USER_ATTRIBUTES)
            salesforce_user = client.get_user(iam_attr, iam_attr_value)
            user_id = salesforce_user.get('Id') if salesforce_user else None

            if not user_id:
                error_code, error_message = IAMErrors.USER_DOES_NOT_EXIST
                iam_user_profile.set_result(action=IAMActions.DISABLE_USER,
                                            error_code=error_code,
                                            skip=True,
                                            skip_reason=error_message)
            else:
                salesforce_user = iam_user_profile.map_object(mapper_name=mapper_out,
                                                              incident_type=IAMUserProfile.DISABLE_INCIDENT_TYPE)
                salesforce_user['IsActive'] = False
                salesforce_user = {key: value for key, value in salesforce_user.items() if value is not None}
                res = client.update_user(user_term=user_id, data=salesforce_user)

                iam_user_profile.set_result(success=True,
                                            iden=user_id,
                                            active=False,
                                            action=IAMActions.DISABLE_USER,
                                            details=res
                                            )

        return iam_user_profile

    except Exception as e:
        message, code = handle_exception(e)
        iam_user_profile.set_result(success=False,
                                    error_message=message,
                                    error_code=code,
                                    return_error=code in ERROR_CODES_TO_RETURN_ERROR,
                                    action=IAMActions.DISABLE_USER
                                    )
        return iam_user_profile


def get_all_user_attributes(client):
    """
    This command gets all users, chooses the first
    then, run a second get command that returns all the users attributes
    """
    user_id = ""
    attributes = []

    all_users = client.get_all_users()
    users_list = all_users.get("searchRecords")
    if isinstance(users_list, list):
        user = users_list[0]
        user_id = user.get("Id")

    if user_id:
        user_data = client.get_user('id', user_id)
        user_data.pop('IsActive')  # hard-coded in the CRUD commands
        attributes = list(user_data.keys())
    return attributes


def get_mapping_fields_command(client):
    scheme = get_all_user_attributes(client)
    incident_type_scheme = SchemeTypeMapping(type_name=IAMUserProfile.DEFAULT_INCIDENT_TYPE)

    for field in scheme:
        incident_type_scheme.add_field(field, "Field")

    return GetMappingFieldsResponse([incident_type_scheme])


def assign_permission_set_command(client, args):
    data = {
        'AssigneeId': args.get('user_id'),
        'PermissionSetId': args.get('permission_set_id')
    }
    try:
        res = client.assign_permission_set(data)
        outputs = {
            'success': True,
            'PermissionSetAssign': {'id': res['id']}
        }

    except Exception as e:
        error_message, error_code, = handle_exception(e, is_crud_command=False)
        outputs = {
            'success': False,
            'errorCode': error_code,
            'errorMessage': error_message
        }

    outputs.update(client.command_details)
    return CommandResults(
        outputs=outputs,
        outputs_prefix='IAM.Vendor',
        outputs_key_field='PermissionSetAssign.id'
    )


def get_assigned_permission_set_command(client, args):
    try:
        res = client.get_assigned_permission_set(args.get('user_id'))
        outputs = {
            'success': True,
            'PermissionSetAssignments': res['records']
        }

    except Exception as e:
        error_message, error_code, = handle_exception(e, is_crud_command=False)
        outputs = {
            'success': False,
            'errorCode': error_code,
            'errorMessage': error_message
        }

    outputs.update(client.command_details)
    return CommandResults(
        outputs=outputs,
        outputs_prefix='IAM.Vendor',
        outputs_key_field='PermissionSetAssignments.id'
    )


def delete_assigned_permission_set_command(client, args):
    try:
        client.delete_assigned_permission_set(args.get('permission_set_assignment_id'))
        outputs = {
            'success': True
        }

    except Exception as e:
        error_message, error_code, = handle_exception(e, is_crud_command=False)
        outputs = {
            'success': False,
            'errorCode': error_code,
            'errorMessage': error_message
        }

    outputs.update(client.command_details)
    return CommandResults(
        outputs=outputs,
        outputs_prefix='IAM.Vendor'
    )


def assign_permission_set_license_command(client, args):
    data = {
        'AssigneeId': args.get('user_id'),
        'PermissionSetLicenseId': args.get('permission_set_license_id')
    }
    try:
        res = client.assign_permission_set_license(data)
        outputs = {
            'success': True,
            'PermissionSetLicenseAssign': {'id': res['id']}
        }

    except Exception as e:
        error_message, error_code, = handle_exception(e, is_crud_command=False)
        outputs = {
            'success': False,
            'errorCode': error_code,
            'errorMessage': error_message
        }

    outputs.update(client.command_details)
    return CommandResults(
        outputs=outputs,
        outputs_prefix='IAM.Vendor',
        outputs_key_field='PermissionSetLicenseAssign.id'
    )


def get_assigned_permission_set_license_command(client, args):
    try:
        res = client.get_assigned_permission_set_license(args.get('user_id'))
        outputs = {
            'success': True,
            'PermissionSetLicenseAssignments': res['records']
        }

    except Exception as e:
        error_message, error_code, = handle_exception(e, is_crud_command=False)
        outputs = {
            'success': False,
            'errorCode': error_code,
            'errorMessage': error_message
        }

    outputs.update(client.command_details)
    return CommandResults(
        outputs=outputs,
        outputs_prefix='IAM.Vendor'
    )


def delete_assigned_permission_set_license_command(client, args):
    permission_set_assignment_license_id = args.get('permission_set_assignment_license_id')
    try:
        client.delete_assigned_permission_set_license(permission_set_assignment_license_id)
        outputs = {
            'success': True
        }

    except Exception as e:
        error_message, error_code, = handle_exception(e, is_crud_command=False)
        outputs = {
            'success': False,
            'errorCode': error_code,
            'errorMessage': error_message
        }

    outputs.update(client.command_details)
    return CommandResults(
        outputs=outputs,
        outputs_prefix='IAM.Vendor'
    )


def assign_package_license_command(client, args):
    data = {
        "UserId": args.get('user_id'),
        "PackageLicenseId": args.get('package_license_id')
    }
    try:
        res = client.assign_package_license(data)
        outputs = {
            'success': True,
            'PackageLicenseAssign': {'id': res['id']}
        }

    except Exception as e:
        error_message, error_code, = handle_exception(e, is_crud_command=False)
        outputs = {
            'success': False,
            'errorCode': error_code,
            'errorMessage': error_message
        }

    outputs.update(client.command_details)
    return CommandResults(
        outputs=outputs,
        outputs_prefix='IAM.Vendor',
        outputs_key_field='PackageLicenseAssign.id'
    )


def get_assigned_package_license_command(client, args):
    user_id = args.get('user_id')

    try:
        res = client.get_assigned_package_license(user_id)
        outputs = {
            'success': True,
            'PackageLicenseAssignments': res['records']
        }

    except Exception as e:
        error_message, error_code, = handle_exception(e, is_crud_command=False)
        outputs = {
            'success': False,
            'errorCode': error_code,
            'errorMessage': error_message
        }

    outputs.update(client.command_details)
    return CommandResults(
        outputs=outputs,
        outputs_prefix='IAM.Vendor'
    )


def delete_assigned_package_license_command(client, args):
    user_package_license_id = args.get('user_package_license_id')
    try:
        client.delete_assigned_package_license(user_package_license_id)
        outputs = {
            'success': True
        }

    except Exception as e:
        error_message, error_code, = handle_exception(e, is_crud_command=False)
        outputs = {
            'success': False,
            'errorCode': error_code,
            'errorMessage': error_message
        }

    outputs.update(client.command_details)
    return CommandResults(
        outputs=outputs,
        outputs_prefix='IAM.Vendor'
    )


def freeze_unfreeze_user_account_command(client, args, freeze=True):
    user_login_id = args.get('user_login_id')
    data = {'IsFrozen': 'false' if not freeze else 'true'}

    try:
        client.freeze_unfreeze_user_account(user_login_id, data)
        outputs = {
            'success': True
        }

    except Exception as e:
        error_message, error_code = handle_exception(e, is_crud_command=False)
        outputs = {
            'success': False,
            'errorCode': error_code,
            'errorMessage': error_message
        }

    outputs.update(client.command_details)
    return CommandResults(
        outputs=outputs,
        outputs_prefix='IAM.Vendor'
    )


def get_user_isfrozen_status_command(client, args):
    user_id = args.get('user_id')

    res = client.get_user_isfrozen_status(user_id)

    try:
        res = client.get_user_isfrozen_status(user_id)
        outputs = {
            'success': True,
            'UserIsfrozenStatus': res['records']
        }

    except Exception as e:
        error_message, error_code = handle_exception(e, is_crud_command=False)
        outputs = {
            'success': False,
            'errorCode': error_code,
            'errorMessage': error_message
        }

    outputs.update(client.command_details)
    return CommandResults(
        outputs=outputs,
        outputs_prefix='IAM.Vendor'
    )


def main():

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    # get the service API url
    base_url = params.get('url')
    # checks for '/' at the end url, if it is not available add it
    if base_url[-1] != '/':
        base_url += '/'

    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    client_id = params.get('consumer_key')
    client_secret = params.get('consumer_secret')

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    mapper_in = params.get('mapper_in', DEFAULT_INCOMING_MAPPER)
    mapper_out = params.get('mapper_out', DEFAULT_OUTGOING_MAPPER)

    is_create_enabled = params.get("create_user_enabled")
    is_update_enabled = demisto.params().get("update_user_enabled")
    is_disable_enabled = demisto.params().get("disable_user_enabled")
    is_enable_enabled = demisto.params().get("enable_user_enabled")
    create_if_not_exists = demisto.params().get("create_if_not_exists")

    LOG(f'Command being called is {command}')

    try:
        client = Client(
            demisto_params=params,
            base_url=base_url,
            conn_client_id=client_id,
            conn_client_secret=client_secret,
            conn_username=username,
            conn_password=password,
            ok_codes=(200, 201, 204),
            verify=verify_certificate,
            proxy=proxy
        )

        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'iam-get-user':
            user_profile = get_user_command(client, args, mapper_in, mapper_out)
            return_results(user_profile)

        elif command == 'iam-create-user':
            user_profile = create_user_command(client, args, mapper_out, is_create_enabled, is_update_enabled,
                                               is_enable_enabled)
            return_results(user_profile)

        elif command == 'iam-update-user':
            user_profile = update_user_command(client, args, mapper_out, is_update_enabled, is_enable_enabled,
                                               is_create_enabled, create_if_not_exists)
            return_results(user_profile)

        elif command == 'iam-disable-user':
            user_profile = disable_user_command(client, args, mapper_out, is_disable_enabled)
            return_results(user_profile)

        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields_command(client))

        elif command == 'salesforce-assign-permission-set':
            return_results(assign_permission_set_command(client, args))

        elif command == 'salesforce-get-assigned-permission-set':
            return_results(get_assigned_permission_set_command(client, args))

        elif command == 'salesforce-delete-assigned-permission-set':
            return_results(delete_assigned_permission_set_command(client, args))

        elif command == 'salesforce-assign-permission-set-license':
            return_results(assign_permission_set_license_command(client, args))

        elif command == 'salesforce-get-assigned-permission-set-license':
            return_results(get_assigned_permission_set_license_command(client, args))

        elif command == 'salesforce-delete-assigned-permission-set-license':
            return_results(delete_assigned_permission_set_license_command(client, args))

        elif command == 'salesforce-assign-package-license':
            return_results(assign_package_license_command(client, args))

        elif command == 'salesforce-get-assigned-package-license':
            return_results(get_assigned_package_license_command(client, args))

        elif command == 'salesforce-delete-assigned-package-license':
            return_results(delete_assigned_package_license_command(client, args))

        elif command == 'salesforce-unfreeze-user-account':
            return_results(freeze_unfreeze_user_account_command(client, args, freeze=True))

        elif command == 'salesforce-freeze-user-account':
            return_results(freeze_unfreeze_user_account_command(client, args, freeze=False))

        elif command == 'salesforce-get-user-isfrozen-status':
            return_results(get_user_isfrozen_status_command(client, args))

    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {e}. Traceback: {traceback.format_exc()}')


from IAMApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

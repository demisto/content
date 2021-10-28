import demistomock as demisto
from CommonServerPython import *
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


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

    def get_first_available_iam_user_attr(self, iam_attrs: List[str], use_old_user_data: bool = True):
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
                    email=user_profile.get_attribute('email'),
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
                        user_app_data = client.disable_user(user_app_data.id)
                    user_profile.set_result(
                        action=IAMActions.DISABLE_USER,
                        active=False,
                        iden=user_app_data.id,
                        email=user_profile.get_attribute('email'),
                        username=user_app_data.username,
                        details=user_app_data.full_data
                    )

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
                        email=user_profile.get_attribute('email'),
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
                        updated_user.is_active = True if allow_enable else False

                    if updated_user.email is None:
                        updated_user.email = user_profile.get_attribute('email')

                    user_profile.set_result(
                        action=IAMActions.UPDATE_USER,
                        active=updated_user.is_active,
                        iden=updated_user.id,
                        email=updated_user.email,
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


import traceback
import urllib3
# Disable insecure warnings
urllib3.disable_warnings()


ERROR_CODES_TO_SKIP = [
    404
]

'''CLIENT CLASS'''


class Client(BaseClient):
    """ A client class that implements logic to authenticate with the application. """
    def __init__(self, base_url, api_key, headers, proxy=False, verify=True, ok_codes=None, manager_email=None):
        super().__init__(base_url, verify, proxy, ok_codes, headers)
        self.api_key = api_key
        self.manager_id = self.get_manager_id(manager_email)

    def test(self):
        """ Tests connectivity with the application. """

        uri = '/api/v2/users.json/'
        params = {'api_key': self.api_key,
                  'user[login]': 123}
        self._http_request(method='GET', url_suffix=uri, params=params, timeout=30)

    def get_manager_id(self, manager_email: Optional[str]) -> str:
        """ Gets the user's manager ID from manager email.
        :type manager_email: ``str``
        :param manager_email: user's manager email

        :return: The user's manager ID
        :rtype: ``str``
        """

        # Get manager ID.
        manager_id = ''
        if manager_email:
            res = self.get_user('email', manager_email)
            if res is not None:
                manager_id = res.id
        return manager_id

    def get_user(self, filter_name: str, filter_value: str) -> Optional[IAMUserAppData]:
        """ Queries the user in the application using REST API by its iam get attributes,
        and returns an IAMUserAppData object
        that holds the user_id, username, is_active and app_data attributes given in the query response.

        :type filter_name: ``str``
        :param filter_name: Name of the filter to retrieve the user by.

        :type filter_value: ``str``
        :param filter_value: Value corresponding to given filter to retrieve user by.

        :return: An IAMUserAppData object if user exists, None otherwise.
        :rtype: ``Optional[IAMUserAppData]``
        """
        uri = '/api/v2/users.json/'
        params = {'api_key': self.api_key,
                  f'user[{filter_name}]': filter_value}
        res = self._http_request(
            method='GET',
            url_suffix=uri,
            params=params,
            timeout=30
        )
        if isinstance(res, dict):
            res = [res]
        if res and len(res) == 1:
            user_app_data = res[0]
            user_id = user_app_data.get('id')
            is_active = user_app_data.get('is_active')
            username = user_app_data.get('login')

            return IAMUserAppData(user_id, username, is_active, user_app_data)
        return None

    def create_user(self, user_data: Dict[str, Any]) -> IAMUserAppData:
        """ Creates a user in the application using REST API.

        :type user_data: ``Dict[str, Any]``
        :param user_data: User data in the application format

        :return: An IAMUserAppData object that contains the data of the created user in the application.
        :rtype: ``IAMUserAppData``
        """
        uri = '/api/v2/users.json'
        params = {'api_key': self.api_key}
        if self.manager_id:
            user_data['manager_id'] = self.manager_id
        user_app_data = self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=user_data,
            params=params,
            timeout=30
        )
        user_id = user_app_data.get('id')
        is_active = user_app_data.get('is_active')
        username = user_app_data.get('login')
        return IAMUserAppData(user_id, username, is_active, user_app_data)

    def update_user(self, user_id: str, user_data: Dict[str, Any]) -> IAMUserAppData:
        """ Updates a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :type user_data: ``Dict[str, Any]``
        :param user_data: User data in the application format

        :return: An IAMUserAppData object that contains the data of the updated user in the application.
        :rtype: ``IAMUserAppData``
        """
        uri = f'/api/v2/users/{user_id}'
        params = {'api_key': self.api_key}
        if self.manager_id:
            user_data['manager_id'] = self.manager_id
        self._http_request(
            method='PATCH',
            url_suffix=uri,
            json_data=user_data,
            params=params,
            resp_type='response',
            timeout=30
        )

        username = user_data.get('login')

        return IAMUserAppData(user_id=user_id, username=username, is_active=None, app_data=user_data)

    def enable_user(self, user_id: str) -> IAMUserAppData:
        """ Enables a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """
        user_data = {
            'is_active': 'true'
        }
        return self.update_user(user_id, user_data)

    def disable_user(self, user_id: str) -> IAMUserAppData:
        """ Disables a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """
        user_data = {
            'is_active': 'false'
        }
        return self.update_user(user_id, user_data)

    def get_app_fields(self) -> Dict[str, Any]:
        """ Gets a dictionary of the user schema fields in the application and their description.

        :return: The user schema fields dictionary
        :rtype: ``Dict[str, str]``
        """
        uri = '/api/v2/users.json/'
        params = {'api_key': self.api_key}
        res = self._http_request(
            method='GET',
            url_suffix=uri,
            params=params,
            timeout=30
        )
        if isinstance(res, dict):
            res = [res]
        if len(res) > 0:
            res = res[0]
        return {key: "" for key, val in res.items()}

    @staticmethod
    def handle_exception(user_profile: IAMUserProfile,
                         e: Union[DemistoException, Exception],
                         action: IAMActions):
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
                                error_message=error_message)

        demisto.error(traceback.format_exc())


'''HELPER FUNCTIONS'''


def get_error_details(res: Dict[str, Any]) -> str:
    """ Parses the error details retrieved from the application and outputs the resulted string.

    :type res: ``Dict[str, Any]``
    :param res: The error data retrieved from the application.

    :return: The parsed error details.
    :rtype: ``str``
    """
    err = res.get('error', '')
    if err:
        return str(err)
    return str(res)


'''COMMAND FUNCTIONS'''


def test_module(client: Client):
    """ Tests connectivity with the client. """

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


def main():
    user_profile = None
    params = demisto.params()
    base_url = urljoin(params['url'].strip('/'))
    api_key = params.get('api_key')
    mapper_in = params.get('mapper_in')
    mapper_out = params.get('mapper_out')
    verify_certificate = not params.get('insecure', True)
    proxy = params.get('proxy', False)
    command = demisto.command()
    args = demisto.args()

    is_create_enabled = params.get("create_user_enabled")
    is_enable_enabled = params.get("enable_user_enabled")
    is_disable_enabled = params.get("disable_user_enabled")
    is_update_enabled = params.get("update_user_enabled")
    create_if_not_exists = params.get("create_if_not_exists")

    iam_command = IAMCommand(is_create_enabled, is_enable_enabled, is_disable_enabled, is_update_enabled,
                             create_if_not_exists, mapper_in, mapper_out, get_user_iam_attrs=['id', 'login', 'email'])

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        proxy=proxy,
        headers=headers,
        ok_codes=(200, 201),
        api_key=api_key,
        manager_email=safe_load_json(args.get('user-profile', {})).get('manageremailaddress'),
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
            test_module(client)

        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields(client))

    except Exception as exc:
        # For any other integration command exception, return an error
        return_error(f'Failed to execute {command} command.\nError: {exc}', error=traceback.format_exc())


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

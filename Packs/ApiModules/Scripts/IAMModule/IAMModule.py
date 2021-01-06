import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


class IAMErrors(object):
    """
    An enum class to manually handle errors in IAM integrations
    :return: None
    :rtype: ``None``
    """
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

    INDICATOR_TYPE = 'User Profile'

    def __init__(self, user_profile, user_profile_delta=None):
        self._user_profile = safe_load_json(user_profile)
        self._user_profile_delta = safe_load_json(user_profile_delta) if user_profile_delta else {}
        self._vendor_action_results = []

    def get_attribute(self, item):
        return self._user_profile.get(item)

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

    def map_object(self, mapper_name, mapping_type=None):
        """ Returns the user data, in an application data format.

        :type mapper_name: ``str``
        :param mapper_name: The outgoing mapper from XSOAR to the application.

        :type mapping_type: ``str``
        :param mapping_type: The mapping type of the mapper (optional).

        :return: the user data, in the app data format.
        :rtype: ``dict``
        """
        if not mapping_type:
            mapping_type = IAMUserProfile.INDICATOR_TYPE
        if not self._user_profile:
            raise DemistoException('You must provide the user profile data.')
        app_data = demisto.mapObject(self._user_profile, mapper_name, mapping_type)
        return app_data

    def update_with_app_data(self, app_data, mapper_name, mapping_type=None):
        """ updates the user_profile attribute according to the given app_data

        :type app_data: ``dict``
        :param app_data: The user data in app

        :type mapper_name: ``str``
        :param mapper_name: Incoming mapper name

        :type mapping_type: ``str``
        :param mapping_type: Optional - mapping type
        """
        if not mapping_type:
            mapping_type = IAMUserProfile.INDICATOR_TYPE
        if not isinstance(app_data, dict):
            app_data = safe_load_json(app_data)
        self._user_profile = demisto.mapObject(app_data, mapper_name, mapping_type)


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
    def __init__(self, user_id, username, is_active, app_data):
        self.id = user_id
        self.username = username
        self.is_active = is_active
        self.full_data = app_data


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
    def __init__(self, is_create_enabled=True, is_disable_enabled=True, is_update_enabled=True,
                 create_if_not_exists=True, mapper_in=None, mapper_out=None):
        """ The IAMCommand c'tor

        :param is_create_enabled: (bool) Whether or not the `iam-create-user` command is enabled in the instance
        :param is_disable_enabled: (bool) Whether or not the `iam-disable-user` command is enabled in the instance
        :param is_update_enabled: (bool) Whether or not the `iam-update-user` command is enabled in the instance
        :param create_if_not_exists: (bool) Whether or not to create a user if does not exist in the application
        :param mapper_in: (str) Incoming mapper from the application to Cortex XSOAR
        :param mapper_out: (str) Outgoing mapper from the Cortex XSOAR to the application
        """
        self.is_create_enabled = is_create_enabled
        self.is_disable_enabled = is_disable_enabled
        self.is_update_enabled = is_update_enabled
        self.create_if_not_exists = create_if_not_exists
        self.mapper_in = mapper_in
        self.mapper_out = mapper_out

    def get_user(self, client, args):
        """ Searches a user in the application and updates the user profile object with the data.
            If not found, the error details will be resulted instead.

        :param client: (Client) The integration Client object that implements a get_user() method
        :param args: (dict) The `iam-get-user` command arguments
        :return: (IAMUserProfile) The user profile object.
        """
        user_profile = IAMUserProfile(user_profile=args.get('user-profile'))
        try:
            email = user_profile.get_attribute('email')
            user_app_data = client.get_user(email)
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
                    email=email,
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

        user_profile = IAMUserProfile(user_profile=args.get('user-profile'))
        if not self.is_disable_enabled:
            user_profile.set_result(action=IAMActions.DISABLE_USER,
                                    skip=True,
                                    skip_reason='Command is disabled.')
        else:
            try:
                email = user_profile.get_attribute('email')
                user_app_data = client.get_user(email)
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
                        email=email,
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

        user_profile = IAMUserProfile(user_profile=args.get('user-profile'))

        if not self.is_create_enabled:
            user_profile.set_result(action=IAMActions.CREATE_USER,
                                    skip=True,
                                    skip_reason='Command is disabled.')
        else:
            try:
                email = user_profile.get_attribute('email')
                user_app_data = client.get_user(email)
                if user_app_data:
                    # if user exists, update it
                    user_profile = self.update_user(client, args)

                else:
                    app_profile = user_profile.map_object(self.mapper_out)
                    created_user = client.create_user(app_profile)
                    user_profile.set_result(
                        action=IAMActions.CREATE_USER,
                        active=created_user.is_active,
                        iden=created_user.id,
                        email=email,
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

        user_profile = IAMUserProfile(user_profile=args.get('user-profile'))
        allow_enable = args.get('allow-enable') == 'true'
        if not self.is_update_enabled:
            user_profile.set_result(action=IAMActions.UPDATE_USER,
                                    skip=True,
                                    skip_reason='Command is disabled.')
        else:
            try:
                email = user_profile.get_attribute('email')
                user_app_data = client.get_user(email)
                if user_app_data:
                    app_profile = user_profile.map_object(self.mapper_out)

                    if allow_enable and not user_app_data.is_active:
                        client.enable_user(user_app_data.id)

                    updated_user = client.update_user(user_app_data.id, app_profile)
                    user_profile.set_result(
                        action=IAMActions.UPDATE_USER,
                        active=updated_user.is_active,
                        iden=updated_user.id,
                        email=email,
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

import demistomock as demisto
from CommonServerPython import *
from IAMApiModule import *
from smartsheet.users import Users
import smartsheet
import traceback
import urllib3
# Disable insecure warnings
urllib3.disable_warnings()


ERROR_CODES_TO_SKIP = [
    404
]

'''CLIENT CLASS'''


class Client:
    def __init__(self, user: Users, remove_from_sharing: bool, transfer_sheets: bool,
                 transfer_to_email: Optional[str], send_mail: bool) -> None:
        self.user = user
        self.remove_from_sharing = remove_from_sharing
        self.transfer_sheets = transfer_sheets
        self.transfer_to_email = transfer_to_email
        self.send_mail = send_mail

    def test(self):
        """ Tests connectivity with the application. """
        res = self.user.get_current_user().to_dict()
        if res.get('id'):
            return 'ok'
        else:
            return res.get('result', {}).get('message') or res

    def get_user(self, attr_name: str, attr_value: str) -> Optional[IAMUserAppData]:
        """ Queries the user in the application using smartsheet SDK by its id/email, and returns an IAMUserAppData 
        object that holds the user_id, is_active and app_data attributes given in the query response.

        :type attr_name: ``str``
        :param attr_name: Name of attribute to search by

        :type attr_value: ``str``
        :param attr_value: Value of the attribute

        :return: An IAMUserAppData object if user exists, None otherwise.
        :rtype: ``Optional[IAMUserAppData]``
        """
        if attr_name == 'id':
            res = self.user.list_users(id=attr_value).to_dict()

        else:  # attr_name == 'email'
            res = self.user.list_users(email=attr_value).to_dict()

        if res.get('result', {}).get('statusCode') > 299:
            raise DemistoException(res.get('result', {}).get('message'), res=res)

        if res and len(res.get('data', [])) == 1:
            user_app_data = res.get('data')[0]

            user_id = user_app_data.get('id')
            is_active = user_app_data.get('status') in ['ACTIVE', 'PENDING']

            return IAMUserAppData(user_id, None, is_active, user_app_data)
        return None

    def create_user(self, user_data: Dict[str, Any]) -> IAMUserAppData:
        """ Creates a user in the application using smartsheet SDK.

        :type user_data: ``Dict[str, Any]``
        :param user_data: User data in the application format

        :return: An IAMUserAppData object that contains the data of the created user in the application.
        :rtype: ``IAMUserAppData``
        """
        data_obj = smartsheet.models.User(user_data)
        res = self.user.add_user(data_obj, send_email=self.send_mail).to_dict()

        if res.get('result', {}).get('statusCode') > 299:
            raise DemistoException(res.get('result', {}).get('message'), res=res)

        user_app_data = res.get('result')
        user_id = user_app_data.get('id')
        is_active = user_app_data.get('status', 'ACTIVE') in ['ACTIVE', 'PENDING']

        return IAMUserAppData(user_id, None, is_active, user_app_data)

    def update_user(self, user_id: str, user_data: Dict[str, Any]) -> IAMUserAppData:
        """ Updates a user in the application using smartsheet SDK.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :type user_data: ``Dict[str, Any]``
        :param user_data: User data in the application format

        :return: An IAMUserAppData object that contains the data of the updated user in the application.
        :rtype: ``IAMUserAppData``
        """
        data_obj = smartsheet.models.User(user_data)
        res = self.user.update_user(user_id, data_obj).to_dict()

        if res.get('result', {}).get('statusCode') > 299:
            raise DemistoException(res.get('result', {}).get('message'), res=res)

        user_app_data = res.get('result')
        user_id = user_app_data.get('id')
        is_active = user_app_data.get('status', 'ACTIVE') in ['ACTIVE', 'PENDING']

        return IAMUserAppData(user_id, None, is_active, user_app_data)

    def enable_user(self, user_id: str) -> None:
        # No need to implement - when user is terminated it is removed,
        # so a rehire should execute create_user().
        return None

    def get_user_to_transfer_sheets(self) -> Optional[str]:
        if self.transfer_to_email:
            res = self.get_user(self.transfer_to_email)
            if res:
                return res.id
        return None

    def disable_user(self, user_id: str) -> IAMUserAppData:
        """ Removes a user in the application using smartsheet SDK.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """
        res = self.user.remove_user(
            user_id,
            transfer_to=self.get_user_to_transfer_sheets(),
            transfer_sheets=self.transfer_sheets,
            remove_from_sharing=self.remove_from_sharing
        ).to_dict()

        if res.get('result', {}).get('statusCode') > 299:
            raise DemistoException(res.get('result', {}).get('message'), res=res)

        return IAMUserAppData(user_id, None, False, res)

    def get_app_fields(self) -> Dict[str, Any]:
        """ Gets a dictionary of the user schema fields in the application and their description.

        :return: The user schema fields dictionary
        :rtype: ``Dict[str, str]``
        """
        default_fields_list = ['email', 'name', 'firstName', 'lastName',
                               'admin', 'licensedSheetCreator', 'groupAdmin', 'resourceViewer']
        fields_to_exclude = ['id', 'profileImage', 'status', 'sheetCount', 'customWelcomeScreenViewed']
        data = self.user.list_users(page_size=1).to_dict().get('data', [])
        if not data:
            return {field: '' for field in default_fields_list}
        return {field: '' for field in data[0].keys() if field not in fields_to_exclude}

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
            error_code = e.res.get('result').get('statusCode')
            error_message = e.res.get('result', {}).get('message') or str(e)

            if action == IAMActions.DISABLE_USER and error_code in ERROR_CODES_TO_SKIP:
                skip_message = 'User does not exist in the system.'
                user_profile.set_result(action=action,
                                        skip=True,
                                        skip_reason=skip_message)
                return
        else:
            error_code = ''
            error_message = str(e)

        user_profile.set_result(action=action,
                                success=False,
                                error_code=error_code,
                                error_message=f'{error_message}\n{traceback.format_exc()}')

        demisto.error(traceback.format_exc())


'''COMMAND FUNCTIONS'''


def test_module(client: Client):
    """ Tests connectivity with the client. """
    return client.test()


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


def get_transfer_to_email(args: Dict[str, Any], default: Optional[str] = None):
    user_profile = safe_load_json(args.get('user-profile', {}))
    return user_profile.get('manageremail') or default


def main():
    user_profile = None
    params = demisto.params()
    access_token = params.get('credentials', {}).get('password')
    mapper_in = params.get('mapper_in')
    mapper_out = params.get('mapper_out')
    command = demisto.command()
    args = demisto.args()

    is_create_enabled = params.get("create_user_enabled")
    is_enable_enabled = params.get("enable_user_enabled")
    is_disable_enabled = params.get("disable_user_enabled")
    is_update_enabled = params.get("update_user_enabled")
    create_if_not_exists = params.get("create_if_not_exists")

    remove_from_sharing = params.get("remove_from_sharing")
    transfer_to_email = get_transfer_to_email(args, default=params.get("default_transfer_to"))
    transfer_sheets = params.get("transfer_sheets")
    send_mail = params.get("send_mail")

    iam_command = IAMCommand(is_create_enabled, is_enable_enabled, is_disable_enabled, is_update_enabled,
                             create_if_not_exists, mapper_in, mapper_out, get_user_iam_attrs=['id', 'email'])

    smartsheet_obj = smartsheet.Smartsheet(access_token=access_token)
    smartsheet_obj.errors_as_exceptions(False)
    client = Client(
        user=Users(smartsheet_obj),
        remove_from_sharing=remove_from_sharing,
        transfer_sheets=transfer_sheets,
        transfer_to_email=transfer_to_email,
        send_mail=send_mail
    )

    demisto.debug(f'Command being called is {command}')

    '''CRUD commands'''

    try:
        serr = sys.stderr
        sys.stderr = StringIO()

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
    finally:
        sys.stderr = serr

    '''non-CRUD commands'''

    try:
        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields(client))

    except Exception:
        # For any other integration command exception, return an error
        return_error(f'Failed to execute {command} command. Traceback: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

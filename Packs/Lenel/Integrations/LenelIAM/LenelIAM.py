import demistomock as demisto
from CommonServerPython import *
from IAMApiModule import *
import traceback
import urllib3
# Disable insecure warnings
urllib3.disable_warnings()


ERROR_CODES_TO_SKIP = [
    404
]
SUPPORTED_GET_USER_IAM_ATTRIBUTES = ['id', 'user_name', 'email', 'employee_id']
SCIM_EXTENSION_SCHEMA = "urn:scim:schemas:extension:custom:1.0:user"

'''CLIENT CLASS'''


class Client(BaseClient):
    """ A client class that implements logic to authenticate with the application. """

    def __init__(self, base_url, username, version, password, verify=True, proxy=False, headers=None, auth=None, ok_codes=None):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers, auth=auth, ok_codes=ok_codes)
        self.username = username
        self.password = password
        self.version = version
        self.session = requests.Session()
        self.get_client_token()
        if not proxy:
            self.session.trust_env = False

    def get_client_token(self):
        uri = '/authentication'
        data = {
            "user_name": self.username,
            "password": self.password
        }
        params = {
            "version": self.version
        }
        res = self._http_request(method='POST', url_suffix=uri, json_data=data, params=params)
        try:
            if res.get("session_token") is not None:
                self._headers['Session-Token'] = res.get("session_token")
            else:
                demisto.error("No session token has been found.")
        except ValueError:
            demisto.error("No response has been found.")

    def test(self):
        """ Tests connectivity with the application. """

        uri = '/authentication'
        data = {
            "user_name": self.username,
            "password": self.password
        }
        query_params = {
            "version": self.version
        }
        self._http_request(method='POST', url_suffix=uri, json_data=data, params=query_params)

    @staticmethod
    def get_cardholder(iam_attribute, iam_attribute_val) -> Optional[str]:
        filter_options = {
            'id': f'ID={iam_attribute_val}',
            'employee_id': f'SSNO="{iam_attribute_val}"',
            'user_name': f'USERNAME="{iam_attribute_val}"',
            'email': f'EMAIL="{iam_attribute_val}"'
        }
        return filter_options.get(iam_attribute, None)

    def get_user(self, iam_attribute: str, iam_attribute_val: str) -> Optional[IAMUserAppData]:
        """ Queries the user in the application using REST API by its email, and returns an IAMUserAppData object
        that holds the user_id, username, is_active and app_data attributes given in the query response.

        :type iam_attribute: ``str``
        :param iam_attribute: The IAM attribute.

        :type iam_attribute_val: ``str``
        :param iam_attribute_val: Value of the given IAM attribute.

        :return: An IAMUserAppData object if user exists, None otherwise.
        :rtype: ``Optional[IAMUserAppData]``
        """
        uri = '/instances'
        cardholder_filter = self.get_cardholder(iam_attribute, iam_attribute_val)
        query_params = {
                'filter': cardholder_filter,
                'version': self.version,
                'type_name': 'Lnl_Cardholder'
            }

        res = self._http_request(
            method='GET',
            url_suffix=uri,
            params=query_params
        )
        result = res.get('item_list')
        count = res.get('count')

        if result and count and count == 1:
            result = result[0]
            lenel_active = result['property_value_map'].get('ACTIVE__XR')
            is_active = lenel_active and lenel_active.lower() == 'true'
            user_id = result['property_value_map']['ID']
            username = result['property_value_map']['USERNAME']

            return IAMUserAppData(user_id, username, is_active, result['property_value_map'])
        return None

    def create_user(self, user_data: Dict[str, Any]) -> IAMUserAppData:
        """ Creates a user in the application using REST API.

        :type user_data: ``Dict[str, Any]``
        :param user_data: User data in the application format

        :return: An IAMUserAppData object that contains the data of the created user in the application.
        :rtype: ``IAMUserAppData``
        """
        lenel_user = {}
        uri = '/instances'
        query_params = {
            'type_name': 'Lnl_Cardholder',
            'version': self.version
        }
        lenel_user['property_value_map'] = user_data
        res = self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=lenel_user,
            params=query_params
        )
        property_value_map = res['property_value_map']
        user_id = property_value_map.get('ID')
        username = property_value_map.get('USERNAME')
        return IAMUserAppData(user_id, username, is_active=True, app_data=res)

    def update_user(self, user_id: str, user_data: Dict[str, Any]) -> Optional[IAMUserAppData]:
        """ Updates a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :type user_data: ``Dict[str, Any]``
        :param user_data: User data in the application format

        :return: An IAMUserAppData object that contains the data of the updated user in the application.
        :rtype: ``IAMUserAppData``
        """
        lenel_user = {}
        uri = '/instances'
        query_params = {
            'type_name': 'Lnl_Cardholder',
            'version': self.version
        }
        lenel_user['property_value_map'] = user_data
        return_warning(lenel_user)
        self._http_request(
            method='PUT',
            url_suffix=uri,
            json_data=lenel_user,
            params=query_params
        )

        return self.get_user('id', user_id)

    def enable_user(self, user_id: str) -> IAMUserAppData:
        """ Enables a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """
        # Note: ENABLE user API endpoints might vary between different APIs.
        # In this example, we use the same endpoint as in update_user() method,
        # But other APIs might have a unique endpoint for this request.

        lenel_user = {
            "property_value_map": {
                'ID': user_id,
                'ACTIVE__XR': True,
            }
        }
        return self.update_user(user_id, lenel_user)

    def disable_user(self, user_id: str) -> Optional[IAMUserAppData]:
        """ Disables a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """
        # Note: DISABLE user API endpoints might vary between different APIs.
        # In this example, we use the same endpoint as in update_user() method,
        # But other APIs might have a unique endpoint for this request.
        lenel_user = {
            "property_value_map": {
                'ID': user_id,
                'ACTIVE__XR': False,
            }
        }
        res = self.update_user(user_id, lenel_user)
        full_data = res.full_data

        details = []
        details.append(full_data)
        # Deactivate the badges associated with the user account
        filter = f'PERSONID={user_id}'
        get_badges_res = self.get_badges(filter)
        res_badgejson = get_badges_res.json()

        badge_list = res_badgejson.get("item_list")
        if badge_list:
            for badge in badge_list:
                badge_key = badge["property_value_map"]['BADGEKEY']
                deactivate_badge_res = self.deactivate_badge(badge_key)
                details.append({
                    f"Badge Key {badge_key}": deactivate_badge_res.json()
                })
                if deactivate_badge_res:
                    demisto.info(f"Deactivated badge for user: {user_id}. Badge Key: {badge_key}")
                else:
                    demisto.error(f"Failed to deactivate badge for user: {user_id}. Badge Key: {badge_key}. "
                                  f"Error Response: {deactivate_badge_res.json()}")
        else:
            demisto.info(f"No badge associated with the user {user_id} for deactivation")

        return self.get_user('id', user_id)

    def get_badges(self, filter):
        uri = '/instances'
        query_params = {
            'filter': filter,
            'version': self.version,
            'type_name': 'Lnl_Badge'
        }
        return self._http_request(
            method='GET',
            url_suffix=uri,
            params=query_params
        )

    def deactivate_badge(self, badge_key):
        uri = '/instances'
        data = {
            "type_name": 'Lnl_Badge',
            "version": "1.0",
            "property_value_map": {
                "BADGEKEY": badge_key,
                "STATUS": 4  # Badge STATUS=4 sets the badge to 'Inactive' status
            }
        }
        return self._http_request(
            method='PUT',
            url_suffix=uri,
            data=data
        )

    def get_app_fields(self) -> Dict[str, Any]:
        """ Gets a dictionary of the user schema fields in the application and their description.

        :return: The user schema fields dictionary
        :rtype: ``Dict[str, str]``
        """

        uri = '/schema'
        res = self._http_request(
            method='GET',
            url_suffix=uri
        )

        fields = res.get('result', [])
        return {field.get('name'): field.get('description') for field in fields}

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
    message = res.get('error', {}).get('message')
    details = res.get('error', {}).get('detail')
    return f'{message}: {details}'


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
    base_url = urljoin(params['url'].strip('/'), '/api/access/onguard/openaccess')
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')
    mapper_in = params.get('mapper_in')
    mapper_out = params.get('mapper_out')
    application_id = params.get('application_id')
    api_version = params.get('api_version', '1.0')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()
    args = demisto.args()

    is_create_enabled = params.get("create_user_enabled")
    is_enable_enabled = params.get("enable_user_enabled")
    is_disable_enabled = params.get("disable_user_enabled")
    is_update_enabled = params.get("update_user_enabled")
    create_if_not_exists = params.get("create_if_not_exists")

    iam_command = IAMCommand(is_create_enabled, is_enable_enabled, is_disable_enabled, is_update_enabled,
                             create_if_not_exists, mapper_in, mapper_out, get_user_iam_attrs=SUPPORTED_GET_USER_IAM_ATTRIBUTES)

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Application-Id': application_id
    }

    client = Client(
        base_url=base_url,
        username=username,
        version=api_version,
        password=password,
        verify=verify_certificate,
        proxy=proxy,
        headers=headers,
        auth=(username, password),
        ok_codes=(200, 201),
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

    except Exception:
        # For any other integration command exception, return an error
        return_error(f'Failed to execute {command} command. Traceback: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

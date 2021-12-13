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

''' CONSTANTS '''
SCIM_EXTENSION_SCHEMA = "urn:scim:schemas:extension:custom:1.0:user"

'''CLIENT CLASS'''


class Client(BaseClient):
    """ A client class that implements logic to authenticate with the application. """

    def test(self):
        """ Tests connectivity with the application. """

        uri = 'scim/v2/Users'
        self._http_request(method='GET', url_suffix=uri)

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
        filter_value = encode_string_results(filter_value)
        if filter_name == 'emails':
            filter_name = 'email'
        if filter_name == 'id':
            uri = f'scim/v2/Users/{filter_value}'
        else:
            uri = f'scim/v2/Users?filter={filter_name} eq {filter_value}'

        res = self._http_request(
            method='GET',
            url_suffix=uri,
        )
        try:
            res_json = res.json()
        except Exception:
            res_json = res
        if filter_name == 'id':
            return IAMUserAppData(user_id=res_json.get('id'),
                                  username=res_json.get('userName'),
                                  is_active=res_json.get('active', False),
                                  app_data=res_json,
                                  email=get_first_primary_email_by_scim_schema(res_json))
        if res_json and res_json.get('totalResults', 0) != 1:
            user_app_data = res_json.get('Resources')[0]
            user_id = user_app_data.get('id')
            is_active = user_app_data.get('active')
            username = user_app_data.get('userName')

            return IAMUserAppData(user_id, username, is_active, user_app_data,
                                  email=get_first_primary_email_by_scim_schema(user_app_data))
        return None

    def create_user(self, user_data: Dict[str, Any]) -> IAMUserAppData:
        """ Creates a user in the application using REST API.

        :type user_data: ``Dict[str, Any]``
        :param user_data: User data in the application format

        :return: An IAMUserAppData object that contains the data of the created user in the application.
        :rtype: ``IAMUserAppData``
        """
        uri = 'scim/v2/Users'
        res = self._http_request(
            method='POST',
            url_suffix=uri,
            data=user_data
        )
        user_app_data = res.json()
        user_id = user_app_data.get('id')
        is_active = True
        username = user_data.get('userName')

        return IAMUserAppData(user_id, username, is_active, user_app_data,
                              email=get_first_primary_email_by_scim_schema(user_app_data))

    def update_user(self, user_id: str, user_data: Dict[str, Any]) -> IAMUserAppData:
        """ Updates a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :type user_data: ``Dict[str, Any]``
        :param user_data: User data in the application format

        :return: An IAMUserAppData object that contains the data of the updated user in the application.
        :rtype: ``IAMUserAppData``
        """
        res = self._http_request(
            'GET',
            url_suffix=f'scim/v2/{user_id}',
        )
        try:
            existing_user_data = res.json()
        except Exception:
            existing_user_data = res

        map_changes_to_existing_user(existing_user_data, user_data)

        uri = f'scim/v2/Users/{user_id}'
        res = self._http_request(
            method='PUT',
            url_suffix=uri,
            data=existing_user_data
        )
        user_app_data = res.json()
        is_active = user_app_data.get('active', False)
        username = user_data.get('userName')

        return IAMUserAppData(user_id, username, is_active, user_app_data,
                              email=get_first_primary_email_by_scim_schema(user_app_data))

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

        user_data = {'active': True}
        return self.update_user(user_id, user_data)

    def disable_user(self, user_id: str) -> IAMUserAppData:
        """ Disables a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """
        # Note: DISABLE user API endpoints might vary between different APIs.
        # In this example, we use the same endpoint as in update_user() method,
        # But other APIs might have a unique endpoint for this request.

        user_data = {'active': False}
        return self.update_user(user_id, user_data)

    def get_app_fields(self) -> Dict[str, Any]:
        """ Gets a dictionary of the user schema fields in the application and their description.

        :return: The user schema fields dictionary
        :rtype: ``Dict[str, str]``
        """
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


def map_changes_to_existing_user(existing_user: dict, new_user_updated_data: dict) -> None:
    """
    The new scim cannot be send as is to the Envoy system
    because this request will delete all the fields
    in the Envoy system and then insert/add the new scim.

    map_changes_to_existing_user does the required changes
    in the existing json as per the new scim coming from the request
    """

    for key, value in new_user_updated_data.items():
        if isinstance(value, list):
            # handle in specific way
            # as of now only emails, phone numbers needs to be handled
            if key in ('emails', 'phoneNumbers'):
                existing_complex_list = existing_user.get(key, [])
                # map emails and phoneNumbers data to the list(existing_complex_list) using new_json
                map_changes_emails_phone_numbers(value, existing_complex_list)
                # add
                new_complex_list = []
                for new_json_item in value:
                    exist = False
                    for existing_json_item in existing_complex_list:
                        if new_json_item.get('type') == existing_json_item.get('type', ''):
                            exist = True
                            break
                    if not exist:
                        new_dict = {'type': new_json_item.get('type'),
                                    'value': new_json_item.get('value')}
                        if new_json_item.get('primary', None) is not None:
                            new_dict.update({'primary': new_json_item.get('primary')})
                        new_complex_list.append(new_dict)
                existing_complex_list.extend(new_complex_list)

            if key in 'addresses':
                existing_complex_list = existing_user.get(key, [])
                # map address data to the list(existing_complex_list) using new_json
                map_changes_address(value, existing_complex_list)
                # add
                new_complex_list = []
                for new_json_item in value:
                    exist = False
                    for existing_json_item in existing_complex_list:
                        if new_json_item.get('type') == existing_json_item.get('type', ''):
                            exist = True
                            break
                    if not exist:
                        new_dict = {'type': new_json_item.get('type'),
                                    'formatted': new_json_item.get('formatted', ''),
                                    'streetAddress': new_json_item.get('streetAddress', ''),
                                    'locality': new_json_item.get('locality', ''),
                                    'region': new_json_item.get('region', ''),
                                    'postalCode': new_json_item.get('postalCode', ''),
                                    'country': new_json_item.get('country', ''),
                                    'primary': new_json_item.get('primary', '')
                                    }
                        new_complex_list.append(new_dict)
                existing_complex_list.extend(new_complex_list)

        elif isinstance(value, dict):
            if key != SCIM_EXTENSION_SCHEMA:
                map_changes_to_existing_user(existing_user.get(key, {}), value)
        else:
            existing_user[key] = [value] if key in ('emails', 'phoneNumbers') else value


def map_changes_emails_phone_numbers(new_list, existing_complex_list):
    # update
    for new_json_item in new_list:
        for existing_json_item in existing_complex_list:
            if existing_json_item.get('type') == new_json_item.get('type'):
                if existing_json_item.get('value') != new_json_item.get('value'):
                    existing_json_item['value'] = new_json_item.get('value')
                if new_json_item.get('primary', None) is not None:
                    existing_json_item['primary'] = new_json_item.get('primary')
                break


def map_changes_address(value, existing_complex_list):
    # update
    for new_json_item in value:
        for existing_json_item in existing_complex_list:
            if existing_json_item.get('type') == new_json_item.get('type'):
                if new_json_item.get('primary', None) is not None:
                    existing_json_item['primary'] = new_json_item.get('primary')
                if existing_json_item.get('formatted') != new_json_item.get('formatted'):
                    existing_json_item['formatted'] = new_json_item.get('formatted')
                if existing_json_item.get('streetAddress') != new_json_item.get('streetAddress'):
                    existing_json_item['streetAddress'] = new_json_item.get('streetAddress')
                if existing_json_item.get('locality') != new_json_item.get('locality'):
                    existing_json_item['locality'] = new_json_item.get('locality')
                if existing_json_item.get('region') != new_json_item.get('region'):
                    existing_json_item['region'] = new_json_item.get('region')
                if existing_json_item.get('postalCode') != new_json_item.get('postalCode'):
                    existing_json_item['postalCode'] = new_json_item.get('postalCode')
                if existing_json_item.get('country') != new_json_item.get('country'):
                    existing_json_item['country'] = new_json_item.get('country')
                break


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
    base_url = urljoin(params['url'].strip('/'), '/api/now/')
    token = params.get('api_key')
    mapper_in = params.get('mapper_in')
    mapper_out = params.get('mapper_out')
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
                             create_if_not_exists, mapper_in, mapper_out,
                             get_user_iam_attrs=['id', 'userName', 'emails'])

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': f'Bearer {token}',
    }

    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        proxy=proxy,
        headers=headers,
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

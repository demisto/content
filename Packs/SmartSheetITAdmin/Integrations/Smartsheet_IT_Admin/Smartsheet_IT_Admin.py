''' IMPORTS '''

from CommonServerPython import *
import smartsheet
import traceback
from smartsheet.users import Users

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
SCIM_EXTENSION_SCHEMA = "urn:scim:schemas:extension:custom:1.0:user"
USER_NOT_FOUND = "User not found"


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, user):
        self.user = user

    def get_user(self, user_id=None, email=None):
        if (user_id is not None):
            res = self.user.get_user(user_id)
        else:
            res = self.user.list_users(email=email)
        return res

    def remove_user(self, user_id, custom_mapping):
        if custom_mapping == '':
            custom_mapping = dict()
        transfer_to = custom_mapping.get('transferTo', None)
        transfer_sheets = custom_mapping.get('transferSheets', False)
        remove_from_sharing = custom_mapping.get('removeFromSharing', False)
        res = self.user.remove_user(user_id, transfer_to=transfer_to, transfer_sheets=transfer_sheets,
                                    remove_from_sharing=remove_from_sharing)
        return res

    def create_user(self, data):
        try:
            data_obj = smartsheet.models.User(data)
            new_user = self.user.add_user(data_obj, send_email=data.get("send_email"))

        except Exception:
            raise Exception("Exception occured", traceback.format_exc())

        return new_user

    def update_user(self, user_term, data):
        new_user = self.user.update_user(user_term, smartsheet.models.User(data))
        return new_user

    # Builds a new user smartsheet dict with pre-defined keys and custom mapping (for user)
    def build_smartsheet_create_user(self, args, scim, custom_mapping):
        parsed_scim_data = map_scim(scim)

        smartsheet_user = {
            "email": parsed_scim_data.get('email'),
            "firstName": parsed_scim_data.get('first_name'),
            "lastName": parsed_scim_data.get('last_name'),
            "locale": parsed_scim_data.get('locale'),
            "timeZone": parsed_scim_data.get('timezone'),
            "alternateEmails": parsed_scim_data.get('alternate_emails'),
            "title": parsed_scim_data.get('title'),
            "department": parsed_scim_data.get('department'),
            "workPhone": parsed_scim_data.get('phone_mobile'),
            "mobilePhone": parsed_scim_data.get('phone_work'),
        }

        if args.get('customMapping'):
            custom_mapping = json.loads(args.get('customMapping'))
        elif custom_mapping:
            custom_mapping = json.loads(custom_mapping)

        extension_schema = scim.get(SCIM_EXTENSION_SCHEMA)
        if custom_mapping and extension_schema:
            for key, value in custom_mapping.items():
                # key is the attribute name in input scim. value is the attribute name of app profile
                user_extension_data = extension_schema.get(key)
                if user_extension_data is not None:
                    smartsheet_user[value] = user_extension_data
        if not smartsheet_user.get('admin', None):
            smartsheet_user['admin'] = False
        if not smartsheet_user.get('licensedSheetCreator', None):
            smartsheet_user['licensedSheetCreator'] = False
        return smartsheet_user

    # Builds a new user prisma profile dict with pre-defined keys and custom mapping (for user)

    def build_smartsheet_update_user(self, args, scim, custom_mapping):
        parsed_scim_data = map_scim(scim)

        smartsheet_user = {
            # "email": parsed_scim_data.get('email'),
            "firstName": parsed_scim_data.get('first_name'),
            "lastName": parsed_scim_data.get('last_name'),
            "locale": parsed_scim_data.get('locale'),
            "timeZone": parsed_scim_data.get('timezone'),
            "alternateEmails": parsed_scim_data.get('alternate_emails'),
            "title": parsed_scim_data.get('title'),
            "department": parsed_scim_data.get('department'),
            "workPhone": parsed_scim_data.get('phone_mobile'),
            "mobilePhone": parsed_scim_data.get('phone_work'),
        }
        if args.get('customMapping'):
            custom_mapping = json.loads(args.get('customMapping'))
        elif custom_mapping:
            custom_mapping = json.loads(custom_mapping)

        extension_schema = scim.get(SCIM_EXTENSION_SCHEMA)
        if custom_mapping and extension_schema:
            for key, value in custom_mapping.items():
                # key is the attribute name in input scim. value is the attribute name of app profile
                user_extension_data = extension_schema.get(key)
                if user_extension_data is not None:
                    smartsheet_user[value] = user_extension_data

        return smartsheet_user

    def build_smartsheet_remove_user(self, args, scim, custom_mapping):

        smartsheet_user = dict()
        if args.get('customMapping'):
            custom_mapping = json.loads(args.get('customMapping'))
        elif custom_mapping:
            custom_mapping = json.loads(custom_mapping)

        extension_schema = scim.get(SCIM_EXTENSION_SCHEMA)
        if custom_mapping and extension_schema:
            for key, value in custom_mapping.items():
                # key is the attribute name in input scim. value is the attribute name of app profile
                user_extension_data = extension_schema.get(key)
                if user_extension_data is not None:
                    smartsheet_user[value] = user_extension_data

        return smartsheet_user


class OutputContext:
    """
        Class to build a generic output and context.
    """

    def __init__(self, success=None, active=None, iden=None, username=None, email=None, errorCode=None,
                 errorMessage=None, details=None):
        self.instanceName = demisto.callingContext['context']['IntegrationInstance']
        self.brand = demisto.callingContext['context']['IntegrationBrand']
        self.command = demisto.command().replace('-', '_').title().replace('_', '')
        self.success = success
        if not active:
            self.active = active
        elif active == "ACTIVE" or active == "PENDING":
            self.active = True
        else:
            self.active = False
        self.iden = iden
        self.username = username
        self.email = email
        self.errorCode = errorCode
        self.errorMessage = errorMessage
        self.details = details
        self.data = {
            "brand": self.brand,
            "instanceName": self.instanceName,
            "success": success,
            "active": self.active,
            "id": iden,
            "username": username,
            "email": email,
            "errorCode": errorCode,
            "errorMessage": errorMessage,
            "details": details
        }


def verify_and_load_scim_data(scim):
    try:
        scim = json.loads(scim)
    except Exception:
        pass
    if type(scim) != dict:
        raise Exception("SCIM data is not a valid JSON " + str(scim))
    return scim


def map_scim(scim):
    try:
        scim = json.loads(scim)
    except Exception:
        pass
    if type(scim) != dict:
        raise Exception('Provided client data is not JSON compatible')

    mapping = {
        "id": "id",
        "userName": "userName",
        "email": "emails(val.primary && val.primary==true).value",
        "alternate_emails": "emails(val.primary && val.primary==false).value",
        "first_name": "name.givenName",
        "last_name": "name.familyName",
        "timezone": "timezone",
        "locale": "locale",
        "phone_home": "phoneNumbers(val.type && val.type=='home').value",
        "phone_mobile": "phoneNumbers(val.type && val.type=='mobile').value",
        "phone_work": "phoneNumbers(val.type && val.type=='work').value",
        "title": "title",
        "department": "department"
    }

    parsed_scim = dict()

    for k, v in mapping.items():
        try:
            value = demisto.dt(scim, v)
            if (type(value) == list):
                parsed_scim[k] = value[0]
            else:
                parsed_scim[k] = value
        except Exception:
            parsed_scim[k] = None
    return parsed_scim


''' COMMAND FUNCTIONS '''


def test_module(client, args):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: Smartsheeet client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    args

    res = client.user.get_current_user()
    res_json = json.loads(str(res))

    if (res_json.get('id', None) is not None):
        return 'ok', None, None
    else:
        message = res_json.get('result').get('message')
        return "Test failed because: {}.".format(message), None, None


def get_user_command(client, args):
    """
        Returning user GET details and status of response.

        Args:   demisto command line argument
        client: Smartsheet

        Returns:
            success : success=True, id, email, login as username, details, active status
            fail : success=False, id, login as username, errorCod, errorMessage, details
    """
    scim = verify_and_load_scim_data(args.get('scim'))
    scim_flat_data = map_scim(scim)
    user_id = scim_flat_data.get('id')
    email = scim_flat_data.get('email')

    if not user_id and not email:
        raise Exception('You must provide either the id or email of the user')

    if user_id:
        res = client.get_user(user_id=user_id)
        res_json = json.loads(str(res))
    else:
        res = client.get_user(email=email)
        res_json = json.loads(str(res))
        res_json = res_json.get('data')
        if res_json:
            res_json = res_json[0]

    if not res_json:
        generic_iam_context = OutputContext(success=False, iden=user_id, email=email, errorCode=404,
                                            errorMessage=USER_NOT_FOUND, details=res_json)
    elif res_json.get('id', None) is not None:
        id = res_json.get('id')
        email = res_json.get('email')
        active = res_json.get('status', False)
        generic_iam_context = OutputContext(success=True, iden=id, email=email, details=res_json,
                                            active=active)
    elif res_json.get('result').get('statusCode') == 404:
        generic_iam_context = OutputContext(success=False, iden=user_id, errorCode=404,
                                            errorMessage=USER_NOT_FOUND, details=res_json)
    else:
        errorMessage = res_json.get('result').get('message')
        errorCode = res_json.get('result').get('statusCode')
        generic_iam_context = OutputContext(success=False, iden=user_id, errorCode=errorCode,
                                            errorMessage=errorMessage, details=res_json)

    generic_iam_context_dt = "{}(val.id == obj.id && val.instanceName == obj.instanceName)".format(
        generic_iam_context.command)

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown('Smartsheet user ' + str(user_id or email) + ' data:', generic_iam_context.data)

    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def remove_user_command(client, args):
    """
        Returning user REMOVE status of response.

        Args:   demisto command line argument
        client: Smartsheet client

        Returns:
            success : success=True, id, email, login as username, details, active status
            fail : success=False, id, login as username, errorCod, errorMessage, details
    """
    custom_mapping = demisto.params().get('customMappingUpdateUser')
    scim = verify_and_load_scim_data(args.get('scim'))
    scim_flat_data = map_scim(scim)
    user_id = scim_flat_data.get('id')

    if not user_id:
        raise Exception('You must provide either the id of the user')

    user_details = client.build_smartsheet_remove_user(args, scim, custom_mapping)

    res = client.remove_user(user_id, user_details)

    res_json = json.loads(str(res))
    if (res_json.get('resultCode', None) == 0):
        generic_iam_context = OutputContext(success=True, iden=user_id, email=None, details=res_json, active=False)
    else:
        errorMessage = res_json.get('result').get('message')
        generic_iam_context = OutputContext(success=False, iden=user_id,
                                            errorCode=res_json.get('result').get('statusCode'),
                                            errorMessage=errorMessage, details=res_json)

    generic_iam_context_dt = "{}(val.id == obj.id && val.instanceName == obj.instanceName)".format(
        generic_iam_context.command)
    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown('Smartsheet user ' + str(user_id) + ' data:', generic_iam_context.data)

    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def update_user_command(client, args):
    """
        Update user using PUT to Smartsheet API , if Connection to the service is successful.

        Args:   demisto command line argument
        client: Smartsheet

        Returns:
            success : success=True, id, email, login as username, details, active status
            fail : success=False, id, login as username, errorCod, errorMessage, details
    """
    custom_mapping = demisto.params().get('customMappingUpdateUser')

    old_scim = verify_and_load_scim_data(args.get('oldScim'))
    new_scim = verify_and_load_scim_data(args.get('newScim'))

    parsed_old_scim = map_scim(old_scim)
    user_id = parsed_old_scim.get('id')

    if not (user_id):
        raise Exception('You must provide id of the user')

    smartsheet_user = client.build_smartsheet_update_user(args, new_scim, custom_mapping)
    # Removing Elements from prisma_user dictionary which was not sent as part of scim
    smartsheet_user = {key: value for key, value in smartsheet_user.items() if value is not None}
    res = client.update_user(user_term=user_id, data=smartsheet_user)

    res_json = json.loads(str(res))

    if (res_json.get('resultCode', None) == 0):
        email_id = res_json.get('result').get('email', '')
        res_json = res_json.get('result')
        active = res_json.get('status', False)
        generic_iam_context = OutputContext(success=True, iden=user_id, email=email_id, details=res_json,
                                            active=active)
    else:
        errorMessage = res_json.get('result').get('message', None)
        generic_iam_context = OutputContext(success=False, iden=parsed_old_scim.get('id'),
                                            errorCode=res_json.get('result').get('statusCode'),
                                            errorMessage=errorMessage, details=res_json)

    generic_iam_context_dt = "{}(val.id == obj.id && val.instanceName == obj.instanceName)".format(
        generic_iam_context.command)

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown('Smartsheet user ' + str(user_id) + ' data:', generic_iam_context.data)

    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def create_user_command(client, args):
    """
        Create user using POST to Smart sheet API, if Connection to the service is successful.

        Args: demisto command line argument
        client: Smart sheet

        Returns:
            success : success=True, id, email, login as username, details, active status
            fail : success=False, id, login as username, errorCode, errorMessage, details
    """

    custom_mapping = demisto.params().get('customMappingCreateUser')

    scim = verify_and_load_scim_data(args.get('scim'))
    parsed_scim = map_scim(scim)

    smartsheet_user = client.build_smartsheet_create_user(args, scim, custom_mapping)

    # Removing Elements from smarsheet dictionary which was not sent as part of scim
    smartsheet_user = {key: value for key, value in smartsheet_user.items() if value is not None}

    res = client.create_user(smartsheet_user)
    res_json = json.loads(str(res))

    if (res_json.get('resultCode', None) == 0):
        user_id = res_json.get('result').get('id', None)
        user_email = res_json.get('result').get('email', None)
        res_json = res_json.get('result')
        generic_iam_context = OutputContext(success=True, iden=user_id, email=user_email, details=res_json,
                                            active=False)  # active is always Pending in smartsheet while creating user.
    elif (res_json.get('result').get('statusCode', None) == 403):
        errorMessage = res_json.get('result').get('message', None)
        generic_iam_context = OutputContext(success=False, iden=None, email=parsed_scim.get('email'), errorCode=409,
                                            errorMessage=errorMessage, details=res_json)
    else:
        errorMessage = res_json.get('result').get('message', None)
        generic_iam_context = OutputContext(success=False, iden=None, email=parsed_scim.get('email'),
                                            errorCode=res_json.get('result').get('statusCode'),
                                            errorMessage=errorMessage, details=res_json)

    generic_iam_context_dt = "{}(val.id == obj.id && val.instanceName == obj.instanceName)".format(
        generic_iam_context.command)

    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown('Smartsheet user data:', generic_iam_context.data)

    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    auth_key = params.get('Authorization')
    try:
        smartsheet_obj = smartsheet.Smartsheet(access_token=auth_key)
        smartsheet_obj.errors_as_exceptions(False)

        user = Users(smartsheet_obj)

        command = demisto.command()

        # demisto.debug(f'Command being called is {demisto.command()}')
        # Commands supported for smartsheet for user
        commands = {
            'test-module': test_module,
            'get-user': get_user_command,
            'disable-user': remove_user_command,
            'create-user': create_user_command,
            'enable-user': create_user_command,
            'update-user': update_user_command
        }

        client = Client(user=user)

        if command in commands:
            human_readable, outputs, raw_response = commands[command](client, demisto.args())
            if raw_response and raw_response.get('success') is False:
                sys.stderr = open(os.devnull, "w")
            return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)

    # Log exceptions
    except Exception:
        demisto.error("Failed to execute {} command. Traceback:{}".format(demisto.command(), traceback.format_exc()))
        return_error("Failed to execute {} command. Traceback:{}".format(demisto.command(), traceback.format_exc()))

    # Log exceptions
    except Exception as e:
        ("Failed to execute {} command. Error: {}".format(demisto.command(), str(e)))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

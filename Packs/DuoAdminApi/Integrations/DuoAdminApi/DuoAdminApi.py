import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# imports
import calendar

import duo_client
# Setup

HOST = demisto.getParam('hostname')
INTEGRATION_KEY = demisto.params().get('credentials_key', {}).get('identifier') or demisto.getParam('integration_key')
SECRET_KEY = demisto.params().get('credentials_key', {}).get('password') or demisto.getParam('secret_key')
USE_SSL = not demisto.params().get('insecure', False)
USE_PROXY = demisto.params().get('proxy', False)

# The duo client returns a signature error upon bad secret
# Convert it to a more informative message using this
INVALID_SECRET_ERROR_STRING = 'Invalid signature in request credentials'

# Maps

OPTIONS_TO_TIME = {
    '10_seconds_ago': datetime.now() - timedelta(seconds=10),
    # left here for backwards compatability
    '1_minutes_ago': datetime.now() - timedelta(minutes=1),
    '1_minute_ago': datetime.now() - timedelta(minutes=1),
    '10_minutes_ago': datetime.now() - timedelta(minutes=10),
    '1_hour_ago': datetime.now() - timedelta(hours=1),
    '10_hours_ago': datetime.now() - timedelta(hours=10),
    '1_day_ago': datetime.now() - timedelta(days=1),
    '1_week_ago': datetime.now() - timedelta(days=7),
    '1_month_ago': datetime.now() - timedelta(days=30),
    '1_year_ago': datetime.now() - timedelta(days=365),
    '5_years_ago': datetime.now() - timedelta(days=1825),
    '10_years_ago': datetime.now() - timedelta(days=3650)
}


def override_make_request(self, method, uri, body, headers):    # pragma: no cover
    """

    This function is an override function to the original
    duo_client.client.Client._make_request function in API version 4.1.0

    The reason for it is that the API creates a bad uri address for the GET requests.

    """

    conn = self._connect()

    conn.request(method, uri, body, headers)
    response = conn.getresponse()
    data = response.read()
    self._disconnect(conn)
    return (response, data)


# Utility Methods

def create_api_call():
    if USE_SSL:
        client = duo_client.Admin(
            ikey=INTEGRATION_KEY,
            skey=SECRET_KEY,
            host=HOST,
        )
    else:
        client = duo_client.Admin(
            ikey=INTEGRATION_KEY,
            skey=SECRET_KEY,
            host=HOST,
            ca_certs='DISABLE'
        )
    try:
        client._make_request = lambda method, uri, body, headers: override_make_request(client, method, uri, body,
                                                                                        headers)

    except Exception as e:
        demisto.error(f"Error making request - failed to create client: {e}")
        raise Exception

    return client


def set_proxy(admin_api):   # pragma: no cover
    try:
        proxy_settings = os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy', '')
        if proxy_settings:
            host, port = get_host_port_from_proxy_settings(proxy_settings)

            if USE_PROXY:
                admin_api.set_proxy(host=host.strip(':'), port=port)

    # if no proxy settings have been set
    except ValueError:
        admin_api.set_proxy(host=None, port=None, proxy_type=None)

    except Exception as e:
        demisto.error(f'Error setting proxy: {e}')
        raise Exception


def get_host_port_from_proxy_settings(proxy_settings):  # pragma: no cover
    proxy_settings_str = str(proxy_settings)

    port = proxy_settings_str.split(':')[-1]

    host_regex_filter = re.search(ipv4Regex, proxy_settings_str)

    if host_regex_filter:
        host = host_regex_filter.group()
    else:
        proxy_settings_str_args = proxy_settings_str.split(':')

        if 'http' in proxy_settings_str:
            host = ':'.join(proxy_settings_str_args[1:-1])[2:]
        else:
            host = ':'.join(proxy_settings_str_args[0:-1])

    return host, port


def time_to_timestamp_milliseconds(time):   # pragma: no cover
    return str(calendar.timegm(time.utctimetuple()) * 1000)


# Generic function that receives a result json, and turns it into an entryObject
def get_entry_for_object(title, obj, contents, context, headers=None):
    if len(obj) == 0:
        return {
            'Type': entryTypes['note'],
            'Contents': contents,
            'ContentsFormat': formats['json'],
            'HumanReadable': "There is no output result",
            'EntryContext': context
        }

    if headers:
        if isinstance(headers, str):
            headers = headers.split(',')

        if isinstance(obj, dict):
            headers = list(set(headers).intersection(set(obj.keys())))

    readable = tableToMarkdown(
        title,
        obj,
        headers,
        lambda h: h.title().replace("_", " ").replace(".", ":")
    )

    return {
        'Type': entryTypes['note'],
        'Contents': obj,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable,
        'EntryContext': context
    }


def get_user_id(admin_api, username):
    res = admin_api.get_users_by_name(username)

    if len(res) == 0:
        return_error("No users found with the given username")

    return res[0]['user_id']


# Methods

# Duo client return 2 different known structures of error messages
def test_instance(admin_api):
    try:
        admin_api.get_users(limit=1)
        demisto.results('ok')

    except Exception as e:
        if hasattr(e, 'data'):
            # error data for 40103 is not informative enough so we write our own
            if e.__getattribute__('data')['code'] == 40103:
                raise Exception('Invalid secret key in request credentials')

            else:
                raise Exception(e.__getattribute__('data')['message'])

        elif hasattr(e, 'strerror'):
            raise Exception(e.__getattribute__('strerror'))

        else:
            raise Exception('Unknown error: ' + str(e))


def get_all_users(admin_api):
    res = admin_api.get_users()

    entry = get_entry_for_object(
        'Users', res, res,
        {
            'DuoAdmin.UserDetails(val.username==obj.username)': res
        },
        headers=[
            'username',
            'user_id',
            'is_enrolled',
            'last_login',
            'realname',
            'email',
            'phones',
            'status'
        ]
    )

    demisto.results(entry)


def get_authentication_logs_by_user(admin_api, args):
    user_name = args.get('username')
    min_time = args.get('from')
    limit = demisto.args().get('limit', '50')
    res = admin_api.get_authentication_log(
        2,
        users=get_user_id(admin_api, user_name),
        mintime=time_to_timestamp_milliseconds(OPTIONS_TO_TIME[min_time]),
        maxtime=time_to_timestamp_milliseconds(datetime.now()),
        limit=limit
    )

    raw_logs = res['authlogs']

    for log in raw_logs:
        log['timestamp'] = formatEpochDate(log['timestamp'])

    entry = get_entry_for_object(
        'Authentication logs for ' + user_name, raw_logs, raw_logs,
        {
            'DuoAdmin.UserDetails(val.username && val.username == obj.username)':
                {
                    'username': user_name,
                    'auth_logs': raw_logs
                }
        },
        headers=[
            'access_device',
            'event_type',
            'result',
            'reason',
            'application',
            'factor',
            'timestamp',
            'auth_device'
        ]
    )
    demisto.results(entry)


def get_devices_by_user(admin_api, args):
    user_name = args.get('username')
    user_id = get_user_id(admin_api, user_name)
    res = admin_api.get_user_phones(user_id)

    entry = get_entry_for_object(
        f'Devices for {user_name}', res, res,
        {
            'DuoAdmin.UserDetails(val.username && val.username == obj.username)':
                {
                    'username': user_name,
                    'phones': res
                }
        }
    )

    demisto.results(entry)


def get_all_devices(admin_api):
    res = admin_api.get_phones()

    entry = get_entry_for_object(
        'Devices', res, res,
        {
            'DuoAdmin.Phones(val.phone_id==obj.phone_id)': res
        }
    )

    demisto.results(entry)


def dissociate_device_by_user(admin_api, args):
    user_name = args.get('username')
    device_id = args.get('device_id')

    user_id = get_user_id(admin_api, user_name)
    admin_api.delete_user_phone(user_id, device_id)
    demisto.results(f'Phone with ID {device_id} was dissociated to user {user_name}')


def associate_device_to_user(admin_api, args):
    user_name = args.get('username')
    device_id = args.get('device_id')

    user_id = get_user_id(admin_api, user_name)
    admin_api.add_user_phone(user_id, device_id)
    demisto.results(f'Phone with ID {device_id} was associated to user {user_name}')


def get_u2f_tokens_by_user(admin_api, args):
    user_name = args.get('username')
    user_id = get_user_id(admin_api, user_name)
    res = admin_api.get_user_u2ftokens(user_id)

    for token in res:
        token['date_added'] = formatEpochDate(token['date_added'])

    entry = get_entry_for_object(
        'U2F Tokens for ' + user_name, res, res,
        {
            'DuoAdmin.UserDetails(val.username && val.username == obj.username)':
                {
                    'username': user_name,
                    'u2ftokens': res
                }
        }
    )

    demisto.results(entry)


def delete_u2f_token(admin_api, args):
    token_id = args.get('token_id')
    admin_api.delete_u2ftoken(token_id)
    demisto.results(f'Token with ID {token_id} deleted successfully')


def get_all_bypass_codes(admin_api):
    res = admin_api.get_bypass_codes()
    entry = get_entry_for_object(
        'Bypass', res, res,
        {
            'DuoAdmin.UserDetails(val.bypass_code_id==obj.bypasscodeid)': res
        },
        headers=[
            'bypass_code_id',
            'admin_email',
            'expiration',
            'reuse_count',
            'user.created',
            'user.email',
            'user.last_login',
            'user.status',
            'user.user_id',
            'user.username'
        ]
    )
    demisto.results(entry)


def get_all_admins(admin_api):
    res = admin_api.get_admins()

    entry = get_entry_for_object(
        'Admins', res, res,
        {
            'DuoAdmin.AdminDetails(val.name==obj.name)': res
        },
        headers=[
            'admin_id',
            'admin_units',
            'created',
            'email',
            'last_login',
            'name',
            'phone',
            'role',
            'status'
        ]
    )
    demisto.results(entry)


def modify_admin_user(admin_api, admin_id=None, name=None, phone=None, password=None,
                      password_change_required=None):
    admin_api.update_admin(admin_id, name, phone, password, password_change_required)
    return CommandResults(readable_output=f'The admin id {admin_id} successfully updated')


def modify_user(admin_api, user_id=None, user_name=None, real_name=None, status=None,
                notes=None, email=None, first_name=None, last_name=None, alias1=None,
                alias2=None, alias3=None,
                alias4=None, aliases=None):
    admin_api.update_user(user_id, user_name, real_name, status, notes, email, first_name,
                          last_name, alias1, alias2, alias3, alias4, argToList(aliases))
    return CommandResults(readable_output=f'The user id {user_id} successfully updated')


def main() -> None:  # pragma: no cover
    args = demisto.args()
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    if not (SECRET_KEY and INTEGRATION_KEY):
        raise DemistoException('Secret Key and Integration Key must be provided.')
    try:
        admin_api = create_api_call()
        set_proxy(admin_api)
        if command == 'test-module':
            test_instance(admin_api)

        elif command == 'duoadmin-get-users':
            get_all_users(admin_api)

        elif command == 'duoadmin-get-admins':
            get_all_admins(admin_api)

        elif command == 'duoadmin-get-bypass-codes':
            get_all_bypass_codes(admin_api)

        elif command == 'duoadmin-get-authentication-logs-by-user':
            get_authentication_logs_by_user(admin_api, args)

        elif command == 'duoadmin-get-devices':
            get_all_devices(admin_api)

        elif command == 'duoadmin-get-devices-by-user':
            get_devices_by_user(admin_api, args)

        elif command == 'duoadmin-associate-device-to-user':
            associate_device_to_user(admin_api, args)

        elif command == 'duoadmin-dissociate-device-from-user':
            dissociate_device_by_user(admin_api, args)

        elif command == 'duoadmin-get-u2f-tokens-by-user':
            get_u2f_tokens_by_user(admin_api, args)

        elif command == 'duoadmin-delete-u2f-token':
            delete_u2f_token(admin_api, args)

        elif command == 'duoadmin-modify-user':
            return_results(modify_user(admin_api, **demisto.args()))

        elif command == 'duoadmin-modify-admin':
            return_results(modify_admin_user(admin_api, **demisto.args()))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

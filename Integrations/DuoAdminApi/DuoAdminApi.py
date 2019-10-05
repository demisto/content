import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
# imports
import calendar
import duo_client

# Setup

HOST = demisto.getParam('hostname')
INTEGRATION_KEY = demisto.getParam('integration_key')
SECRET_KEY = demisto.getParam('secret_key')
USE_SSL = not demisto.params().get('insecure', False)

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


# Utility Methods


def create_api_call():
    if USE_SSL:
        return duo_client.Admin(
            ikey=INTEGRATION_KEY,
            skey=SECRET_KEY,
            host=HOST,
            ca_certs='DISABLE'
        )

    return duo_client.Admin(
        ikey=INTEGRATION_KEY,
        skey=SECRET_KEY,
        host=HOST
    )


def time_to_timestamp_milliseconds(time):
    return str(calendar.timegm(time.utctimetuple()) * 1000)


# Generic function that receives a result json, and turns it into an entryObject
def get_entry_for_object(title, obj, contents, context, headers=None, human_readable=None):
    if len(obj) == 0:
        return {
            'Type': entryTypes['note'],
            'Contents': contents,
            'ContentsFormat': formats['json'],
            'HumanReadable': "There is no output result",
            'EntryContext': context
        }

    if headers:
        if isinstance(headers, (str, unicode)):
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


def get_user_id(username):
    res = admin_api.get_users_by_name(username)

    if len(res) == 0:
        return_error("No users found with the given username")

    return res[0]['user_id']


# Methods

# Duo client return 2 different known structures of error messages
def test_instance():
    try:
        admin_api.get_info_summary()
        demisto.results('ok')

    except Exception as e:
        if hasattr(e, 'data'):
            # error data for 40103 is not informative enough so we write our own
            if e.__getattribute__('data')['code'] == 40103:
                demisto.results('Invalid secret key in request credentials')

            else:
                demisto.results(e.__getattribute__('data')['message'])

        elif hasattr(e, 'strerror'):
            demisto.results(e.__getattribute__('strerror'))

        else:
            demisto.results('Unknown error: ' + str(e))


def get_all_users():
    res = admin_api.get_users()

    entry = get_entry_for_object(
        'Users', res, res,
        {
            'DuoAdmin.UserDetails(val.username==obj.username)': res
        },
        headers=[
            'username',
            'user_id'
        ]
    )

    demisto.results(entry)


def get_authentication_logs_by_user(username, mintime):
    limit = demisto.args().get('limit', '50')
    res = admin_api.get_authentication_log(
        2,
        users=get_user_id(username),
        mintime=time_to_timestamp_milliseconds(OPTIONS_TO_TIME[mintime]),
        maxtime=time_to_timestamp_milliseconds(datetime.now()),
        limit=limit
    )

    raw_logs = res['authlogs']

    for log in raw_logs:
        log['timestamp'] = formatEpochDate(log['timestamp'])

    entry = get_entry_for_object(
        'Authentication logs for ' + username, raw_logs, raw_logs,
        {
            'DuoAdmin.UserDetails(val.username && val.username == obj.username)':
                {
                    'username': username,
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


def get_devices_by_user(username):
    user_id = get_user_id(username)
    res = admin_api.get_user_phones(user_id)

    entry = get_entry_for_object(
        'Devices for ' + username, res, res,
        {
            'DuoAdmin.UserDetails(val.username && val.username == obj.username)':
                {
                    'username': username,
                    'phones': res
                }
        }
    )

    demisto.results(entry)


def get_all_devices():
    res = admin_api.get_phones()

    entry = get_entry_for_object(
        'Devices', res, res,
        {
            'DuoAdmin.Phones(val.phone_id==obj.phone_id)': res
        }
    )

    demisto.results(entry)


def dissociate_device_by_user(username, device_id):
    user_id = get_user_id(username)
    admin_api.delete_user_phone(user_id, device_id)

    demisto.results('Phone with ID ' + device_id + 'was dissociated from user ' + username)


def associate_device_to_user(username, device_id):
    user_id = get_user_id(username)
    admin_api.add_user_phone(user_id, device_id)

    demisto.results('Phone with ID ' + device_id + 'was associated to user ' + username)


def get_u2f_tokens_by_user(username):
    user_id = get_user_id(username)
    res = admin_api.get_user_u2ftokens(user_id)

    for token in res:
        token['date_added'] = formatEpochDate(token['date_added'])

    entry = get_entry_for_object(
        'U2F Tokens for ' + username, res, res,
        {
            'DuoAdmin.UserDetails(val.username && val.username == obj.username)':
                {
                    'username': username,
                    'u2ftokens': res
                }
        }
    )

    demisto.results(entry)


def delete_u2f_token(token_id):
    admin_api.delete_u2ftoken(token_id)
    demisto.results('Token with ID ' + token_id + ' deleted successfully')


# Execution
try:
    handle_proxy()
    admin_api = create_api_call()

    if demisto.command() == 'test-module':
        test_instance()

    if demisto.command() == 'duoadmin-get-users':
        get_all_users()

    if demisto.command() == 'duoadmin-get-authentication-logs-by-user':
        get_authentication_logs_by_user(demisto.getArg('username'), demisto.getArg('from'))

    if demisto.command() == 'duoadmin-get-devices':
        get_all_devices()

    if demisto.command() == 'duoadmin-get-devices-by-user':
        get_devices_by_user(demisto.getArg('username'))

    if demisto.command() == 'duoadmin-associate-device-to-user':
        associate_device_to_user(demisto.getArg('username'), demisto.getArg('device_id'))

    if demisto.command() == 'duoadmin-dissociate-device-from-user':
        dissociate_device_by_user(demisto.getArg('username'), demisto.getArg('device_id'))

    if demisto.command() == 'duoadmin-get-u2f-tokens-by-user':
        get_u2f_tokens_by_user(demisto.getArg('username'))

    if demisto.command() == 'duoadmin-delete-u2f-token':
        delete_u2f_token(demisto.getArg('token_id'))

except Exception, e:
    return_error(e.message)
sys.exit(0)

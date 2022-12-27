import shutil
import demistomock as demisto  # noqa: F401
import jwt
from CommonServerPython import *  # noqa: F401
from datetime import timedelta

import dateparser


OAUTH_TOKEN_GENERATOR_URL = 'https://zoom.us/oauth/token'
# The token’s time to live is 1 hour,
# two minutes were subtract for extra safety.
TOKEN_LIFE_TIME = timedelta(minutes=58)
# maximun records that the api can return in one request
MAX_RECORDS_PER_PAGE = 300

# Note#1: type "Pro" is the old version, and "Licensed" is the new one, and i want to support both.
# Note#2: type "Corporate" is officially not supported any more, but i did not remove it just in case it still works.
USER_TYPE_MAPPING = {
    "Basic": 1,
    "Pro": 2,
    "Licensed": 2,
    "Corporate": 3
}

# ERRORS
INVALID_CREDENTIALS = 'Invalid credentials. Please verify that your credentials are valid.'
INVALID_API_SECRET = 'Invalid API Secret. Please verify that your API Secret is valid.'
INVALID_ID_OR_SECRET = 'Invalid Client ID or Client Secret. Please verify that your ID and Secret is valid.'
WRONG_TIME_FORMAT ="Wrong time format. please use this format: 'yyyy-MM-ddTHH:mm:ssZ' or 'yyyy-MM-ddTHH:mm:ss' "
LIMIT_AND_EXTRA_ARGUMENTS = """Too money arguments. if you choose a limit,
                                       don't enter a user_id or page_size or next_page_token"""
INSTANT_AND_TIME = "Too money arguments. start_time and timezone are for scheduled meetings only."
JBH_TIME_AND_NO_JBH = "Collision arguments. jbh_time argument can be used only if join_before_host is 'True'."
WAITING_ROOM_AND_JBH = "Collision arguments. join_before_ host argument can be used only if waiting_room is 'False'."                 
END_TIMES_AND_END_DATE_TIME =  "Collision arguments. Please choose only one of these two arguments, end_time or end_date_time."
NOT_RECURRING_WITH_RECUURING_ARGUMENTS = "One or more arguments that were filed are used for recurring meeting with fixed time only"
NOT_MONTHLY_AND_MONTHLY_ARGUMENTS = "One or more arguments that were filed are for recurring meeting with fixed time and monthly recurrence_type only"
MONTHLY_RECURRING_MISIING_ARGUMENTS =  """Missing arguments. recurring meeting with fixed time and monthly recurrence_type
            must have the fallowing arguments: monthly_week and monthly_week_day"""
NOT_WEEKLY_WITH_WEEKLY_ARGUMENTS = "Weekly_days is for weekly recurrence_type only"
EXTRA_PARAMS = """Too many fields were filled.
                                   You should fill the Account ID, Client ID, and Client Secret fields (OAuth),
                                   OR the API Key and API Secret fields (JWT - Deprecated)"""
'''CLIENT CLASS'''


class Client(BaseClient):
    """ A client class that implements logic to authenticate with Zoom application. """

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        api_secret: str | None = None,
        account_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        verify=True,
        proxy=False,
    ):
        super().__init__(base_url, verify, proxy)
        self.api_key = api_key
        self.api_secret = api_secret
        self.account_id = account_id
        self.client_id = client_id
        self.client_secret = client_secret
        is_jwt = (api_key and api_secret) and not (client_id and client_secret and account_id)
        if is_jwt:
            # the user has chosen to use the JWT authentication method (deprecated)
            self.access_token = get_jwt_token(api_key, api_secret)  # type: ignore[arg-type]
        else:
            # the user has chosen to use the OAUTH authentication method.
            try:
                self.access_token = self.get_oauth_token()
            except Exception:
                demisto.debug("Cannot get access token")
                self.access_token = None

    def generate_oauth_token(self):
        """
    Generate an OAuth Access token using the app credentials (AKA: client id and client secret) and the account id

    :return: valid token
    """
        token_res = self._http_request(method="POST", full_url=OAUTH_TOKEN_GENERATOR_URL,
                                       params={"account_id": self.account_id,
                                               "grant_type": "account_credentials"},
                                       auth=(self.client_id, self.client_secret))
        return token_res.get('access_token')

    def get_oauth_token(self, force_gen_new_token=False):
        """
            Retrieves the token from the server if it's expired and updates the global HEADERS to include it

            :param force_gen_new_token: If set to True will generate a new token regardless of time passed

            :rtype: ``str``
            :return: Token
        """
        now = datetime.now()
        ctx = get_integration_context()

        if not ctx or not ctx.get('token_info').get('generation_time', force_gen_new_token):
            # new token is needed
            oauth_token = self.generate_oauth_token()
            ctx = {}
        else:
            generation_time = dateparser.parse(ctx.get('token_info').get('generation_time'))
            if generation_time:
                time_passed = now - generation_time
            else:
                time_passed = TOKEN_LIFE_TIME
            if time_passed < TOKEN_LIFE_TIME:
                # token hasn't expired
                return ctx.get('token_info').get('oauth_token')
            else:
                # token expired
                oauth_token = self.generate_oauth_token()

        ctx.update({'token_info': {'oauth_token': oauth_token, 'generation_time': now.strftime("%Y-%m-%dT%H:%M:%S")}})
        set_integration_context(ctx)
        return oauth_token

    def error_handled_http_request(self, method, url_suffix='', full_url=None, headers=None,
                                   auth=None, json_data=None, params=None, return_empty_response: bool = False, resp_type: str = 'json'):

        # all future functions should call this function instead of the original _http_request.
        # This is needed because the OAuth token may not behave consistently,
        # First the func will make an http request with a token,
        # and if it turns out to be invalid, the func will retry again with a new token.
        try:
            return super()._http_request(method, url_suffix, full_url, headers, auth, json_data, params, return_empty_response,resp_type)
        except DemistoException as e:
            if ('Invalid access token' in e.message
                    or "Access token is expired." in e.message):
                self.access_token = self.generate_oauth_token()
                headers = {'authorization': f'Bearer {self.access_token}'}
            return super()._http_request(method, url_suffix, full_url, headers, auth, json_data, params, return_empty_response,resp_type )

    def zoom_create_user(self, user_type_num: int, email: str, first_name: str, last_name: str):
        return self.error_handled_http_request(
            method='POST',
            url_suffix='users',
            headers={'authorization': f'Bearer {self.access_token}'},
            json_data={
                'action': 'create',
                'user_info': {
                    'email': email,
                    'type': user_type_num,
                    'first_name': first_name,
                    'last_name': last_name}},
        )

    def zoom_list_users(self, page_size: int, status: str = "active",
                        next_page_token: str = None,
                        role_id: str = None, url_suffix: str = None,
                        page_number: int = None):
        return self.error_handled_http_request(
            method='GET',
            url_suffix=url_suffix,
            headers={'authorization': f'Bearer {self.access_token}'},
            params={
                'status': status,
                'page_size': page_size,
                'page_number': page_number,
                'next_page_token': next_page_token,
                'role_id': role_id})

    def zoom_delete_user(self, user_id: str, action: str):
        return self.error_handled_http_request(
            method='DELETE',
            url_suffix='users/' + user_id,
            headers={'authorization': f'Bearer {self.access_token}'},
            json_data={'action': action},
            resp_type='response',
            return_empty_response=True
        )

    def zoom_create_meeting(self, url_suffix: str, json_data: dict):
        return self.error_handled_http_request(
            method='POST',
            url_suffix=url_suffix,
            headers={'authorization': f'Bearer {self.access_token}'},
            json_data=json_data)

    def zoom_meeting_get(self, meeting_id: str, occurrence_id: str | None = None,
                         show_previous_occurrences: bool | str = False):
        return self.error_handled_http_request(
            method='GET',
            url_suffix=f"/meetings/{meeting_id}",
            headers={'authorization': f'Bearer {self.access_token}'},
            params={
                "occurrence_id": occurrence_id,
                "show_previous_occurrences": show_previous_occurrences
            })

    def zoom_meeting_list(self, user_id: str, next_page_token: str | None = None, page_size: int | str = 30,
                          limit: int | str | None = None, type: str = None, page_number: int = None):
        return self.error_handled_http_request(
            method='GET',
            url_suffix=f"users/{user_id}/meetings",
            headers={'authorization': f'Bearer {self.access_token}'},
            params={
                'type': type,
                'next_page_token': next_page_token,
                'page_size': page_size,
                'page_number': page_number
            })


'''HELPER FUNCTIONS'''


def get_jwt_token(apiKey: str, apiSecret: str) -> str:
    """
    Encode the JWT token given the api ket and secret
    """
    now = datetime.now()
    expire_time = int(now.strftime('%s')) + 5000
    payload = {
        'iss': apiKey,

        'exp': expire_time
    }
    encoded = jwt.encode(payload, apiSecret, algorithm='HS256')
    return encoded


def test_module(client: Client):
    """Tests connectivity with the client.
    Takes as an argument all client arguments to create a new client
    """
    try:
        # running an arbitrary command to test the connection
        client.zoom_list_users(page_size=1, url_suffix="users")
    except DemistoException as e:
        error_message = e.message
        if 'Invalid access token' in error_message:
            error_message = INVALID_CREDENTIALS
        elif "The Token's Signature resulted invalid" in error_message:
            error_message = INVALID_API_SECRET 
        elif 'Invalid client_id or client_secret' in error_message:
            error_message = INVALID_ID_OR_SECRET 
        else:
            error_message = f'Problem reaching Zoom API, check your credentials. Error message: {error_message}'
        return error_message
    return 'ok'


def remove_None_values_from_dict(dict_to_reduce: Dict[str, Any]):
    """
    Removes None values (but not False values) from a given dict and from the nested dicts in it.
    """
    reduced_dict = {}
    for key, value in dict_to_reduce.items():
        if value != None:
            if isinstance(value, dict):
                reduced_nested_dict = remove_None_values_from_dict(value)
                if reduced_nested_dict:
                    reduced_dict[key] = reduced_nested_dict
            else:
                reduced_dict[key] = value

    return reduced_dict


def check_start_time_format(start_time):
    """checking if the time format is a full time format"""
    expected_format = "%Y-%m-%dT%H:%M:%S"
    if start_time.endswith("Z"):
        expected_format += "%z"
    try:
        datetime.strptime(start_time, expected_format)
    except ValueError as e:
        raise DemistoException(WRONG_TIME_FORMAT) from e


def manual_list_user_pagination(client: Client, next_page_token: str, page_size: int,
                                limit: int, status: str, role_id: str):
    res = []
    if limit < MAX_RECORDS_PER_PAGE:
        # i dont need the maximum
        page_size = limit
    else:
        # i need the maximum. for this API, page_size must be a const while using next_page_token.
        page_size = MAX_RECORDS_PER_PAGE
    while limit > 0 and next_page_token != '':
        basic_request = client.zoom_list_users(page_size=page_size, status=status,
                                               next_page_token=next_page_token,
                                               role_id=role_id, url_suffix="users")
        next_page_token = basic_request.get("next_page_token")
    
        res.append(basic_request)
        limit -= MAX_RECORDS_PER_PAGE
    return res


def manual_meeting_list_pagination(client: Client, user_id: str, next_page_token: str | None, page_size: int,
                                   limit: int, type: str):
    res = []
    if limit < MAX_RECORDS_PER_PAGE:
        # i dont need the maximum
        page_size = limit
    else:
        # i need the maximum. for this API, page_size must be a const while using next_page_token.
        page_size = MAX_RECORDS_PER_PAGE
    while limit > 0 and next_page_token != '':
        basic_request = client.zoom_meeting_list(user_id=user_id,
                                                 next_page_token=next_page_token,
                                                 page_size=page_size,
                                                 type=type)
        next_page_token = basic_request.get("next_page_token")
        # collect all the results together
        res.append(basic_request)
        # subtract what i already got
        limit -= MAX_RECORDS_PER_PAGE
    return res


'''FORMATTING FUNCTIONS'''


def zoom_list_users_command(client: Client, page_size: int = 30, user_id: str = None,
                            status: str = "active", next_page_token: str = None,
                            role_id: str = None, limit: int = None, page_number: int = None) -> CommandResults:
  
    # PREPROCESSING
    if not user_id:
        url_suffix = 'users'
    else:
        url_suffix = f'users/{user_id}'

    page_size = arg_to_number(page_size)
    page_number = arg_to_number(page_number)
    if limit:
        limit = arg_to_number(limit)
        # "page_size" is specific referring to demisto.args,
        # because of the error raising, i need to distinguish
        # between a argument the user entered and the default argument
        args = demisto.args()
        if "page_size" in args or next_page_token or user_id:
            # arguments collision
            raise DemistoException(LIMIT_AND_EXTRA_ARGUMENTS )
        else:
            # multiple requests are needed
            raw_data = manual_list_user_pagination(client=client, next_page_token=next_page_token,  # type: ignore[arg-type]
                                                   page_size=page_size,  # type: ignore[arg-type]
                                                   limit=limit, status=status, role_id=role_id)     # type: ignore[arg-type]
            # parsing the data
            all_info = []
            for pages in range(len(raw_data)):
                page = raw_data[pages].get("users")
                for record in range(len(page)):
                    all_info.append(page[record])
                    # since page_zise must be a const, i may need to return only part of the response
                    if len(all_info) >= limit:
                        break

            md = tableToMarkdown('Users', all_info, ['id', 'email',
                                                     'type', 'pmi', 'verified', 'created_at', 'status', 'role_id'])
            md += '\n' + tableToMarkdown('Metadata', [raw_data][0][0], ['total_records'])
            raw_data = raw_data[0]
    else:
        # only one request is needed
        raw_data = client.zoom_list_users(page_size=page_size, status=status,                      # type: ignore[arg-type]
                                          next_page_token=next_page_token,
                                          role_id=role_id, url_suffix=url_suffix, page_number=page_number)
        # parsing the data according to the different given arguments
        if user_id:
            md = tableToMarkdown('User', [raw_data], ['id', 'email',
                                                      'type', 'pmi', 'verified', 'created_at', 'status', 'role_id'])
        else:
            md = tableToMarkdown('Users', raw_data.get("users"), ['id', 'email',
                                                                  'type', 'pmi', 'verified', 'created_at', 'status', 'role_id'])
            md += '\n' + tableToMarkdown('Metadata', [raw_data], ['page_count', 'page_number',
                                                                  'page_size', 'total_records', 'next_page_token'])
    return CommandResults(
        outputs_prefix='Zoom',
        readable_output=md,
        outputs={
            'User': raw_data.get('users'),
            'Metadata': {'Count': raw_data.get('page_count'),
                         'Number': raw_data.get('page_number'),
                         'Size': raw_data.get('page_size'),
                         'Total': raw_data.get('total_records')}
        },
        raw_response=raw_data
    )


def zoom_create_user_command(client: Client, user_type: str, email: str, first_name: str, last_name: str) -> CommandResults:
    user_type_num = USER_TYPE_MAPPING.get(user_type)
    raw_data = client.zoom_create_user(user_type_num, email, first_name, last_name)
    return CommandResults(
        outputs_prefix='Zoom.User',
        readable_output=f"User created successfully with ID: {raw_data.get('id')}",
        outputs=raw_data,
        raw_response=raw_data
    )


def zoom_delete_user_command(client: Client, user_id: str, action: str) -> CommandResults:
    client.zoom_delete_user(user_id, action)
    return CommandResults(
        outputs_prefix='Zoom',
        readable_output=f'User {user_id} was deleted successfully',
    )


def zoom_create_meeting_command(
        client: Client,
        user_id: str,
        topic: str,
        host_video: bool | str = True,
        jbh_time: int | str | None = None,
        start_time: str = None,
        timezone: str = None,
        type: str = "instant",
        auto_record_meeting: str = "none",
        encryption_type: str = "enhanced_encryption",
        join_before_host: bool | str = False,
        meeting_authentication: bool | str = False,
        waiting_room: bool | str = False,
        end_date_time: str | None = None,
        end_times: int | str = 1,
        monthly_day: int | str = 1,
        monthly_week: int | str | None = None,
        monthly_week_day: int | str | None = None,
        repeat_interval: int | str | None = None,
        recurrence_type: int | str | None = None,
        weekly_days: int | str = 1) -> CommandResults:

    # converting
    host_video = argToBoolean(host_video)
    join_before_host = argToBoolean(join_before_host)
    meeting_authentication = argToBoolean(meeting_authentication)
    waiting_room = argToBoolean(waiting_room)
    end_times = arg_to_number(end_times)
    monthly_day = arg_to_number(monthly_day)
    monthly_week = arg_to_number(monthly_week)
    monthly_week_day = arg_to_number(monthly_week_day)
    repeat_interval = arg_to_number(repeat_interval)
    weekly_days = arg_to_number(weekly_days)

    num_type = 1  # "instant"
    if type == "scheduled":
        num_type = 2
    elif type == "recurring meeting with fixed time":
        num_type = 8

    # argument checking
    # for arguments that have a default value, i use demisto.args to trigger an exception if user entered a value.
    args = demisto.args()
    if type == "instant" and (timezone or start_time):
        raise DemistoException(INSTANT_AND_TIME)

    if jbh_time and not join_before_host:
        raise DemistoException(JBH_TIME_AND_NO_JBH)

    if waiting_room and join_before_host:
        raise DemistoException(WAITING_ROOM_AND_JBH )

    if args.get("end_times") and end_date_time:
        raise DemistoException(END_TIMES_AND_END_DATE_TIME)

    if num_type != 8 and any((end_date_time, args.get("end_times"), args.get("monthly_day"),
                              monthly_week, monthly_week_day, repeat_interval, args.get("weekly_days"))):
        raise DemistoException(NOT_RECURRING_WITH_RECUURING_ARGUMENTS )

    if num_type == 8 and recurrence_type != 3 and any((args.get("monthly_day"),
                                                       monthly_week, monthly_week_day)):
        raise DemistoException( NOT_MONTHLY_AND_MONTHLY_ARGUMENTS)

    if num_type == 8 and recurrence_type == 3 and not (monthly_week and monthly_week_day) and not args.get("monthly_day"):
        raise DemistoException(MONTHLY_RECURRING_MISIING_ARGUMENTS)

    if num_type == 8 and recurrence_type != 2 and args.get("weekly_days"):
        raise DemistoException(NOT_WEEKLY_WITH_WEEKLY_ARGUMENTS )

    if num_type == 8 and not recurrence_type:
        raise DemistoException(
            "Missing arguments. recurring meeting with fixed time is missing this argument: recurrence_type")

    # converting separately after the argument checking, because 0 as an int is equaled to false
    jbh_time = arg_to_number(jbh_time)

    if start_time:
        check_start_time_format(start_time)

    json_all_data = {}

    # special section for recurring meeting with fixed time
    if num_type == 8:
        if recurrence_type == "Daily":
            recurrence_type = 1
        elif recurrence_type == "Weekly":
            recurrence_type = 2
        elif recurrence_type == "Monthly":
            recurrence_type = 3
        json_all_data.update({"recurrence": {
            "end_date_time": end_date_time,
            "end_times": end_times,
            "monthly_day": monthly_day,
            "monthly_week": monthly_week,
            "monthly_week_day": monthly_week_day,
            "repeat_interval": repeat_interval,
            "type": recurrence_type,
            "weekly_days": weekly_days
        }})
    json_all_data.update({
        "settings": {
            "auto_recording": auto_record_meeting,
            "encryption_type": encryption_type,
            "host_video": host_video,
            "jbh_time": jbh_time,
            "join_before_host": join_before_host,
            "meeting_authentication": meeting_authentication,
            "waiting_room": waiting_room
        },
        "start_time": start_time,
        "timezone": timezone,
        "type": num_type,
        "topic": topic,
    })
    # remove all keys with val of None
    json_data = remove_None_values_from_dict(json_all_data)
    url_suffix = f"users/{user_id}/meetings"
    # call the API
    raw_data = client.zoom_create_meeting(url_suffix=url_suffix, json_data=json_data)
    # parsing the response
    if type == "recurring meeting with fixed time":
        basic_info = [raw_data], ['uuid', 'id', 'host_id', 'host_email', 'topic',
                                  'type', 'status',
                                  'timezone', 'created_at', 'start_url', 'join_url',
                                  ][0]
        additinal_info = raw_data["occurrences"], ['start_time', 'duration']
        all_info = []
        all_info.append(basic_info[0][0])
        all_info[0].update(additinal_info[0][0])

        md = tableToMarkdown('Meeting details', [all_info][0], ['uuid', 'id', 'host_id', 'host_email', 'topic',
                                                                'type', 'status', 'start_time', 'duration',
                                                                'timezone', 'created_at', 'start_url', 'join_url'
                                                                ])
    else:
        md = tableToMarkdown('Meeting details', [raw_data], ['uuid', 'id', 'host_id', 'host_email', 'topic',
                                                             'type', 'status', 'start_time', 'duration',
                                                             'timezone', 'created_at', 'start_url', 'join_url'])
    # removing passwords from the response#
    safe_raw_data = raw_data
    for sensitive_info in ["password", "pstn_password", "encrypted_password", "h323_password"]:
        safe_raw_data.pop(sensitive_info, None)
    return CommandResults(
        outputs_prefix='Zoom.Meeting',
        readable_output=md,
        outputs=safe_raw_data,
        raw_response=raw_data
    )


def zoom_fetch_recording_command():
    # this is the original code with no changes at all.
    # this part will be removed in the future
    # waiting for a paid account
    def get_jwt(apiKey, apiSecret):
        """
        Encode the JWT token given the api ket and secret
        """
        tt = datetime.now()
        expire_time = int(tt.strftime('%s')) + 5000
        payload = {
            'iss': apiKey,
            'exp': expire_time
        }
        encoded = jwt.encode(payload, apiSecret, algorithm='HS256')
        return encoded
    URL = 'https://api.zoom.us/v2/'
    ACCESS_TOKEN = get_jwt(demisto.getParam('api_key'), demisto.getParam('api_secret'))
    PARAMS = {'access_token': ACCESS_TOKEN}
    HEADERS = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    USE_SSL = not demisto.params().get('insecure', False)
    meeting = demisto.getArg('meeting_id')
    res = requests.get(URL + 'meetings/%s/recordings' % meeting, headers=HEADERS, params=PARAMS, verify=USE_SSL)
    if res.status_code == requests.codes.ok:
        data = res.json()
        recording_files = data['recording_files']
        for file in recording_files:
            download_url = file['download_url']
            r = requests.get(download_url, stream=True)
            if r.status_code < 200 or r.status_code > 299:
                return_error('Unable to download recording for meeting %s: [%d] - %s' % (meeting, r.status_code, r.text))

            filename = 'recording_%s_%s.mp4' % (meeting, file['id'])
            with open(filename, 'wb') as f:
                r.raw.decode_content = True
                shutil.copyfileobj(r.raw, f)

            demisto.results(file_result_existing_file(filename))
            rf = requests.delete(URL + 'meetings/%s/recordings/%s' % (meeting, file['id']), headers=HEADERS,
                                 params=PARAMS, verify=USE_SSL)
            if rf.status_code == 204:
                demisto.results('File ' + filename + ' was moved to trash.')
            else:
                demisto.results('Failed to delete file ' + filename + '.')
    else:
        return_error('Download of recording failed: [%d] - %s' % (res.status_code, res.text))


def zoom_meeting_get_command(client: Client, meeting_id: str, occurrence_id: str = None,
                             show_previous_occurrences: bool = True) -> CommandResults:
   
    show_previous_occurrences = argToBoolean(show_previous_occurrences)
   
    raw_data = client.zoom_meeting_get(meeting_id, occurrence_id, show_previous_occurrences)
    # parsing the response
    md = tableToMarkdown('Meeting details', [raw_data], ['uuid', 'id', 'host_id', 'host_email', 'topic',
                                                         'type', 'status', 'start_time', 'duration',
                                                         'timezone', 'agenda', 'created_at', 'start_url', 'join_url',
                                                         ])
    # removing passwords from the response#
    safe_raw_data = raw_data
    for sensitive_info in ["password", "pstn_password", "encrypted_password", "h323_password"]:
        safe_raw_data.pop(sensitive_info, None)
    return CommandResults(
        outputs_prefix='Zoom.Meeting',
        readable_output=md,
        outputs_key_field=str(safe_raw_data["id"]),
        outputs=safe_raw_data,
        raw_response=raw_data
    )


def zoom_meeting_list_command(client: Client, user_id: str, next_page_token: str = None,
                              page_size: int = 30, limit: int = None, type: str = None, page_number: int = None) -> CommandResults:
    # converting
    page_size = arg_to_number(page_size)
    page_number = arg_to_number(page_number)
    limit = arg_to_number(limit)
    args = demisto.args()
    # "page_size" is specific referring to demisto.args,
    # because the error raising, i need to distinguish
    # between a user argument and the defult argument
    if limit:
        if "page_size" in args or next_page_token or page_number:
            # arguments collision
            raise DemistoException(LIMIT_AND_EXTRA_ARGUMENTS)
        else:
            # multiple request are needed
            raw_data = manual_meeting_list_pagination(client=client, user_id=user_id, next_page_token=next_page_token,
                                                      page_size=page_size,  # type: ignore[arg-type]
                                                      limit=limit, type=type)                          # type: ignore[arg-type]
            # parsing the data
            all_info = []
            for pages in range(len(raw_data)):
                page = raw_data[pages].get("meetings")

                for record in range(len(page)):
                    all_info.append(page[record])
                    if len(all_info) >= limit:
                        break
            md = tableToMarkdown("Meeting list", all_info, ['uuid', 'id',
                                                            'host_id', 'topic', 'type', 'start time', 'duration',
                                                            'timezone', 'created_at', 'join_url'
                                                            ])
            md += "\n" + tableToMarkdown('Metadata', [raw_data][0][0], ['total_records'])
            raw_data = raw_data[0]

    else:
        # one request in needed
        raw_data = client.zoom_meeting_list(user_id=user_id, next_page_token=next_page_token,
                                            page_size=page_size, limit=limit, type=type, page_number=page_number)
        # parsing the data
        md = tableToMarkdown("Meeting list", raw_data.get("meetings"), ['uuid', 'id',
                                                                        'host_id', 'topic', 'type', 'start_time', 'duration',
                                                                        'timezone', 'created_at', 'join_url'
                                                                        ])
        md += "\n" + tableToMarkdown('Metadata', [raw_data], ['next_page_token', 'page_size', 'page_number', 'total_records'])

    return CommandResults(
        outputs_prefix='Zoom',
        readable_output=md,
        # keeping the syntax of the output of the previous version
        outputs={
            'Meeting': raw_data,
            'Metadata': {'Size': raw_data.get('page_size'),
                         'Total': raw_data.get('total_records')}
        },
        raw_response=raw_data
    )


def check_authentication_type_parameters(api_key: str, api_secret: str,
                                         # checking if the user entered extra parameters
                                         # at the configuration level
                                         account_id: str, client_id: str, client_secret: str):
    if any((api_key, api_secret)) and any((account_id, client_id, client_secret)):
        raise DemistoException(EXTRA_PARAMS)


def main():  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    base_url = params.get('url')
    api_key = params.get('api_key')
    api_secret = params.get('api_secret')
    account_id = params.get('account_id')
    client_id = params.get('credentials', {}).get('identifier')
    client_secret = params.get('credentials', {}).get('password')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()

    # this is to avoid BC. because some of the arguments given as <a-b>, i.e "user-list"
    args = {key.replace('-', '_'): val for key, val in args.items()}

    try:
        check_authentication_type_parameters(api_key, api_secret, account_id, client_id, client_secret)

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            api_key=api_key,
            api_secret=api_secret,
            account_id=account_id,
            client_id=client_id,
            client_secret=client_secret,
        )

        if command == 'test-module':
            return_results(test_module(client=client))

        demisto.debug(f'Command being called is {command}')

        '''CRUD commands'''
        if command == 'zoom-create-user':
            results = zoom_create_user_command(client, **args)
        elif command == 'zoom-create-meeting':
            results = zoom_create_meeting_command(client, **args)
        elif command == 'zoom-meeting-get':
            results = zoom_meeting_get_command(client, **args)
        elif command == 'zoom-meeting-list':
            results = zoom_meeting_list_command(client, **args)
        elif command == 'zoom-delete-user':
            results = zoom_delete_user_command(client, **args)
        elif command == 'zoom-fetch-recording':
            results = zoom_fetch_recording_command()
        elif command == 'zoom-list-users':
            results = zoom_list_users_command(client, **args)
        else:
            return_error('Unrecognized command: ' + demisto.command())
        return_results(results)

    except DemistoException as e:
        # For any other integration command exception, return an error
        return_error(f'Failed to execute {command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

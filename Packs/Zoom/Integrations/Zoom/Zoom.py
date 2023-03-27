import shutil
from ZoomApiModule import *
import demistomock as demisto  # noqa: F401
# import jwt
from CommonServerPython import *  # noqa: F401
# from datetime import timedelta
from traceback import format_exc
# import dateparser

# OAUTH_TOKEN_GENERATOR_URL = 'https://zoom.us/oauth/token'
# # The token’s time to live is 1 hour,
# # two minutes were subtract for extra safety.
# TOKEN_LIFE_TIME = timedelta(minutes=58)
# # the lifetime for an JWT token is 90 minutes == 5400 seconds
# # 400 seconds were subtract for extra safety.
# JWT_LIFETIME = 5000
# # maximun records that the api can return in one request
# MAX_RECORDS_PER_PAGE = 300

# Note#1: type "Pro" is the old version, and "Licensed" is the new one, and i want to support both.
# Note#2: type "Corporate" is officially not supported any more, but i did not remove it just in case it still works.
USER_TYPE_MAPPING = {
    "Basic": 1,
    "Pro": 2,
    "Licensed": 2,
    "Corporate": 3
}
MONTHLY_RECURRING_TYPE_MAPPING = {
    "Daily": 1,
    "Weekly": 2,
    "Monthly": 3
}
INSTANT = "Instant"
SCHEDULED = "Scheduled"
RECURRING_WITH_TIME = "Recurring meeting with fixed time"

MEETING_TYPE_NUM_MAPPING = {
    "Instant": 1,
    "Scheduled": 2,
    "Recurring meeting with fixed time": 8
}
FILE_TYPE_MAPPING = {
    'MP4': 'Video',
    'M4A': 'Audio'
}
# ERRORS
# INVALID_CREDENTIALS = 'Invalid credentials. Verify that your credentials are valid.'
# INVALID_API_SECRET = 'Invalid API Secret. Verify that your API Secret is valid.'
# INVALID_ID_OR_SECRET = 'Invalid Client ID or Client Secret. Verify that your ID and Secret is valid.'
WRONG_TIME_FORMAT = "Wrong time format. Use this format: 'yyyy-MM-ddTHH:mm:ssZ' or 'yyyy-MM-ddTHH:mm:ss' "
LIMIT_AND_EXTRA_ARGUMENTS = """Too many arguments. If you choose a limit,
                                       don't enter a user_id or page_size or next_page_token or page_number."""
LIMIT_AND_EXTRA_ARGUMENTS_MEETING_LIST = """Too many arguments. If you choose a limit,
                                       don't enter a page_size or next_page_token or page_number."""
INSTANT_AND_TIME = "Too many arguments.Use start_time and timezone for scheduled meetings only."
JBH_TIME_AND_NO_JBH = """Collision arguments.
join_before_host_time argument can be used only if join_before_host is 'True'."""
WAITING_ROOM_AND_JBH = "Collision arguments. join_before_host argument can be used only if waiting_room is 'False'."
END_TIMES_AND_END_DATE_TIME = "Collision arguments. Choose only one of these two arguments, end_time or end_date_time."
NOT_RECURRING_WITH_RECURRING_ARGUMENTS = """One or more arguments that were filed
are used for a recurring meeting with a fixed time only."""
NOT_MONTHLY_AND_MONTHLY_ARGUMENTS = """One or more arguments that were
filed are for a recurring meeting with a fixed time and monthly recurrence_type only."""
MONTHLY_RECURRING_MISIING_ARGUMENTS = """Missing arguments. A recurring meeting with a fixed time and monthly recurrence_type
            must have the following arguments: monthly_week and monthly_week_day."""
NOT_WEEKLY_WITH_WEEKLY_ARGUMENTS = "Weekly_days is for weekly recurrence_type only."
EXTRA_PARAMS = """Too many fields were filled.
You should fill the Account ID, Client ID, and Client Secret fields (OAuth),
OR the API Key and API Secret fields (JWT - Deprecated)."""
RECURRING_MISSING_ARGUMENTS = """Missing arguments. A recurring meeting with a fixed
time is missing this argument: recurrence_type."""
'''CLIENT CLASS'''


# class Client(BaseClient):
#     """ A client class that implements logic to authenticate with Zoom application. """

#     def __init__(
#         self,
#         base_url: str,
#         api_key: str | None = None,
#         api_secret: str | None = None,
#         account_id: str | None = None,
#         client_id: str | None = None,
#         client_secret: str | None = None,
#         verify=True,
#         proxy=False,
#     ):
#         super().__init__(base_url, verify, proxy)
#         self.api_key = api_key
#         self.api_secret = api_secret
#         self.account_id = account_id
#         self.client_id = client_id
#         self.client_secret = client_secret
#         is_jwt = (api_key and api_secret) and not (client_id and client_secret and account_id)
#         if is_jwt:
#             # the user has chosen to use the JWT authentication method (deprecated)
#             self.access_token: str | None = get_jwt_token(api_key, api_secret)  # type: ignore[arg-type]
#         else:
#             # the user has chosen to use the OAUTH authentication method.
#             try:
#                 self.access_token = self.get_oauth_token()
#             except Exception as e:
#                 demisto.debug(f"Cannot get access token. Error: {e}")
#                 self.access_token = None

#     def generate_oauth_token(self):
#         """
#     Generate an OAuth Access token using the app credentials (AKA: client id and client secret) and the account id

#     :return: valid token
#     """
#         token_res = self._http_request(method="POST", full_url=OAUTH_TOKEN_GENERATOR_URL,
#                                        params={"account_id": self.account_id,
#                                                "grant_type": "account_credentials"},
#                                        auth=(self.client_id, self.client_secret))
#         return token_res.get('access_token')

#     def get_oauth_token(self, force_gen_new_token=False):
#         """
#             Retrieves the token from the server if it's expired and updates the global HEADERS to include it

#             :param force_gen_new_token: If set to True will generate a new token regardless of time passed

#             :rtype: ``str``
#             :return: Token
#         """
#         now = datetime.now()
#         ctx = get_integration_context()

#         if not ctx or not ctx.get('token_info').get('generation_time', force_gen_new_token):
#             # new token is needed
#             oauth_token = self.generate_oauth_token()
#             ctx = {}
#         else:
#             if generation_time := dateparser.parse(
#                 ctx.get('token_info').get('generation_time')
#             ):
#                 time_passed = now - generation_time
#             else:
#                 time_passed = TOKEN_LIFE_TIME
#             if time_passed < TOKEN_LIFE_TIME:
#                 # token hasn't expired
#                 return ctx.get('token_info').get('oauth_token')
#             else:
#                 # token expired
#                 oauth_token = self.generate_oauth_token()

#         ctx.update({'token_info': {'oauth_token': oauth_token, 'generation_time': now.strftime("%Y-%m-%dT%H:%M:%S")}})
#         set_integration_context(ctx)
#         return oauth_token

#     def error_handled_http_request(self, method, url_suffix='', full_url=None, headers=None,
#                                    auth=None, json_data=None, params=None,
#                                    return_empty_response: bool = False, resp_type: str = 'json', stream: bool = False):

#         # all future functions should call this function instead of the original _http_request.
#         # This is needed because the OAuth token may not behave consistently,
#         # First the func will make an http request with a token,
#         # and if it turns out to be invalid, the func will retry again with a new token.
#         try:
#             return super()._http_request(method=method, url_suffix=url_suffix, full_url=full_url, headers=headers,
#                                          auth=auth, json_data=json_data, params=params,
#                                          return_empty_response=return_empty_response, resp_type=resp_type, stream=stream)
#         except DemistoException as e:
#             if ('Invalid access token' in e.message
#                     or "Access token is expired." in e.message):
#                 self.access_token = self.generate_oauth_token()
#                 headers = {'authorization': f'Bearer {self.access_token}'}
#                 return super()._http_request(method=method, url_suffix=url_suffix, full_url=full_url, headers=headers,
#                                              auth=auth, json_data=json_data, params=params,
#                                              return_empty_response=return_empty_response, resp_type=resp_type, stream=stream)
#             else:
#                 raise DemistoException(e.message)

class Client(Zoom_Client):
    #     """ A client class that implements logic to authenticate with Zoom application. """

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

    def zoom_delete_user(self, user: str, action: str):
        return self.error_handled_http_request(
            method='DELETE',
            url_suffix='users/' + user,
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
                          type: str | int | None = None, page_number: int = None):
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

    def zoom_fetch_recording(self, method: str, url_suffix: str = None, full_url: str = None,
                             stream: bool = False, resp_type: str = 'json'):
        return self.error_handled_http_request(
            method=method,
            full_url=full_url,
            url_suffix=url_suffix,
            resp_type=resp_type,
            stream=stream,
            headers={'authorization': f'Bearer {self.access_token}'},
        )


'''HELPER FUNCTIONS'''


# def get_jwt_token(apiKey: str, apiSecret: str) -> str:
#     """
#     Encode the JWT token given the api ket and secret
#     """
#     now = datetime.now()
#     expire_time = int(now.strftime('%s')) + JWT_LIFETIME
#     payload = {
#         'iss': apiKey,

#         'exp': expire_time
#     }
#     encoded = jwt.encode(payload, apiSecret, algorithm='HS256')
#     return encoded


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
        if value is not None:
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


def manual_list_user_pagination(client: Client, next_page_token: str | None,
                                limit: int, status: str, role_id: str | None):
    res = []
    page_size = min(limit, MAX_RECORDS_PER_PAGE)
    while limit > 0 and next_page_token != '':
        response = client.zoom_list_users(page_size=page_size, status=status,
                                          next_page_token=next_page_token,
                                          role_id=role_id, url_suffix="users")
        next_page_token = response.get("next_page_token")

        res.append(response)
        limit -= MAX_RECORDS_PER_PAGE
    return res


def manual_meeting_list_pagination(client: Client, user_id: str, next_page_token: str | None,
                                   limit: int, type: str | int | None):
    res = []
    page_size = min(limit, MAX_RECORDS_PER_PAGE)
    while limit > 0 and next_page_token != '':
        response = client.zoom_meeting_list(user_id=user_id,
                                            next_page_token=next_page_token,
                                            page_size=page_size,
                                            type=type)
        next_page_token = response.get("next_page_token")
        res.append(response)
        # subtract what i already got
        limit -= MAX_RECORDS_PER_PAGE
    return res


def remove_extra_info_list_users(limit, raw_data):
    """_summary_
    Due to the fact that page_size must be const,
    Extra information may be provided to me, such as:
    In the case of limit = 301, manual_list_users_pagination will return 600 users (MAX_RECORDS * 2),
    The last 299 must be removed.

    Args:
        limit (int): the number of records the user asked for
        raw_data (dict):the entire response from the pagination function
    """
    all_info = []
    for page in raw_data:
        users_info = page.get("users", [])
        for user in users_info:
            all_info.append(user)
            if len(all_info) >= limit:
                return all_info
    return all_info


def remove_extra_info_meeting_list(limit, raw_data):
    """
    Due to the fact that page_size must be const,
    Extra information may be provided to me, such as:
    In the case of limit = 301, manual_meeting_list_pagination will return 600 meetings (MAX_RECORDS * 2),
    The last 299 must be removed.

    Args:
        limit (int): the number of records the user asked for
        raw_data (dict):the entire response from the pagination function
    """
    all_info = []
    for page in raw_data:
        meetings = page.get("meetings")
        for meeting in meetings:
            all_info.append(meeting)
            if len(all_info) >= limit:
                return all_info
    return all_info


'''FORMATTING FUNCTIONS'''


def zoom_list_users_command(client, **args) -> CommandResults:

    # PREPROCESSING
    client = client
    page_size = arg_to_number(args.get('page_size', 30))
    user_id = args.get('user_id')
    status = args.get('status', "active")
    next_page_token = args.get('next_page_token')
    role_id = args.get('role_id')
    limit = arg_to_number(args.get('limit'))
    page_number = arg_to_number(args.get('page_number', 1))

    url_suffix = f'users/{user_id}' if user_id else 'users'

    if limit:
        if "page_size" in args or "page_number" in args or next_page_token or user_id:
            # arguments collision
            raise DemistoException(LIMIT_AND_EXTRA_ARGUMENTS)
        else:
            # multiple requests are needed
            raw_data = manual_list_user_pagination(client=client, next_page_token=next_page_token,
                                                   limit=limit, status=status, role_id=role_id)

            minimal_needed_info = remove_extra_info_list_users(limit, raw_data)

            md = tableToMarkdown('Users', minimal_needed_info, ['id', 'email',
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


def zoom_create_user_command(client, **args) -> CommandResults:
    client = client
    user_type = args.get('user_type', "")
    email = args.get('email')
    first_name = args.get('first_name')
    last_name = args.get('last_name')
    user_type_num = USER_TYPE_MAPPING.get(user_type)
    raw_data = client.zoom_create_user(user_type_num, email, first_name, last_name)
    return CommandResults(
        outputs_prefix='Zoom.User',
        readable_output=f"User created successfully with ID: {raw_data.get('id')}",
        outputs=raw_data,
        raw_response=raw_data
    )


def zoom_delete_user_command(client, **args) -> CommandResults:
    client = client
    user = args.get('user')
    action = args.get("action")
    client.zoom_delete_user(user, action)
    return CommandResults(
        readable_output=f'User {user} was deleted successfully',
    )


def zoom_create_meeting_command(client, **args) -> CommandResults:
    client = client
    user_id = args.get('user')
    topic = args.get('topic', "")
    host_video = argToBoolean(args.get('host_video', True))
    join_before_host_time = args.get('join_before_host_time')
    start_time = args.get('start_time')
    timezone = args.get('timezone', "")
    type = args.get('type', "Instant")
    auto_record_meeting = args.get('auto_record_meeting')
    encryption_type = args.get('encryption_type')
    join_before_host = argToBoolean(args.get('join_before_host', False))
    meeting_authentication = argToBoolean(args.get('meeting_authentication', False))
    waiting_room = argToBoolean(args.get('waiting_room', False))
    end_date_time = args.get('end_date_time')
    end_times = arg_to_number(args.get('end_times', 1))
    monthly_day = arg_to_number(args.get('monthly_day', 1))
    monthly_week = arg_to_number(args.get('monthly_week'))
    monthly_week_day = arg_to_number(args.get('monthly_week_day'))
    repeat_interval = arg_to_number(args.get('repeat_interval'))
    recurrence_type = args.get('recurrence_type', "")
    weekly_days = arg_to_number(args.get('weekly_days', 1))

    num_type: int | None = MEETING_TYPE_NUM_MAPPING.get(type)

    # argument checking
    if type == INSTANT and (timezone or start_time):
        raise DemistoException(INSTANT_AND_TIME)

    if join_before_host_time and not join_before_host:
        raise DemistoException(JBH_TIME_AND_NO_JBH)

    if waiting_room and join_before_host:
        raise DemistoException(WAITING_ROOM_AND_JBH)

    if args.get("end_times") and end_date_time:
        raise DemistoException(END_TIMES_AND_END_DATE_TIME)

    if type != RECURRING_WITH_TIME and any((end_date_time, args.get("end_times"), args.get("monthly_day"),
                                            monthly_week, monthly_week_day, repeat_interval, args.get("weekly_days"))):
        raise DemistoException(NOT_RECURRING_WITH_RECURRING_ARGUMENTS)

    if type == RECURRING_WITH_TIME and recurrence_type != "Monthly" and any((args.get("monthly_day"),
                                                                             monthly_week, monthly_week_day)):
        raise DemistoException(NOT_MONTHLY_AND_MONTHLY_ARGUMENTS)

    if (type == RECURRING_WITH_TIME and recurrence_type == "Monthly"
            and not (monthly_week and monthly_week_day) and not args.get("monthly_day")):
        raise DemistoException(MONTHLY_RECURRING_MISIING_ARGUMENTS)

    if type == RECURRING_WITH_TIME and recurrence_type != "Weekly" and args.get("weekly_days"):
        raise DemistoException(NOT_WEEKLY_WITH_WEEKLY_ARGUMENTS)

    if type == RECURRING_WITH_TIME and not recurrence_type:
        raise DemistoException(RECURRING_MISSING_ARGUMENTS)

    # converting separately after the argument checking, because 0 as an int is equaled to false
    join_before_host_time = arg_to_number(join_before_host_time)

    if start_time:
        check_start_time_format(start_time)

    json_all_data: Dict[str, Union[Any, None, int]] = {}

    # special section for recurring meeting with fixed time
    if type == RECURRING_WITH_TIME:
        recurrence_type_num = MONTHLY_RECURRING_TYPE_MAPPING.get(recurrence_type)
        json_all_data.update({"recurrence": {
            "end_date_time": end_date_time,
            "end_times": end_times,
            "monthly_day": monthly_day,
            "monthly_week": monthly_week,
            "monthly_week_day": monthly_week_day,
            "repeat_interval": repeat_interval,
            "type": recurrence_type_num,
            "weekly_days": weekly_days
        }})
    json_all_data.update({
        "settings": {
            "auto_recording": auto_record_meeting,
            "encryption_type": encryption_type,
            "host_video": host_video,
            "jbh_time": join_before_host_time,
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
    if type == "Recurring meeting with fixed time":
        raw_data.update({'start_time': raw_data.get("occurrences")[0].get('start_time')})
        raw_data.update({'duration': raw_data.get("occurrences")[0].get('duration')})

    md = tableToMarkdown('Meeting details', [raw_data], ['uuid', 'id', 'host_id', 'host_email', 'topic',
                                                         'type', 'status', 'start_time', 'duration',
                                                         'timezone', 'created_at', 'start_url', 'join_url'
                                                         ])

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


def zoom_fetch_recording_command(client: Client, **args):
    # preprocessing
    results = []
    meeting_id = args.get('meeting_id')
    delete_after = argToBoolean(args.get('delete_after'))
    client = client

    data = client.zoom_fetch_recording(
        method='GET',
        url_suffix=f'meetings/{meeting_id}/recordings'
    )
    recording_files = data.get('recording_files')
    # Getting the audio and video files which are contained in every recording.
    for file in recording_files:
        download_url = file.get('download_url')
        try:
            # download the file
            demisto.debug(f"Trying to download the files of meeting {meeting_id}")
            record = client.zoom_fetch_recording(
                method='GET',
                full_url=download_url,
                resp_type='response',
                stream=True
            )
            file_type = file.get('file_type')
            file_type_as_literal = FILE_TYPE_MAPPING.get(file_type)
            # save the file
            filename = f'recording_{meeting_id}_{file.get("id")}.{file_type}'
            with open(filename, 'wb') as f:
                # Saving the content of the file locally.
                record.raw.decode_content = True
                shutil.copyfileobj(record.raw, f)

            results.append(file_result_existing_file(filename))
            results.append(CommandResults(
                readable_output=f"The {file_type_as_literal} file {filename} was downloaded successfully"))

            if delete_after:
                try:
                    # delete the file from the cloud
                    demisto.debug(f"Trying to delete the file {filename}")
                    client.zoom_fetch_recording(
                        method='DELETE',
                        url_suffix=f'meetings/{meeting_id}/recordings/{file["id"]}',
                        resp_type='response'
                    )
                    results.append(CommandResults(
                        readable_output=f"The {file_type_as_literal} file {filename} was successfully removed from the cloud."))
                except DemistoException as e:
                    results.append(CommandResults(
                        readable_output=f"Failed to delete file {filename}. {e}"))

        except DemistoException as e:
            raise DemistoException(
                f'Unable to download recording for meeting {meeting_id}: {e}')

    return results


def zoom_meeting_get_command(client, **args) -> CommandResults:
    client = client
    meeting_id = args.get('meeting_id')
    occurrence_id = args.get('occurrence_id')
    show_previous_occurrences = argToBoolean(args.get('show_previous_occurrences'))

    raw_data = client.zoom_meeting_get(meeting_id, occurrence_id, show_previous_occurrences)
    # parsing the response
    md = tableToMarkdown('Meeting details', raw_data, ['uuid', 'id', 'host_id', 'host_email', 'topic',
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
        outputs_key_field="id",
        outputs=safe_raw_data,
        raw_response=raw_data
    )


def zoom_meeting_list_command(client, **args) -> CommandResults:
    client = client
    user_id = args.get('user_id', '')
    next_page_token = args.get('next_page_token')
    page_size = arg_to_number(args.get('page_size', 30))
    limit = arg_to_number(args.get('limit'))
    type = args.get('type')
    page_number = arg_to_number(args.get('page_number', 1))

    if limit:
        if "page_size" in args or next_page_token or 'page_number' in args:
            # arguments collision
            raise DemistoException(LIMIT_AND_EXTRA_ARGUMENTS_MEETING_LIST)
        else:
            # multiple request are needed
            raw_data = manual_meeting_list_pagination(client=client, user_id=user_id, next_page_token=next_page_token,
                                                      limit=limit, type=type)

            minimal_needed_info = remove_extra_info_meeting_list(limit=limit, raw_data=raw_data)

            md = tableToMarkdown("Meeting list", minimal_needed_info, ['uuid', 'id',
                                                                       'host_id', 'topic', 'type', 'start time', 'duration',
                                                                       'timezone', 'created_at', 'join_url'
                                                                       ])
            md += "\n" + tableToMarkdown('Metadata', [raw_data][0][0], ['total_records'])
            raw_data = raw_data[0]

    else:
        # one request in needed
        raw_data = client.zoom_meeting_list(user_id=user_id, next_page_token=next_page_token,
                                            page_size=page_size, type=type, page_number=page_number)
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
    api_key = params.get('creds_api_key', {}).get('password') or params.get('apiKey')
    api_secret = params.get('creds_api_secret', {}).get('password') or params.get('apiSecret')
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
            results = zoom_fetch_recording_command(client, **args)
        elif command == 'zoom-list-users':
            results = zoom_list_users_command(client, **args)
        else:
            return_error('Unrecognized command: ' + demisto.command())
        return_results(results)

    except DemistoException as e:
        # For any other integration command exception, return an error
        demisto.error(format_exc())
        return_error(f'Failed to execute {command} command. Error: {str(e)}.')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

import shutil
import demistomock as demisto  # noqa: F401
import jwt
from CommonServerPython import *  # noqa: F401
from datetime import timedelta
import dateparser


BASE_URL = 'https://api.zoom.us/v2/'
OAUTH_TOKEN_GENERATOR_URL = 'https://zoom.us/oauth/token'
# The token’s time to live is 1 hour,
# two minutes were subtract for extra safety.
TOKEN_LIFE_TIME = timedelta(minutes=58)
# maximun records that the api can return in one request
MAX_RECORDS_PER_PAGE = 300


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
            self.access_token = self.get_oauth_token()

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

        if not ctx or not ctx.get('generation_time', force_gen_new_token):
            # new token is needed
            oauth_token = self.generate_oauth_token()
            ctx = {}
        else:
            generation_time = dateparser.parse(ctx.get('generation_time'))
            if generation_time:
                time_passed = now - generation_time
            else:
                time_passed = TOKEN_LIFE_TIME
            if time_passed < TOKEN_LIFE_TIME:
                # token hasn't expired
                return ctx.get('oauth_token')
            else:
                # token expired
                oauth_token = self.generate_oauth_token()

        ctx.update({'oauth_token': oauth_token, 'generation_time': now.strftime("%Y-%m-%dT%H:%M:%S")})
        set_integration_context(ctx)
        return oauth_token

    def _http_request(self, method, url_suffix='', full_url=None, headers=None, auth=None, json_data=None, params=None, data=None,
                      files=None, timeout=None, resp_type='json', ok_codes=None, return_empty_response=False, retries=0,
                      status_list_to_retry=None, backoff_factor=5, raise_on_redirect=False, raise_on_status=False,
                      error_handler=None, empty_valid_codes=None, **kwargs):
        # This is a rewrite of the classic _http_request,
        # all future functions should call this function instead of the original _http_request.
        # This is needed because the OAuth token may not behave consistently,
        # First the func will make an http request with a token,
        # and if it turns out to be invalid, the func will retry again with a new token.
        try:
            return super()._http_request(method, url_suffix, full_url, headers, auth, json_data, params,
                                         data, files, timeout, resp_type, ok_codes, return_empty_response, retries,
                                         status_list_to_retry, backoff_factor, raise_on_redirect, raise_on_status, error_handler,
                                         empty_valid_codes, **kwargs)
        except DemistoException as e:
            if ('Invalid access token' in e.message
                or "Access token is expired." in e.message
                    or "Access token is expired." in e.message):
                self.access_token = self.generate_oauth_token()
                headers = {'authorization': f'Bearer {self.access_token}'}
            return super()._http_request(method, url_suffix, full_url, headers, auth, json_data, params,
                                         data, files, timeout, resp_type, ok_codes, return_empty_response, retries,
                                         status_list_to_retry, backoff_factor, raise_on_redirect, raise_on_status, error_handler,
                                         empty_valid_codes, **kwargs)

    def zoom_user_create(self, user_type: str, email: str, first_name: str, last_name: str):
        ut = user_type
        user_type = 1  # Basic
        if ut == 'Pro':
            user_type = 2
        elif ut == 'Corporate':
            user_type = 3

        return self._http_request(
            method='POST',
            url_suffix='users',
            headers={'authorization': f'Bearer {self.access_token}'},
            json_data={
                'action': 'create',
                'user_info': {
                    'email': email,
                    'type': user_type,
                    'first_name': first_name,
                    'last_name': last_name}},
        )

    def zoom_user_list(self, page_size: int | str = 30, user_id: str = None, status: str = "active",
                       next_page_token: str = None,
                       role_id: str = None, limit: int | str | None = None):
        if not user_id:
            url_suffix = 'users'
        else:
            url_suffix = f'users/{user_id}'

        page_size = arg_to_number(page_size)
        if limit:
            limit = arg_to_number(limit)
            # "page_size" is specific referring to demisto.args,
            # because the error raising, i need to distinguish
            # between a user argument and the default argument
            args = demisto.args()
            if limit and ("page_size" in args or next_page_token or user_id):
                # arguments collision
                raise DemistoException("""Too money arguments. if you choose a limit,
                                       don't enter a user_id or page_size or next_page_token""")
            else:
                # multiple requests are needed
                return self.manual_user_list_pagination(next_page_token, page_size,  # type: ignore[arg-type]
                                                        limit, status, role_id)     # type: ignore[arg-type]
        # one request is needed
        return self.user_list_basic_request(page_size, status,                      # type: ignore[arg-type]
                                            next_page_token,
                                            role_id, url_suffix)

    def manual_user_list_pagination(self, next_page_token: str, page_size: int, limit: int, status: str, role_id: str):
        res = []
        while limit > 0 and next_page_token != '':
            if limit < MAX_RECORDS_PER_PAGE:
                # i dont need the maximum
                page_size = limit
            else:
                # i need the maximum
                page_size = MAX_RECORDS_PER_PAGE

            basic_request = self.user_list_basic_request(page_size, status,
                                                         next_page_token,
                                                         role_id, url_suffix="users")
            next_page_token = basic_request.get("next_page_token")
            # collect all the results together
            res.append(basic_request)
            # subtract what i already got
            limit -= MAX_RECORDS_PER_PAGE
        return res

    def user_list_basic_request(self, page_size: int = 30, status: str = "active",
                                next_page_token: str = None,
                                role_id: str = None, url_suffix: str = None):
        return self._http_request(
            method='GET',
            url_suffix=url_suffix,
            headers={'authorization': f'Bearer {self.access_token}'},
            params={
                'status': status,
                'page_size': page_size,
                'next_page_token': next_page_token,
                'role_id': role_id
            })

    def zoom_user_delete(self, user_id: str, action: str):
        return self._http_request(
            method='DELETE',
            url_suffix='users/' + user_id,
            headers={'authorization': f'Bearer {self.access_token}'},
            json_data={'action': action},
            resp_type='response',
            return_empty_response=True
        )

    def zoom_meeting_create(self, user_id: str,
                            topic: str,
                            host_video: bool | str = True,
                            jbh_time: int | str | None = None,
                            start_time: str = None,
                            timezone: str = None,
                            type: str = "instant",
                            auto_recording: str = "none",
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
                            weekly_days: int | str = 1
                            ):

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

        if recurrence_type == "Daily":
            recurrence_type = 1
        elif recurrence_type == "Weekly":
            recurrence_type = 2
        elif recurrence_type == "Monthly":
            recurrence_type = 3

        num_type = 1
        if type == "scheduled":
            num_type = 2
        elif type == "recurring meeting with no fixed time":
            num_type = 3
        elif type == "recurring meeting with fixed time":
            num_type = 8

        # argument checking
        # for arguments that have a default value, i use demisto.args to trigger an exception if user entered a value.
        args = demisto.args()
        if type == "instant" and (timezone or start_time):
            raise DemistoException("Too money arguments. start_time and timezone are for scheduled meetings only.")

        if jbh_time and not join_before_host:
            raise DemistoException("Collision arguments. jbh_time argument can be used only if join_before_host is 'True'.")

        if waiting_room and join_before_host:
            raise DemistoException("Collision arguments. join_before_ host argument can be used only if waiting_room is 'False'.")

        if args.get("end_times") and end_date_time:
            raise DemistoException(
                "Collision arguments. Please choose only one of these two arguments, end_time or end_date_time.")

        if num_type != 8 and any((end_date_time, args.get("end_times"), args.get("monthly_day"),
                                 monthly_week, monthly_week_day, repeat_interval, args.get("weekly_days"))):
            raise DemistoException("One or more arguments that were filed are used for recurring meeting with fixed time only")

        if num_type == 8 and recurrence_type != 3 and any((args.get("monthly_day"),
                                                          monthly_week, monthly_week_day)):
            raise DemistoException(
                "One or more arguments that were filed are for recurring meeting with fixed time and monthly recurrence_type only")

        if num_type == 8 and recurrence_type == 3 and not (monthly_week and monthly_week_day) and not args.get("monthly_day"):
            raise DemistoException(
                """Missing arguments. recurring meeting with fixed time and monthly recurrence_type
                must have the fallowing arguments: monthly_week and monthly_week_day""")

        if num_type == 8 and recurrence_type != 2 and args.get("weekly_days"):
            raise DemistoException("Weekly_days is for weekly recurrence_type only")

        # converting separately after the argument checking, because 0 as an int is equaled to false
        jbh_time = arg_to_number(jbh_time)

        json_all_data = {}

        # special section for recurring meeting with fixed time
        if num_type == 8:
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
                "auto_recording": auto_recording,
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
        return self._http_request(
            method='POST',
            url_suffix=f"users/{user_id}/meetings",
            headers={'authorization': f'Bearer {self.access_token}'},
            # remove all keys with val of None
            json_data=remove_None_values_from_dict(json_all_data))

    def zoom_meeting_get(self, meeting_id: str, occurrence_id: str = None,
                         show_previous_occurrences: bool | str = True):
        # converting
        show_previous_occurrences = argToBoolean(show_previous_occurrences)

        return self._http_request(
            method='GET',
            url_suffix=f"/meetings/{meeting_id}",
            headers={'authorization': f'Bearer {self.access_token}'},
            params={
                "occurrence_id": occurrence_id,
                "show_previous_occurrences": show_previous_occurrences
            })

    def zoom_meeting_list(self, user_id: str, next_page_token: str | None = None, page_size: int | str = 30,
                          limit: int | str | None = None, type: str = None):
        page_size = arg_to_number(page_size)
        if limit:
            limit = arg_to_number(limit)
            args = demisto.args()
            # "page_size" is specific referring to demisto.args,
            # because the error raising, i need to distinguish
            # between a user argument and the defult argument
            if limit and ("page_size" in args or next_page_token):
                # arguments collision
                raise DemistoException("Too money arguments. if you choose a limit, don't enter a page_size or next_page_token")
            else:
                # multiple request are needed
                return self.manual_meeting_list_pagination(user_id, next_page_token, page_size,  # type: ignore[arg-type]
                                                           limit, type)                          # type: ignore[arg-type]
                # one request in needed
        return self.meeting_list_basic_request(user_id, next_page_token, page_size,               # type: ignore[arg-type]
                                               type)

    def manual_meeting_list_pagination(self, user_id: str, next_page_token: str | None, page_size: int,
                                       limit: int, type: str):
        res = []
        while limit > 0 and next_page_token != '':
            if limit < MAX_RECORDS_PER_PAGE:
                # i dont need the maximum
                page_size = limit
            else:
                # i need the maximum
                page_size = MAX_RECORDS_PER_PAGE

            basic_request = self.meeting_list_basic_request(user_id, next_page_token, page_size,
                                                            type)
            next_page_token = basic_request.get("next_page_token")
            # collect all the results together
            res.append(basic_request)
            # subtract what i already got
            limit -= MAX_RECORDS_PER_PAGE
        return res

    def meeting_list_basic_request(self, user_id: str, next_page_token: str = None, page_size: int | str = 30,
                                   type: str = None):
        return self._http_request(
            method='GET',
            url_suffix=f"users/{user_id}/meetings",
            headers={'authorization': f'Bearer {self.access_token}'},
            params={
                'type': type,
                'next_page_token': next_page_token,
                'page_size': page_size
            })

    def zoom_recording_get(self, meeting_id: str):
        succeed = []
        failed = []
        meeting = meeting_id
        try:
            data = self._http_request(
                method='GET',
                url_suffix=f'meetings/{meeting}/recordings',
                headers={'authorization': f'Bearer {self.access_token}'},
            )
            recording_files = data['recording_files']
            for file in recording_files:
                download_BASE_URL = file['download_BASE_URL']
                try:
                    r = self._http_request(
                        method='GET',
                        full_url=download_BASE_URL,
                        stream=True
                    )
                    filename = f'recording_{meeting}_{file["id"]}.mp4'
                    with open(filename, 'wb') as f:
                        r.raw.decode_content = True
                        shutil.copyfileobj(r.raw, f)

                    succeed.append(file_result_existing_file(filename))
                except DemistoException as e:
                    raise DemistoException(
                        f'Unable to download recording for meeting {meeting}: [{e.res.status_code}] - {e.res.text}')
                try:
                    self._http_request(
                        method='DELETE',
                        url_suffix=f'meetings/{meeting}/recordings/{file["id"]}',
                        headers={'authorization': f'Bearer {self.access_token}'},
                    )
                    succeed.append('File ' + filename + ' was moved to trash.')
                except DemistoException:
                    failed.append('Failed to delete file ' + filename + '.')

                return (succeed, failed)

        except DemistoException as e:
            raise DemistoException(f'Unable to reach the recording: [{e.res.status_code}] - {e.res.text}')


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


def test_module(
    verify,
    proxy,
    api_key,
    api_secret,
    account_id,
    client_id,
    client_secret,
):
    """Tests connectivity with the client.
    Takes as an argument all client arguments to create a new client
    """
    try:
        client = Client(
            base_url=BASE_URL,
            verify=verify,
            proxy=proxy,
            api_key=api_key,
            api_secret=api_secret,
            account_id=account_id,
            client_id=client_id,
            client_secret=client_secret,
        )
        # running an arbitrary command to test the connection
        client.zoom_user_list(1, None, 'active')
    except DemistoException as e:
        error_message = e.message
        if 'Invalid access token' in error_message:
            error_message = 'Invalid credentials. Please verify that your credentials are valid.'
        elif "The Token's Signature resulted invalid" in error_message:
            error_message = 'Invalid API Secret. Please verify that your API Secret is valid.'
        elif 'Invalid client_id or client_secret' in error_message:
            error_message = 'Invalid Client ID or Client Secret. Please verify that your ID and Secret is valid.'
        else:
            error_message = f'Problem reaching Zoom API, check your credentials. Error message: {error_message}'
        return error_message
    return 'ok'


# def only_relevant_arguments(dict) -> dict:
#     # remove all the keys with value of None
#     new_dict = {k: v for k, v in dict.items() if v != None}
#     return new_dict

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


'''FORMATTING FUNCTIONS'''


def zoom_user_list_command(client: Client, page_size: int = 30, user_id: str = None,
                           status: str = "active", next_page_token: str = None,
                           role_id: str = None, limit: int = None) -> CommandResults:
    raw_data = client.zoom_user_list(page_size, user_id, status, next_page_token, role_id, limit)
    # parsing the data according to the different given arguments
    if limit:
        all_info = []
        for pages in range(len(raw_data)):
            page = raw_data[pages].get("users")
            for record in range(len(page)):
                all_info.append(page[record])

        md = tableToMarkdown('Users', all_info, ['id', 'email',
                                                 'type', 'pmi', 'verified', 'created_at', 'status', 'role_id'])
        md += '\n' + tableToMarkdown('Metadata', [raw_data][0][0], ['total_records'])
        raw_data = raw_data[0]
    else:
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
        outputs={'Metadata': {
            'Count': raw_data.get('page_count'),
            # TODO this line?
            'Number': raw_data.get('page_number'),
            'Size': raw_data.get('page_size'),
            'Total': raw_data.get('total_records')
        }},
        raw_response=raw_data
    )


def zoom_user_create_command(client: Client, user_type: str, email: str, first_name: str, last_name: str) -> CommandResults:
    raw_data = client.zoom_user_create(user_type, email, first_name, last_name)
    return CommandResults(
        outputs_prefix='Zoom',
        readable_output=f"User created successfully with ID{raw_data.get('id')}",
        outputs={"Zoom.User": raw_data},
        raw_response=raw_data
    )


def zoom_user_delete_command(client: Client, user_id: str, action: str) -> CommandResults:
    client.zoom_user_delete(user_id, action)
    return CommandResults(
        outputs_prefix='Zoom',
        readable_output=f'User {user_id} was deleted successfully',
    )


def zoom_meeting_create_command(
        client: Client,
        user_id: str,
        topic: str,
        host_video: bool | str = True,
        jbh_time: int | str | None = None,
        start_time: str = None,
        timezone: str = None,
        type: str = "instant",
        auto_recording: str = "none",
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
    raw_data = client.zoom_meeting_create(user_id, topic, host_video, jbh_time,
                                          start_time, timezone, type,
                                          auto_recording,
                                          encryption_type,
                                          join_before_host,
                                          meeting_authentication,
                                          waiting_room,
                                          end_date_time,
                                          end_times,
                                          monthly_day,
                                          monthly_week,
                                          monthly_week_day,
                                          repeat_interval,
                                          recurrence_type,
                                          weekly_days)
    # if type == "recurring meeting with fixed time":
    #     basic_info = [raw_data], ['uuid', 'id', 'host_id', 'host_email', 'topic',
    #                               'type', 'status',
    #                               'timezone', 'created_at', 'start_url', 'join_url',
    #                               ][0]
    #     additinal_info = raw_data["occurrences"], ['start_time', 'duration']
    #     all_info = []
    #     all_info.append(basic_info[0][0])
    #     all_info[0].update(additinal_info[0][0])
    #     md = f"""Meeting created successfully.
    #     Start it [here]({raw_data.get("start_url")}) and join [here]({raw_data.get("join_url")})."""
    #     md += "\n" + tableToMarkdown('Meeting details', [all_info][0], ['uuid', 'id', 'host_id', 'host_email', 'topic',
    #                                                                     'type', 'status', 'start_time', 'duration',
    #                                                                     'timezone', 'created_at', 'start_url', 'join_url'
    #                                                                     ])
    # else:
    md = f"""Meeting created successfully.
        Start it [here]({raw_data.get("start_url")}) and join [here]({raw_data.get("join_url")})."""
    md += "\n" + tableToMarkdown('Meeting details', [raw_data])
    return CommandResults(
        outputs_prefix='Zoom.meetings',
        readable_output=md,
        outputs={'Zoom.Meeting': raw_data},
        raw_response=raw_data
    )


def zoom_recording_get_command(client: Client, meeting_id: str) -> CommandResults:
    raw_data = client.zoom_recording_get(meeting_id)
    return CommandResults(
        outputs_prefix='Zoom',
        readable_output=raw_data,
        raw_response=raw_data
    )


def zoom_meeting_get_command(client: Client, meeting_id: str, occurrence_id: str = None,
                             show_previous_occurrences: bool = True) -> CommandResults:
    raw_data = client.zoom_meeting_get(meeting_id, occurrence_id, show_previous_occurrences)
    md = tableToMarkdown('Meeting details', [raw_data], ['uuid', 'id', 'host_id', 'host_email', 'topic',
                                                         'type', 'status', 'start_time', 'duration',
                                                         'timezone', 'agenda', 'created_at', 'start_url', 'join_url',
                                                         ])
    return CommandResults(
        outputs_prefix='Zoom.meetings',
        readable_output=md,
        # TODO do i need this line?
        outputs={'Zoom.Meeting': raw_data},
        raw_response=raw_data
    )


def zoom_meeting_list_command(client: Client, user_id: str, next_page_token: str = None,
                              page_size: int = 30, limit: int = None, type: str = None) -> CommandResults:
    raw_data = client.zoom_meeting_list(user_id, next_page_token, page_size, limit, type)
    # parsing the data according to the different given arguments
    if limit:
        all_info = []
        for pages in range(len(raw_data)):
            page = raw_data[pages].get("meetings")

            for record in range(len(page)):
                all_info.append(page[record])
        md = tableToMarkdown("Meeting list", all_info, ['uuid', 'id',
                                                        'host_id', 'topic', 'type', 'start time', 'duration',
                                                        'timezone', 'created_at', 'join_url'
                                                        ])
        md += "\n" + tableToMarkdown('Metadata', [raw_data][0][0], ['total_records'])
    else:
        md = tableToMarkdown("Meeting list", raw_data.get("meetings"), ['uuid', 'id',
                                                                        'host_id', 'topic', 'type', 'start time', 'duration',
                                                                        'timezone', 'created_at', 'join_url'
                                                                        ])
        md += "\n" + tableToMarkdown('Metadata', [raw_data], ['next_page_token', 'page_size', 'total_records'])

    return CommandResults(
        outputs_prefix='Zoom.meetings',
        readable_output=md,
        # TODO do i need this line?
        outputs={'Zoom.Meeting': raw_data},
        raw_response=raw_data
    )


def check_authentication_type_parameters(api_key: str, api_secret: str,
                                         # checking if the user entered extra parameters
                                         # at the configuration level
                                         account_id: str, client_id: str, client_secret: str):
    if any((api_key, api_secret)) and any((account_id, client_id, client_secret)):
        raise DemistoException("""Too many fields were filled.
                                   You should fill the Account ID, Client ID, and Client Secret fields (OAuth),
                                   OR the API Key and API Secret fields (JWT - Deprecated)""")


def main():  # pragma: no cover
    # TODO do i need this line?
    results: Union[CommandResults, str, List[CommandResults]]

    params = demisto.params()
    args = demisto.args()
    api_key = params.get('api_key')
    api_secret = params.get('api_secret')
    account_id = params.get('account_id')
    client_id = params.get('credentials', {}).get('identifier')
    client_secret = params.get('credentials', {}).get('password')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()

    # this is for BC, because the arguments given as <a-b>, i.e "user-list"
    args = {key.replace('-', '_'): val for key, val in args.items()}

    try:
        check_authentication_type_parameters(api_key, api_secret, account_id, client_id, client_secret)
        if command == 'test-module':
            return_results(test_module(
                verify=verify_certificate,
                proxy=proxy,
                api_key=api_key,
                api_secret=api_secret,
                account_id=account_id,
                client_id=client_id,
                client_secret=client_secret,
            ))

        client = Client(
            base_url=BASE_URL,
            verify=verify_certificate,
            proxy=proxy,
            api_key=api_key,
            api_secret=api_secret,
            account_id=account_id,
            client_id=client_id,
            client_secret=client_secret,
        )

        demisto.debug(f'Command being called is {command}')

        '''CRUD commands'''
        if command == 'zoom-user-create':
            results = zoom_user_create_command(client, **args)
        elif command == 'zoom-meeting-create':
            results = zoom_meeting_create_command(client, **args)
        elif command == 'zoom-meeting-get':
            results = zoom_meeting_get_command(client, **args)
        elif command == 'zoom-meeting-list':
            results = zoom_meeting_list_command(client, **args)
        elif command == 'zoom-user-delete':
            results = zoom_user_delete_command(client, **args)
        elif command == 'zoom-recording-get':
            results = zoom_recording_get_command(client, **args)
        elif command == 'zoom-user-list':
            results = zoom_user_list_command(client, **args)
        else:
            return_error('Unrecognized command: ' + demisto.command())
        return_results(results)

    except DemistoException as e:
        # For any other integration command exception, return an error
        return_error(f'Failed to execute {command} command. Error: {str(e)}')
        # TODO maybe refer to specific parts, like "e.res.status_code, e.res.text"
        # and the error line shuld be modified to feet all kinds of error


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

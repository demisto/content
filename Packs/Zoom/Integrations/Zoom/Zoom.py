import shutil
import demistomock as demisto  # noqa: F401
import jwt
from CommonServerPython import *  # noqa: F401
import dateparser

if not demisto.getParam('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

BASE_URL = 'https://api.zoom.us/v2/'
OAUTH_TOKEN_GENERATOR_URL = 'https://zoom.us/oauth/token'
# The token’s time to live is 1 hour,
# two minutes were subtract for extra safety.
TOKEN_LIFE_TIME = timedelta(minutes=58)


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

    def test(self):
        """Tests connectivity with the application. """
        self.zoom_list_users()
        return 'ok'

    def zoom_create_user(self):
        ut = demisto.getArg('user_type')
        user_type = 1  # Basic
        if ut == 'Pro':
            user_type = 2
        elif ut == 'Corporate':
            user_type = 3
        try:
            data = self._http_request(
                method='POST',
                url_suffix='users',
                headers={'authorization': f'Bearer {self.access_token}'},
                json={
                    'action': 'create',
                    'user_info': {
                        'email': demisto.getArg('email'),
                        'type': user_type,
                        'first_name': demisto.getArg('first_name'),
                        'last_name': demisto.getArg('last_name')}
                },
            )
            return_results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': data,
                'HumanReadable': 'User created successfully with ID %s' % data.get('id'),
                'EntryContext': {'Zoom.User': data}
            })
        except DemistoException as e:
            return_error('User creation failed: [%d] - %s' % (e.res.status_code, e.res.text))

    def zoom_list_users(self):
        try:
            data = self._http_request(
                method='GET',
                url_suffix='users',
                headers={'authorization': f'Bearer {self.access_token}'},
                params={
                    'status': demisto.getArg('status'),
                    'page_size': demisto.getArg('page-size'),
                    'page_number': demisto.getArg('page-number')
                }
            )
            md = tableToMarkdown('Users', data.get('users'), ['id', 'first_name', 'last_name', 'email', 'type'])
            md += '\n' + tableToMarkdown('Metadata', [data], ['page_count', 'page_number', 'page_size', 'total_records'])
            return_results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': data,
                'HumanReadable': md,
                'EntryContext': {
                    'Zoom.User': data.get('users'),
                    'Zoom.Metadata': {
                        'Count': data.get('page_count'),
                        'Number': data.get('page_number'),
                        'Size': data.get('page_size'),
                        'Total': data.get('total_records')
                    }
                }
            })
        except DemistoException as e:
            return_error('Failed to list users: [%d] - %s' % (e.res.status_code, e.res.text))

    def zoom_delete_user(self):
        try:
            self._http_request(
                method='DELETE',
                url_suffix='users/' + demisto.getArg('user'),
                headers={'authorization': f'Bearer {self.access_token}'},
                params={'action': demisto.getArg('action')})
            return_results('User %s deleted successfully' % demisto.getArg('user'))
        except DemistoException as e:
            return_error('User deletion failed: [%d] - %s' % (e.res.status_code, e.res.text))

    def zoom_create_meeting(self):
        auto_recording = "none"
        if (demisto.getArg('auto_record_meeting') == 'yes'):
            auto_recording = "cloud"
            params = {
                'type': 1,
                'topic': demisto.getArg('topic'),
                'settings': {
                    'join_before_host': True,
                    'auto_recording': auto_recording
                }
            }
        if (demisto.args()['type'] == 'Scheduled'):
            params.update({
                'type': 2,
                'start_time': demisto.getArg('start-time'),
                'timezone': demisto.getArg('timezone'),
            })
        try:
            data = self._http_request(
                method='POST',
                url_suffix="users/%s/meetings" % demisto.getArg('user'),
                headers={'authorization': f'Bearer {self.access_token}'},
                json=params)
            md = 'Meeting created successfully.\nStart it [here](%s) and join [here](%s).' % (
                data.get('start_BASE_URL'), data.get('join_BASE_URL'))
            return_results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': data,
                'HumanReadable': md,
                'EntryContext': {'Zoom.Meeting': data}
            })
        except DemistoException as e:
            return_error('Meeting creation failed: [%d] - %s' % (e.res.status_code, e.res.text))

    def zoom_fetch_recording(self):
        meeting = demisto.getArg('meeting_id')
        try:
            data = self._http_request(
                method='GET',
                url_suffix='meetings/%s/recordings' % meeting,
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
                except DemistoException as e:
                    return_error(
                        'Unable to download recording for meeting %s: [%d] - %s' % (meeting, e.res.status_code, e.res.text))

                filename = 'recording_%s_%s.mp4' % (meeting, file['id'])
                with open(filename, 'wb') as f:
                    r.raw.decode_content = True
                    shutil.copyfileobj(r.raw, f)
                return_results(file_result_existing_file(filename))

                try:
                    self._http_request(
                        method='DELETE',
                        url_suffix='meetings/%s/recordings/%s' % (meeting, file['id']),
                        headers={'authorization': f'Bearer {self.access_token}'},
                    )
                    return_results('File ' + filename + ' was moved to trash.')
                except DemistoException:
                    return_error('Failed to delete file ' + filename + '.')

        except DemistoException as e:
            return_error('Download of recording failed: [%d] - %s' % (e.res.status_code, e.res.text))


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
        client.test()
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


def main():
    # user_profile = None
    params = demisto.params()
    api_key = params.get('api_key')
    api_secret = params.get('api_secret')
    account_id = params.get('account_id')
    client_id = params.get('credentials', {}).get('identifier')
    client_secret = params.get('credentials', {}).get('password')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()

    try:
        if any((api_key, api_secret)) and any((account_id, client_id, client_secret)):
            raise DemistoException("""Too many fields were filled.
                                   You should fill the Account ID, Client ID, and Client Secret fields (OAuth),
                                   OR the API Key and API Secret fields (JWT - Deprecated)""")

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

        '''commands'''
        if command == 'zoom-create-user':
            client.zoom_create_user()
        elif command == 'zoom-create-meeting':
            client.zoom_create_user()
        elif command == 'zoom-delete-user':
            client.zoom_delete_user()
        elif command == 'zoom-fetch-recording':
            client.zoom_fetch_recording()
        elif command == 'zoom-list-users':
            client.zoom_list_users()
        else:
            return_error('Unrecognized command: ' + demisto.command())

    except DemistoException as e:
        # For any other integration command exception, return an error
        return_error(f'Failed to execute {command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

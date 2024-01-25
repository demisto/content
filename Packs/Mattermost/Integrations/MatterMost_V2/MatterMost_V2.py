import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
DEFAULT_PAGE_NUMBER = 0
DEFAULT_PAGE_SIZE = 50
DEFAULT_LIMIT = 50
''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the MatterMost API
    """

    def __init__(
        self,
        base_url: str,
        headers: dict,
        bot_access_token: str | None = None,
        personal_access_bot: str | None = None,
        team_name: str | None = None,
        notification_channel: str | None = None,
        verify=True,
        proxy=False,
    ):
        super().__init__(base_url, verify, proxy, headers=headers)
        self.bot_access_token = bot_access_token
        self.personal_access_bot = personal_access_bot
        self.team_name = team_name
        self.notification_channel = notification_channel

    def get_team_request(self, team_name: str) -> dict[str, str]:
        """Gets a team details based on its name

        :type dummy: ``str``
        :param dummy: string to add in the dummy dict that is returned

        :return: dict as {"dummy": dummy}
        :rtype: ``str``
        """
        response = self._http_request(method='GET', url_suffix=f'/api/v4/teams/name/{team_name}')

        return response

    def list_channel_request(self, team_id: str, params: dict, get_private: bool = False) -> list[dict[str, Any]]:

        if get_private:
            response = self._http_request(method='GET', url_suffix=f'/api/v4/teams/{team_id}/channels/private', params=params)
        else:
            response = self._http_request(method='GET', url_suffix=f'/api/v4/teams/{team_id}/channels', params=params)

        return response

    def create_channel_request(self, params: dict) -> dict[str, str]:

        response = self._http_request(method='POST', url_suffix='/api/v4/channels', params=params)

        return response

    def get_channel_by_name_and_team_name_request(self, team_name: str, channel_name: str) -> dict[str, Any]:

        response = self._http_request(method='GET', url_suffix=f'/api/v4/teams/name/{team_name}/channels/name/{channel_name}')

        return response

    def add_channel_member_request(self, channel_id: str, data: dict) -> dict[str, str]:

        response = self._http_request(method='POST', url_suffix=f'/api/v4/channels/{channel_id}/members', data=data)

        return response

    def remove_channel_member_request(self, channel_id: str, user_id: dict) -> dict[str, str]:

        response = self._http_request(method='DELETE', url_suffix=f'/api/v4/channels/{channel_id}/members/{user_id}')

        return response

    def list_users_request(self, params: dict) -> list[dict[str, Any]]:

        response = self._http_request(method='GET', url_suffix='/api/v4/users', params=params)

        return response

    def close_channel_request(self, channel_id: str) -> list[dict[str, Any]]:

        response = self._http_request(method='DELETE', url_suffix=f'/api/v4/channels/{channel_id}')

        return response

    def send_file_request(self, file_info: dict, params: dict) -> dict[str, str]:

        files = {'file': (file_info['name'], open(file_info['path'], 'rb'))}

        response = self._http_request(
            method='POST',
            url_suffix='/api/v4/files',
            files=files,
            params=params
        )
        return response

    def create_post_request(self, params: dict) -> list[dict[str, Any]]:

        response = self._http_request(method='POST', url_suffix='/api/v4/posts', params=params)

        return response


''' HELPER FUNCTIONS '''


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:

        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def get_team_command(client: Client, args: dict[str, Any]) -> CommandResults:

    team_name = args.get('team_name', '')

    team_details = client.get_team_request(team_name)

    hr = tableToMarkdown('Team details:', team_details)
    return CommandResults(
        outputs_prefix='Mattermost.Team',
        outputs_key_field='name',
        outputs=team_details,
        readable_output=hr,
    )


def list_channels_command(client: Client, args: dict[str, Any]) -> CommandResults:

    team_name = args.get('team_name', client.team_name)
    include_private_channels = argToBoolean(args.get('include_private_channels', False))
    page = args.get('page', DEFAULT_PAGE_NUMBER)
    page_size = args.get('page_size', DEFAULT_PAGE_NUMBER)
    args.get('limit', DEFAULT_LIMIT)

    team_details = client.get_team_request(team_name)

    params = {'page': page, 'page_size': page_size}
    channel_details = client.list_channel_request(team_details.get('id'), params)

    if include_private_channels:
        channel_details += client.list_channel_request(team_details.get('id'), params, get_private=True)

    hr = tableToMarkdown('Channels:', channel_details)
    return CommandResults(
        outputs_prefix='Mattermost.Channel',
        outputs_key_field='name',
        outputs=channel_details,
        readable_output=hr,
    )


def create_channel_command(client: Client, args: dict[str, Any]) -> CommandResults:

    team_name = args.get('team_name', '')
    channel_name = args.get('name', '')
    channel_display_name = args.get('display_name')
    channel_type = 'O' if args.get('type') == 'Public' else 'P'
    purpose = args.get('purpose', '')
    header = args.get('header')

    team_details = client.get_team_request(team_name)

    params = {'team_id': team_details.get('id'),
              'name': channel_name,
              'display_name': channel_display_name,
              'type': channel_type,
              'purpose': purpose,
              'header': header}

    channel_details = client.create_channel_request(params)
    hr = f'The channel {channel_display_name} was created successfully, with channel ID: {channel_details.get("id")}'
    return CommandResults(
        outputs_prefix='Mattermost.Channel',
        outputs_key_field='name',
        outputs=channel_details,
        readable_output=hr
    )


def add_channel_member_command(client: Client, args: dict[str, Any]) -> CommandResults:

    team_name = args.get('team_name', '')
    channel_name = args.get('channel_name', '')
    user_id = args.get('user_id', '')

    channel_details = client.get_channel_by_name_and_team_name_request(team_name, channel_name)

    data = {'user_id': user_id}
    client.add_channel_member_request(channel_details.get('id'), data)

    hr = f'The member {user_id} was added to the channel successfully, with channel ID: {channel_details.get("id")}'
    return CommandResults(
        readable_output=hr
    )


def remove_channel_member_command(client: Client, args: dict[str, Any]) -> CommandResults:

    team_name = args.get('team_name', '')
    channel_name = args.get('channel_name', '')
    user_id = args.get('user_id', '')

    channel_details = client.get_channel_by_name_and_team_name_request(team_name, channel_name)

    client.remove_channel_member_request(channel_details.get('id'), user_id)

    hr = f'The member {user_id} was removed from the channel successfully.'
    return CommandResults(
        readable_output=hr
    )


def close_channel_command(client: Client, args: dict[str, Any]) -> CommandResults:
    team_name = args.get('team_name', '')
    channel_name = args.get('channel_name', '')

    channel_details = client.get_channel_by_name_and_team_name_request(team_name, channel_name)

    client.close_channel_request(channel_details.get('id'))

    hr = f'The channel {channel_name} was delete successfully.'
    return CommandResults(
        readable_output=hr
    )


def list_users_command(client: Client, args: dict[str, Any]) -> CommandResults:

    team_name = args.get('team_name', '')
    channel_id = args.get('channel_id', '')
    page = args.get('page', DEFAULT_PAGE_NUMBER)
    page_size = args.get('page_size', DEFAULT_PAGE_NUMBER)
    args.get('limit', DEFAULT_LIMIT)

    if team_name:
        team_details = client.get_team_request(team_name)
        team_id = team_details.get('id')
    else:
        team_id = ''

    params = {'page': page, 'page_size': page_size, 'in_team': team_id, 'in_channel': channel_id}

    users = client.list_users_request(params)

    hr = tableToMarkdown('Users:', users)
    return CommandResults(
        outputs_prefix='Mattermost.User',
        outputs_key_field='id',
        outputs=users,
        readable_output=hr,
    )


def send_file_command(client, args) -> CommandResults:

    channel_name = args.get('channel_name')
    team_name = args.get('team_name', '')
    message = args.get('message')
    entry_id = args.get('entry_id')

    channel_details = client.get_channel_by_name_and_team_name_request(team_name, channel_name)

    file_info = demisto.getFilePath(entry_id)
    params = {'channel_id': channel_details.get('id'),
              'filename': file_info['name']}

    upload_response = client.send_file_request(file_info, params)

    params = {'channel_id': channel_details.get('id'),
              'message': message,
              'file_ids': [upload_response.get('file_infos')[0].get('id')]}   # always uploading a single file

    client.create_post_request(params)

    return CommandResults(
        readable_output=f'file {file_info["name"]} was successfully sent to channel {channel_name}'
    )


''' MAIN FUNCTION '''


def main():  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    url = params.get('url', '')

    bot_access_token = params.get('bot_access_token', {}).get('password')
    personal_access_bot = params.get('personal_access_bot', {}).get('password')
    team_name = params.get('team_name')
    notification_channel = params.get('notification_channel')

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    global SECRET_TOKEN, LONG_RUNNING, MIRRORING_ENABLED, CACHE_EXPIRY, CACHED_INTEGRATION_CONTEXT
    SECRET_TOKEN = secret_token
    LONG_RUNNING = params.get('longRunning', False)
    MIRRORING_ENABLED = params.get('mirroring', False)

    # Pull initial Cached context and set the Expiry
    CACHE_EXPIRY = next_expiry_time()
    CACHED_INTEGRATION_CONTEXT = get_integration_context(SYNC_CONTEXT)

    if MIRRORING_ENABLED and (not LONG_RUNNING or not SECRET_TOKEN or not bot_client_id or not bot_client_secret or not bot_jid):
        raise DemistoException("""Mirroring is enabled, however long running is disabled
or the necessary bot authentication parameters are missing.
For mirrors to work correctly, long running must be enabled and you must provide all
the zoom-bot following parameters:
secret token,
Bot JID,
bot client id and secret id""")
    if LONG_RUNNING:
        try:
            port = int(params.get('longRunningPort'))
        except ValueError as e:
            raise ValueError(f'Invalid listen port - {e}')

    command = demisto.command()
    # this is to avoid BC. because some of the arguments given as <a-b>, i.e "user-list"
    args = {key.replace('-', '_'): val for key, val in args.items()}

    try:
        global CLIENT
        headers = {'Authorization': f'Brearer {personal_access_bot}'}

        client = Client(
            base_url=url,
            headers=headers,
            verify=verify_certificate,
            proxy=proxy,
            bot_access_token=bot_access_token,
            personal_access_bot=personal_access_bot,
            team_name=team_name,
            notification_channel=notification_channel,
        )
        CLIENT = client

        if command == 'test-module':
            return_results(test_module(client=client))

        demisto.debug(f'Command being called is {command}')

        if command == 'long-running-execution':
            run_long_running(port)
        elif command == 'mattermost-get-team':
            return_results(get_team_command(CLIENT, args))
        elif command == 'mattermost-list-channels':
            return_results(list_channels_command(CLIENT, args))
        elif command == 'mattermost-create-channel':
            return_results(create_channel_command(CLIENT, args))
        elif command == 'mattermost-add-channel-member':
            return_results(add_channel_member_command(CLIENT, args))
        elif command == 'mattermost-remove-channel-member':
            return_results(remove_channel_member_command(CLIENT, args))
        elif command == 'mattermost-list-users':
            return_results(list_users_command(CLIENT, args))
        elif command == 'mattermost-close-channel':
            return_results(close_channel_command(CLIENT, args))
        elif command == 'mattermost-send-file':
            return_results(send_file_command(CLIENT, args))
        else:
            return_error('Unrecognized command: ' + demisto.command())

    except DemistoException as e:
        # For any other integration command exception, return an error
        demisto.error(format_exc())
        return_error(f'Failed to execute {command} command. Error: {str(e)}.')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

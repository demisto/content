from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import urllib3
import traceback

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class Error(Exception):
    """Base class for exceptions in this module."""


class NotFoundError(Error):
    """Exception raised for 404 - Page Not Found errors.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message


class Client(BaseClient):

    def __init__(self, url: str, use_ssl: bool, use_proxy: bool, fetch_interval_hours: float = 1):
        super().__init__(url, verify=use_ssl, proxy=use_proxy)
        self.fetch_interval_hours = fetch_interval_hours

    def http_request(self, name, resp_type=None):
        """
        initiates a http request to openphish
        """
        data = self._http_request(
            method='GET',
            url_suffix=name,
            resp_type=resp_type,
        )
        return data


def _save_urls_to_instance(client: Client):
    """
    gets urls from api and load it to instance's memory
    raise NotFoundError if the http request to the api failed.

    """
    try:
        # gets the urls from api and formats them
        data = client.http_request('feed.txt', resp_type='text')
        data = data.splitlines()
        data = list(map(remove_backslash, data))

        context = {"list": data,
                   "timestamp": date_to_timestamp(datetime.now(), DATE_FORMAT)}
        set_integration_context(context)

    except NotFoundError as e:
        raise Exception(f'Check server URL - {e.message}')


def _is_reload_needed(client: Client, data: dict) -> bool:
    """
    Checks if there is a need to reload the data from api to instance's memory
    Args:
        data: a dictionary of the type {'list': <list of urls>, 'timestamp': <timestamp>}

    Returns: True if the timestamp is older then required by the client.fetch_interval_hours
    or if the memory is empty, Otherwise False.

    """
    if not data or not data.get('timestamp') or not data.get('list'):
        return True
    now = datetime.now()

    if data.get('timestamp') <= date_to_timestamp(now - timedelta(hours=client.fetch_interval_hours)):
        return True

    return False


def test_module(client: Client) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: OpenPhish client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    _save_urls_to_instance(client)
    return "ok"


def remove_backslash(url: str) -> str:
    """

    Args:
        url: a string representing a url

    Returns: the string without last '/' if such exists.

    """
    url.strip()
    if url.endswith('/'):
        return url[:-1]
    return url


def url_command(client: Client, **kwargs) -> List[CommandResults]:
    data = get_integration_context()
    if _is_reload_needed(client, data):
        reload_command(client)
        data = get_integration_context()

    command_results: List[CommandResults] = []
    if not data:
        raise DemistoException("Data was not saved correctly to the integration context.")

    url_list_from_user = argToList(kwargs.get('url'))
    urls_in_db = data.get('list', [])
    for url in url_list_from_user:
        url_fixed = remove_backslash(url)
        if url_fixed in urls_in_db:
            dbotscore = Common.DBotScore.BAD
            desc = 'Match found in OpenPhish database'
            markdown = f"#### Found matches for given URL {url}\n"
        else:
            dbotscore = Common.DBotScore.NONE
            desc = ""
            markdown = f"#### No matches for URL {url}\n"

        dbot = Common.DBotScore(
            url, DBotScoreType.URL,
            'OpenPhish', dbotscore, desc,
            reliability=demisto.params().get('integrationReliability')
        )
        url_object = Common.URL(url, dbot)
        command_results.append(CommandResults(
            indicator=url_object,
            readable_output=markdown,
        ))

    return command_results


def reload_command(client: Client, **kwargs) -> CommandResults:
    _save_urls_to_instance(client)
    return CommandResults(readable_output='Database was updated successfully to the integration context.')


def status_command(client: Client, **kwargs) -> CommandResults:
    data = get_integration_context()

    md = "OpenPhish Database Status\n"
    if data and data.get('list', None):
        md += f"Total **{str(len(data.get('list')))}** URLs loaded.\n"
        load_time = timestamp_to_datestring(data.get('timestamp'),
                                            "%a %b %d %Y %H:%M:%S (UTC)",
                                            is_utc=True)
        md += f"Last load time **{load_time}**\n"
    else:
        md += "Database not loaded.\n"

    return CommandResults(readable_output=md)


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    demisto.debug(f'Command being called is {demisto.command()}')

    # get the service API url
    base_url = "http://openphish.com"
    https_base_url = "https://openphish.com"

    commands = {
        'url': url_command,
        'openphish-reload': reload_command,
        'openphish-status': status_command,
    }
    user_params = demisto.params()
    hours_to_refresh = user_params.get('fetchIntervalHours', '1')

    try:
        hours_to_refresh = float(hours_to_refresh)
        use_ssl = not user_params.get('insecure', False)
        use_proxy = user_params.get('proxy', False)
        use_https = user_params.get('https', False)
        client = Client(
            url=https_base_url if use_https else base_url,
            use_ssl=use_ssl,
            use_proxy=use_proxy,
            fetch_interval_hours=hours_to_refresh)

        command = demisto.command()
        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        elif command in commands:
            return_results(commands[command](client, **demisto.args()))

    # Log exceptions
    except ValueError:
        return_error('Invalid parameter was given as database refresh interval.')
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)} \n '
                     f'tracback: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

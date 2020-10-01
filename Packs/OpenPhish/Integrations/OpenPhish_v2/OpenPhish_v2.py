from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import requests
import dateparser
from typing import Dict

requests.packages.urllib3.disable_warnings()
import traceback

# Disable insecure warnings
''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
API_PATH = "http://openphish.com"


class Error(Exception):
    """Base class for exceptions in this module."""
    pass


class NotFoundError(Error):
    """Exception raised for 404 - Page Not Found errors.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, url: str, use_ssl: bool, use_proxy: bool, fetch_interval_hours: float = 1):
        super().__init__(url, verify=use_ssl, proxy=use_proxy)
        self.fetch_interval_hours = fetch_interval_hours

    def http_request(self, name, resp_type=None):
        """
        initiates a http request to a test url
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
        # gets the urls from api with unite format
        data = client.http_request('feed.txt', resp_type='text')
        data = data.splitlines()
        data = list(map(remove_backslash, data))

        context = {"list": data,
                   "timestamp": date_to_timestamp(datetime.now(), DATE_FORMAT)}
        set_integration_context(context)

    except NotFoundError as e:
        return_error('Check server URL - ' + e.message)


def _is_reload_needed(client: Client, data: Dict[str, str]) -> bool:
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
    if int(data.get('timestamp')) < date_to_timestamp(now - timedelta(hours=client.fetch_interval_hours)):
        return True
    return False


def test_module(client) -> str:
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


def url_command(client: Client, **kwargs) -> CommandResults:
    data = get_integration_context()
    if _is_reload_needed(client, data):
        reload_command(client)
        data = get_integration_context()

    url_object_list = []
    if not data:
        raise DemistoException("Data was not saved correctly")

    url_list_from_user = argToList(kwargs.get('url'))
    markdown = "### OpenPhish Database - URL Query\n"
    urls_in_db = data.get('list', [])
    for url in url_list_from_user:
        url_fixed = remove_backslash(url)
        if url_fixed in urls_in_db:
            dbotscore = Common.DBotScore.BAD
            desc = 'Match found in OpenPhish database'
            markdown += "#### Found matches for given URL " + url + "\n"
        else:
            dbotscore = Common.DBotScore.NONE
            desc = None
            markdown += "#### No matches for URL " + url + "\n"

        dbot = Common.DBotScore(url, DBotScoreType.URL, 'OpenPhish', dbotscore, desc)
        url_object_list.append(Common.URL(url, dbot))

    return CommandResults(indicators=url_object_list, readable_output=markdown)


def reload_command(client: Client, **kwargs) -> CommandResults:
    _save_urls_to_instance(client)
    return CommandResults(readable_output='updated successfully')


def status_command(client: Client, **kwargs) -> CommandResults:
    data = get_integration_context()

    md = "OpenPhish Database Status\n"
    if data and data.get('list', None):
        md += "Total **" + str(len(data.get('list'))) + "** URLs loaded.\n"
        md += "Last load time **" + timestamp_to_datestring(data.get('timestamp'),
                                                            "%a %b %d %Y %H:%M:%S",
                                                            is_utc=True) + "**\n"
    else:
        md += "Database not loaded.\n"

    return CommandResults(readable_output=md)


demisto.debug(f'Command being called is {demisto.command()}')


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    # get the service API url
    base_url = API_PATH

    commands = {
        'url': url_command,
        'openphish-reload': reload_command,
        'openphish-status': status_command,
    }

    hours_to_refresh = demisto.params().get('fetchIntervalHours', '1')
    try:
        hours_to_refresh = float(hours_to_refresh)
    except ValueError:
        return_error(f'Invalid parameter was given as database refresh interval.')

    try:
        use_ssl = not demisto.params().get('insecure', False)
        use_proxy = demisto.params().get('proxy', False)
        client = Client(
            url=base_url,
            use_ssl=use_ssl,
            use_proxy=use_proxy,
            fetch_interval_hours=hours_to_refresh)

        command = demisto.command()
        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif command in commands:
            return_results(commands[command](client, **demisto.args()))

        else:

            return_error('Command not found.')

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)} \n '
                     f'tracback: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

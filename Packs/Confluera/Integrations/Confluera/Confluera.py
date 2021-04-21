''' IMPORTS '''
from CommonServerPython import *
from CommonServerUserPython import *

import requests
from typing import Any, Dict, List

# disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client will implement the service API, should not contain Cortex XSOAR logic.
    Should do requests and return data
    """

    def login(self, username: str, password: str) -> Dict[str, Any]:
        """ Returns access_token

        :type username: ``str``
        :param username: username to log user in to confluera iq-hub

        :type password: ``str``
        :param password: password to log user in to confluera iq-hub

        :return: Dictionary containing access token
        :rtype: ``Dict``
        """
        data = {
            "email": username,
            "password": password
        }

        return self._http_request(
            method='POST',
            url_suffix='/login',
            data=data
        )

    def fetch_detections(self, token: str, hours: str) -> Dict[str, Any]:
        headers = {
            'Authorization': f'Bearer {token}'
        }

        return self._http_request(
            method='GET',
            headers=headers,
            url_suffix='/ioc-detections/' + hours,
        )

    def fetch_progressions(self, token: str, hours: str) -> Dict[str, Any]:
        headers = {
            'Authorization': f'Bearer {token}'
        }

        return self._http_request(
            method='GET',
            headers=headers,
            url_suffix='/trails/' + hours,
        )

    def fetch_trail_details(self, token: str, trail_id: str) -> Dict[str, Any]:
        headers = {
            'Authorization': f'Bearer {token}'
        }

        return self._http_request(
            method='GET',
            headers=headers,
            url_suffix='/trails/' + trail_id,
        )


def login_command(client: Client, username: str, password: str) -> CommandResults:
    """confluera-login command : Returns login response including access token

    :type client: ``Client``
    :param Client: Confluera client to use

    :type username: ``str``
    :param username: username to log into Iq-Hub portal

    :type password: ``str``
    :param password: password to log into Iq-Hub portal

    :return:
      A ``CommandResults`` object that is then passed to ``return_results``,
      that contains the login response from Iq-Hub portal

    :rtype: ``CommandResults``
    """

    if not username:
        raise ValueError('Username not specified')
    if not password:
        raise ValueError('Password not specified')

    result = client.login(username, password)

    markdown = '### IQ-HUB login successful.\n'
    markdown += tableToMarkdown('Login Response :', result)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix='Confluera.LoginData',
        outputs_key_field='access_token',
        outputs=result
    )


def fetch_detections_command(client: Client, args: Dict[str, Any], detections_url: str) -> List[CommandResults]:
    """confluera-fetch-detections command : Returns detections present in Confluera
      Iq-Hub portal.

    :type client: ``Client``
    :param Client: Confluera client to use

    :type args: ``str``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['token']`` is used as access token
        ``args['hours']`` is used as timestamp for which detections will be fetched

    :type detections_url: ``str``
    :param detections_url: Endpoint to access detections present on Confluera's Iq-Hub portal.

    :return:
      A ``CommandResults`` object that is then passed to ``return_results``,
      that contains the login response from Iq-Hub portal

    :rtype: ``CommandResults``
    """
    token = args.get('access_token', None)
    hours = args.get('hours', None)

    if not token:
        raise ValueError('Access token not specified')
    if not hours:
        raise ValueError('hours not specified')

    result = client.fetch_detections(token, hours)

    command_results: List[CommandResults] = []

    total_detections = 0
    for idx, ioc in enumerate(result):
        total_detections += 1

    # output 1
    detections_log = {
        "Total Detections": total_detections,
        "Detections URL": detections_url,
    }
    command_results.append(CommandResults(
        readable_output=tableToMarkdown('Detections Log: ', detections_log, url_keys=('Detections URL')),
        outputs=detections_log
    ))

    # output 2
    if total_detections != 0:
        markdown = '### Successfully fetched ' + str(total_detections) + ' detections. \n'
    else:
        markdown = '### Detections Unavailable.'

    markdown += tableToMarkdown('Detections:', result)

    command_results.append(CommandResults(
        readable_output=markdown,
        outputs_prefix='Confluera.Detections',
        outputs=result
    ))

    return command_results


def fetch_progressions_command(client: Client, args: Dict[str, Any], progressions_url: str) -> List[CommandResults]:
    """confluera-fetch-progressions command : Returns progressions present in Confluera
      Iq-Hub portal.

    :type client: ``Client``
    :param Client: Confluera client to use

    :type args: ``str``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['token']`` is used as access token
        ``args['hours']`` is used as timestamp for which progressions will be fetched

    :type progressions_url: ``str``
    :param progressions_url: Endpoint to access progressions present on Confluera's Iq-Hub portal.

    :return:
      A ``CommandResults`` object that is then passed to ``return_results``,
      that contains the login response from Iq-Hub portal

    :rtype: ``CommandResults``
    """
    token = args.get('access_token', None)
    hours = args.get('hours', None)

    if not token:
        raise ValueError('Access token not specified')
    if not hours:
        raise ValueError('hours not specified')

    result = client.fetch_progressions(token, hours)

    command_results: List[CommandResults] = []

    total_progressions = 0
    for idx, ioc in enumerate(result):
        total_progressions += 1

    # output 1
    progressions_log = {
        "Total Progressions": total_progressions,
        "Progressions URL": progressions_url,
    }
    command_results.append(CommandResults(
        readable_output=tableToMarkdown('Progressions Log: ', progressions_log, url_keys=('Progressions URL')),
        outputs=progressions_log
    ))

    # output 2
    if total_progressions != 0:
        markdown = '### Successfully fetched ' + str(total_progressions) + ' progressions. \n'
    else:
        markdown = '### Progressions Unavailable.'

    markdown += tableToMarkdown('Progressions:', result)

    command_results.append(CommandResults(
        readable_output=markdown,
        outputs_prefix='Confluera.Progressions',
        outputs=result
    ))

    return command_results


def fetch_trail_details_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """confluera-fetch-trail-details command : Returns details of a progression ,
      present in Confluera Iq-Hub portal ,of which provided detection is a part of.

    :type client: ``Client``
    :param Client: Confluera client to use

    :type args: ``str``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['token']`` is used as access token
        ``args['trailId']`` is used as id for fetching details of a particular progression

    :return:
      A ``CommandResults`` object that is then passed to ``return_results``,
      that contains the login response from Iq-Hub portal

    :rtype: ``CommandResults``
    """
    token = args.get('access_token', None)
    trail_id = args.get('trail_id', None)

    if not token:
        raise ValueError('Access token not specified')
    if not trail_id:
        raise ValueError('hours not specified')

    result = client.fetch_trail_details(token, trail_id)

    markdown = tableToMarkdown('Trail Details:', result)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix='Confluera.TrailDetails',
        outputs=result
    )


def main() -> None:
    """main function, parses params and runs command functions
    """

    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    base_url = demisto.params().get('url')
    username = demisto.params().get('username', None)
    password = demisto.params().get('password', None)
    detections_url = demisto.params().get('detections_url', None)
    progressions_url = demisto.params().get('progressions_url', None)

    demisto.debug(f'Command being called is {demisto.command()}')

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy)

        if demisto.command() == 'confluera-login':
            return_results(login_command(client, username, password))

        elif demisto.command() == 'confluera-fetch-progressions':
            return_results(fetch_progressions_command(client, demisto.args(), progressions_url))

        elif demisto.command() == 'confluera-fetch-detections':
            return_results(fetch_detections_command(client, demisto.args(), detections_url))

        elif demisto.command() == 'confluera-fetch-trail-details':
            return_results(fetch_trail_details_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

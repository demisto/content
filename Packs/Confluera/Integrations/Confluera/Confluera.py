''' IMPORTS '''
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3
from typing import Any

# disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client will implement the service API, should not contain Cortex XSOAR logic.
    Should do requests and return data
    """

    def __init__(self, base_url: str, username: str, password: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._server = base_url
        self._username = username
        self._password = password

    def login(self) -> dict[str, Any]:
        data = {
            "email": self._username,
            "password": self._password
        }

        return self._http_request(
            method='POST',
            url_suffix='/login',
            data=data
        )

    def get_access_token(self):
        """
        Get an access token that was previously cerated. If it is still valid, else, genearte a new access token from
        the login API.
        :return: String containing access token
        :rtype: ``str``
        """
        previous_token = get_integration_context()

        # check if there is an existing access token
        if previous_token.get('access_token') and previous_token.get('expires') > int(time.time()):
            return previous_token.get('access_token')
        else:
            try:
                res = self.login()
                if res['access_token']:
                    integration_cotext = {
                        'access_token': res['access_token'],
                        'expires': res['expires'],
                    }
                    set_integration_context(integration_cotext)
                    return res['access_token']
            except Exception as e:
                return_error(
                    f'Error occurred while creating an access token. Please check the instance configuration.\n\n{e.args[0]}')

    def fetch_detections(self, token: str, hours: str) -> dict[str, Any]:
        headers = {
            'Authorization': f'Bearer {token}'
        }

        return self._http_request(
            method='GET',
            headers=headers,
            url_suffix='/ioc-detections/' + hours,
        )

    def fetch_progressions(self, token: str, hours: str) -> dict[str, Any]:
        headers = {
            'Authorization': f'Bearer {token}'
        }

        return self._http_request(
            method='GET',
            headers=headers,
            url_suffix='/trails/' + hours,
        )

    def fetch_trail_details(self, token: str, trail_id: str) -> dict[str, Any]:
        headers = {
            'Authorization': f'Bearer {token}'
        }

        return self._http_request(
            method='GET',
            headers=headers,
            url_suffix='/trails/' + trail_id,
        )


def test_module(client: Client, args: dict[str, Any]) -> str:
    token = client.get_access_token()
    hours = args.get('hours', '72')

    if not token:
        raise ValueError('Invalid access token')
    if not hours:
        raise ValueError('hours not specified')

    try:
        client.fetch_detections(token, hours)
    except DemistoException as e:
        raise e
    return 'ok'


def fetch_detections_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    """confluera-fetch-detections command : Returns detections present in Confluera
      Iq-Hub portal.

    :type client: ``Client``
    :param Client: Confluera client to use

    :type args: ``str``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['token']`` is used as access token
        ``args['hours']`` is used as timestamp for which detections will be fetched

    :return:
      A ``CommandResults`` object that is then passed to ``return_results``,
      that contains the login response from Iq-Hub portal

    :rtype: ``CommandResults``
    """
    token = client.get_access_token()
    hours = args.get('hours', None)

    if not token:
        raise ValueError('Access token not specified')
    if not hours:
        raise ValueError('hours not specified')

    result = client.fetch_detections(token, hours)

    command_results: list[CommandResults] = []

    total_detections = 0
    for idx, ioc in enumerate(result):
        total_detections += 1

    # output 1
    detections_log = {
        "Total Detections": total_detections,
        "Detections URL": client._server + '/#/detections',
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


def fetch_progressions_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    """confluera-fetch-progressions command : Returns progressions present in Confluera
      Iq-Hub portal.

    :type client: ``Client``
    :param Client: Confluera client to use

    :type args: ``str``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['token']`` is used as access token
        ``args['hours']`` is used as timestamp for which progressions will be fetched

    :return:
      A ``CommandResults`` object that is then passed to ``return_results``,
      that contains the login response from Iq-Hub portal

    :rtype: ``CommandResults``
    """
    token = client.get_access_token()
    hours = args.get('hours', None)

    if not token:
        raise ValueError('Access token not specified')
    if not hours:
        raise ValueError('hours not specified')

    result = client.fetch_progressions(token, hours)

    command_results: list[CommandResults] = []

    total_progressions = 0
    for idx, ioc in enumerate(result):
        total_progressions += 1

    # output 1
    progressions_log = {
        "Total Progressions": total_progressions,
        "Progressions URL": client._server + '/#/monitor/cyber-attacks/active',
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


def fetch_trail_details_command(client: Client, args: dict[str, Any]) -> CommandResults:
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
    token = client.get_access_token()
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
    username = demisto.params().get('username', None)['identifier']
    password = demisto.params().get('username', None)['password']

    demisto.debug(f'Command being called is {demisto.command()}')

    try:
        client = Client(
            base_url=base_url,
            username=username,
            password=password,
            verify=verify_certificate,
            proxy=proxy)

        if demisto.command() == 'test-module':
            return_results(test_module(client, demisto.args()))

        elif demisto.command() == 'confluera-fetch-progressions':
            return_results(fetch_progressions_command(client, demisto.args()))

        elif demisto.command() == 'confluera-fetch-detections':
            return_results(fetch_detections_command(client, demisto.args()))

        elif demisto.command() == 'confluera-fetch-trail-details':
            return_results(fetch_trail_details_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

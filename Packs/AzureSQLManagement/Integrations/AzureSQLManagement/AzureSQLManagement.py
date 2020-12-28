import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import urllib3
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def get_alert(self, alert_id: str) -> Dict[str, Any]:
        """Gets a specific HelloWorld alert by id

        :type alert_id: ``str``
        :param alert_id: id of the alert to return

        :return: dict containing the alert as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method='GET',
            url_suffix='/get_alert_details',
            params={
                'alert_id': alert_id
            }
        )


''' HELPER FUNCTIONS '''


def parse_domain_date(domain_date: Union[List[str], str], date_format: str = '%Y-%m-%dT%H:%M:%S.000Z') -> Optional[str]:
    """Converts whois date format to an ISO8601 string

    Converts the HelloWorld domain WHOIS date (YYYY-mm-dd HH:MM:SS) format
    in a datetime. If a list is returned with multiple elements, takes only
    the first one.

    :type domain_date: ``Union[List[str],str]``
    :param date_format:
        a string or list of strings with the format 'YYYY-mm-DD HH:MM:SS'

    :return: Parsed time in ISO8601 format
    :rtype: ``Optional[str]``
    """

    if isinstance(domain_date, str):
        # if str parse the value
        domain_date_dt = dateparser.parse(domain_date)
        if domain_date_dt:
            return domain_date_dt.strftime(date_format)
    elif isinstance(domain_date, list) and len(domain_date) > 0 and isinstance(domain_date[0], str):
        # if list with at least one element, parse the first element
        domain_date_dt = dateparser.parse(domain_date[0])
        if domain_date_dt:
            return domain_date_dt.strftime(date_format)
    # in any other case return nothing
    return None


''' COMMAND FUNCTIONS '''


def test_module(client: Client, first_fetch_time: int) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type name: ``str``
    :param name: name to append to the 'Hello' string

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    # INTEGRATION DEVELOPER TIP
    # Client class should raise the exceptions, but if the test fails
    # the exception text is printed to the Cortex XSOAR UI.
    # If you have some specific errors you want to capture (i.e. auth failure)
    # you should catch the exception here and return a string with a more
    # readable output (for example return 'Authentication Error, API Key
    # invalid').
    # Cortex XSOAR will print everything you return different than 'ok' as
    # an error
    try:
        client.search_alerts(max_results=1, start_time=first_fetch_time, alert_status=None, alert_type=None,
                             severity=None)
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def azure_sql_servers_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """azure-sql-servers-list command: Returns a list of all servers

    :type client: ``Client``
    :param Client: AzureSQLManagement client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['server_name']`` list of scan IDs or single scan ID

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains a scan status

    :rtype: ``CommandResults``
    """

    server_name = args.get('server_name')

    server_list = client.azure_sql_servers_list(server_name=server_name)

    readable_output = tableToMarkdown('Servers List', server_list)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='HelloWorld.Scan',
        outputs_key_field='scan_id',
        outputs=scan_list
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions
    """

    base_url = f'https://management.azure.com/subscriptions/{subscription_id}'

    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            subscription_id=params.get('subscription_id', ''),
            resource_group_name=params.get('resource_group_name', ''),
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
        )
        commands = {
            'azure-sql-servers-list': azure_sql_servers_list_command,
            'azure-sql-db-list': azure_sql_db_list_command,
            'azure-sql-db-audit-policy-list': azure_sql_db_audit_policy_list_command,
            'azure-sql-db-audit-policy-create-update': azure_sql_db_audit_policy_create_update_command,
            'azure-sql-db-threat-policy-get': azure_sql_db_threat_policy_get_command,
            'azure-sql-db-threat-policy-create-update': azure_sql_db_threat_policy_create_update_command,
            'azure-nsg-auth-start': start_auth,
            'azure-nsg-auth-complete': complete_auth,
            'azure-nsg-auth-reset': reset_auth,
        }
        if command == 'test-module':
            return_error("Please run `!azure-nsg-auth-start` and `!azure-nsg-auth-complete` to log in."
                         " For more details press the (?) button.")

        if command == 'azure-nsg-auth-test':
            return_results(test_connection(client, params))
        else:
            return_results(commands[command](client, **args))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

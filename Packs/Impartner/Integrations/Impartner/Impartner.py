import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, base_url, verify: bool, api_key: str = ""):
        headers = {
            'Authorization': 'prm-key ' + api_key
        }
        super().__init__(base_url=base_url, verify=verify, headers=headers)

    def get_accounts_list(self, params):
        result = self._http_request(method="GET", url_suffix="/account", params=params, headers=self._headers)
        return result

    def get_accounts_id(self, id, params):
        result = self._http_request(method="GET", url_suffix=f"/account/{id}", params=params, headers=self._headers)
        return result


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:  # pragma: no cover
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
        res = client.get_accounts_list({})
        if res.get('success'):
            message = 'ok'
    except DemistoException as e:
        raise e
    return message


def impartner_get_account_list_command(client: Client, args: dict[str, Any]) -> CommandResults:

    query = args.get('query', '')
    fields = args.get('fields', 'name, id, recordLink, tech_BD_Assigned_for_XSOAR__cf')
    filter = args.get('filter', '')
    orderby = args.get('orderby', '')
    skip = args.get('skip', '0')
    take = args.get('take', '10')
    params = assign_params(q=query, fields=fields, filter=filter, orderby=orderby, skip=skip, take=take)

    # Call the Client function and get the raw response
    result = client.get_accounts_list(params)
    parsed_result = result.get('data', {})
    readable_output = tableToMarkdown('List of accounts', parsed_result.get('results'))
    return CommandResults(
        outputs_prefix='Impartner.Account',
        readable_output=readable_output,
        outputs_key_field='id',
        outputs=parsed_result)


def impartner_get_account_id_command(client: Client, args: dict[str, Any]) -> CommandResults:

    id = args.get('id')
    fields = args.get('fields')
    all_fields = argToBoolean(args.get('all_fields', False))
    if all_fields:
        fields = ""
    params = assign_params(fields=fields)
    # Call the Client function and get the raw response
    result = client.get_accounts_id(id, params)
    parsed_result = result.get('data', {})
    if all_fields:
        context_result = {'id': parsed_result.get('id'), 'isActive': parsed_result.get('isActive'),
                          'tech_BD_Assigned_for_XSOAR__cf': parsed_result.get('tech_BD_Assigned_for_XSOAR__cf'),
                          'mailingCity': parsed_result.get('mailingCity'), 'mailingCountry': parsed_result.get('mailingCountry'),
                          'mailingPostalCode': parsed_result.get('mailingPostalCode'),
                          'mailingState': parsed_result.get('mailingState'), 'mailingStreet': parsed_result.get('mailingStreet'),
                          'name': parsed_result.get('name'), 'recordLink': parsed_result.get('recordLink'),
                          'website': parsed_result.get('website'),
                          'mainProductToIntegrate': parsed_result.get('what_is_your_main_product_you_are_looking_to_integrate'
                                                                      '_with_Palo_Alto_Networks__cf'),
                          'mutualCustomer': parsed_result.get('if_yes_please_share_at_least_1_mutual_customer_that_will_use_and'
                                                              '_test_the_integration__cf'),
                          'tpA_Product_s__cf': parsed_result.get('tpA_Product_s__cf'),
                          'integration_Status__cf': parsed_result.get('integration_Status__cf'),
                          'target_customers__cf': parsed_result.get('target_customers__cf'),
                          'company_Main_Market_Segment__cf': parsed_result.get('company_Main_Market_Segment__cf'),
                          'panW_Integration_Product__cf': parsed_result.get('panW_Integration_Product__cf'),
                          'account_Integration_Status__cf': parsed_result.get('account_Integration_Status__cf'),
                          'accountTimeline': parsed_result.get('if_there_is_a_timeline_to_complete_the_integration_please_enter'
                                                               '_the_date__cf')
                          }
    else:
        context_result = {'name': parsed_result.get('name'), 'id': parsed_result.get('id'),
                          'link': parsed_result.get('recordLink'),
                          'tech_BD_Assigned_for_XSOAR__cf': parsed_result.get('tech_BD_Assigned_for_XSOAR__cf')}
    readable_list = {'name': parsed_result.get('name'), 'ID': parsed_result.get('id'), 'link': parsed_result.get('recordLink'),
                     'PST Engineer': parsed_result.get('tech_BD_Assigned_for_XSOAR__cf')}
    readable_output = tableToMarkdown('Account Details', readable_list,
                                      ['name', 'ID', 'link', 'PST Engineer'],
                                      headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix='Impartner.Account',
        readable_output=readable_output,
        outputs_key_field='id',
        outputs=context_result,
    )


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    api_key = demisto.params().get('credentials', {}).get('password')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api/objects/v1/')
    verify_certificate = not demisto.params().get('insecure', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            api_key=api_key,
            verify=verify_certificate)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'impartner-get-account-list':
            return_results(impartner_get_account_list_command(client, demisto.args()))
        elif demisto.command() == 'impartner-get-account-id':
            return_results(impartner_get_account_id_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

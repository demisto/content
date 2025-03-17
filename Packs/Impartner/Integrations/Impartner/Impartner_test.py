import json
import pytest


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_list_command(mocker):
    """
        Scenario: executing command impartner-get-account-list.

        Given:
        - client and no specific parameters

        When:
        - Calling command impartner-get-account-list

        Then:
        - return the relevant results
    """
    from Impartner import Client, impartner_get_account_list_command

    client = Client(base_url='some_mock_url', verify=False)
    args = {'all_fields': 'FALSE'}
    api_response = util_load_json('test_data/list_command_response.json')
    mocker.patch('Impartner.Client.get_accounts_list', return_value=api_response)
    response = impartner_get_account_list_command(client, args)

    assert response.outputs == api_response.get('data')


@pytest.mark.parametrize(
    "args, res",
    [
        ({'id': '1111', 'all_fields': 'TRUE'}, {'id': 11111111, 'isActive': True, 'tech_BD_Assigned_for_XSOAR__cf': 'Edi',
                                                'mailingCity': 'Palo Alto', 'mailingCountry': 'United States',
                                                'mailingPostalCode': '11111', 'mailingState': 'California',
                                                'mailingStreet': '236 test Ave', 'name': 'test_account',
                                                'recordLink': 'https://prod.impartner.live/load/ACT/11111111',
                                                'website': 'https://www.test-account.ai/', 'mainProductToIntegrate': 'test',
                                                'mutualCustomer': 'test', 'tpA_Product_s__cf': 'test',
                                                'integration_Status__cf': 'Integration Approved',
                                                'target_customers__cf': ['Large Enterprise', 'SMB', 'SME'],
                                                'company_Main_Market_Segment__cf': ['Automation Orchestration & SOC tools',
                                                                                    'Data Security Governance & Classification'],
                                                'panW_Integration_Product__cf': ['test'],
                                                'account_Integration_Status__cf': ['Integrations in Process'],
                                                'accountTimeline': '2022-06-30T00:00:00'}),
        ({'id': '1111', 'all_fields': 'FALSE'}, {'tech_BD_Assigned_for_XSOAR__cf': 'Edi', 'id': 11111111,
                                                 'link': 'https://prod.impartner.live/load/ACT/11111111', 'name': 'test_account'})
    ]
)
def test_id_command(mocker, args, res):
    """
        Scenario: executing command impartner-get-account-id.

        Given:
        - client and the id

        When:
        - Calling command impartner-get-account-id

        Then:
        - return the relevant results
    """
    from Impartner import Client, impartner_get_account_id_command

    client = Client(base_url='some_mock_url', verify=False)
    api_response = util_load_json('test_data/id_command_response.json')
    mocker.patch('Impartner.Client.get_accounts_id', return_value=api_response)
    response = impartner_get_account_id_command(client, args)

    assert response.outputs == res

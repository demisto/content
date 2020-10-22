from Anomali_Enterprise import *


def test_domain_command(mocker):
    """
    Given:
        - a domain

    When:
        - mocking the server response, running domain_command

    Then:
        - validating whether the domain is malicious
        - validating the returned context data

    """
    client = Client(server_url='test', username='test', password='1234', verify=True, proxy=False)
    return_data = {'data': {'test.com': {'malware_family': '', 'probability': 0}}, 'result': 'success'}
    mocker.patch.object(client, 'domain_request', return_value=return_data)
    command_results = domain_command(client, args={'domain': 'test.com'})
    output = command_results.to_context().get('EntryContext', {})
    dbot_key = 'DBotScore(val.Indicator && val.Indicator == obj.Indicator &&' \
               ' val.Vendor == obj.Vendor && val.Type == obj.Type)'
    expected_result = {'Domain': [{'Name': 'test.com'}],
                       'DBotScore': [
                           {'Indicator': 'test.com',
                            'Type': 'domain',
                            'Vendor': 'Anomali Enterprise',
                            'Score': 0}
                       ]
                       }
    assert output.get('Domain(val.Name && val.Name == obj.Name)', []) == expected_result.get('Domain')
    assert output.get(dbot_key, []) == expected_result.get('DBotScore')

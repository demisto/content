from Anomali_Enterprise import *


def test_domain_command_benign(mocker):
    """
    Given:
        - a domain

    When:
        - mocking the server response for a benign domain, running domain_command

    Then:
        - validating the domain is unknown
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


def test_domain_command_malicious(mocker):
    """
    Given:
        - a domain

    When:
        - mocking the server response for a malicious domain, running domain_command

    Then:
        - validating the domain is unknown
        - validating the returned context data

    """
    client = Client(server_url='test', username='test', password='1234', verify=True, proxy=False)
    return_data = {'data': {'malicious.com': {'malware_family': 'my_malware', 'probability': 0.9}}, 'result': 'success'}
    mocker.patch.object(client, 'domain_request', return_value=return_data)
    command_results = domain_command(client, args={'domain': 'malicious.com'})
    output = command_results.to_context().get('EntryContext', {})
    dbot_key = 'DBotScore(val.Indicator && val.Indicator == obj.Indicator &&' \
               ' val.Vendor == obj.Vendor && val.Type == obj.Type)'
    expected_result = {
        'Domain': [
            {'Malicious': {'Description': 'my_malware', 'Vendor': 'Anomali Enterprise'},
             'Name': 'malicious.com'}
        ],
        'DBotScore': [
            {
                'Indicator': 'malicious.com',
                'Type': 'domain',
                'Vendor': 'Anomali Enterprise',
                'Score': 3
            }
        ]
    }

    assert output.get('Domain(val.Name && val.Name == obj.Name)', []) == expected_result.get('Domain')
    assert output.get(dbot_key, []) == expected_result.get('DBotScore')

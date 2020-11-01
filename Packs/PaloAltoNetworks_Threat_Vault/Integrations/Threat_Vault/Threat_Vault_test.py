from Threat_Vault import *


def test_dns_get_by_id(mocker):
    """
    Given:
        - a dns signature ID
    When:
        - mocking the server response for an ID, running dns_get_by_id
    Then:
        - validating the returned context data
    """
    client = Client(api_key='XXXXXXXX-XXX-XXXX-XXXX-XXXXXXXX', verify=True, proxy=False)
    return_data = {
        'signatureId': 325235352, 'signatureName': 'generic:accounts.google.com.sign-google.com',
        'domainName': 'accounts.google.com.sign-google.com', 'createTime': '2020-01-15 23:57:54 (UTC)',
        'category': 'malware', 'active': True,
        'release': {
            'wildfire': {'latestReleaseVersion': 0, 'firstReleaseVersion': 0},
            'antivirus': {'latestReleaseVersion': 0, 'firstReleaseVersion': 0}
        }
    }
    print('gdfsbfd')
    mocker.patch.object(client, 'dns_signature_get_request', return_value=return_data)
    command_results = dns_signature_get(client, args={'domain': 'test.com'})
    output = command_results.to_context()
    print(str(output))
    # assert output.get('Domain(val.Name && val.Name == obj.Name)', []) == expected_result.get('Domain')
    # assert output.get(dbot_key, []) == expected_result.get('DBotScore')

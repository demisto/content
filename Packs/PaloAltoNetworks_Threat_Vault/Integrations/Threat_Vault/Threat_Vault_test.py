from Threat_Vault import Client, dns_get_by_id, antispyware_get_by_id


def test_dns_get_by_id(mocker):
    """
    Given:
        - a dns signature ID
    When:
        - mocking the server response for an ID, running dns_get_by_id
    Then:
        - validating the returned context data
    """
    client = Client(api_key='XXXXXXXX-XXX-XXXX-XXXX-XXXXXXXXXXXX', verify=True, proxy=False)
    return_data = {
        'signatureId': 325235352, 'signatureName': 'generic:accounts.google.com.sign-google.com',
        'domainName': 'accounts.google.com.sign-google.com', 'createTime': '2020-01-15 23:57:54 (UTC)',
        'category': 'malware', 'active': True,
        'release': {
            'wildfire': {'latestReleaseVersion': 0, 'firstReleaseVersion': 0},
            'antivirus': {'latestReleaseVersion': 0, 'firstReleaseVersion': 0}
        }
    }
    mocker.patch.object(client, 'dns_signature_get_request', return_value=return_data)
    command_results = dns_get_by_id(client, args={'dns_signature_id': '325235352'})
    print(str(command_results))
    output = command_results.to_context()
    print(str(output))
    # assert output.get('Domain(val.Name && val.Name == obj.Name)', []) == expected_result.get('Domain')
    # assert output.get(dbot_key, []) == expected_result.get('DBotScore')


def test_antispyware_get_by_id(mocker):
    """
    Given:
        - a anti spyware signature ID
    When:
        - mocking the server response for an ID, running antispyware_get_by_id
    Then:
        - validating the returned context data
    """
    client = Client(api_key='XXXXXXXX-XXX-XXXX-XXXX-XXXXXXXXXXXX', verify=True, proxy=False)
    return_data = {
        'metadata': {
            'severity': 'medium',
            'reference': 'http://www.microsoft.com/security/portal/Threat/Encyclopedia/Entry.aspx?Name=Win32/Autorun,'
                         'http://blogs.technet.com/b/mmpc/archive/2011/02/08/breaking-up-the-romance-between-malware-'
                         'and-autorun.aspx,http://nakedsecurity.sophos.com/2011/06/15/usb-autorun-malware-on-the-wane/',
            'panOsMaximumVersion': '',
            'description': 'This signature detects a variety of user-agents in HTTP request headers that have been'
                           ' known to be used by the Autorun family of malicious software, and not known to be used by'
                           ' legitimate clients. The request header should be inspected to investigate the suspect'
                           ' user-agent. If the user-agent is atypical or unexpected, the endpoint should be inspected'
                           ' to determine the user-agent used to generate the request on the machine'
                           ' (typically malware).',
            'panOsMinimumVersion': '6.1.0', 'action': 'alert', 'category': 'spyware', 'changeData': ''
        },
        'cve': '', 'signatureName': 'Autorun User-Agent Traffic', 'vendor': '', 'signatureType': 'spyware',
        'firstReleaseTime': '2011-05-23 UTC', 'signatureId': 10001, 'latestReleaseTime': '2020-10-30 UTC',
        'latestReleaseVersion': 8338, 'status': 'released', 'firstReleaseVersion': 248
    }
    mocker.patch.object(client, 'antispyware_get_by_id_request', return_value=return_data)
    command_results = antispyware_get_by_id(client, args={'signature_id': '10001'})
    output = command_results.to_context()
    print(str(output))
    # assert output.get('Domain(val.Name && val.Name == obj.Name)', []) == expected_result.get('Domain')
    # assert output.get(dbot_key, []) == expected_result.get('DBotScore')

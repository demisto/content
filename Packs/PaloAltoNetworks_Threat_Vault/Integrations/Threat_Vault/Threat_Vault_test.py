import pytest
from Threat_Vault import Client, antivirus_signature_get, file_command, dns_get_by_id, antispyware_get_by_id, \
    ip_geo_get, ip_command, antispyware_signature_search, signature_search_results


def test_antivirus_get_by_id(mocker):
    """
    https://docs.paloaltonetworks.com/autofocus/autofocus-api/perform-direct-searches/get-antivirus-signature.html
    Given:
        - an antivirus signature ID
    When:
        - mocking the server response for an ID, running antivirus_signature_get
    Then:
        - validating the returned context data
    """
    client = Client(api_key='XXXXXXXX-XXX-XXXX-XXXX-XXXXXXXXXXXX', verify=True, proxy=False)
    return_data = {
        "active": True,
        "createTime": "2010-10-01 10:28:57 (UTC)",
        "release": {
            "antivirus": {
                "firstReleaseTime": "2010-10-03 15:04:58 UTC",
                "firstReleaseVersion": 334,
                "latestReleaseVersion": 0
            },
            "wildfire": {
                "firstReleaseVersion": 0,
                "latestReleaseVersion": 0
            }
        },
        "sha256": [
            "7a520be9db919a09d8ccd9b78c11885a6e97bc9cc87414558254cef3081dccf8",
            "9e12c5cdb069f74487c11758e732d72047b72bedf4373aa9e3a58e8e158380f8"
        ],
        "signatureId": 93534285,
        "signatureName": "Worm/Win32.autorun.crck"
    }
    mocker.patch.object(client, 'antivirus_signature_get_request', return_value=return_data)
    command_results = antivirus_signature_get(client, args={'signature_id': '93534285'})
    output = command_results.to_context()
    expected_result = {
        'ThreatVault.Antivirus(val.signatureId == obj.signatureId)':
            {
                "active": True,
                "createTime": "2010-10-01 10:28:57 (UTC)",
                "release": {
                    "antivirus": {
                        "firstReleaseTime": "2010-10-03 15:04:58 UTC",
                        "firstReleaseVersion": 334,
                        "latestReleaseVersion": 0
                    },
                    "wildfire": {
                        "firstReleaseVersion": 0,
                        "latestReleaseVersion": 0
                    }
                },
                "sha256": [
                    "7a520be9db919a09d8ccd9b78c11885a6e97bc9cc87414558254cef3081dccf8",
                    "9e12c5cdb069f74487c11758e732d72047b72bedf4373aa9e3a58e8e158380f8"
                ],
                "signatureId": 93534285,
                "signatureName": "Worm/Win32.autorun.crck"
            }
    }

    assert output.get('EntryContext') == expected_result


def test_antivirus_get_by_id_no_ids():
    """
    https://docs.paloaltonetworks.com/autofocus/autofocus-api/perform-direct-searches/get-antivirus-signature.html
    Given:
        - no args
    When:
        - running antivirus_signature_get
    Then:
        - validating the raised error
    """
    client = Client(api_key='XXXXXXXX-XXX-XXXX-XXXX-XXXXXXXXXXXX', verify=True, proxy=False)

    with pytest.raises(Exception, match="Please submit a sha256 or a signature_id."):
        antivirus_signature_get(client, args={})


def test_file_command(mocker):
    """
    Given:
        - sha256 representing an antivirus
    When:
        - running file_command command
    Then
        - Validate the reputation of the sha256 is malicious.
    """
    client = Client(api_key='XXXXXXXX-XXX-XXXX-XXXX-XXXXXXXXXXXX', verify=True, proxy=False)
    return_data = {
        "active": True,
        "createTime": "2010-10-01 10:28:57 (UTC)",
        "release": {
            "antivirus": {
                "firstReleaseTime": "2010-10-03 15:04:58 UTC",
                "firstReleaseVersion": 334,
                "latestReleaseVersion": 0
            },
            "wildfire": {
                "firstReleaseVersion": 0,
                "latestReleaseVersion": 0
            }
        },
        "sha256": [
            "7a520be9db919a09d8ccd9b78c11885a6e97bc9cc87414558254cef3081dccf8",
            "9e12c5cdb069f74487c11758e732d72047b72bedf4373aa9e3a58e8e158380f8"
        ],
        "signatureId": 93534285,
        "signatureName": "Worm/Win32.autorun.crck"
    }
    mocker.patch.object(client, 'antivirus_signature_get_request', return_value=return_data)
    command_results_list = file_command(
        client, args={'file': '7a520be9db919a09d8ccd9b78c11885a6e97bc9cc87414558254cef3081dccf8'})

    assert command_results_list[0].indicator.dbot_score.score == 3


def test_dns_get_by_id(mocker):
    """
    https://docs.paloaltonetworks.com/autofocus/autofocus-api/perform-direct-searches/get-anti-spyware-signature.html
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
    output = command_results.to_context()
    expected_result = {
        'ThreatVault.DNS(val.signatureId == obj.signatureId)':
            {
                'signatureId': 325235352, 'signatureName': 'generic:accounts.google.com.sign-google.com',
                'domainName': 'accounts.google.com.sign-google.com', 'createTime': '2020-01-15 23:57:54 (UTC)',
                'category': 'malware', 'active': True,
                'release': {
                    'wildfire': {'latestReleaseVersion': 0, 'firstReleaseVersion': 0},
                    'antivirus': {'latestReleaseVersion': 0, 'firstReleaseVersion': 0}
                }
            }
    }

    assert output.get('EntryContext') == expected_result


def test_antispyware_get_by_id(mocker):
    """
    https://docs.paloaltonetworks.com/autofocus/autofocus-api/perform-direct-searches/get-vulnerability-signature.html
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
    expected_result = {
        'ThreatVault.AntiSpyware(val.signatureId == obj.signatureId)':
            {
                'metadata':
                    {
                        'severity': 'medium',
                        'reference': 'http://www.microsoft.com/security/portal/Threat/Encyclopedia/Entry.aspx?Name='
                                     'Win32/Autorun,http://blogs.technet.com/b/mmpc/archive/2011/02/08/breaking-up-'
                                     'the-romance-between-malware-and-autorun.aspx,http://nakedsecurity.sophos.com/'
                                     '2011/06/15/usb-autorun-malware-on-the-wane/', 'panOsMaximumVersion': '',
                        'description': 'This signature detects a variety of user-agents in HTTP request headers that'
                                       ' have been known to be used by the Autorun family of malicious software, and'
                                       ' not known to be used by legitimate clients. The request header should be'
                                       ' inspected to investigate the suspect user-agent. If the user-agent is atypical'
                                       ' or unexpected, the endpoint should be inspected to determine the user-agent'
                                       ' used to generate the request on the machine (typically malware).',
                        'panOsMinimumVersion': '6.1.0', 'action': 'alert', 'category': 'spyware', 'changeData': ''
                    },
                'cve': '', 'signatureName': 'Autorun User-Agent Traffic', 'vendor': '', 'signatureType': 'spyware',
                'firstReleaseTime': '2011-05-23 UTC', 'signatureId': 10001, 'latestReleaseTime': '2020-10-30 UTC',
                'latestReleaseVersion': 8338, 'status': 'released', 'firstReleaseVersion': 248
            }
    }

    assert output.get('EntryContext') == expected_result


def test_ip_geo_get(mocker):
    """
    https://docs.paloaltonetworks.com/autofocus/autofocus-api/perform-direct-searches/get-geolocation.html
    Given:
        - an ip
    When:
        - mocking the server response for an IP, running ip_geo_get
    Then:
        - validating the returned context data
    """
    client = Client(api_key='XXXXXXXX-XXX-XXXX-XXXX-XXXXXXXXXXXX', verify=True, proxy=False)
    return_data = {'ipAddress': '1.1.1.1', 'countryCode': 'AU', 'countryName': 'Australia'}
    mocker.patch.object(client, 'ip_geo_get_request', return_value=return_data)
    command_results = ip_geo_get(client, args={'ip': '1.1.1.1'})
    output = command_results.to_context()
    expected_result = {
        'ThreatVault.IP(val.ipAddress == obj.ipAddress)':
            {
                'ipAddress': '1.1.1.1', 'countryCode': 'AU', 'countryName': 'Australia'
            }
    }

    assert output.get('EntryContext') == expected_result


def test_ip_command(mocker):
    """
    https://docs.paloaltonetworks.com/autofocus/autofocus-api/perform-direct-searches/get-geolocation.html
    Given:
        - an ip
    When:
        - mocking the server response for an IP, running ip_command
    Then:
        - validating the generated indicator dbot score
        - validating the generated indicator country
    """
    client = Client(api_key='XXXXXXXX-XXX-XXXX-XXXX-XXXXXXXXXXXX', verify=True, proxy=False)
    return_data = {'ipAddress': '8.8.8.8', 'countryCode': 'US', 'countryName': 'United States'}
    mocker.patch.object(client, 'ip_geo_get_request', return_value=return_data)
    command_results_list = ip_command(client, args={'ip': '8.8.8.8'})

    assert command_results_list[0].indicator.dbot_score.score == 0
    assert command_results_list[0].indicator.geo_country == 'United States'


def test_antispyware_signature_search_wrongful_arguments():
    """
    Given:
        - wrongful args to the antispyware_signature_search command
    When:
        - running antispyware_signature_search
    Then:
        - validating the raised error
    """
    client = Client(api_key='XXXXXXXX-XXX-XXXX-XXXX-XXXXXXXXXXXX', verify=True, proxy=False)
    wrong_args_err = 'Please provide either a signature_name or a cve or a vendor.'

    with pytest.raises(Exception, match=wrong_args_err):
        antispyware_signature_search(client, args={'signature_name': '1234', 'cve': 'CVE-2020'})
    with pytest.raises(Exception, match=wrong_args_err):
        antispyware_signature_search(client, args={'signature_name': '1234', 'vendor': 'panw'})
    with pytest.raises(Exception, match=wrong_args_err):
        antispyware_signature_search(client, args={'vendor': 'panw', 'cve': 'CVE-2020'})


def test_signature_search_results_dns(mocker):
    """
    https://docs.paloaltonetworks.com/autofocus/autofocus-api/perform-autofocus-searches/search-signatures.html
    Given:
        - a search_request_id
    When:
        - mocking the server response for a search_request_id of a domainName, running signature_search_results
    Then:
        - validating the returned context data
        - validating the returned human readable
    """
    client = Client(api_key='XXXXXXXX-XXX-XXXX-XXXX-XXXXXXXXXXXX', verify=True, proxy=False)
    return_data = {
        "page_count": 1,
        "signatures": [
            {
                "active": True,
                "category": "malware",
                "createTime": "2015-03-03 14:45:03 (UTC)",
                "domainName": "mail-google.com.co",
                "release": {
                    "antivirus": {
                        "firstReleaseTime": "2015-03-03 15:11:53 UTC",
                        "firstReleaseVersion": 1890,
                        "latestReleaseVersion": 0
                    },
                    "wildfire": {
                        "firstReleaseVersion": 0,
                        "latestReleaseVersion": 0
                    }
                },
                "signatureId": 44101494,
                "signatureName": "generic:mail-google.com.co"
            }
        ],
        "total_count": 5306
    }
    mocker.patch.object(client, 'signature_search_results_request', return_value=return_data)
    command_results = signature_search_results(client, args={'search_request_id': 'mock_domain', 'size': '1'})
    output = command_results.to_context()
    expected_context = {
        'ThreatVault.Search(val.search_request_id == obj.search_request_id)':
            {
                "page_count": 1,
                "signatures": [
                    {
                        "active": True,
                        "category": "malware",
                        "createTime": "2015-03-03 14:45:03 (UTC)",
                        "domainName": "mail-google.com.co",
                        "release": {
                            "antivirus": {
                                "firstReleaseTime": "2015-03-03 15:11:53 UTC",
                                "firstReleaseVersion": 1890,
                                "latestReleaseVersion": 0
                            },
                            "wildfire": {
                                "firstReleaseVersion": 0,
                                "latestReleaseVersion": 0
                            }
                        },
                        "signatureId": 44101494,
                        "signatureName": "generic:mail-google.com.co"
                    }
                ],
                "total_count": 5306,
                'search_request_id': 'mock_domain',
                'status': 'completed'
            }
    }
    expected_hr = '### Signature search are showing 1 of 5306 results:\n|signatureId|signatureName|domainName|' \
                  'category|\n|---|---|---|---|\n| 44101494 | generic:mail-google.com.co | mail-google.com.co |' \
                  ' malware |\n'

    assert output.get('EntryContext') == expected_context
    assert output.get('HumanReadable') == expected_hr


def test_signature_search_results_anti_spyware_cve(mocker):
    """
    https://docs.paloaltonetworks.com/autofocus/autofocus-api/perform-autofocus-searches/search-signatures.html
    Given:
        - a search_request_id
    When:
        - mocking the server response for a search_request_id of a cve, running signature_search_results
    Then:
        - validating the returned context data
        - validating the returned human readable
    """
    client = Client(api_key='XXXXXXXX-XXX-XXXX-XXXX-XXXXXXXXXXXX', verify=True, proxy=False)
    return_data = {
        "page_count": 1,
        "signatures": [
            {
                "cve": "CVE-2015-8650",
                "firstReleaseTime": "2015-12-28 UTC",
                "firstReleaseVersion": 548,
                "latestReleaseTime": "2020-10-30 UTC",
                "latestReleaseVersion": 8338,
                "metadata": {
                    "action": "reset-both",
                    "category": "code-execution",
                    "changeData": "",
                    "description": "Adobe Flash Player is prone to an use after free vulnerability while parsing"
                                   " certain crafted SWF files. The vulnerability is due to the lack of proper checks"
                                   " on SWF file, leading to an use after free vulnerability. An attacker could"
                                   " exploit the vulnerability by sending a crafted SWF file. A successful attack"
                                   " could lead to remote code execution with the privileges of the current"
                                   " logged-in user.",
                    "panOsMaximumVersion": "",
                    "panOsMinimumVersion": "7.1.0",
                    "reference": "https://helpx.adobe.com/security/products/flash-player/apsb16-01.html",
                    "severity": "high"
                },
                "signatureId": 38692,
                "signatureName": "Adobe Flash Player Use After Free Vulnerability",
                "signatureType": "vulnerability",
                "status": "released",
                "vendor": "APSB16-01"
            }
        ],
        "status": "completed",
        "total_count": 1
    }
    mocker.patch.object(client, 'signature_search_results_request', return_value=return_data)
    command_results = signature_search_results(client, args={'search_request_id': 'mock_cve', 'size': '1'})
    output = command_results.to_context()
    expected_context = {
        'ThreatVault.Search(val.search_request_id == obj.search_request_id)':
            {
                "page_count": 1,
                "search_request_id": "mock_cve",
                "signatures": [
                    {
                        "cve": "CVE-2015-8650",
                        "firstReleaseTime": "2015-12-28 UTC",
                        "firstReleaseVersion": 548,
                        "latestReleaseTime": "2020-10-30 UTC",
                        "latestReleaseVersion": 8338,
                        "metadata": {
                            "action": "reset-both",
                            "category": "code-execution",
                            "changeData": "",
                            "description": "Adobe Flash Player is prone to an use after free vulnerability while"
                                           " parsing certain crafted SWF files. The vulnerability is due to the lack"
                                           " of proper checks on SWF file, leading to an use after free vulnerability."
                                           " An attacker could exploit the vulnerability by sending a crafted SWF file."
                                           " A successful attack could lead to remote code execution with the"
                                           " privileges of the current logged-in user.",
                            "panOsMaximumVersion": "",
                            "panOsMinimumVersion": "7.1.0",
                            "reference": "https://helpx.adobe.com/security/products/flash-player/apsb16-01.html",
                            "severity": "high"
                        },
                        "signatureId": 38692,
                        "signatureName": "Adobe Flash Player Use After Free Vulnerability",
                        "signatureType": "vulnerability",
                        "status": "released",
                        "vendor": "APSB16-01"
                    }
                ],
                "status": "completed",
                "total_count": 1,
            }
    }
    expected_hr = '### Signature search are showing 1 of 1 results:\n|signatureId|signatureName|cve|' \
                  'signatureType|status|firstReleaseTime|latestReleaseTime|\n|---|---|---|---|---|---|---|\n|' \
                  ' 38692 | Adobe Flash Player Use After Free Vulnerability | CVE-2015-8650 |' \
                  ' vulnerability | released | 2015-12-28 UTC | 2020-10-30 UTC |\n'

    assert output.get('EntryContext') == expected_context
    assert output.get('HumanReadable') == expected_hr

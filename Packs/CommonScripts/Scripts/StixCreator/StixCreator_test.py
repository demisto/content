import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import pytest
from StixCreator import main, guess_indicator_type, create_sco_stix_uuid, create_sdo_stix_uuid, \
    add_file_fields_to_indicator, create_stix_sco_indicator

FILE_INDICATOR = \
    {
        'indicators':
            {
                '0': {'expirationStatus': 'active', 'firstSeen': '2022-07-31T13:26:05Z',
                      'indicator_type': 'File',
                      'lastSeen': '2022-07-31T13:26:05Z', 'score': 'good',
                      'timestamp': '2022-07-31T13:26:05Z',
                      'value': 'e14daa9c88a7ec91d770ae262758db73b6593b178527a2d7bba14159fad5f1c2'
                      }
            }
    }

MALWARE_INDICATOR = \
    {
        'indicators':
            {
                '0': {'expirationStatus': 'active', 'firstSeen': '2022-07-31T13:26:05Z',
                      'indicator_type': 'Malware',
                      'lastSeen': '2022-07-31T13:26:05Z', 'score': 'bad',
                      'timestamp': '2022-07-31T13:26:05Z',
                      'value': 'Bad Malware',
                      'ismalwarefamily': 'True',
                      }
            }
    }

ATTACK_PATTERN_INDICATOR = \
    {
        'indicators':
            {
                '0': {'expirationStatus': 'active', 'firstSeen': '2022-07-31T13:26:05Z',
                      'indicator_type': 'Attack Pattern',
                      'lastSeen': '2022-07-31T13:26:05Z', 'score': 'unknown',
                      'timestamp': '2022-07-31T13:26:05Z',
                      'value': 'Attack Pattern',
                      'mitreid': 'T1111',
                      }
            }
    }

DOMAIN_INDICATORS = \
    {
        'indicators':
            {
                '0': {'expirationStatus': 'active', 'firstSeen': '2022-07-31T13:24:44Z',
                      'indicator_type': 'CVE',
                      'lastSeen': '2022-07-31T13:24:44Z', 'score': 'Unknown',
                      'timestamp': '2022-07-31T13:24:44Z',
                      'value': 'test.com'
                      },
                '1': {'expirationStatus': 'active', 'firstSeen': '2022-07-31T13:24:40Z',
                      'indicator_type': 'Attack Pattern',
                      'lastSeen': '2022-07-31T13:24:40Z', 'score': 'suspicious',
                      'timestamp': '2022-07-31T13:24:40Z',
                      'value': 'bad.com'
                      }
            }
    }

IP_INDICATOR_SCO = {  # checking the new logic
    "indicators": {
        "0": {
            "expirationStatus": "active",
            "firstSeen": "2023-04-18T12:17:38+03:00",
            "indicator_type": "IP",
            "lastSeen": "2023-04-18T12:17:38+03:00",
            "score": "Unknown",
            "timestamp": "2023-04-18T12:17:38+03:00",
            "value": "8.8.8.8",
        }
    },
    "sco_flag": "true",
}

IP_INDICATOR_SDO = {  # checking bc
    "indicators": {
        "0": {
            "expirationStatus": "active",
            "firstSeen": "2023-04-18T12:17:38+03:00",
            "indicator_type": "IP",
            "lastSeen": "2023-04-18T12:17:38+03:00",
            "score": "Unknown",
            "timestamp": "2023-04-18T12:17:38+03:00",
            "value": "8.8.8.8",
        }
    },
    "sco_flag": "false",
}


@pytest.mark.parametrize('indicators, stix_type', [(DOMAIN_INDICATORS, 'bundle'),
                                                   (FILE_INDICATOR, 'indicator'),
                                                   (MALWARE_INDICATOR, 'malware'),
                                                   (ATTACK_PATTERN_INDICATOR, 'attack-pattern'),
                                                   (IP_INDICATOR_SCO, 'ipv4-addr'),
                                                   (IP_INDICATOR_SDO, 'indicator')])
def test_stixCreator_with_indicators(mocker, indicators, stix_type):
    mocker.patch.object(demisto, 'args', return_value=indicators)
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0]
    assert stix_type in results[0]['Contents']


@pytest.mark.parametrize('k,v,exp', (
    ('actually-ip', '', 'ip'),  # key detection
    ('', '1.1.1.1', 'ip'),      # val detection (further tested in CSP_test.py)
    ('sha1sh', '', 'sha1'),     # key detection
    ('test', 't', 'test'),      # no detection
))
def test_guess_indicator_type(k, v, exp):
    a = guess_indicator_type(k, v)
    assert a == exp


xsoar_indicator_1 = {'expirationStatus': 'active',
                     'firstSeen': '2023-04-19T17:43:07+03:00',
                     'indicator_type': 'Account',
                     'lastSeen': '2023-04-19T17:43:07+03:00',
                     'score': 'Unknown',
                     'timestamp': '2023-04-19T17:43:07+03:00',
                     'value': 'test@test.com'}
stix_type_1 = "user-account"
value_1 = 'test@test.com'
expected_stix_id_1 = "user-account--783b9e67-d7b0-58f3-b566-58ac7881a3bc"

xsoar_indicator_2 = {'expirationStatus': 'active',
                     'firstSeen': '2023-04-20T10:20:04+03:00',
                     'indicator_type': 'File',
                     'lastSeen': '2023-04-20T10:20:04+03:00',
                     'score': 'Unknown', 'sourceBrands': 'VirusTotal',
                     'sourceInstances': 'VirusTotal',
                     'timestamp': '2023-04-20T10:20:04+03:00',
                     'value': '701393b3b8e6ae6e70effcda7598a8cf92d0adb1aaeb5aa91c73004519644801'}
stix_type_2 = "file"
value_2 = '701393b3b8e6ae6e70effcda7598a8cf92d0adb1aaeb5aa91c73004519644801'
expected_stix_id_2 = "file--3e26aab3-dfc3-57c5-8fe2-45cfde8fe7c8"

xsoar_indicator_3 = {'expirationStatus': 'active',
                     'firstSeen': '2023-04-18T12:17:38+03:00',
                     'indicator_type': 'IP',
                     'lastSeen': '2023-04-18T12:17:38+03:00',
                     'score': 'Unknown',
                     'timestamp': '2023-04-18T12:17:38+03:00',
                     'value': '8.8.8.8'}
stix_type_3 = "ipv4-addr"
value_3 = '8.8.8.8'
expected_stix_id_3 = "ipv4-addr--2f689bf9-0ff2-545f-aa61-e495eb8cecc7"

test_test_create_sco_stix_uuid_params = [(xsoar_indicator_1, stix_type_1, value_1, expected_stix_id_1),
                                         (xsoar_indicator_2, stix_type_2, value_2, expected_stix_id_2),
                                         (xsoar_indicator_3, stix_type_3, value_3, expected_stix_id_3)]


@pytest.mark.parametrize('xsoar_indicator, stix_type, value, expected_stix_id', test_test_create_sco_stix_uuid_params)
def test_create_sco_stix_uuid(xsoar_indicator, stix_type, value, expected_stix_id):
    """
    Given:
    - Case 1: A XSOAR indicator of type 'Account', with a stix type of 'user-account' and a value of 'test@test.com'.
    - Case 2: A XSOAR indicator of type 'File', with a stix type of 'file' and a value of
        '701393b3b8e6ae6e70effcda7598a8cf92d0adb1aaeb5aa91c73004519644801'.
    - Case 3: A XSOAR indicator of type 'IP', with a stix type of 'ipv4-addr' and a value of '8.8.8.8'.
    When:
        - Creating a SCO indicator and calling create_sco_stix_uuid.
    Then:
     - Case 1: Assert the ID looks like 'user-account--783b9e67-d7b0-58f3-b566-58ac7881a3bc'.
     - Case 2: Assert the ID looks like 'file--3e26aab3-dfc3-57c5-8fe2-45cfde8fe7c8'.
     - Case 3: Assert the ID looks like 'ipv4-addr--2f689bf9-0ff2-545f-aa61-e495eb8cecc7'.
    """
    stix_id = create_sco_stix_uuid(xsoar_indicator, stix_type, value)
    assert expected_stix_id == stix_id


sdo_xsoar_indicator_1 = {
    "expirationStatus": "active",
    "firstSeen": "2023-04-19T13:05:01+03:00",
    "indicator_type": "Attack Pattern",
    "lastSeen": "2023-04-19T13:05:01+03:00",
    "score": "Unknown",
    "timestamp": "2023-04-19T13:05:01+03:00",
    "value": "T111",
}
sdo_stix_type_1 = 'attack-pattern'
sdo_value_1 = 'T111'
sdo_expected_stix_id_1 = 'attack-pattern--116d410f-50f9-5f0d-b677-2a9b95812a3e'

sdo_xsoar_indicator_2 = {
    "expirationStatus": "active",
    "firstSeen": "2023-04-20T17:20:10+03:00",
    "indicator_type": "Malware",
    "lastSeen": "2023-04-20T17:20:10+03:00",
    "score": "Unknown",
    "timestamp": "2023-04-20T17:20:10+03:00",
    "value": "bad malware",
    "ismalwarefamily": "True",
}
sdo_stix_type_2 = 'malware'
sdo_value_2 = 'bad malware'
sdo_expected_stix_id_2 = 'malware--bddcf01f-9fd0-5107-a013-4b174285babc'

test_create_sdo_stix_uuid_params = [(sdo_xsoar_indicator_1, sdo_stix_type_1, sdo_value_1, sdo_expected_stix_id_1),
                                    (sdo_xsoar_indicator_2, sdo_stix_type_2, sdo_value_2, sdo_expected_stix_id_2)]


@pytest.mark.parametrize('xsoar_indicator, stix_type, value, expected_stix_id', test_create_sdo_stix_uuid_params)
def test_create_sdo_stix_uuid(xsoar_indicator, stix_type, value, expected_stix_id):
    """
    Given:
        - Case 1: A XSOAR indicator of type 'Attack Pattern', with a stix type of 'attack-pattern' and a value of 'T111'.
        - Case 2: A XSOAR indicator of type 'Malware', with a stix type of 'malware' and a value of 'bad malware'.
    When:
        - Creating a SDO indicator and calling create_sco_stix_uuid.
    Then:
     - Case 1: Assert the ID looks like 'attack-pattern--116d410f-50f9-5f0d-b677-2a9b95812a3e'.
     - Case 2: Assert the ID looks like 'malware--bddcf01f-9fd0-5107-a013-4b174285babc'.
    """
    stix_id = create_sdo_stix_uuid(xsoar_indicator, stix_type, value)
    assert expected_stix_id == stix_id


xsoar_indicator_file = {'expirationStatus': 'active',
                        'firstSeen': '2023-05-07T14:42:59Z',
                        'indicator_type': 'File',
                        'lastSeen': '2023-05-07T14:42:59Z',
                        'score': 'Unknown',
                        'sha1': '57218c316b6921e2cd61027a2387edc31a2d9471',
                        'sha256': 'f1945cd6c19e56b3c1c78943ef5ec18116907a4ca1efc40a57d48ab1db7adfc5',
                        'sha512': '37c783b80b1d458b89e712c2dfe2777050eff0aefc9f6d8beedee77807d9aeb2e27d14815cf4f0229'
                                  'b1d36c186bb5f2b5ef55e632b108cc41e9fb964c39b42a5',
                        'ssdeep': '3:g:g',
                        'timestamp': '2023-05-07T14:42:59Z'}


def test_add_file_fields_to_indicator():
    """
    Given:
        - A dictionary representing a xsoar indicator.
    When:
        - Creating a dictionary containing the file hashes.
    Then:
        - check the hashes dictionary
    """
    expected_hashes_dict = {'SHA-1': '57218c316b6921e2cd61027a2387edc31a2d9471',
                            'SHA-256': 'f1945cd6c19e56b3c1c78943ef5ec18116907a4ca1efc40a57d48ab1db7adfc5',
                            'SHA-512': '37c783b80b1d458b89e712c2dfe2777050eff0aefc9f6d8beedee77807d9aeb2e27d14815cf4f0'
                                       '229b1d36c186bb5f2b5ef55e632b108cc41e9fb964c39b42a5'}
    value = xsoar_indicator_file.get('value', '')
    result = add_file_fields_to_indicator(xsoar_indicator_file, value)
    assert expected_hashes_dict == result


xsoar_indicator_domain = {'expirationStatus': 'active',
                          'firstSeen': '2023-05-07T13:18:27Z',
                          'indicator_type': 'Domain',
                          'lastSeen': '2023-05-07T13:18:27Z',
                          'score': 'Unknown',
                          'timestamp': '2023-05-07T13:18:27Z',
                          'value': 'hello@test.com'}
xsoar_indicator_asn = {'expirationStatus': 'active',
                       'firstSeen': '2023-05-07T07:37:30Z',
                       'indicator_type': 'ASN',
                       'lastSeen': '2023-05-07T07:37:30Z',
                       'name': 'name',
                       'score': 'Unknown',
                       'timestamp': '2023-05-07T07:37:30Z'}

file_stix_id = 'file--a1b6bbfd-73cd-5fef-9e12-9453e3b74cc5'
domain_stix_id = 'domain-name--fdf407b4-c3d0-5011-a66c-5ef889593b08'
asn_stix_id = 'autonomous-system--937a0541-d893-5707-ad67-bcfe8398164e'

file_stix_type = 'file'
domain_stix_type = 'domain-name'
asn_stix_type = 'autonomous-system'

file_value = 'f1945cd6c19e56b3c1c78943ef5ec18116907a4ca1efc40a57d48ab1db7adfc5'
domain_value = 'hello@test.com'
asn_value = '54538'

expectes_stix_file_indicator = {'type': 'file',
                                'spec_version': '2.1',
                                'id': 'file--a1b6bbfd-73cd-5fef-9e12-9453e3b74cc5',
                                'hashes': {
                                    'SHA-1': '57218c316b6921e2cd61027a2387edc31a2d9471',
                                    'SHA-256': 'f1945cd6c19e56b3c1c78943ef5ec18116907a4ca1efc40a57d48ab1db7adfc5',
                                    'SHA-512': '37c783b80b1d458b89e712c2dfe2777050eff0aefc9f6d8beedee77807d9aeb2e27d14'
                                               '815cf4f0229b1d36c186bb5f2b5ef55e632b108cc41e9fb964c39b42a5'}}
expectes_stix_domain_indicator = {'type': 'domain-name',
                                  'spec_version': '2.1',
                                  'value': 'hello@test.com',
                                  'id': 'domain-name--fdf407b4-c3d0-5011-a66c-5ef889593b08'}
expectes_stix_asn_indicator = {'type': 'autonomous-system',
                               'spec_version': '2.1',
                               'id': 'autonomous-system--937a0541-d893-5707-ad67-bcfe8398164e',
                               'number': '54538',
                               'name': 'name'}
params_test_create_stix_sco_indicator = [(file_stix_id, file_stix_type, file_value, xsoar_indicator_file,
                                          expectes_stix_file_indicator),
                                         (domain_stix_id, domain_stix_type, domain_value, xsoar_indicator_domain,
                                          expectes_stix_domain_indicator),
                                         (asn_stix_id, asn_stix_type, asn_value, xsoar_indicator_asn,
                                          expectes_stix_asn_indicator)]


@pytest.mark.parametrize('stix_id, stix_type, value, xsoar_indicator, expectes_stix_indicator',
                         params_test_create_stix_sco_indicator)
def test_create_stix_sco_indicator(stix_id, stix_type, value, xsoar_indicator, expectes_stix_indicator):
    """
    Given:
        - Case 1: A XSOAR indicator of type 'File', with a stix id of 'file--a1b6bbfd-73cd-5fef-9e12-9453e3b74cc5',
            stix type of 'file' and a value of 'f1945cd6c19e56b3c1c78943ef5ec18116907a4ca1efc40a57d48ab1db7adfc5'.
        - Case 2: A XSOAR indicator of type 'Domain', with a stix id of
            'domain-name--fdf407b4-c3d0-5011-a66c-5ef889593b08', stix type of 'domain-name' and a value of
            'hello@test.com'.
        - Case 2: A XSOAR indicator of type 'ASN', with a stix id of
            'autonomous-system--937a0541-d893-5707-ad67-bcfe8398164e', stix type of 'autonomous-system' and a value of
            '54538'.
    When:
        - Creating a SCO indicator and calling create_stix_sco_indicator.
    Then:
         - Assert the indicator dictionary is as expected.
    """
    result = create_stix_sco_indicator(stix_id, stix_type, value, xsoar_indicator)
    assert result == expectes_stix_indicator

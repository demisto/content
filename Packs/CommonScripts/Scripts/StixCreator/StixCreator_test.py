import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import pytest
from StixCreator import main, guess_indicator_type, add_file_fields_to_indicator, create_stix_sco_indicator

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


@pytest.mark.parametrize('indicators, stix_type', [(DOMAIN_INDICATORS, 'bundle')])
def test_stixCreator_with_indicators_spec_version(mocker, indicators, stix_type):
    """
    Given:
        - A list of indicators.
    When:
        - Creating a bundle.
    Then:
         - Assert the spec_version is not empty.
    """
    mocker.patch.object(demisto, 'args', return_value=indicators)
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0]
    json_content = json.loads(results[0]['Contents'])
    assert "spec_version" in json_content
    assert json_content["spec_version"] == "2.1"
    assert stix_type in results[0]['Contents']

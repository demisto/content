import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import pytest
from StixCreator import main, guess_indicator_type

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

DOMAIN_INDICATORS = \
    {
        'indicators':
            {
                '0': {'expirationStatus': 'active', 'firstSeen': '2022-07-31T13:24:44Z',
                      'indicator_type': 'cve',
                      'lastSeen': '2022-07-31T13:24:44Z', 'score': 'Unknown',
                      'timestamp': '2022-07-31T13:24:44Z',
                      'value': 'test.com'
                      },
                '1': {'expirationStatus': 'active', 'firstSeen': '2022-07-31T13:24:40Z',
                      'indicator_type': 'attack pattern',
                      'lastSeen': '2022-07-31T13:24:40Z', 'score': 'suspicious',
                      'timestamp': '2022-07-31T13:24:40Z',
                      'value': 'bad.com'
                      }
            }
    }


@pytest.mark.parametrize('indicators, stix_type', [(DOMAIN_INDICATORS, 'bundle'), (FILE_INDICATOR, 'indicator')])
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

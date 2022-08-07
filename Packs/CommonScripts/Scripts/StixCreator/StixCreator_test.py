import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import pytest
from StixCreator import main
import json

from stix2 import Bundle, ExternalReference, Indicator, Vulnerability
from stix2 import AttackPattern, Campaign, Malware, Infrastructure, IntrusionSet, Report, ThreatActor
from stix2 import Tool, CourseOfAction
from typing import Any, Callable

INDICATORS = \
    [({'indicators':
           {'0': {'expirationStatus': 'active', 'firstSeen': '2022-07-31T13:24:44Z', 'indicator_type': 'Domain',
                  'lastSeen': '2022-07-31T13:24:44Z', 'score': 'Unknown', 'timestamp': '2022-07-31T13:24:44Z',
                  'value': 'test.com'},
            '1': {'expirationStatus': 'active', 'firstSeen': '2022-07-31T13:24:40Z', 'indicator_type': 'Domain',
                  'lastSeen': '2022-07-31T13:24:40Z', 'score': 'Unknown', 'timestamp': '2022-07-31T13:24:40Z',
                  'value': 'bad.com'}
            }
       }, 'bundle'),
     ({'indicators': {
         '0': {'expirationStatus': 'active', 'firstSeen': '2022-07-31T13:26:05Z', 'indicator_type': 'File',
               'lastSeen': '2022-07-31T13:26:05Z', 'score': 'Unknown', 'timestamp': '2022-07-31T13:26:05Z',
               'value': 'e14daa9c88a7ec91d770ae262758db73b6593b178527a2d7bba14159fad5f1c2'}
     }
      }, 'indicator'
     )]


@pytest.mark.parametrize('indicators, stix_type', INDICATORS)
def test_stixCreator(mocker, indicators, stix_type):
    mocker.patch.object(demisto, 'args', return_value=indicators)
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0]
    assert stix_type in results[0]['Contents']

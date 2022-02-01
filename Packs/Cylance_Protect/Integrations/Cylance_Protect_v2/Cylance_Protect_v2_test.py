import pytest

import CommonServerPython
import demistomock as demisto
from Cylance_Protect_v2 import create_dbot_score_entry, translate_score, FILE_THRESHOLD

THREAT_OUTPUT = {u'cylance_score': -1.0, u'name': u'SysMonitor.exe', u'classification': u'Malware', u'sub_classification': u'Virus', u'av_industry': None, u'unique_to_cylance': False, u'last_found': u'2019-01-28T23:36:58', u'global_quarantined': False, u'file_size': 2177386, u'safelisted': False, u'sha256': u'055D7A25DECF6769BF4FB2F3BC9FD3159C8B42972818177E44975929D97292DE', u'md5': u'B4EA38EB798EA1C1E067DFD176B882BB'}


def test_get_threats():
    """
    Given
        - demisto args
    When
        - calls the function get_threats
    Then
        - checks if 'EntryContext' in demisto.results is an array with entrues from type DBotScore
    """
    threat = THREAT_OUTPUT
    dbot_score = translate_score(threat['cylance_score'], FILE_THRESHOLD)
    dbot_score_entry = create_dbot_score_entry(THREAT_OUTPUT, dbot_score)
    assert type(dbot_score_entry) == CommonServerPython.Common.DBotScore

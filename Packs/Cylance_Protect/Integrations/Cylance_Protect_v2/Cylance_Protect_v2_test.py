import demistomock as demisto
from CommonServerPython import Common
from Cylance_Protect_v2 import create_dbot_score_entry, translate_score, FILE_THRESHOLD, load_server_url

THREAT_OUTPUT = {u'cylance_score': -1.0, u'name': u'SysMonitor.exe',
                 u'classification': u'Malware',
                 u'sub_classification': u'Virus',
                 u'av_industry': None,
                 u'unique_to_cylance': False,
                 u'last_found': u'2019-01-28T23:36:58',
                 u'global_quarantined': False,
                 u'file_size': 2177386,
                 u'safelisted': False,
                 u'sha256': u'055D7A25DECF6769BF4FB2F3BC9FD3159C8B42972818177E44975929D97292DE',
                 u'md5': u'B4EA38EB798EA1C1E067DFD176B882BB',
                 }


def test_create_dbot_score_entry():
    """
    Given
        - a threat and a dbot score
    When
        - calls the function create_dbot_score_entry
    Then
        - checks if dbot_score_entry is from type DBotScore

    """

    threat = THREAT_OUTPUT
    dbot_score = translate_score(threat['cylance_score'], FILE_THRESHOLD)
    dbot_score_entry = create_dbot_score_entry(THREAT_OUTPUT, dbot_score)
    assert isinstance(dbot_score_entry, Common.DBotScore)

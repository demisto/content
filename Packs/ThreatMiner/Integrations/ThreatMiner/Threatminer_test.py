import demistomock as demisto
from ThreatMiner import get_dbot_score_report
from CommonServerPython import DBotScoreReliability

DBOT_SCORES = {
    'Reliability': 'C - Fairly reliable',
    'Vendor': 'ThreatMiner',
    'Indicator': 'CA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB',
    'Score': 0,
    'Type': 'File'
}


def test_reliability_in_dbot(mocker):
    """
        Given:
            - The user reliability param
        When:
            - Running get_dbot_score_report
        Then:
            - Verify dbot_score outputs as excepted
    """
    mocker.patch.object(demisto, 'args', return_value={'threshold': '10'})

    dbot_score = get_dbot_score_report(0, 'CA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB', {},
                                       DBotScoreReliability.C)

    assert dbot_score == DBOT_SCORES

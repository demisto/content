import demistomock as demisto
from ThreatMiner import get_dbot_score_report
from CommonServerPython import DBotScoreReliability


def test_reliability_in_dbot(mocker):
    mocker.patch.object(demisto, 'args', return_value={'threshold': '10'})

    dbot = get_dbot_score_report(0, 'CA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB', {},
                                    DBotScoreReliability.C)

    assert dbot['Reliability'] == DBotScoreReliability.C

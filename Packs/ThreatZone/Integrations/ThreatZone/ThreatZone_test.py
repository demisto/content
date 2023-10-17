import demistomock as demisto
from CommonServerPython import *
from ThreatZone import generate_dbotscore

DBOT_SCORES = {
    'Reliability': 'A - Completely reliable"',
    'Vendor': 'Threatzone',
    'Indicator': '6e899ff7ef160d96787f505b7a9e17b789695bf3206a130c462b3820898257d0',
    'Score': 3,
    'Type': 'File'
}


def test_generate_dbotscore(mocker):
    """
        Given:
            - The indicator, report dict, type
        When:
            - Running generate_dbotscore
        Then:
            - Verify generate_dbotscore outputs as excepted
    """
    mocker.patch.object(demisto, 'args', return_value={'integrationReliability': DBotScoreReliability.A})

    dbot_score = generate_dbotscore(
        "6e899ff7ef160d96787f505b7a9e17b789695bf3206a130c462b3820898257d0",
        {'THREAT_LEVEL': 3},
        'file'
    )

    assert dbot_score == DBOT_SCORES

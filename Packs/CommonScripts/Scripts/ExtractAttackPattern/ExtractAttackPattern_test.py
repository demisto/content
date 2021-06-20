from CommonServerPython import *


ATTACK_PATTERN_OBJ = [{"name": "Two-Factor Authentication Interception"}]


def test_fetch_indicators(mocker):
    """
    Given
    - MITRE ID to extract
    When
    - we need to get its value (name).
    Then
    - run the ExtractAttackPattern script
    Validate that name extracted successfully from the ID.
    """
    from ExtractAttackPattern import is_valid_attack_pattern
    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Contents': [
        {'id': 'T1530', 'value': 'Data from Cloud Storage Object'},
        {'id': 'T1602', 'value': 'Data from Configuration Repository'}
    ]}])

    indicators = is_valid_attack_pattern(['T1530', 'T1602'])
    assert indicators == ['Data from Cloud Storage Object', 'Data from Configuration Repository']

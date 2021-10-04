from ExtractAttackPattern import is_valid_attack_pattern
from CommonServerPython import *


def test_extract_existing_mitre_ids(mocker):
    """
    Given
    - MITRE IDs to extract
    When
    - we need to get its value (name).
    Then
    - run the ExtractAttackPattern script
    Validate that name extracted successfully from the ID.
    """
    mocker.patch.object(demisto, 'executeCommand', return_value=[{}, {}, {'Contents': [
        {'id': 'T1530', 'value': 'Data from Cloud Storage Object'},
        {'id': 'T1602', 'value': 'Data from Configuration Repository'}
    ]}])

    indicators = is_valid_attack_pattern(['T1530', 'T1602'])
    assert indicators == ['Data from Cloud Storage Object', 'Data from Configuration Repository']

    mocker.patch.object(demisto, 'executeCommand', side_effect=ValueError(
        'verify you have proper integration enabled to support it'))
    mocker.patch.object(demisto, 'info')

    result = is_valid_attack_pattern(['T1530', 'T1602'])
    assert not result
    assert demisto.info.call_args[0][0] == 'Unsupported Command : mitre-get-indicator-name, ' \
        'verify you have proper integration (MITRE ATTACK v2) enabled to support it. ' \
        'This Is needed in order to auto extract MITRE IDs and translate them to Attack Pattern IOCs'


def test_extract_non_existing_mitre_ids(mocker):
    mocker.patch.object(demisto, 'executeCommand', return_value=[])

    indicators = is_valid_attack_pattern(['T1111', 'T2222'])
    assert indicators == []


def test_extract_existing_mitre_id(mocker):
    """
    Given
    - MITRE ID to extract
    When
    - we need to get its value (name).
    Then
    - run the ExtractAttackPattern script
    Validate that name extracted successfully from the ID.
    """
    mocker.patch.object(demisto, 'executeCommand', return_value=[{}, {}, {'Contents':
                        [{'id': 'T1530', 'value': 'Data from Cloud Storage Object'}]}])

    indicators = is_valid_attack_pattern(['T1530'])
    assert indicators == ['Data from Cloud Storage Object']

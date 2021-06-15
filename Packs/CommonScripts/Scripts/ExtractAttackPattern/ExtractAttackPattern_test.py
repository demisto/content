import json
import pytest
from stix2 import TAXIICollectionSource


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
    mocker.patch.object(TAXIICollectionSource, "__init__", return_value=None)
    mocker.patch.object(TAXIICollectionSource, 'query', return_value=ATTACK_PATTERN_OBJ)

    indicators = is_valid_attack_pattern('T1111')
    assert indicators == 'Two-Factor Authentication Interception'

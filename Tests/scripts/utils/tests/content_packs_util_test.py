import json
import os
import pytest
from demisto_sdk.commands.common.constants import (PACK_METADATA_CERTIFICATION,
                                                   PACK_METADATA_SUPPORT,
                                                   PACKS_DIR,
                                                   PACKS_PACK_META_FILE_NAME)

from Tests.scripts.utils.content_packs_util import (is_pack_xsoar_supported,
                                                    should_test_content_pack, get_test_pack_name)

with open('Tests/scripts/infrastructure_tests/tests_data/mock_id_set.json', 'r') as mock_id_set_f:
    MOCK_ID_SET = json.load(mock_id_set_f)


@pytest.mark.parametrize("pack_metadata_content, expected", [
    ({PACK_METADATA_SUPPORT: 'xsoar'}, True),
    ({PACK_METADATA_SUPPORT: 'community'}, False),
    ({PACK_METADATA_SUPPORT: 'partner'}, False)
])
def test_is_pack_xsoar_supported(tmp_path, pack_metadata_content, expected):
    """
    Given:
        - Case A: XSOAR supported content pack
        - Case B: Certified content Pack
        - Case C: Partner supported content pack

    When:
        - Checking if pack is certified

    Then:
        - Case A: Verify pack is certified, since it is XSOAR supported
        - Case B: Verify pack is certified, since it is set to be
        - Case C: Verify pack is not certified, since it is partner supported and not set to be certified
    """
    pack_metadata_file = tmp_path / PACKS_PACK_META_FILE_NAME
    pack_metadata_file.write_text(json.dumps(pack_metadata_content))
    assert is_pack_xsoar_supported(str(tmp_path)) == expected


def test_is_pack_certified_pack_metadata_does_not_exist(tmp_path):
    """
    Given:
        - Content pack without pack metadata file in it

    When:
        - Checking if pack is certified

    Then:
        - Verify content pack counts as non-certified
    """
    assert not is_pack_xsoar_supported(str(tmp_path))


@pytest.mark.parametrize("pack_metadata_content, pack_name, expected", [
    ({PACK_METADATA_SUPPORT: 'xsoar'}, 'CortexXDR', True),
    ({PACK_METADATA_SUPPORT: 'xsoar'}, 'NonSupported', False)
])
def test_should_test_content_pack(mocker, tmp_path, pack_metadata_content, pack_name, expected):
    """
    Given:
        - Case A: CortexXDR content pack
        - Case B: NonSupported content pack

    When:
        - Checking if pack should be tested

    Then:
        - Case A: Verify pack should be tested
        - Case B: Verify pack should not be tested
    """
    # Creating temp dirs
    packs_dir = tmp_path / PACKS_DIR
    packs_dir.mkdir()
    pack = packs_dir / pack_name
    pack.mkdir()
    pack_metadata_file = pack / PACKS_PACK_META_FILE_NAME
    pack_metadata_file.write_text(json.dumps(pack_metadata_content))

    # Mocking os.path.join to return the temp path created instead the path in content
    mocker.patch.object(os.path, 'join', return_value=str(pack_metadata_file))
    assert should_test_content_pack(pack_name) == expected

@pytest.mark.parametrize("test_id, expected", [
    ('Test XDR Playbook', 'CortexXDR'),
    ('PagerDuty Test', None),
    ('Dummy Test ID', None)
])
def test_get_test_pack_name(test_id, expected):
    """
    Given
        - Case A: Valid test playbook ID - 'Test XDR Playbook' that appear in index_json and has a pack.
        - Case B: Test playbook ID - 'PagerDuty Test' that has no pack in index_json.
        - Case C: Test playbook ID - 'Dummy Test ID' that doesn't appear in index.json.
    When
        Getting the pack name for a given test playbook ID.

    Then
        - Case A: Verify the returned pack name is 'CortexXDR' (the pack 'Test XDR Playbook' is in).
        - Case B: Verify no return pack name.
        - Case C: Verify no return pack name.
    """
    assert get_test_pack_name(test_id, MOCK_ID_SET) == expected

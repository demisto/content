import json

import pytest
from demisto_sdk.commands.common.constants import (PACK_METADATA_CERTIFICATION,
                                                   PACK_METADATA_SUPPORT,
                                                   PACKS_PACK_META_FILE_NAME)

from Tests.scripts.utils.content_packs_util import (is_pack_certified,
                                                    should_test_content_pack)


@pytest.mark.parametrize("pack_metadata_content, expected", [
    ({PACK_METADATA_SUPPORT: 'xsoar'}, True),
    ({PACK_METADATA_CERTIFICATION: 'certified'}, True),
    ({PACK_METADATA_SUPPORT: 'partner'}, False)
])
def test_is_pack_certified(tmp_path, pack_metadata_content, expected):
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
    assert is_pack_certified(str(tmp_path)) == expected


def test_is_pack_certified_pack_metadata_does_not_exist(tmp_path):
    """
    Given:
        - Content pack without pack metadata file in it

    When:
        - Checking if pack is certified

    Then:
        - Verify content pack counts as non-certified
    """
    assert not is_pack_certified(str(tmp_path))


@pytest.mark.parametrize("pack_name, expected", [
    ('CortexXDR', True),
    ('NonSupported', False)
])
def test_should_test_content_pack(pack_name, expected):
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
    assert should_test_content_pack(pack_name) == expected

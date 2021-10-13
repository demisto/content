import json
import os

import pytest

from Tests.scripts.collect_tests_and_content_packs import get_packs_from_landing_page
from Tests.scripts.utils.content_packs_util import (is_pack_xsoar_supported,
                                                    is_pack_deprecated,
                                                    should_test_content_pack, should_install_content_pack)
from demisto_sdk.commands.common.constants import (PACK_METADATA_SUPPORT,
                                                   PACKS_DIR,
                                                   PACKS_PACK_META_FILE_NAME)

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
    os.mkdir(tmp_path / 'Packs')
    os.mkdir(tmp_path / 'Packs' / 'DummyPack')
    pack_metadata_file = tmp_path / 'Packs' / 'DummyPack' / PACKS_PACK_META_FILE_NAME
    pack_metadata_file.write_text(json.dumps(pack_metadata_content))
    assert is_pack_xsoar_supported(str(pack_metadata_file)) == expected


@pytest.mark.parametrize("pack_metadata_content, expected", [
    ({'hidden': False}, False),
    ({'hidden': True}, True),
])
def test_is_pack_deprecated(tmp_path, pack_metadata_content, expected):
    """
    Given:
        - Case A: Pack is not deprecated
        - Case B: Pack is deprecated

    When:
        - Checking if pack is deprecated

    Then:
        - Case A: Verify pack is not deprecated, since the 'hidden' flag is set to 'false'
        - Case B: Verify pack is deprecated, since the 'hidden' flag is set to 'true'
    """
    os.mkdir(tmp_path / 'Packs')
    os.mkdir(tmp_path / 'Packs' / 'BitcoinAbuse')
    pack_metadata_file = tmp_path / 'Packs' / 'BitcoinAbuse' / PACKS_PACK_META_FILE_NAME
    pack_metadata_file.write_text(json.dumps(pack_metadata_content))
    assert is_pack_deprecated(str(tmp_path / 'Packs' / 'BitcoinAbuse')) == expected


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
    ({PACK_METADATA_SUPPORT: 'xsoar'}, 'CortexXDR', (True, '')),
    ({PACK_METADATA_SUPPORT: 'xsoar'}, 'NonSupported', (False, 'Pack is either the "NonSupported" pack or the '
                                                               '"DeprecatedContent" pack.')),
    ({'hidden': True, PACK_METADATA_SUPPORT: 'xsoar'}, 'CortexXDR', (False, 'Pack is Deprecated'))
])
def test_should_test_content_pack(mocker, tmp_path, pack_metadata_content, pack_name, expected):
    """
    Given:
        - Case A: CortexXDR content pack
        - Case B: NonSupported content pack
        - Case C: Deprecated CortexXDR content pack

    When:
        - Checking if pack should be tested

    Then:
        - Case A: Verify pack should be tested
        - Case B: Verify pack should not be tested
        - Case C: Verify pack should not be tested
    """
    # Creating temp dirs
    pack = tmp_path / PACKS_DIR / pack_name
    pack.mkdir(parents=True)
    pack_metadata_file = pack / PACKS_PACK_META_FILE_NAME
    pack_metadata_file.write_text(json.dumps(pack_metadata_content))

    # Mocking os.path.join to return the temp path created instead the path in content
    mocker.patch.object(os.path, 'join', return_value=str(pack_metadata_file))
    assert should_test_content_pack(pack_name) == expected


@pytest.mark.parametrize("pack_metadata_content, pack_name, expected", [
    ({PACK_METADATA_SUPPORT: 'partner'}, 'Partner', (True, '')),
    ({PACK_METADATA_SUPPORT: 'community'}, 'Community', (True, '')),
    ({PACK_METADATA_SUPPORT: 'xsoar'}, 'NonSupported', (False, 'Pack is either the "NonSupported" pack or the '
                                                               '"DeprecatedContent" pack.')),
    ({'hidden': True, PACK_METADATA_SUPPORT: 'xsoar'}, 'CortexXDR', (False, 'Pack is Deprecated')),

    ({PACK_METADATA_SUPPORT: 'xsoar'}, 'ApiModules',
     (False, "Pack should be ignored as it one of the files to ignore: ['__init__.py', "
             "'ApiModules', 'NonSupported']"))
])
def test_should_install_content_pack(mocker, tmp_path, pack_metadata_content, pack_name, expected):
    """
    Given:
        - Case A: Partner content pack
        - Case B: Community content pack
        - Case C: NonSupported content pack
        - Case D: Deprecated CortexXDR content pack
        - Case E: ApiModules content pack

    When:
        - Checking if pack should be installed

    Then:
        - Case A: Verify pack should be installed
        - Case B: Verify pack should be installed
        - Case C: Verify pack should not be installed
        - Case D: Verify pack should not be installed
        - Case E: Verify pack should not be installed
    """
    # Creating temp dirs
    pack = tmp_path / PACKS_DIR / pack_name
    pack.mkdir(parents=True)
    pack_metadata_file = pack / PACKS_PACK_META_FILE_NAME
    pack_metadata_file.write_text(json.dumps(pack_metadata_content))

    # Mocking os.path.join to return the temp path created instead the path in content
    mocker.patch.object(os.path, 'join', return_value=str(pack_metadata_file))
    assert should_install_content_pack(pack_name) == expected


def test_get_packs_from_landing_page(mocker, tmp_path):
    """
    Given:
        The diff output for the landing page sections file

    When:
        - A pack is modified (added or removed)

    Then:
        - Ensure that pack is returned by the 'get_packs_from_landing_page' method.
    """
    git_diff = '''
    diff --git a/Tests/Marketplace/landingPage_sections.json b/Tests/Marketplace/landingPage_sections.json
    index 953a91ed0f..eb96c36117 100644
    --- a/Tests/Marketplace/landingPage_sections.json
    +++ b/Tests/Marketplace/landingPage_sections.json
    @@ -17,7 +17,8 @@
         "NIST",
         "GenericWebhook",
         "GraphQL",
    -    "GenericSQL"
    +    "GenericSQL",
    +    "my test pack"
       ]'''
    landing_page_sections_mock = {"description": "description",
                                  "sections": ["Featured"],
                                  "Featured": [
                                      "NIST",
                                      "GenericWebhook",
                                      "GraphQL",
                                      "GenericSQL",
                                      "my test pack"
                                  ]}
    landing_page_sections_file = tmp_path / 'landing_page.json'
    landing_page_sections_file.write_text(json.dumps(landing_page_sections_mock))
    mocker.patch('Tests.scripts.collect_tests_and_content_packs.LANDING_PAGE_SECTIONS_JSON_PATH',
                 landing_page_sections_file)
    mocker.patch('Tests.scripts.collect_tests_and_content_packs.tools.run_command', return_value=git_diff)
    assert 'my test pack' in get_packs_from_landing_page('branch_name')

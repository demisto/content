import os
import re

from demisto_sdk.commands.common.tools import get_pack_name
from release_notes_generator import get_release_notes_dict, generate_release_notes_summary

VERSION = 'VERSION'
ASSET_ID = 'ASSET_ID'


def check_assertions_on_release_notes_dict(rn_dict):
    assert '1.0.1' not in rn_dict['FakePack_1'].keys()
    # assert DUMMY_RELEASE_NOTE_CONTENT in rn_dict['FakePack1']['2.0.0']
    assert len(rn_dict['FakePack_2'].items()) == 1


def check_assertions_on_release_notes_summary(rn_summary):
    assert '# Cortex XSOAR Content Release Notes for version {} ({})\n'.format(VERSION, ASSET_ID)

    assert '## FakePack1 Pack v1.0.1' not in rn_summary
    assert '- __FakePack1_Integration1__' not in rn_summary
    # assert '- __FakePack_1_FakeIntegration_2__' in rn_summary
    # assert '## FakePack_1 Pack v2.0.0' in rn_summary
    # assert '- __FakePack_1_FakeIntegration_2__' in rn_summary
    #
    # assert '## FakePack_2 Pack v1.0.1' in rn_summary
    # assert '- __FakePack_1_FakeScript_1__' in rn_summary
    # assert '- __FakePack_1_FakeIntegration_2__' in rn_summary
    # assert '## FakePack_2 Pack v2.0.0' in rn_summary
    # assert '- __FakePack_2_FakeIntegration_2__' in rn_summary


def mock_get_pack_name(mocker, file_path):
    match = re.search(r'', file_path)


def test_release_notes_generator(mocker):
    """
    Given
    - A content repository with valid packs.

    When
    - Adding integrations and updating release notes.

    Then
    - Ensure release notes generator creates a valid summary.
    """
    test_data_path = 'Tests/scripts/infrastructure_tests/tests_data/RN_tests_data'
    release_notes_files = [
        os.path.join(test_data_path, 'FakePack1', 'ReleaseNotes', '1_0_1.md'),
        os.path.join(test_data_path, 'FakePack1', 'ReleaseNotes', '1_1_0.md'),
        os.path.join(test_data_path, 'FakePack1', 'ReleaseNotes', '2_0_0.md'),
        os.path.join(test_data_path, 'FakePack2', 'ReleaseNotes', '1_0_1.md'),
        os.path.join(test_data_path, 'FakePack2', 'ReleaseNotes', '1_1_0.md')
    ]

    mocker.patch.object('demisto_sdk.commands.common.tools', get_pack_name, side_effect=mock_get_pack_name)

    rn_dict = get_release_notes_dict(release_notes_files)
    check_assertions_on_release_notes_dict(rn_dict)

    rn_summary = generate_release_notes_summary(rn_dict, VERSION, ASSET_ID)
    check_assertions_on_release_notes_summary(rn_summary)



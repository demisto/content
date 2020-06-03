import os
import re
from release_notes_generator import get_release_notes_dict, generate_release_notes_summary

TEST_DATA_PATH = 'Tests/scripts/infrastructure_tests/tests_data/RN_tests_data'

VERSION = 'VERSION'
ASSET_ID = 'ASSET_ID'

EMPTY_LINES_REGEX = r'\s*-\s*\n'


def test_release_notes_summary_two_packs():
    """
    Given
    - A repository of two packs updates and release notes:
      - FakePack1 with versions 1.1.0 and 2.0.0
      - FakePack2 version 1.1.0

    When
    - Generating a release notes summary file.

    Then
    - Ensure release notes generator creates a valid summary, by checking:
      - the output of get_release_notes_dict() is a valid dict of (pack_name, dict(pack_version, release_note)).
      - the release notes summary contains two packs with 3 updates:
        - FakePack1 with versions 1.1.0 and 2.0.0
        - FakePack2 with versions 1.1.0
    """
    release_notes_files = [
        os.path.join(TEST_DATA_PATH, 'FakePack1', 'ReleaseNotes', '1_1_0.md'),
        os.path.join(TEST_DATA_PATH, 'FakePack1', 'ReleaseNotes', '2_0_0.md'),
        os.path.join(TEST_DATA_PATH, 'FakePack2', 'ReleaseNotes', '1_1_0.md')
    ]

    rn_dict = get_release_notes_dict(release_notes_files)

    assert '1.1.0' in rn_dict['FakePack1'].keys()
    assert '2.0.0' in rn_dict['FakePack1'].keys()
    assert '1.1.0' in rn_dict['FakePack2'].keys()

    rn_summary = generate_release_notes_summary(rn_dict, VERSION, ASSET_ID)

    assert VERSION in rn_summary and ASSET_ID in rn_summary  # summary title
    assert '## FakePack1 Pack v1.1.0' in rn_summary
    assert '- __FakePack1_Integration1__' in rn_summary
    assert 'This is a fake minor release note.' in rn_summary
    assert '## FakePack1 Pack v2.0.0' in rn_summary
    assert '- __FakePack2_Script1__' in rn_summary
    assert 'This is a fake major release note.' in rn_summary


def test_release_notes_summary_with_empty_lines_in_rn():
    """
    Given
    - A repository contains a FakePack3 update with ignored release notes.

    When
    - Generating a release notes summary file.

    Then
    - Ensure release notes generator creates a valid summary, by checking:
      - the output of get_release_notes_dict() is a dict of (pack_name, dict(pack_version, release_note)).
      - empty lines (with dashes) are removed from the release notes summary.
    """
    release_notes_files = [
        os.path.join(TEST_DATA_PATH, 'FakePack3', 'ReleaseNotes', '1_0_1.md')
    ]

    rn_dict = get_release_notes_dict(release_notes_files)

    assert '1.0.1' in rn_dict['FakePack3'].keys()
    assert len(rn_dict) == 1

    rn_summary = generate_release_notes_summary(rn_dict, VERSION, ASSET_ID)

    print(rn_summary)

    match = re.search(EMPTY_LINES_REGEX, rn_summary)
    assert match is None


def test_release_notes_summary_with_ignored_rns():
    """
    Given
    - A repository of a packs update and release notes:
      - FakePack4 with versions 1.0.1 and 1.1.0

    When
    - Generating a release notes summary file.

    Then
    - Ensure release notes generator creates a valid summary, by checking:
      - the output of get_release_notes_dict() is a valid dict of (pack_name, dict(pack_version, release_note))
      - the release notes summary contains one packs with 1 updates:
        - FakePack4 version 1.1.0
      - the summary does not contain release notes 1.0.1, because it is ignored.
    """
    release_notes_files = [
        os.path.join(TEST_DATA_PATH, 'FakePack4', 'ReleaseNotes', '1_0_1.md'),
        os.path.join(TEST_DATA_PATH, 'FakePack4', 'ReleaseNotes', '1_1_0.md')
    ]

    rn_dict = get_release_notes_dict(release_notes_files)

    assert '1.1.0' in rn_dict['FakePack4'].keys()
    assert len(rn_dict) == 1

    rn_summary = generate_release_notes_summary(rn_dict, VERSION, ASSET_ID)

    assert '## FakePack4 Pack v1.1.0' in rn_summary
    assert '- __FakePack4_Script1__' in rn_summary


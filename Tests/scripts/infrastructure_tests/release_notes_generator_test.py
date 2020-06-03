import os
import re
from release_notes_generator import get_release_notes_dict, generate_release_notes_summary

TEST_DATA_PATH = 'Tests/scripts/infrastructure_tests/tests_data/RN_tests_data'

VERSION = 'VERSION'
ASSET_ID = 'ASSET_ID'

RN_TITLE = r'# [^\n]* {} ({})\n'.format(VERSION, ASSET_ID)
RN_TITLE += r'##### [^\n]*\n'


def check_assertions_on_release_notes_dict(rn_dict):
    assert '1.0.1' not in rn_dict['FakePack1'].keys()
    assert '1.1.0' in rn_dict['FakePack1'].keys()
    assert '2.0.0' in rn_dict['FakePack1'].keys()

    assert '1.0.1' not in rn_dict['FakePack2'].keys()
    assert '1.1.0' in rn_dict['FakePack2'].keys()


def test_release_notes_summary_with_empty_lines_in_rn():
    """
    Given
    - A repository of two packs updates and release notes:
      - FakePack1 with versions 1.0.1, 1.1.0 and 2.0.0
      - FakePack2 with versions 1.0.1 and 1.1.0

    When
    - Generating a release notes summary file.

    Then
    - Ensure release notes generator creates a valid summary, by checking:
      - the output of get_release_notes_dict() is a valid dict of (pack_name, dict(pack_version, release_note))
      - the release notes summary contains two packs with 3 updates:
        - FakePack1 with versions 1.1.0 and 2.0.0
        - FakePack2 with versions 1.1.0
      - the summary does not contain release notes 1.0.0 in each pack, because they are ignored.
    """
    release_notes_files = [
        os.path.join(TEST_DATA_PATH, 'FakePack3', 'ReleaseNotes', '1_0_1.md')
    ]

    rn_dict = get_release_notes_dict(release_notes_files)
    check_assertions_on_release_notes_dict(rn_dict)

    rn_summary = generate_release_notes_summary(rn_dict, VERSION, ASSET_ID)

    assert rn_summary  # todo


def test_release_notes_summary_two_packs():
    """
    Given
    - A repository of two packs updates and release notes:
      - FakePack1 with versions 1.1.0 and 2.0.0
      - FakePack2 with version 1.1.0

    When
    - Generating a release notes summary file.

    Then
    - Ensure release notes generator creates a valid summary, by checking:
      - the output of get_release_notes_dict() is a valid dict of (pack_name, dict(pack_version, release_note))
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

    assert re.search(RN_TITLE, rn_summary)
    assert '## FakePack1 Pack v1.0.1' not in rn_summary
    assert '- __FakePack1_Integration1__' in rn_summary
    assert '## FakePack1 Pack v1.1.0' in rn_summary
    assert 'This is a fake minor release note.' in rn_summary
    assert '## FakePack1 Pack v2.0.0' in rn_summary
    assert 'This is a fake major release note.' in rn_summary
    assert '- __FakePack2_Script1__' in rn_summary


def test_release_notes_summary_with_ignored_rns():
    """
    Given
    - A repository of two packs updates and release notes:
      - FakePack1 with versions 1.0.1, 1.1.0 and 2.0.0
      - FakePack2 with versions 1.0.1 and 1.1.0

    When
    - Generating a release notes summary file.

    Then
    - Ensure release notes generator creates a valid summary, by checking:
      - the output of get_release_notes_dict() is a valid dict of (pack_name, dict(pack_version, release_note))
      - the release notes summary contains two packs with 3 updates:
        - FakePack1 with versions 1.1.0 and 2.0.0
        - FakePack2 with versions 1.1.0
      - the summary contains a valid title.
      - the summary does not contain release notes 1.0.0 in each pack, because they are ignored.
    """
    release_notes_files = [
        os.path.join(TEST_DATA_PATH, 'FakePack1', 'ReleaseNotes', '1_0_1.md'),
        os.path.join(TEST_DATA_PATH, 'FakePack1', 'ReleaseNotes', '1_1_0.md')
    ]

    rn_dict = get_release_notes_dict(release_notes_files)

    assert len(rn_dict) == 0

    rn_summary = generate_release_notes_summary(rn_dict, VERSION, ASSET_ID)

    pattern = re.compile(RN_TITLE)
    assert pattern.match(rn_summary)

import os
import re
from Utils.release_notes_generator import (get_release_notes_dict,
                                           generate_release_notes_summary,
                                           get_pack_entities,
                                           read_and_format_release_note,
                                           merge_version_blocks,
                                           EMPTY_LINES_REGEX)

TEST_DATA_PATH = 'Tests/scripts/infrastructure_tests/tests_data/RN_tests_data'

VERSION = 'VERSION'
ASSET_ID = 'ASSET_ID'


class TestReadAndFormatReleaseNote:
    def test_sanity(self):
        """
        Given
        - A release note file with 2 Integrations:
            - FakePack1_Integration1
            - FakePack1_Integration2

        When
        - Formatting a release notes file.

        Then
        - Ensure both integration appear in the formatted string
        """
        rn_file = os.path.join(TEST_DATA_PATH, 'FakePack1', 'ReleaseNotes', '1_1_0.md')
        formatted_text = read_and_format_release_note(rn_file)
        assert 'FakePack1_Integration1' in formatted_text
        assert 'FakePack1_Integration2' in formatted_text

    def test_ignored_release_notes_block(self):
        """
        Given
        - A release note file with an Integration and a Script:
            - FakePack4_Script1
            - FakePack4_Integration1 - should be ignored

        When
        - Formatting a release notes file.

        Then
        - Ensure only the script appears in the formatted string
        """
        rn_file = os.path.join(TEST_DATA_PATH, 'FakePack4', 'ReleaseNotes', '1_1_0.md')
        formatted_text = read_and_format_release_note(rn_file)
        assert 'FakePack4_Script1' in formatted_text
        assert 'FakePack4_Integration1' not in formatted_text

    def test_ignored_entire_release_note(self):
        """
        Given
        - A release note file with an Integration and a Script:
            - FakePack4_Script1
            - FakePack4_Integration1

        When
        - Formatting a release notes file.

        Then
        - Ensure formatted string is empty.
        """
        rn_file = os.path.join(TEST_DATA_PATH, 'FakePack4', 'ReleaseNotes', '1_0_1.md')
        formatted_text = read_and_format_release_note(rn_file)
        assert formatted_text == ''


class TestGenerateReleaseNotesSummary:
    def setup(self):
        self._version = VERSION
        self._asset_id = ASSET_ID
        self._outfile = 'temp.md'

    def test_added_pack(self):
        """
        Given
        - A repository of two new packs:
          - FakePack3 version 1.0.0
          - FakePack4 version 1.0.0

        When
        - Generating a release notes summary file.

        Then
        - Ensure release notes generator creates a valid summary, by checking:
          - the release notes summary contains two packs:
            - FakePack3 with version 1.0.0
            - FakePack4 with version 1.0.0
        """
        new_packs_rn = {
            'FakePack3': get_pack_entities(os.path.join(TEST_DATA_PATH, 'FakePack3')),
            'FakePack4': get_pack_entities(os.path.join(TEST_DATA_PATH, 'FakePack4')),
        }

        rn_summary = generate_release_notes_summary(new_packs_rn, {}, self._version, self._asset_id, 'temp.md')

        assert '## New: FakePack3 Pack v1.0.0' in rn_summary
        assert '## New: FakePack4 Pack v1.0.0' in rn_summary

    def test_two_packs(self):
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
            os.path.join(TEST_DATA_PATH, 'FakePack2', 'ReleaseNotes', '1_1_0.md'),
        ]

        rn_dict = get_release_notes_dict(release_notes_files)

        assert '1.1.0' in rn_dict['FakePack1'].keys()
        assert '2.0.0' in rn_dict['FakePack1'].keys()
        assert '1.1.0' in rn_dict['FakePack2'].keys()

        rn_summary = generate_release_notes_summary({}, rn_dict, self._version, self._asset_id, self._outfile)

        assert VERSION in rn_summary and ASSET_ID in rn_summary  # summary title
        assert '### FakePack1 Pack v2.0.0' in rn_summary
        assert '##### FakePack1_Integration1' in rn_summary
        assert 'This is a fake1 minor release note.' in rn_summary
        assert 'This is a fake1 major release note.' in rn_summary
        assert '### FakePack2 Pack v1.1.0' in rn_summary
        assert '##### FakePack2_Script1' in rn_summary
        assert 'This is a fake2 major release note.' in rn_summary

    def test_release_notes_summary_with_empty_lines_in_rn(self):
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

        rn_summary = generate_release_notes_summary({}, rn_dict, self._version, self._asset_id, self._outfile)

        print(rn_summary)

        match = re.search(EMPTY_LINES_REGEX, rn_summary)
        assert match is None

    def test_release_notes_summary_with_ignored_rns(self):
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
            os.path.join(TEST_DATA_PATH, 'FakePack4', 'ReleaseNotes', '1_1_0.md'),
        ]

        rn_dict = get_release_notes_dict(release_notes_files)

        assert '1.1.0' in rn_dict['FakePack4'].keys()
        assert len(rn_dict) == 1

        rn_summary = generate_release_notes_summary({}, rn_dict, self._version, self._asset_id, self._outfile)

        assert '### FakePack4 Pack v1.1.0' in rn_summary
        assert '##### FakePack4_Script1' in rn_summary


class TestMergeVersionBlocks:
    def test_sanity(self):
        """
        Given
            two changes in foreign content types

        When
            two pack versions that modified different items.

        Then
            type sections appears one after the other
        """
        release_notes_paths = [
            os.path.join(TEST_DATA_PATH, 'FakePack1', 'ReleaseNotes', '1_1_0.md'),
            os.path.join(TEST_DATA_PATH, 'FakePack1', 'ReleaseNotes', '2_1_0.md'),
        ]

        pack_versions_dict = {}
        for path in release_notes_paths:
            with open(path) as file_:
                pack_versions_dict[os.path.basename(os.path.splitext(path)[0])] = file_.read()

        rn_block = merge_version_blocks('FakePack', pack_versions_dict)

        assert 'FakePack1_Playbook1' in rn_block
        assert 'FakePack1_Playbook2' in rn_block
        assert 'FakePack1_Integration1' in rn_block
        assert 'FakePack1_Integration2' in rn_block
        assert 'v2_1_0' in rn_block
        assert 'v1_1_0' not in rn_block

    def test_similiar_entities(self):
        """
        Given
            two changes in similar content entities

        When
            two pack versions that modified the same items.

        Then
            one integration section appears
            one entity title for each one with two comments
        """
        release_notes_paths = [
            os.path.join(TEST_DATA_PATH, 'FakePack1', 'ReleaseNotes', '1_1_0.md'),
            os.path.join(TEST_DATA_PATH, 'FakePack1', 'ReleaseNotes', '2_0_0.md'),
        ]

        pack_versions_dict = {}
        for path in release_notes_paths:
            with open(path) as file_:
                pack_versions_dict[os.path.basename(os.path.splitext(path)[0])] = file_.read()

        rn_block = merge_version_blocks('FakePack', pack_versions_dict)

        assert rn_block.count('Integrations') == 1
        assert rn_block.count('FakePack1_Integration1') == 1
        assert rn_block.count('FakePack1_Integration2') == 1
        assert 'v2_0_0' in rn_block
        assert 'v1_1_0' not in rn_block
        assert 'fake1 minor' in rn_block
        assert 'fake2 minor' in rn_block
        assert 'fake1 major' in rn_block
        assert 'fake2 major' in rn_block

import os
import re
from Utils.release_notes_generator import (get_release_notes_dict,
                                           generate_release_notes_summary,
                                           get_pack_entities,
                                           read_and_format_release_note,
                                           merge_version_blocks,
                                           EMPTY_LINES_REGEX,
                                           get_new_entity_record,
                                           construct_entities_block,
                                           aggregate_release_notes,
                                           aggregate_release_notes_for_marketplace)

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
        packs_metadta_dict = {
            'FakePack3': {},
            'FakePack4': {}
        }

        rn_summary = generate_release_notes_summary(
            new_packs_rn, {}, packs_metadta_dict, self._version, self._asset_id, 'temp.md')

        assert '## New: FakePack3 Pack v1.0.0' in rn_summary
        assert '## New: FakePack4 Pack v1.0.0' in rn_summary

    def test_added_partner_pack(self):
        """
        Given
        - A repository of two new packs:
          - FakePack3 version 1.0.0, metadata "supports" field has value "partner"
          - FakePack4 version 1.0.0

        When
        - Generating a release notes summary file.

        Then
        - Ensure release notes generator creates a valid summary, by checking:
          - the release notes summary contains two packs:
            - FakePack3 with version 1.0.0 and has the string "(Partner Supported)" after the version
            - FakePack4 with version 1.0.0 dose not have the string "(Partner Supported)" after the version
        """
        new_packs_rn = {
            'FakePack3': get_pack_entities(os.path.join(TEST_DATA_PATH, 'FakePack3')),
            'FakePack4': get_pack_entities(os.path.join(TEST_DATA_PATH, 'FakePack4')),
        }
        packs_metadta_dict = {
            'FakePack3': {'support': 'partner'},
            'FakePack4': {'support': 'xsoar'}
        }

        rn_summary = generate_release_notes_summary(
            new_packs_rn, {}, packs_metadta_dict, self._version, self._asset_id, 'temp.md')

        assert '## New: FakePack3 Pack v1.0.0 (Partner Supported)' in rn_summary
        assert '## New: FakePack4 Pack v1.0.0' in rn_summary
        assert '## New: FakePack4 Pack v1.0.0 (Partner Supported)' not in rn_summary

    def test_added_contribution_pack(self):
        """
        Given
        - A repository of two new packs:
          - FakePack3 version 1.0.0, metadata "supports" field has value "contribution"
          - FakePack4 version 1.0.0

        When
        - Generating a release notes summary file.

        Then
        - Ensure release notes generator creates a valid summary, by checking:
          - the release notes summary contains two packs:
            - FakePack3 with version 1.0.0 and has the string "(Community Contributed)" after the version
            - FakePack4 with version 1.0.0 dose not have the string "(Community Contributed)" after the version
        """
        new_packs_rn = {
            'FakePack3': get_pack_entities(os.path.join(TEST_DATA_PATH, 'FakePack3')),
            'FakePack4': get_pack_entities(os.path.join(TEST_DATA_PATH, 'FakePack4')),
        }
        packs_metadta_dict = {
            'FakePack3': {'support': 'community'},
            'FakePack4': {'support': 'xsoar'}
        }

        rn_summary = generate_release_notes_summary(
            new_packs_rn, {}, packs_metadta_dict, self._version, self._asset_id, 'temp.md')

        assert '## New: FakePack3 Pack v1.0.0 (Community Contributed)' in rn_summary
        assert '## New: FakePack4 Pack v1.0.0' in rn_summary
        assert '## New: FakePack4 Pack v1.0.0 (Community Contributed)' not in rn_summary

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

        rn_dict, _ = get_release_notes_dict(release_notes_files)

        packs_metadta_dict = {
            'FakePack1': {},
            'FakePack2': {}
        }

        assert '1.1.0' in rn_dict['FakePack1'].keys()
        assert '2.0.0' in rn_dict['FakePack1'].keys()
        assert '1.1.0' in rn_dict['FakePack2'].keys()

        rn_summary = generate_release_notes_summary({}, rn_dict, packs_metadta_dict, self._version, self._asset_id, self._outfile)

        assert VERSION in rn_summary and ASSET_ID in rn_summary  # summary title
        assert '### FakePack1 Pack v2.0.0' in rn_summary
        assert '##### FakePack1_Integration1' in rn_summary
        assert 'This is a fake1 minor release note.' in rn_summary
        assert 'This is a fake1 major release note.' in rn_summary
        assert '### FakePack2 Pack v1.1.0' in rn_summary
        assert '##### FakePack2_Script1' in rn_summary
        assert 'This is a fake2 major release note.' in rn_summary

    def test_updated_partner_pack(self):
        """
        Given
        - A repository of two packs updates and release notes:
          - FakePack1 with version 2.0.0 metadata "supports" field has value "partner"
          - FakePack2 version 1.1.0

        When
        - Generating a release notes summary file.

        Then
        - Ensure release notes generator creates a valid summary, by checking:
          - the output of get_release_notes_dict() is a valid dict of (pack_name, dict(pack_version, release_note)).
          - the release notes summary contains two packs with the flowing:
            - FakePack1 with version 2.0.0 and has the string "(Partner Supported)" after the version
            - FakePack2 with version 1.1.0 dose not have the string "(Partner Supported)" after the version
        """
        release_notes_files = [
            os.path.join(TEST_DATA_PATH, 'FakePack1', 'ReleaseNotes', '1_1_0.md'),
            os.path.join(TEST_DATA_PATH, 'FakePack1', 'ReleaseNotes', '2_0_0.md'),
            os.path.join(TEST_DATA_PATH, 'FakePack2', 'ReleaseNotes', '1_1_0.md'),
        ]

        rn_dict, _ = get_release_notes_dict(release_notes_files)

        packs_metadta_dict = {
            'FakePack1': {'support': 'partner'},
            'FakePack2': {'support': 'xsoar'}
        }

        assert '2.0.0' in rn_dict['FakePack1'].keys()
        assert '1.1.0' in rn_dict['FakePack2'].keys()

        rn_summary = generate_release_notes_summary({}, rn_dict, packs_metadta_dict, self._version, self._asset_id, self._outfile)

        assert VERSION in rn_summary and ASSET_ID in rn_summary  # summary title
        assert '### FakePack1 Pack v2.0.0 (Partner Supported)' in rn_summary
        assert '### FakePack2 Pack v1.1.0' in rn_summary
        assert '### FakePack2 Pack v1.1.0 (Partner Supported)' not in rn_summary

    def test_updated_community_pack(self):
        """
        Given
        - A repository of two packs updates and release notes:
          - FakePack1 with version 2.0.0 metadata "supports" field has value "community"
          - FakePack2 version 1.1.0

        When
        - Generating a release notes summary file.

        Then
        - Ensure release notes generator creates a valid summary, by checking:
          - the output of get_release_notes_dict() is a valid dict of (pack_name, dict(pack_version, release_note)).
          - the release notes summary contains two packs with the following:
            - FakePack1 with version 2.0.0 and has the string "(Community Supported)" after the version
            - FakePack2 with version 1.1.0 DOES NOT have the string "(Community Supported)" after the version
        """
        release_notes_files = [
            os.path.join(TEST_DATA_PATH, 'FakePack1', 'ReleaseNotes', '1_1_0.md'),
            os.path.join(TEST_DATA_PATH, 'FakePack1', 'ReleaseNotes', '2_0_0.md'),
            os.path.join(TEST_DATA_PATH, 'FakePack2', 'ReleaseNotes', '1_1_0.md'),
        ]

        rn_dict, _ = get_release_notes_dict(release_notes_files)

        packs_metadta_dict = {
            'FakePack1': {'support': 'community'},
            'FakePack2': {'support': 'xsoar'}
        }

        assert '2.0.0' in rn_dict['FakePack1'].keys()
        assert '1.1.0' in rn_dict['FakePack2'].keys()

        rn_summary = generate_release_notes_summary({}, rn_dict, packs_metadta_dict, self._version, self._asset_id, self._outfile)

        assert VERSION in rn_summary and ASSET_ID in rn_summary  # summary title
        assert '### FakePack1 Pack v2.0.0 (Community Contributed)' in rn_summary
        assert '### FakePack2 Pack v1.1.0' in rn_summary
        assert '### FakePack2 Pack v1.1.0 (Community Contributed)' not in rn_summary

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

        packs_metadta_dict = {
            'FakePack3': {}
        }

        rn_dict, _ = get_release_notes_dict(release_notes_files)

        assert '1.0.1' in rn_dict['FakePack3'].keys()
        assert len(rn_dict) == 1

        rn_summary = generate_release_notes_summary({}, rn_dict, packs_metadta_dict, self._version, self._asset_id, self._outfile)

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
        packs_metadta_dict = {
            'FakePack4': {}
        }

        rn_dict, _ = get_release_notes_dict(release_notes_files)

        assert '1.1.0' in rn_dict['FakePack4'].keys()
        assert len(rn_dict) == 1

        rn_summary = generate_release_notes_summary({}, rn_dict, packs_metadta_dict, self._version, self._asset_id, self._outfile)

        assert '### FakePack4 Pack v1.1.0' in rn_summary
        assert '##### FakePack4_Script1' in rn_summary


class TestMergeVersionBlocks:
    def test_aggregate_release_notes_for_marketplace(self):
        """
        Given
        - Two release notes files with content entity instance wrapped with ** and entity type contains spaces.
        When
        - Merging the two release notes files into one file.
        Then
        - Ensure that the content entity instance is wrapped with **.
        - Ensure that the content entity type contains whitespace.
        - Ensure that the content of both RN files appears in the result file.
        """
        release_notes_paths = [
            os.path.join(TEST_DATA_PATH, 'FakePack6', 'ReleaseNotes', '1_0_1.md'),
            os.path.join(TEST_DATA_PATH, 'FakePack6', 'ReleaseNotes', '1_0_2.md'),
        ]

        pack_versions_dict = {}
        for path in release_notes_paths:
            with open(path) as file_:
                pack_versions_dict[os.path.basename(os.path.splitext(path)[0])] = file_.read()

        rn_block = aggregate_release_notes_for_marketplace(pack_versions_dict)

        assert 'Incident Fields' in rn_block
        assert '**XDR Alerts**' in rn_block
        assert 'First' in rn_block
        assert 'Second' in rn_block
        assert rn_block.endswith('\n')
        assert rn_block.startswith('\n')

    def test_spaced_content_entity_and_old_format(self):
        """
        Given
        - Two release notes files with content entity instance wrapped with ** and entity type contains spaces.
        When
        - Merging the two release notes files into one file.
        Then
        - Ensure that the content entity instance is wrapped with **.
        - Ensure that the content entity type contains whitespace.
        - Ensure that the content of both RN files appears in the result file.
        """
        release_notes_paths = [
            os.path.join(TEST_DATA_PATH, 'FakePack6', 'ReleaseNotes', '1_0_1.md'),
            os.path.join(TEST_DATA_PATH, 'FakePack6', 'ReleaseNotes', '1_0_2.md'),
        ]

        pack_versions_dict = {}
        for path in release_notes_paths:
            with open(path) as file_:
                pack_versions_dict[os.path.basename(os.path.splitext(path)[0])] = file_.read()

        rn_block, latest_version = merge_version_blocks(pack_versions_dict)

        assert 'Incident Fields' in rn_block
        assert '**XDR Alerts**' in rn_block
        assert 'First' in rn_block
        assert 'Second' in rn_block
        assert latest_version == '1_0_2'

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

        rn_block = aggregate_release_notes('FakePack', pack_versions_dict, {})

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

        rn_block = aggregate_release_notes('FakePack', pack_versions_dict, {})

        assert rn_block.count('Integrations') == 1
        assert rn_block.count('FakePack1_Integration1') == 1
        assert rn_block.count('FakePack1_Integration2') == 1
        assert 'v2_0_0' in rn_block
        assert 'v1_1_0' not in rn_block
        assert 'fake1 minor' in rn_block
        assert 'fake2 minor' in rn_block
        assert 'fake1 major' in rn_block
        assert 'fake2 major' in rn_block

    def test_get_new_entity_record_integration(self):
        """
        Given
            fake integration path.

        When
            getting entity record for integration.

        Then
            Ensure the method is valid and returns the integration name and description.
        """
        name, description = get_new_entity_record(os.path.join(TEST_DATA_PATH,
                                                               'FakePack5', 'Integrations', 'fake_integration.yml'))

        assert name == 'fake_integration'
        assert description == 'Use the Zoom integration manage your Zoom users and meetings'

    def test_get_new_entity_record_layout(self):
        """
        Given
            fake layout path.

        When
            getting entity record for layout.

        Then
            Ensure the method is valid and returns the layout name and description.
        """
        name, description = get_new_entity_record(os.path.join(TEST_DATA_PATH,
                                                               'FakePack5', 'Layouts', 'fake_layout.json'))

        assert name == 'Fake layout - Close'
        assert description == ''

    def test_get_new_entity_record_classifier(self):
        """
        Given
            fake classifier path.

        When
            getting entity record for classifier.

        Then
            Ensure the method is valid and returns the classifier name and description.
        """
        name, description = get_new_entity_record(os.path.join(TEST_DATA_PATH,
                                                               'FakePack5', 'Classifiers', 'fake_classifier.json'))

        assert name == 'Fake classifier'
        assert description == 'Maps incoming Prisma Cloud event fields.'

    def test_construct_entities_block_integration(self):
        """
        Given
            integration entities_data.

        When
            generates pack release note block for integration.

        Then
            Ensure the method is valid and the release note block contains Tanium integration.
        """
        entities_data = {'Integrations': {'Tanium': 'Tanium endpoint security and systems management'}}
        rn = construct_entities_block(entities_data)
        assert '### Integrations' in rn
        assert '##### Tanium' in rn
        assert 'Tanium endpoint security and systems management' in rn

    def test_construct_entities_block_indicator_types(self):
        """
        Given
            indicator type entities_data.

        When
            generates pack release note block for indicator type.

        Then
            Ensure the method is valid and the release note block contains accountRep indicator.
        """
        entities_data = {'IndicatorTypes': {'accountRep': ''}}
        rn = construct_entities_block(entities_data)
        assert '### Indicator Types' in rn
        assert '- **accountRep**' in rn

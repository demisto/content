import json
import os
from distutils.version import LooseVersion
from typing import List, Dict, Optional, Any, Tuple

import pytest

from Tests.Marketplace.release_notes_bc_calculator import ReleaseNotesBreakingChangesCalc


class TestReleaseNotesBreakingChangesCalc:
    CHANGELOG_ENTRY_CONTAINS_BC_VERSION_INPUTS = [(LooseVersion('0.0.0'), LooseVersion('1.0.0'), [], dict(), dict()),
                                                  (
                                                      LooseVersion('0.0.0'), LooseVersion('1.0.0'),
                                                      [LooseVersion('1.0.1')], {'1.0.1': 'BC text'}, dict()),
                                                  (
                                                      LooseVersion('0.0.0'), LooseVersion('1.0.0'),
                                                      [LooseVersion('1.0.0')], {'1.0.0': None},
                                                      {'1.0.0': None}),
                                                  (
                                                      LooseVersion('2.3.1'), LooseVersion('2.4.0'),
                                                      [LooseVersion('2.3.1')], {'2.3.1': 'BC text'},
                                                      dict()),
                                                  (LooseVersion('2.3.1'), LooseVersion('2.4.0'),
                                                   [LooseVersion('2.3.1'), LooseVersion('2.3.2')],
                                                   {'2.3.1': None, '2.3.2': 'BC Text 232'}, {'2.3.2': 'BC Text 232'})]

    @pytest.mark.parametrize('predecessor_version, rn_version, bc_versions_list,bc_version_to_text, expected',
                             CHANGELOG_ENTRY_CONTAINS_BC_VERSION_INPUTS)
    def test_changelog_entry_contains_bc_version(self, predecessor_version: LooseVersion, rn_version: LooseVersion,
                                                 bc_versions_list: List[LooseVersion],
                                                 bc_version_to_text, expected):
        """
           Given:
           - predecessor_version: Predecessor version of the changelog entry.
           - rn_version: RN version of the current processed changelog entry
            When:
            - Checking whether current 'rn_version' contains a BC version.
            Case a: Pack does not contain any BC versions.
            Case b: Pack contains BC versions, but not between 'predecessor_version' to 'rn_version' range.
            Case c: Pack contains BC versions, and it is the exact 'rn_version'.
            Case d: Pack contains BC versions, and it is the exact 'predecessor_version'.
            Case e: Pack contains BC versions, and it is the between 'predecessor_version' to 'rn_version' range.
           Then:
           Validate expected bool is returned.
           Case a: Validate false is returned.
           Case b: Validate false is returned.
           Case c: Validate true is returned, because there is a BC version that matches the
                   rule 'predecessor_version' < bc_version <= 'rn_version' (equals to 'rn_version').
           Case d: Validate false is returned, because there is no BC version that matches the
                   rule 'predecessor_version' < bc_version <= 'rn_version' (equals to 'predecessor_version' which is
                   outside range).
           Case e: Validate true is returned, because there is a BC version that matches the
                   rule 'predecessor_version' < bc_version <= 'rn_version' (above 'predecessor_version',
                   below 'rn_version').
       """
        assert ReleaseNotesBreakingChangesCalc._changelog_entry_bc_versions(
            predecessor_version, rn_version, bc_versions_list, bc_version_to_text) == expected

    def test_breaking_changes_versions_to_text(self, tmpdir):
        """
        Given:
        - Release notes directory (class field)

        When:
        - Creating dict of BC version to mapping. Including all possibilities:
        1) RN does not have corresponding config file.
        2) RN has corresponding config file, breakingChanges is set to true, text does not exist.
        3) RN has corresponding config file, breakingChanges is set to true, text exists.
        4) RN has corresponding config file, breakingChanges is set to false, text does not exist.
        5) RN has corresponding config file, breakingChanges is set to false, text exists.

        Then:
        - Ensure expected mapping is done.
        case 2 contains only breakingChanges: True entry.
        case 3 contains both breakingChanges: True and text entries.

        """
        rn_dir = f'{tmpdir}/ReleaseNotes'
        os.mkdir(rn_dir)
        create_rn_file(rn_dir, '1_0_1', 'some RN to see it is filtered by its extension')
        create_rn_config_file(rn_dir, '1_0_2', {'breakingChanges': True})
        create_rn_config_file(rn_dir, '1_0_3', {'breakingChanges': True, 'breakingChangesNotes': 'this is BC'})
        create_rn_config_file(rn_dir, '1_0_4', {'breakingChanges': False})
        create_rn_config_file(rn_dir, '1_0_5', {'breakingChanges': False, 'breakingChangesNotes': 'this is BC'})

        rn_bc_calc: ReleaseNotesBreakingChangesCalc = ReleaseNotesBreakingChangesCalc(rn_dir)

        expected: Dict[str, Optional[str]] = {'1.0.2': None, '1.0.3': 'this is BC'}

        assert rn_bc_calc._breaking_changes_versions_to_text() == expected

    SPLIT_BC_VERSIONS_WITH_AND_WITHOUT_TEXT_INPUTS = [(dict(), ([], [])),
                                                      ({'1.0.2': 'bc text 1'}, (['bc text 1'], [])),
                                                      ({'1.0.2': None}, ([], ['1.0.2'])),
                                                      ({'1.0.2': None, '1.0.4': None, '1.0.5': 'txt1', '1.0.6': 'txt2'},
                                                       (['txt1', 'txt2'], ['1.0.2', '1.0.4'])),
                                                      ]

    @pytest.mark.parametrize('bc_versions, expected', SPLIT_BC_VERSIONS_WITH_AND_WITHOUT_TEXT_INPUTS)
    def test_split_bc_versions_with_and_without_text(self, bc_versions: Dict[str, Optional[str]],
                                                     expected: Tuple[List[str], List[str]]):
        """
        Given:
        - 'bc_versions': Dict of BC versions to text.

        When:
        - Splitting 'bc_versions' to two lists of versions with/without text.

        Then:
        - Ensure expected results are returned.
        """
        assert ReleaseNotesBreakingChangesCalc._split_bc_versions_with_and_without_text(bc_versions) == expected

    def test_get_release_notes_concat_str_non_empty(self, tmpdir):
        """
        Given:
        - 'bc_versions': Dict of BC versions to text.

        When:
        - Splitting 'bc_versions' to two lists of versions with/without text.

        Then:
        - Ensure expected results are returned.
        """
        rn_dir: str = f'{tmpdir}/ReleaseNotes'
        os.mkdir(rn_dir)
        create_rn_file(rn_dir, '1_0_1', 'txt1')
        create_rn_file(rn_dir, '1_0_2', 'txt2')
        rn_bc_calc: ReleaseNotesBreakingChangesCalc = ReleaseNotesBreakingChangesCalc(rn_dir)
        assert rn_bc_calc._get_release_notes_concat_str(['1_0_1.md', '1_0_2.md']) == '\ntxt1\ntxt2'

    def test_get_release_notes_concat_str_empty(self):
        """
        Given:
        - 'bc_versions': Empty dict of BC versions to text.

        When:
        - Splitting 'bc_versions' to two lists of versions with/without text.

        Then:
        - Ensure empty results are returned.
        """
        rn_bc_calc: ReleaseNotesBreakingChangesCalc = ReleaseNotesBreakingChangesCalc('')
        assert rn_bc_calc._get_release_notes_concat_str([]) == ''

    def test_handle_many_bc_versions_some_with_text(self, tmpdir):
        """
        Given:
        - 'text_of_bc_versions': Text of BC versions containing specific BC text.
        - 'bc_versions_without_text': BC versions that do not contain specific BC text

        When:
        - Handling a case were one aggregated changelog entry contains both BCs with text and without text.

        Then:
        - Ensure expected test is returned
        """
        rn_dir: str = f'{tmpdir}/ReleaseNotes'
        os.mkdir(rn_dir)
        create_rn_file(rn_dir, '1_0_2', 'no bc1')
        create_rn_file(rn_dir, '1_0_6', 'no bc2')
        text_of_bc_versions: List[str] = ['txt1', 'txt2']
        bc_versions_without_text: List[str] = ['1.0.2', '1.0.6']

        rn_bc_calc: ReleaseNotesBreakingChangesCalc = ReleaseNotesBreakingChangesCalc(rn_dir)

        expected_concat_str: str = 'txt1\ntxt2\nno bc1\nno bc2'
        assert rn_bc_calc._handle_many_bc_versions_some_with_text(text_of_bc_versions,
                                                                  bc_versions_without_text) == expected_concat_str

    CALCULATE_BC_TEXT_NON_MIXED_CASES_INPUTS = [(dict(), None), ({'1.0.2': None}, None), ({'1.0.2': 'txt1'}, 'txt1'),
                                                ({'1.0.2': 'txt1', '1.0.4': 'txt5'}, 'txt1\ntxt5')]

    @pytest.mark.parametrize('bc_version_to_text, expected', CALCULATE_BC_TEXT_NON_MIXED_CASES_INPUTS)
    def test_calculate_bc_text_non_mixed_cases(self, bc_version_to_text: Dict[str, Optional[str]],
                                               expected: Optional[str]):
        """
        Given:
        - 'text_of_bc_versions': Text of BC versions containing specific BC text.

        When:
        - Calculating text for changelog entry
        Case a: Only one BC in aggregated changelog entry:
        Case b: More than one BC in aggregated entry, all of them containing text.

        Then:
        - Ensure expected text is returned.

        """
        rn_bc_calc: ReleaseNotesBreakingChangesCalc = ReleaseNotesBreakingChangesCalc('')
        assert rn_bc_calc._calculate_bc_text(bc_version_to_text) == expected

    def test_calculate_bc_text_mixed_case(self, tmpdir):
        """
        Given:
        - 'text_of_bc_versions': Text of BC versions containing specific BC text.

        When:
        - Handling a case were one aggregated changelog entry contains both BCs with text and without text.

        Then:
        - Ensure expected text is returned
        """
        rn_dir: str = f'{tmpdir}/ReleaseNotes'
        os.mkdir(rn_dir)
        create_rn_file(rn_dir, '1_0_2', 'bc notes without bc text')
        create_rn_file(rn_dir, '1_0_6', 'RN for 1_0_6')
        create_rn_config_file(rn_dir, '1_0_2', {'breakingChanges': True})
        create_rn_config_file(rn_dir, '1_0_6', {'breakingChanges': True, 'breakingChangesNotes': 'bc txt2'})

        rn_bc_calc: ReleaseNotesBreakingChangesCalc = ReleaseNotesBreakingChangesCalc(rn_dir)

        expected_text: str = 'bc txt2\nbc notes without bc text'
        assert rn_bc_calc._calculate_bc_text(bc_version_to_text={'1_0_2': None, '1_0_6': 'bc txt2'}) == expected_text

    def test_add_bc_entries_if_needed(self, tmpdir):
        """
       Given:
       - changelog: Changelog file data represented as a dictionary.

        When:
        - Updating 'breakingChanges' entry for each changelog dict entry.

       Then:
        - Validate changelog 'breakingChanges' field for each entries are updated as expected. This test includes
          all four types of possible changes:
          a) Entry without breaking changes, changes to entry with breaking changes.
          b) Entry without breaking changes, changes to entry with breaking changes containing BC text.
          c) Entry without breaking changes, does not change.
          d) Entry with breaking changes, changes to entry without breaking changes.
          e) Entry with breaking changes, changes to entry with BC text.
          f) Entry with breaking changes, changes to entry without BC text.
       """
        rn_dir = f'{tmpdir}/ReleaseNotes'
        os.mkdir(rn_dir)
        for i in range(17, 26):
            create_rn_file(rn_dir, f'1.12.{i}', f'RN of 1.12.{i}')
        create_rn_config_file(rn_dir, '1_12_20', {'breakingChanges': True})
        create_rn_config_file(rn_dir, '1_12_22', {'breakingChanges': True})
        create_rn_config_file(rn_dir, '1_12_24', {'breakingChanges': True, 'breakingChangesNotes': 'bc 24'})
        create_rn_config_file(rn_dir, '1_12_25', {'breakingChanges': True, 'breakingChangesNotes': 'bc 25'})
        changelog: Dict[str, Any] = {
            '1.12.20': {
                'releaseNotes': 'RN of 1.12.20',
                'displayName': '1.12.18 - 392682',
                'released': '2021-07-05T02:00:02Z',
                'breakingChanges': True
            },
            '1.12.17': {
                'releaseNotes': 'RN of 1.12.17',
                'displayName': '1.12.17 - 392184',
                'released': '2021-07-02T23:15:52Z',
                'breakingChanges': True
            },
            '1.12.16': {
                'releaseNotes': 'RN of 1.12.16',
                'displayName': '1.12.16 - 391562',
                'released': '2021-06-30T23:32:59Z'
            },
            '1.12.23': {
                'releaseNotes': 'RN of 1.12.23',
                'displayName': '1.12.23 - 393823',
                'released': '2021-07-06T23:27:59Z'
            },
            '1.12.24': {
                'releaseNotes': 'RN of 1.12.23',
                'displayName': '1.12.23 - 393823',
                'released': '2021-07-06T23:27:59Z',
                'breakingChanges': True
            },
            '1.12.25': {
                'releaseNotes': 'RN of 1.12.23',
                'displayName': '1.12.23 - 393823',
                'released': '2021-07-06T23:27:59Z',
            }
        }
        expected_changelog: Dict[str, Any] = {
            '1.12.20': {
                'releaseNotes': 'RN of 1.12.20',
                'displayName': '1.12.18 - 392682',
                'released': '2021-07-05T02:00:02Z',
                'breakingChanges': True
            },
            '1.12.17': {
                'releaseNotes': 'RN of 1.12.17',
                'displayName': '1.12.17 - 392184',
                'released': '2021-07-02T23:15:52Z'
            },
            '1.12.16': {
                'releaseNotes': 'RN of 1.12.16',
                'displayName': '1.12.16 - 391562',
                'released': '2021-06-30T23:32:59Z'
            },
            '1.12.23': {
                'releaseNotes': 'RN of 1.12.23',
                'displayName': '1.12.23 - 393823',
                'released': '2021-07-06T23:27:59Z',
                'breakingChanges': True
            },
            '1.12.24': {
                'releaseNotes': 'RN of 1.12.23',
                'displayName': '1.12.23 - 393823',
                'released': '2021-07-06T23:27:59Z',
                'breakingChanges': True,
                'breakingChangesNotes': 'bc 24'
            },
            '1.12.25': {
                'releaseNotes': 'RN of 1.12.23',
                'displayName': '1.12.23 - 393823',
                'released': '2021-07-06T23:27:59Z',
                'breakingChanges': True,
                'breakingChangesNotes': 'bc 25'
            }
        }
        rn_bc_calc: ReleaseNotesBreakingChangesCalc = ReleaseNotesBreakingChangesCalc(rn_dir)
        rn_bc_calc.add_bc_entries_if_needed(changelog)
        assert changelog == expected_changelog

    def test_add_bc_entries_if_needed_rn_dir_does_not_exist(self):
        """
       Given:
       - Changelog

        When:
        - Updating changelog entries with BC entries. RN dir does not exist

       Then:
        - Ensure no modification is done to the changelog.
       """
        rn_bc_calc: ReleaseNotesBreakingChangesCalc = ReleaseNotesBreakingChangesCalc('not_real_path')
        changelog: Dict = {'a': 1}
        rn_bc_calc.add_bc_entries_if_needed(changelog)
        assert changelog == {'a': 1}

    def test_update_changelog_with_bc_empty(self, dummy_pack):
        """
       Given:
       - Empty changelog file

        When:
        - Updating 'breakingChanges' entry for each changelog dict entry.

       Then:
        - Ensure empty changelog is returned as expected.
       """
        changelog: Dict[str, Any] = dict()
        dummy_pack.update_changelog_with_bc(changelog)
        assert changelog == dict()


def create_rn_config_file(rn_dir: str, version: str, data: Dict):
    with open(f'{rn_dir}/{version}.json', 'w') as f:
        f.write(json.dumps(data))


def create_rn_file(rn_dir: str, version: str, text: str):
    with open(f'{rn_dir}/{version}.md', 'w') as f:
        f.write(text)

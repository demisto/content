import logging
import os
from distutils.version import LooseVersion
from typing import Dict, Optional, List, Any, Tuple

import Tests.Marketplace.marketplace_services as mps


class ReleaseNotesBreakingChangesCalc:
    def __init__(self, release_notes_dir: str):
        self.release_notes_dir: str = release_notes_dir

    def add_bc_entries_if_needed(self, changelog: Dict[str, Any]) -> None:
        """
        Receives changelog, checks if there exists a BC version in each changelog entry (as changelog entry might be
        zipped into few RN versions, check if at least one of the versions is BC).
        Check if RN is BC is done by doing the following:
         1) Check if RN has corresponding config file, e.g 1_0_1.md has corresponding 1_0_1.json file.
         2) If it does, check if `isBreakingChanges` field is true
        If such version exists, adds a
        true value to 'breakingChanges' field.
        if JSON file also has breakingChangesNotes configures, adds `breakingChangesNotes` field to changelog file.
        This function iterates every entry in changelog because it takes into consideration four scenarios:
          a) Entry without breaking changes, changes to entry with breaking changes (because at least one of the
             versions in the entry was marked as breaking changes).
          b) Entry without breaking changes, does not change.
          c) Entry with breaking changes, changes to entry without breaking changes (because all the BC versions
             corresponding to the changelog entry were re-marked as not BC).
          d) Entry with breaking changes, does not change.
        Args:
            changelog (Dict[str, Any]): Changelog data represented as a dict.

        Returns:
            (None): Modifies changelog, adds bool value to 'breakingChanges' and `breakingChangesNotes` fields to every
             changelog entry, according to the logic described above.
        """
        if not os.path.exists(self.release_notes_dir):
            return
        bc_version_to_text: Dict[str, Optional[str]] = self._breaking_changes_versions_to_text()
        loose_versions: List[LooseVersion] = [LooseVersion(bc_ver) for bc_ver in bc_version_to_text.keys()]
        predecessor_version: LooseVersion = LooseVersion('0.0.0')
        for rn_version in sorted(changelog.keys(), key=LooseVersion):
            rn_loose_version: LooseVersion = LooseVersion(rn_version)
            if bc_versions := self._changelog_entry_bc_versions(predecessor_version, rn_loose_version, loose_versions,
                                                                bc_version_to_text):
                changelog[rn_version]['breakingChanges'] = True
                if bc_text := self._calculate_bc_text(bc_versions):
                    changelog[rn_version]['breakingChangesNotes'] = bc_text
                else:
                    changelog[rn_version].pop('breakingChangesNotes', None)
            else:
                changelog[rn_version].pop('breakingChanges', None)
            predecessor_version = rn_loose_version

    def _calculate_bc_text(self, bc_version_to_text: Dict[str, Optional[str]]) -> Optional[str]:
        """
        Receives BC versions to dict for current changelog entry. Calculates text for for BC entry.
        Args:
            bc_version_to_text (Dict[str, Optional[str]): {bc version, bc_text}

        Returns:
            (Optional[str]): Text for entry if such was added.
            If none is returned, server will list the full RN as the BC notes instead.
        """
        # Handle cases of one BC version in entry.
        if len(bc_version_to_text) == 1:
            return list(bc_version_to_text.values())[0]
        # Handle cases of more two or more BC versions in entry.
        text_of_bc_versions, bc_without_text = self._split_bc_versions_with_and_without_text(bc_version_to_text)
        # Case one: Not even one BC version contains breaking text.
        if len(text_of_bc_versions) == 0:
            return None
        # Case two: Only part of BC versions contains breaking text.
        elif len(text_of_bc_versions) < len(bc_version_to_text):
            return self._handle_many_bc_versions_some_with_text(text_of_bc_versions, bc_without_text)
        # Case 3: All BC versions contains text.
        else:
            # Important: Currently, implementation of aggregating BCs was decided to concat between them
            # In the future this might be needed to re-thought.
            return '\n'.join(bc_version_to_text.values())

    def _handle_many_bc_versions_some_with_text(self, text_of_bc_versions: List[str],
                                                bc_versions_without_text: List[str], ) -> str:
        """
        Calculates text for changelog entry where some BC versions contain text and some don't.
        Important: Currently, implementation of aggregating BCs was decided to concat between them (and if BC version
        does not have a BC text - concat the whole RN). In the future this might be needed to re-thought.
        Args:
            text_of_bc_versions ([List[str]): List of text of BC versions with text.
            bc_versions_without_text ([List[str]): List of BC versions without text.

        Returns:
            (str): Text for BC entry.
        """
        bc_with_text_str = '\n'.join(text_of_bc_versions)
        rn_file_names_without_text = [f'''{bc_version.replace('.', '_')}.md''' for
                                      bc_version in bc_versions_without_text]
        other_rn_text: str = self._get_release_notes_concat_str(rn_file_names_without_text)
        if not other_rn_text:
            logging.error('No RN text, although text was expected to be found for versions'
                          f' {rn_file_names_without_text}.')
        return f'{bc_with_text_str}{other_rn_text}'

    def _get_release_notes_concat_str(self, rn_file_names: List[str]) -> str:
        """
        Concat all RN data found in given `rn_file_names`
        Args:
            rn_file_names (List[str]): List of all RN files to concat their data.

        Returns:
            (str): Concat RN data
        """
        concat_str: str = ''
        for rn_file_name in rn_file_names:
            rn_file_path = os.path.join(self.release_notes_dir, rn_file_name)
            with open(rn_file_path, 'r') as f:
                # Will make the concat string start with new line on purpose.
                concat_str = f'{concat_str}\n{f.read()}'
        return concat_str

    @staticmethod
    def _split_bc_versions_with_and_without_text(bc_versions: Dict[str, Optional[str]]) -> Tuple[List[str], List[str]]:
        """
        Splits BCs to tuple of BCs text of BCs containing text, and BCs versions that do not contain BC text.
        Args:
            bc_versions (Dict[str, Optional[str]): BC versions mapped to text if exists.

        Returns:
            (Tuple[List[str], List[str]]): (text of bc versions with text, bc_versions_without_text).
        """
        text_of_bc_versions_with_tests: List[str] = []
        bc_versions_without_text: List[str] = []
        for bc_version, bc_text in bc_versions.items():
            if bc_text:
                text_of_bc_versions_with_tests.append(bc_text)
            else:
                bc_versions_without_text.append(bc_version)
        return text_of_bc_versions_with_tests, bc_versions_without_text

    def _breaking_changes_versions_to_text(self) -> Dict[str, Optional[str]]:
        """
        Calculates every BC version in given RN dir and maps it to text if exists.
        Args:

        Returns:
            (Dict[str, Optional[str]]): {dotted_version, text}.
        """
        bc_version_to_text: Dict[str, Optional[str]] = dict()
        # Get all config files in RN dir
        rn_config_file_names = mps.filter_dir_files_by_extension(self.release_notes_dir, '.json')

        for file_name in rn_config_file_names:
            file_data: Dict = mps.load_json(os.path.join(self.release_notes_dir, file_name))
            # Check if version is BC
            if file_data.get('breakingChanges', False):
                # Processing name for easier calculations later on
                processed_name: str = mps.underscore_file_name_to_dotted_version(file_name)
                bc_version_to_text[processed_name] = file_data.get('breakingChangesNotes')
        return bc_version_to_text

    @staticmethod
    def _changelog_entry_bc_versions(predecessor_version: LooseVersion, rn_version: LooseVersion,
                                     breaking_changes_versions: List[LooseVersion],
                                     bc_version_to_text: Dict[str, Optional[str]]) -> Dict[str, Optional[str]]:
        """
        Gets all BC versions of given changelog entry, every BC s.t predecessor_version < BC version <= rn_version.
        Args:
            predecessor_version (LooseVersion): Predecessor version in numeric version order.
            rn_version (LooseVersion): RN version of current processed changelog entry.
            breaking_changes_versions (List[str]): List of BC versions, of dotted format `x.x.x`.
            bc_version_to_text (Dict[str, Optional[str]): List of all BC to text in the given RN dir.

        Returns:
            Dict[str, Optional[str]]: Partial list of `bc_version_to_text`, containing only relevant versions between
                                      given versions.
        """
        return {bc_ver.vstring: bc_version_to_text.get(bc_ver.vstring) for bc_ver in breaking_changes_versions if
                predecessor_version < bc_ver <= rn_version}

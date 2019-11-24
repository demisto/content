import os
import re
from abc import abstractmethod

from Tests.scripts.error_constants import Errors
from Tests.scripts.hook_validations.structure import StructureValidator
from Tests.test_utils import print_error, print_warning, get_release_notes_file_path, get_latest_release_notes_text, \
    run_command


class BaseValidator(object):
    DEFAULT_VERSION = -1

    def __init__(self, structure_validator):
        # type: (StructureValidator) -> None
        self.structure_validator = structure_validator
        self.current_file = structure_validator.current_file
        self.old_file = structure_validator.old_file
        self.file_path = structure_validator.file_path
        self.is_valid = structure_validator.is_valid

    def is_valid_file(self, validate_rn=True):
        tests = [
            self.is_valid_version()
        ]
        # In case of release branch we allow to remove release notes
        if validate_rn and not self.is_release_branch():
            tests.append(self.is_there_release_notes())
        return all(tests)

    @abstractmethod
    def is_valid_version(self):
        # type: () -> bool
        pass

    def _is_valid_version(self):
        # type: () -> bool
        """Base is_valid_version method for files that version is their root.

        Return:
            True if version is valid, else False
        """
        if self.current_file.get('version') != self.DEFAULT_VERSION:
            print_error(Errors.wrong_version(self.file_path, self.DEFAULT_VERSION))
            self.is_valid = False
            return False
        return True

    def is_there_release_notes(self):
        """Validate that the file has proper release notes when modified.
        This function updates the class attribute self._is_valid instead of passing it back and forth.

        Returns:
            (bool): is there release notes
        """
        if self.structure_validator.is_renamed:
            print_warning(Errors.might_need_release_notes(self.file_path))
            return True

        if os.path.isfile(self.file_path):
            rn_path = get_release_notes_file_path(self.file_path)
            release_notes = get_latest_release_notes_text(rn_path)

            # check release_notes file exists and contain text
            if release_notes is None:
                print_error(Errors.missing_release_notes(self.file_path, rn_path))
                self.is_valid = False
                return False
        return True

    @staticmethod
    def is_release_branch():
        # type: () -> bool
        """Check if we are working on a release branch.

        Returns:
            (bool): is release branch
        """
        diff_string_config_yml = run_command("git diff origin/master .circleci/config.yml")
        if re.search(r'[+-][ ]+CONTENT_VERSION: ".*', diff_string_config_yml):
            return True
        return False

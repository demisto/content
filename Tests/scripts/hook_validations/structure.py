import os
import re
import sys
import json
import yaml

from Tests.scripts.constants import *
from Tests.test_utils import print_error, print_warning, run_command, get_json, checked_type

try:
    from pykwalify.core import Core
except ImportError:
    print "Please install pykwalify, you can do it by running: `pip install -I pykwalify`"
    sys.exit(1)


class StructureValidator(object):
    """Structure validator is designed to validate the correctness of the file structure we enter to content repo.

    Attributes:
        _is_valid (bool): the attribute which saves the valid/in-valid status of the current file.
        file_path (str): the path to the file we are examining at the moment.
        is_added_file (bool): whether the file is modified or added.
    """
    SKIPPED_SCHEMAS = [MISC_REGEX, REPORT_REGEX]
    REGEXES_TO_SCHEMA_DICT = {
        INTEGRATION_REGEX: "integration",
        INTEGRATION_YML_REGEX: "integration",
        PLAYBOOK_REGEX: "playbook",
        TEST_PLAYBOOK_REGEX: "test-playbook",
        SCRIPT_REGEX: "script",
        SCRIPT_YML_REGEX: "script",
        WIDGETS_REGEX: "widget",
        DASHBOARD_REGEX: "dashboard",
        CONNECTIONS_REGEX: "canvas-context-connections",
        CLASSIFIER_REGEX: "classifier",
        LAYOUT_REGEX: "layout",
        INCIDENT_FIELDS_REGEX: "incidentfields",
        INCIDENT_FIELD_REGEX: "incidentfield"
    }

    SCHEMAS_PATH = "Tests/schemas/"

    def __init__(self, file_path, is_added_file=False, is_renamed=False):
        self._is_valid = True
        self.file_path = file_path
        self.is_added_file = is_added_file
        self.is_renamed = is_renamed

    def is_file_valid(self):
        """Check if the file as a valid structure.

        Returns:
            bool. Whether the file's structure is valid or not.
        """
        self.is_valid_scheme()
        self.is_valid_version()

        if not self.is_added_file:  # In case the file is modified
            self.is_id_not_modified()
            self.is_valid_fromversion_on_modified()

            if not self.is_release_branch():  # In case of release branch we allow to remove release notes
                self.validate_file_release_notes()

        return self._is_valid

    def is_valid_scheme(self, matching_regex=None):
        """Validate the file scheme according to the scheme we have saved in SCHEMAS_PATH.

        Args:
            matching_regex (str): the regex we want to compare the file with.

        Returns:
            bool. Whether the scheme is valid on self.file_path.
        """
        if matching_regex is None:
            for regex in CHECKED_TYPES_REGEXES:
                if re.match(regex, self.file_path, re.IGNORECASE):
                    matching_regex = regex
                    break

        if matching_regex not in self.SKIPPED_SCHEMAS or os.path.isfile(self.file_path):
            if matching_regex is not None and self.REGEXES_TO_SCHEMA_DICT.get(matching_regex):
                c = Core(source_file=self.file_path,
                         schema_files=[self.SCHEMAS_PATH + self.REGEXES_TO_SCHEMA_DICT.get(matching_regex) + '.yml'])
                try:
                    c.validate(raise_exception=True)
                except Exception as err:
                    print_error('Failed: %s failed' % (self.file_path,))
                    print_error(err)
                    self._is_valid = False
            else:
                print(self.file_path + " doesn't match any of the known supported file prefix/suffix,"
                                       " please make sure that its naming is correct.")
                self._is_valid = False

        return self._is_valid

    @staticmethod
    def validate_reputations_file(json_dict):
        """Validate that the reputations file as version of -1."""
        is_valid = True
        reputations = json_dict.get('reputations')
        for reputation in reputations:
            internal_version = reputation.get('version')
            if internal_version != -1:
                object_id = reputation.get('id')
                print_error("Reputation object with id {} must have version -1".format(object_id))
                is_valid = False

        return is_valid

    def is_valid_version(self):
        """Validate that the version of self.file_path is -1."""
        file_extension = os.path.splitext(self.file_path)[1]
        version_number = -1
        reputations_valid = True
        if file_extension == '.yml':
            yaml_dict = get_json(self.file_path)
            version_number = yaml_dict.get('commonfields', {}).get('version')
            if not version_number:  # some files like playbooks do not have commonfields key
                version_number = yaml_dict.get('version')

        elif file_extension == '.json':
            if checked_type(self.file_path):
                file_name = os.path.basename(self.file_path)
                json_dict = get_json(self.file_path)
                if file_name == "reputations.json":
                    reputations_valid = self.validate_reputations_file(json_dict)
                else:
                    version_number = json_dict.get('version')

        if version_number != -1 or not reputations_valid:
            print_error("The version for our files should always be -1, "
                        "please update the file {}.".format(self.file_path))
            self._is_valid = False

        return self._is_valid

    def is_valid_fromversion_on_modified(self, change_string=None):
        """Check that the fromversion property was not changed on existing Content files.

        Args:
            change_string (string): the string that indicates the changed done on the file(git diff)

        Returns:
            bool. Whether the files' fromversion as been modified or not.
        """
        if self.is_renamed:
            print_warning("fromversion might have been modified, please make sure it hasn't changed.")
            return True

        if not change_string:
            change_string = run_command("git diff HEAD {0}".format(self.file_path))

        is_added_from_version = re.search("\+([ ]+)?fromversion: .*", change_string)
        is_added_from_version_secondary = re.search("\+([ ]+)?\"fromVersion\": .*", change_string)

        if is_added_from_version or is_added_from_version_secondary:
            print_error("You've added fromversion to an existing file in the system, this is not allowed, please undo. "
                        "the file was {}.".format(self.file_path))
            self._is_valid = False

        return self._is_valid

    @staticmethod
    def is_release_branch():
        """Check if we are working on a release branch."""
        diff_string_config_yml = run_command("git diff origin/master .circleci/config.yml")
        if re.search('[+-][ ]+CONTENT_VERSION: ".*', diff_string_config_yml):
            return True

        return False

    def validate_file_release_notes(self):
        """Validate that the file has proper release notes when modified.

        This function updates the class attribute self._is_valid instead of passing it back and forth.
        """
        if self.is_renamed:
            print_warning("You might need RN please make sure to check that.")
            return

        data_dictionary = None
        if os.path.isfile(self.file_path):
            with open(os.path.expanduser(self.file_path), "r") as f:
                if self.file_path.endswith(".json"):
                    data_dictionary = json.load(f)
                elif self.file_path.endswith(".yaml") or self.file_path.endswith('.yml'):
                    try:
                        data_dictionary = yaml.safe_load(f)
                    except Exception as e:
                        print_error(self.file_path + " has yml structure issue. Error was: " + str(e))
                        self._is_valid = False

            if data_dictionary and data_dictionary.get('releaseNotes') is None:
                print_error("File " + self.file_path + " is missing releaseNotes, please add.")
                self._is_valid = False

    def is_id_not_modified(self, change_string=None):
        """Check if the ID of the file has been changed.

        Args:
            change_string (string): the string that indicates the changes done on the file(git diff)

        Returns:
            bool. Whether the file's ID has been modified or not.
        """
        if self.is_renamed:
            print_warning("ID might have changed, please make sure to check you have the correct one.")
            return True

        if not change_string:
            change_string = run_command("git diff HEAD {}".format(self.file_path))

        if re.search("[+-](  )?id: .*", change_string):
            print_error("You've changed the ID of the file {0} please undo.".format(self.file_path))
            self._is_valid = False

        return self._is_valid

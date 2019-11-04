import json
import yaml
import os
import sys

from Tests.scripts.constants import *
from Tests.test_utils import print_error, print_warning, run_command, get_yaml, get_json, checked_type, \
    get_release_notes_file_path, get_latest_release_notes_text

try:
    from pykwalify.core import Core
except ImportError:
    print('Please install pykwalify, you can do it by running: `pip install -I pykwalify`')
    sys.exit(1)


class StructureValidator(object):
    """Structure validator is designed to validate the correctness of the file structure we enter to content repo.

    Attributes:
        _is_valid (bool): the attribute which saves the valid/in-valid status of the current file.
        file_path (str): the path to the file we are examining at the moment.
        is_added_file (bool): whether the file is modified or added.
    """
    VERSION_SCHEMAS = [
        INTEGRATION_REGEX,
        PLAYBOOK_REGEX,
        SCRIPT_REGEX,
        INTEGRATION_YML_REGEX,
        WIDGETS_REGEX,
        DASHBOARD_REGEX,
        CLASSIFIER_REGEX,
        SCRIPT_YML_REGEX,
        INCIDENT_FIELD_REGEX,
        MISC_REGEX,
        REPUTATION_REGEX
    ]
    SKIPPED_SCHEMAS = [
        TEST_DATA_REGEX,
        MISC_REGEX,
        IMAGE_REGEX,
        DESCRIPTION_REGEX,
        PIPFILE_REGEX,
        REPORT_REGEX,
        SCRIPT_PY_REGEX,
        SCRIPT_JS_REGEX,
        INTEGRATION_JS_REGEX,
        INTEGRATION_PY_REGEX,
        REPUTATION_REGEX,
        BETA_INTEGRATION_YML_REGEX,
        BETA_INTEGRATION_REGEX,
        BETA_SCRIPT_REGEX,
        BETA_PLAYBOOK_REGEX,
    ]
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
        INCIDENT_FIELD_REGEX: "incidentfield",
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
        self.is_file_id_without_slashes()

        if not self.is_added_file:  # In case the file is modified
            self.is_id_not_modified()
            self.is_valid_fromversion_on_modified()
            # In case of release branch we allow to remove release notes
            if not self.is_release_branch() and not self._is_beta_integration():
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
            for regex in self.SKIPPED_SCHEMAS:
                if re.match(regex, self.file_path, re.IGNORECASE):
                    return True

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
                    print_error(str(err))
                    self._is_valid = False
            else:
                print_error(self.file_path + " doesn't match any of the known supported file prefix/suffix,"
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

    @staticmethod
    def validate_layout_file(json_dict):
        """Validate that the layout file has version of -1."""
        is_valid = True
        layout = json_dict.get('layout')
        if layout.get('version') != -1:
            is_valid = False

        return is_valid

    def is_valid_version(self):
        """Validate that the version of self.file_path is -1."""
        file_extension = os.path.splitext(self.file_path)[1]
        version_number = -1
        reputations_valid = True
        layouts_valid = True
        if file_extension == '.yml':
            yaml_dict = get_yaml(self.file_path)
            version_number = yaml_dict.get('commonfields', {}).get('version')
            if not version_number:  # some files like playbooks do not have commonfields key
                version_number = yaml_dict.get('version')

        elif file_extension == '.json':
            if checked_type(self.file_path, self.VERSION_SCHEMAS):
                file_name = os.path.basename(self.file_path)
                json_dict = get_json(self.file_path)
                if file_name == "reputations.json":
                    reputations_valid = self.validate_reputations_file(json_dict)
                elif re.match(LAYOUT_REGEX, self.file_path, re.IGNORECASE):
                    layouts_valid = self.validate_layout_file(json_dict)
                else:
                    version_number = json_dict.get('version')

        if version_number != -1 or not reputations_valid or not layouts_valid:
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

        is_added_from_version = re.search(r"\+([ ]+)?fromversion: .*", change_string)
        is_added_from_version_secondary = re.search(r"\+([ ]+)?\"fromVersion\": .*", change_string)

        if is_added_from_version or is_added_from_version_secondary:
            print_error("You've added fromversion to an existing file in the system, this is not allowed, please undo. "
                        "the file was {}.".format(self.file_path))
            self._is_valid = False

        return self._is_valid

    @staticmethod
    def is_release_branch():
        """Check if we are working on a release branch."""
        diff_string_config_yml = run_command("git diff origin/master .circleci/config.yml")
        if re.search(r'[+-][ ]+CONTENT_VERSION: ".*', diff_string_config_yml):
            return True

        return False

    def _is_beta_integration(self):
        """Checks if file is under Beta_integration dir"""
        return re.match(BETA_INTEGRATION_REGEX, self.file_path, re.IGNORECASE) or \
            re.match(BETA_INTEGRATION_YML_REGEX, self.file_path, re.IGNORECASE)

    def validate_file_release_notes(self):
        """Validate that the file has proper release notes when modified.

        This function updates the class attribute self._is_valid instead of passing it back and forth.
        """
        if self.is_renamed:
            print_warning("You might need RN please make sure to check that.")
            return

        if os.path.isfile(self.file_path):
            rn_path = get_release_notes_file_path(self.file_path)
            rn = get_latest_release_notes_text(rn_path)

            # check rn file exists and contain text
            if rn is None:
                print_error('File {} is missing releaseNotes, Please add it under {}'.format(self.file_path, rn_path))
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

    def load_data_from_file(self):
        file_type_suffix_to_loading_func = {
            '.yml': yaml.safe_load,
            '.json': json.load,
        }

        file_extension = os.path.splitext(self.file_path)[1]
        if file_extension not in file_type_suffix_to_loading_func:
            print_error("An unknown error has occurred. Please retry.")

        load_function = file_type_suffix_to_loading_func[file_extension]
        with open(self.file_path, 'r') as file_obj:
            loaded_file_data = load_function(file_obj)
            return loaded_file_data

    @staticmethod
    def get_file_id_from_loaded_file_data(loaded_file_data):
        file_id = loaded_file_data.get('id')
        if not file_id:
            # In integrations/scripts, the id is under 'commonfields'.
            file_id = loaded_file_data.get('commonfields', {}).get('id')
        if not file_id:
            # In layout, the id is under 'layout'.
            file_id = loaded_file_data.get('layout', {}).get('id')

        return file_id

    def is_file_id_without_slashes(self):
        """Check if the ID of the file contains any slashes ('/').

        Returns:
            bool. Whether the file's ID contains slashes or not.
        """
        loaded_file_data = self.load_data_from_file()
        file_id = self.get_file_id_from_loaded_file_data(loaded_file_data)
        if (not file_id and loaded_file_data['name'] == 'reputations'):
            return True
        if not file_id or '/' in file_id:
            self._is_valid = False
            print_error("File's ID contains slashes - please remove.")
            return False
        return True

"""
This script is used to validate the files in Content repository. Specifically for each file:
1) Proper prefix
2) Proper suffix
3) Valid yml/json schema
4) Having ReleaseNotes if applicable.

It can be run to check only commited changes (if the first argument is 'true') or all the files in the repo.
Note - if it is run for all the files in the repo it won't check releaseNotes, use `setContentDescriptor.sh`
for that task.
"""
import glob
import sys
try:
    import yaml
except ImportError:
    print "Please install pyyaml, you can do it by running: `pip install pyyaml`"
    sys.exit(1)
try:
    from pykwalify.core import Core
except ImportError:
    print "Please install pykwalify, you can do it by running: `pip install -I pykwalify`"
    sys.exit(1)

import re
import os
import json
import argparse
from subprocess import Popen, PIPE
from distutils.version import LooseVersion

# from secrets import get_secrets
from Tests.scripts.hook_validations.script import ScriptValidator
from Tests.scripts.hook_validations.integration import IntegrationValidator
from update_id_set import get_script_data, get_playbook_data, get_integration_data, get_script_package_data

# Magic Numbers
IMAGE_MAX_SIZE = 10 * 1024  # 10kB

# dirs
INTEGRATIONS_DIR = "Integrations"
SCRIPTS_DIR = "Scripts"
PLAYBOOKS_DIR = "Playbooks"
TEST_PLAYBOOKS_DIR = "TestPlaybooks"
REPORTS_DIR = "Reports"
DASHBOARDS_DIR = "Dashboards"
WIDGETS_DIR = "Widgets"
INCIDENT_FIELDS_DIR = "IncidentFields"
LAYOUTS_DIR = "Layouts"
CLASSIFIERS_DIR = "Classifiers"
MISC_DIR = "Misc"
CONNECTIONS_DIR = "Connections"

# file types regexes
IMAGE_REGEX = r".*\.png"
SCRIPT_YML_REGEX = r"{}.*\.yml".format(SCRIPTS_DIR)
SCRIPT_PY_REGEX = r"{}.*\.py".format(SCRIPTS_DIR)
SCRIPT_JS_REGEX = r"{}.*\.js".format(SCRIPTS_DIR)
INTEGRATION_YML_REGEX = r"{}.*\.yml".format(INTEGRATIONS_DIR)
INTEGRATION_REGEX = r"{}.*integration-.*\.yml".format(INTEGRATIONS_DIR)
PLAYBOOK_REGEX = r"{}.*playbook-.*\.yml".format(PLAYBOOKS_DIR)
TEST_SCRIPT_REGEX = r"{}.*script-.*\.yml".format(TEST_PLAYBOOKS_DIR)
TEST_PLAYBOOK_REGEX = r"{}.*playbook-.*\.yml".format(TEST_PLAYBOOKS_DIR)
SCRIPT_REGEX = r"{}.*script-.*\.yml".format(SCRIPTS_DIR)
WIDGETS_REGEX = r"{}.*widget-.*\.json".format(WIDGETS_DIR)
DASHBOARD_REGEX = r"{}.*dashboard-.*\.json".format(DASHBOARDS_DIR)
CONNECTIONS_REGEX = r"{}.*canvas-context-connections.*\.json".format(CONNECTIONS_DIR)
CLASSIFIER_REGEX = r"{}.*classifier-.*\.json".format(CLASSIFIERS_DIR)
LAYOUT_REGEX = r"{}.*layout-.*\.json".format(LAYOUTS_DIR)
INCIDENT_FIELDS_REGEX = r"{}.*incidentfields.*\.json".format(INCIDENT_FIELDS_DIR)
INCIDENT_FIELD_REGEX = r"{}.*incidentfield-.*\.json".format(INCIDENT_FIELDS_DIR)
MISC_REGEX = r"{}.*reputations.*\.json".format(MISC_DIR)
REPORT_REGEX = r"{}.*report-.*\.json".format(REPORTS_DIR)

CHECKED_TYPES_REGEXES = [INTEGRATION_REGEX, PLAYBOOK_REGEX, SCRIPT_REGEX, INTEGRATION_YML_REGEX,
                         WIDGETS_REGEX, DASHBOARD_REGEX, CONNECTIONS_REGEX, CLASSIFIER_REGEX, SCRIPT_YML_REGEX,
                         LAYOUT_REGEX, INCIDENT_FIELDS_REGEX, INCIDENT_FIELD_REGEX, MISC_REGEX, REPORT_REGEX]

SKIPPED_SCHEMAS = [MISC_REGEX, REPORT_REGEX]

KNOWN_FILE_STATUSES = ['a', 'm', 'd', 'r100']

REGEXES_TO_SCHEMA_DIC = {
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


DIRS = [INTEGRATIONS_DIR, SCRIPTS_DIR, PLAYBOOKS_DIR, REPORTS_DIR, DASHBOARDS_DIR, WIDGETS_DIR, INCIDENT_FIELDS_DIR,
        LAYOUTS_DIR, CLASSIFIERS_DIR, MISC_DIR]


class LOG_COLORS:
    NATIVE = '\033[m'
    RED = '\033[01;31m'
    GREEN = '\033[01;32m'


# print srt in the given color
def print_color(msg, color):
    print(str(color) + str(msg) + LOG_COLORS.NATIVE)


def print_error(error_str):
    print_color(error_str, LOG_COLORS.RED)


def run_git_command(command):
    p = Popen(command.split(), stdout=PIPE, stderr=PIPE)
    output, err = p.communicate()
    if err:
        print_error("Failed to run git command " + command)
        sys.exit(1)
    return output


def checked_type(file_path):
    for regex in CHECKED_TYPES_REGEXES:
        if re.match(regex, file_path, re.IGNORECASE):
            return True
    return False


def get_modified_files(files_string):
    all_files = files_string.split('\n')
    deleted_files = set([])
    added_files_list = set([])
    modified_files_list = set([])
    for f in all_files:
        file_data = f.split()
        if not file_data:
            continue

        file_status = file_data[0]
        file_path = file_data[1]

        if file_path.endswith('.js') or file_path.endswith('.py'):
            continue
        if file_status.lower() == 'm' and checked_type(file_path) and not file_path.startswith('.'):
            modified_files_list.add(file_path)
        elif file_status.lower() == 'a' and checked_type(file_path) and not file_path.startswith('.'):
            added_files_list.add(file_path)
        elif file_status.lower() == 'd' and checked_type(file_path) and not file_path.startswith('.'):
            deleted_files.add(file_path)
        elif file_status.lower() == 'r100' and checked_type(file_path):
            modified_files_list.add(file_data[2])
        elif file_status.lower() not in KNOWN_FILE_STATUSES:
            print_error(file_path + " file status is an unknown known one, "
                                    "please check. File status was: " + file_status)

    return modified_files_list, added_files_list, deleted_files


def get_script_or_integration_id(file_path):
    data_dictionary = get_json(file_path)

    if data_dictionary:
        commonfields = data_dictionary.get('commonfields', {})
        return commonfields.get('id', ['-', ])


def get_json(file_path):
    data_dictionary = None
    with open(os.path.expanduser(file_path), "r") as f:
        if file_path.endswith(".yaml") or file_path.endswith('.yml'):
            try:
                data_dictionary = yaml.safe_load(f)
            except Exception as e:
                print_error(file_path + " has yml structure issue. Error was: " + str(e))
                return []

    if type(data_dictionary) is dict:
        return data_dictionary
    else:
        return {}


def collect_ids(file_path):
    """Collect id mentioned in file_path"""
    data_dictionary = get_json(file_path)

    if data_dictionary:
        return data_dictionary.get('id', '-')


def get_modified_and_added_files(branch_name, is_circle):
    all_changed_files_string = run_git_command("git diff --name-status origin/master...{}".format(branch_name))
    modified_files, added_files, _ = get_modified_files(all_changed_files_string)

    if not is_circle:
        files_string = run_git_command("git diff --name-status --no-merges HEAD")

        non_committed_modified_files, non_committed_added_files, non_committed_deleted_files = \
            get_modified_files(files_string)
        all_changed_files_string = run_git_command("git diff --name-status origin/master")
        modified_files_from_master, added_files_from_master, _ = get_modified_files(all_changed_files_string)

        for mod_file in modified_files_from_master:
            if mod_file in non_committed_modified_files:
                modified_files.add(mod_file)

        for add_file in added_files_from_master:
            if add_file in non_committed_added_files:
                added_files.add(add_file)

        for deleted_file in non_committed_deleted_files:
            modified_files = modified_files - {deleted_file}
            added_files = added_files - {deleted_file}

        for non_commited_mod_file in non_committed_modified_files:
            added_files = added_files - {non_commited_mod_file}

        new_added_files = set([])
        for added_file in added_files:
            if added_file in non_committed_added_files:
                new_added_files.add(added_file)

        added_files = new_added_files

    return modified_files, added_files


def get_from_version(file_path):
    data_dictionary = get_json(file_path)

    if data_dictionary:
        from_version = data_dictionary.get('fromversion', '0.0.0')
        if from_version == "":
            return "0.0.0"

        if not re.match(r"^\d{1,2}\.\d{1,2}\.\d{1,2}$", from_version):
            raise ValueError("{} fromversion is invalid \"{}\". "
                             "Should be of format: 4.0.0 or 4.5.0".format(file_path, from_version))

        return from_version


def get_to_version(file_path):
    data_dictionary = get_json(file_path)

    if data_dictionary:
        to_version = data_dictionary.get('fromversion', '99.99.99')
        if not re.match(r"^\d{1,2}\.\d{1,2}\.\d{1,2}$", to_version):
            raise ValueError("{} toversion is invalid \"{}\". "
                             "Should be of format: 4.0.0 or 4.5.0".format(file_path, to_version))

        return to_version


class ImageValidator(object):
    def __init__(self, file_path):
        self.file_path = file_path
        self._is_valid = True

    def is_invalid_image(self):
        return not self._is_valid

    def validate(self):
        self.oversize_image()
        if '.png' not in self.file_path:
            self.is_existing_image()

    def oversize_image(self):
        if re.match(IMAGE_REGEX, self.file_path, re.IGNORECASE):
            if os.path.getsize(self.file_path) > IMAGE_MAX_SIZE:
                print_error("{} has too large logo, please update the logo to be under 10kB".format(self.file_path))
                self._is_valid = False

        else:
            data_dictionary = get_json(self.file_path)
            image = data_dictionary.get('image', '')

            if ((len(image) - 22) / 4.0) * 3 > IMAGE_MAX_SIZE:
                print_error("{} has too large logo, please update the logo to be under 10kB".format(self.file_path))
                self._is_valid = False

    def is_existing_image(self):
        is_image_in_yml = False
        is_image_in_package = False
        if get_json(self.file_path).get('image'):
            is_image_in_yml = True

        if not re.match(INTEGRATION_REGEX, self.file_path, re.IGNORECASE):
            package_path = os.path.dirname(self.file_path)
            image_path = glob.glob(package_path + '/*.png')
            if image_path:
                if is_image_in_yml:
                    print_error("You have added an image both in the package and in the yml "
                                "file, please update the package {}".format(package_path))
                    return False

                is_image_in_package = True

        if not (is_image_in_package or is_image_in_yml):
            print_error("You have failed to add an image in the yml/package for {}".format(self.file_path))

        return is_image_in_package or is_image_in_yml


class IDSetValidator(object):
    ID_SET_PATH = "./Tests/id_set.json"

    def __init__(self, is_circle):
        self._valid_id = True
        self.is_circle = is_circle
        self.id_set = self.load_id_set()

        self.script_set = self.id_set['scripts']
        self.playbook_set = self.id_set['playbooks']
        self.integration_set = self.id_set['integrations']
        self.test_playbook_set = self.id_set['TestPlaybooks']

    def is_invalid_id(self):
        return_value = not self._valid_id
        self._valid_id = True
        return return_value

    def load_id_set(self):
        with open(self.ID_SET_PATH, 'r') as id_set_file:
            try:
                id_set = json.load(id_set_file)
            except ValueError, ex:
                if "Expecting property name" in ex.message:
                    print_error("You probably merged from master and your id_set.json has conflicts. "
                                "Run `python Tests/scripts/update_id_set.py -r`, it should reindex your id_set.json")
                    raise ex
                else:
                    raise ex

            return id_set

    def check_if_the_id_is_valid_one(self, objects_set, compared_id, file_path, compared_obj_data=None):
        if compared_obj_data is None:
            from_version = get_from_version(file_path)

        else:
            value = compared_obj_data.values()[0]
            from_version = value.get('fromversion', '0.0.0')

        data_dict = get_json(file_path)
        if data_dict.get('name') != compared_id:
            print_error("The ID is not equal to the name, the convetion is for them to be identical, please fix that,"
                        " the file is {}".format(file_path))
            self._valid_id = False

        for obj in objects_set:
            obj_id = obj.keys()[0]
            obj_data = obj.values()[0]
            if obj_id == compared_id:
                if LooseVersion(from_version) <= LooseVersion(obj_data.get('toversion', '99.99.99')):
                    print_error("The ID {0} already exists, please update the file {1} or update the "
                                "id_set.json toversion field of this id to match the "
                                "old occurrence of this id".format(compared_id, file_path))
                    self._valid_id = False

    def is_valid_in_id_set(self, file_path, obj_data, obj_set):
        is_found = False
        file_id = obj_data.keys()[0]

        for checked_instance in obj_set:
            checked_instance_id = checked_instance.keys()[0]
            checked_instance_data = checked_instance[checked_instance_id]
            checked_instance_toversion = checked_instance_data.get('toversion', '99.99.99')
            checked_instance_fromversion = checked_instance_data.get('fromversion', '0.0.0')
            obj_to_version = obj_data[file_id].get('toversion', '99.99.99')
            obj_from_version = obj_data[file_id].get('fromversion', '0.0.0')
            if checked_instance_id == file_id and checked_instance_toversion == obj_to_version and \
                    checked_instance_fromversion == obj_from_version:
                is_found = True
                if checked_instance_data != obj_data[file_id]:
                    print_error("You have failed to update id_set.json with the data of {} "
                                "please run `python Tests/scripts/update_id_set.py`".format(file_path))
                    return False

        if not is_found:
            print_error("You have failed to update id_set.json with the data of {} "
                        "please run `python Tests/scripts/update_id_set.py`".format(file_path))
            return False

        return True

    def validate_playbook_in_set(self, file_path, playbook_set):
        playbook_data = get_playbook_data(file_path)
        return self.is_valid_in_id_set(file_path, playbook_data, playbook_set)

    def validate_script_in_set(self, file_path, script_set, script_data=None):
        if script_data is None:
            script_data = get_script_data(file_path)

        return self.is_valid_in_id_set(file_path, script_data, script_set)

    def validate_integration_in_set(self, file_path, integration_set):
        integration_data = get_integration_data(file_path)
        return self.is_valid_in_id_set(file_path, integration_data, integration_set)

    def is_file_valid_in_set(self, file_path):
        is_valid = True
        if self.is_circle:  # No need to check on local env because the id_set will contain this info after the commit
            if re.match(PLAYBOOK_REGEX, file_path, re.IGNORECASE):
                is_valid = self.validate_playbook_in_set(file_path, self.playbook_set)

            elif re.match(TEST_PLAYBOOK_REGEX, file_path, re.IGNORECASE):
                is_valid = self.validate_playbook_in_set(file_path, self.test_playbook_set)

            elif re.match(TEST_SCRIPT_REGEX, file_path, re.IGNORECASE) or \
                    re.match(SCRIPT_REGEX, file_path, re.IGNORECASE):
                is_valid = self.validate_script_in_set(file_path, self.script_set)

            elif re.match(INTEGRATION_REGEX, file_path, re.IGNORECASE) or \
                    re.match(INTEGRATION_YML_REGEX, file_path, re.IGNORECASE):

                is_valid = self.validate_integration_in_set(file_path, self.integration_set)

            elif re.match(SCRIPT_YML_REGEX, file_path, re.IGNORECASE) or \
                    re.match(SCRIPT_PY_REGEX, file_path, re.IGNORECASE) or \
                    re.match(SCRIPT_JS_REGEX, file_path, re.IGNORECASE):

                yml_path, code = get_script_package_data(os.path.dirname(file_path))
                script_data = get_script_data(yml_path, script_code=code)

                is_valid = self.validate_script_in_set(yml_path, self.script_set, script_data)

        return is_valid

    def check_if_there_is_id_duplicates(self, file_path):
        if not self.is_circle:
            if re.match(TEST_PLAYBOOK_REGEX, file_path, re.IGNORECASE):
                self.check_if_the_id_is_valid_one(self.test_playbook_set, collect_ids(file_path), file_path)

            elif re.match(SCRIPT_REGEX, file_path, re.IGNORECASE) or \
                    re.match(TEST_SCRIPT_REGEX, file_path, re.IGNORECASE):
                self.check_if_the_id_is_valid_one(self.script_set, get_script_or_integration_id(file_path), file_path)

            elif re.match(INTEGRATION_REGEX, file_path, re.IGNORECASE) or \
                    re.match(INTEGRATION_YML_REGEX, file_path, re.IGNORECASE):

                self.check_if_the_id_is_valid_one(self.integration_set,
                                                  get_script_or_integration_id(file_path), file_path)

            elif re.match(PLAYBOOK_REGEX, file_path, re.IGNORECASE):
                self.check_if_the_id_is_valid_one(self.playbook_set, collect_ids(file_path), file_path)

            elif re.match(SCRIPT_YML_REGEX, file_path, re.IGNORECASE) or \
                    re.match(SCRIPT_PY_REGEX, file_path, re.IGNORECASE) or \
                    re.match(SCRIPT_JS_REGEX, file_path, re.IGNORECASE):

                yml_path, code = get_script_package_data(os.path.dirname(file_path))
                script_data = get_script_data(yml_path, script_code=code)
                self.check_if_the_id_is_valid_one(self.script_set, get_script_or_integration_id(yml_path),
                                                  yml_path, script_data)


class StructureValidator(object):
    CONF_PATH = "./Tests/conf.json"

    def __init__(self, is_circle=False):
        self._is_valid = True
        self.is_circle = is_circle

        self.conf_data = self.load_conf_file()
        self.id_set_validator = IDSetValidator(is_circle)

    def is_invalid(self):
        return not self._is_valid

    def load_conf_file(self):
        with open(self.CONF_PATH) as data_file:
            return json.load(data_file)

    def validate_description_in_conf_dict(self, checked_dict):
        """Validate that the checked_dict as description for all it's fields.

        Args:
            checked_dict (dict): Dictionary from conf.json file.
        """
        problematic_instances = []
        for instance, description in checked_dict.items():
            if description == "":
                problematic_instances.append(instance)

        if problematic_instances:
            self._is_valid = False
            print("Those instances don't have description:\n{0}".format('\n'.join(problematic_instances)))

    def is_valid_conf_json(self):
        """Validate the fields skipped_tests and skipped_integrations in conf.json file."""
        skipped_tests_conf = self.conf_data['skipped_tests']
        skipped_integrations_conf = self.conf_data['skipped_integrations']

        self.validate_description_in_conf_dict(skipped_tests_conf)
        self.validate_description_in_conf_dict(skipped_integrations_conf)
        # TODO: add Ben's section once he merges the mock issue.

        return self._is_valid

    def validate_scheme(self, file_path, matching_regex=None):
        if matching_regex is None:
            for regex in CHECKED_TYPES_REGEXES:
                if re.match(regex, file_path, re.IGNORECASE):
                    matching_regex = regex
                    break

        if matching_regex not in SKIPPED_SCHEMAS or os.path.isfile(file_path):
            if matching_regex is not None and REGEXES_TO_SCHEMA_DIC.get(matching_regex):
                c = Core(source_file=file_path,
                         schema_files=[SCHEMAS_PATH + REGEXES_TO_SCHEMA_DIC.get(matching_regex) + '.yml'])
                try:
                    c.validate(raise_exception=True)
                except Exception as err:
                    print_error('Failed: %s failed' % (file_path,))
                    print_error(err)
                    self._is_valid = False
            else:
                print file_path + " doesn't match any of the known supported file prefix/suffix," \
                                  " please make sure that its naming is correct."
                self._is_valid = False

    def validate_reputations(self, json_dict):
        is_valid = True
        reputations = json_dict.get('reputations')
        for reputation in reputations:
            internal_version = reputation.get('version')
            if internal_version != -1:
                object_id = reputation.get('id')
                print_error("Reputation object with id {} must have version -1".format(object_id))
                is_valid = False

        return is_valid

    def validate_version(self, file_path):
        file_extension = os.path.splitext(file_path)[1]
        version_number = -1
        reputations_valid = True
        if file_extension == '.yml':
            yaml_dict = get_json(file_path)
            version_number = yaml_dict.get('commonfields', {}).get('version')
            if not version_number:  # some files like playbooks do not have commonfields key
                version_number = yaml_dict.get('version')

        elif file_extension == '.json':
            if checked_type(file_path):
                file_name = os.path.basename(file_path)
                with open(file_path) as json_file:
                    json_dict = json.load(json_file)
                    if file_name == "reputations.json":
                        reputations_valid = validate_reputations(json_dict)
                    else:
                        version_number = json_dict.get('version')

        if version_number != -1 or not reputations_valid:
            print_error("The version for our files should always be -1, please update the file {}.".format(file_path))
            self._is_valid = False

    def validate_id_not_changed(self, file_path):
        change_string = run_git_command("git diff HEAD {}".format(file_path))
        if re.search("[+-](  )?id: .*", change_string):
            print_error("You've changed the ID of the file {0} please undo.".format(file_path))
            self._is_valid = False

    def validate_fromversion_on_modified(self, file_path):
        change_string = run_git_command("git diff HEAD {0}".format(file_path))
        is_added_from_version = re.search("\+([ ]+)?fromversion: .*", change_string)
        is_added_from_version_secondary = re.search("\+([ ]+)?\"fromVersion\": .*", change_string)

        if is_added_from_version or is_added_from_version_secondary:
            print_error("You've added fromversion to an existing file in the system, this is not allowed, please undo. "
                        "the file was {}.".format(file_path))
            self._is_valid = False

    def is_release_branch(self):
        diff_string_config_yml = run_git_command("git diff origin/master .circleci/config.yml")
        if re.search('[+-][ ]+CONTENT_VERSION: ".*', diff_string_config_yml):
            return True

        return False

    def validate_file_release_notes(self, file_path):
        data_dictionary = None
        if os.path.isfile(file_path):
            with open(os.path.expanduser(file_path), "r") as f:
                if file_path.endswith(".json"):
                    data_dictionary = json.load(f)
                elif file_path.endswith(".yaml") or file_path.endswith('.yml'):
                    try:
                        data_dictionary = yaml.safe_load(f)
                    except Exception as e:
                        print_error(file_path + " has yml structure issue. Error was: " + str(e))
                        self._is_valid = False

            if data_dictionary and data_dictionary.get('releaseNotes') is None:
                print_error("File " + file_path + " is missing releaseNotes, please add.")
                self._is_valid = False

    def is_test_in_conf_json(self, file_path):
        file_id = collect_ids(file_path)

        with open(self.CONF_PATH) as data_file:
            conf = json.load(data_file)

        conf_tests = conf['tests']
        for test in conf_tests:
            playbook_id = test['playbookID']
            if file_id == playbook_id:
                return True

        print_error("You've failed to add the {0} to conf.json".format(file_path))
        return False

    def validate_modified_files(self, modified_files):
        for file_path in modified_files:
            print "Validating {}".format(file_path)
            self.validate_scheme(file_path)
            self.validate_version(file_path)
            self.validate_id_not_changed(file_path)
            self.validate_fromversion_on_modified(file_path)

            if not self.is_release_branch():
                self.validate_file_release_notes(file_path)

            if self.id_set_validator.is_file_valid_in_set(file_path):
                self._is_valid = False

            elif re.match(INTEGRATION_REGEX, file_path, re.IGNORECASE) or \
                    re.match(INTEGRATION_YML_REGEX, file_path, re.IGNORECASE):

                image_validator = ImageValidator(file_path)
                if image_validator.is_invalid_image():
                    self._is_valid = False

                integration_validator = IntegrationValidator(file_path)
                if not integration_validator.is_backward_compatible():
                    self._is_valid = False

            elif re.match(SCRIPT_REGEX, file_path, re.IGNORECASE):
                script_validator = ScriptValidator(file_path)
                if not script_validator.is_backward_compatible():
                    self._is_valid = False

            elif re.match(SCRIPT_YML_REGEX, file_path, re.IGNORECASE) or \
                    re.match(SCRIPT_PY_REGEX, file_path, re.IGNORECASE) or \
                    re.match(SCRIPT_JS_REGEX, file_path, re.IGNORECASE):

                yml_path, _ = get_script_package_data(os.path.dirname(file_path))
                script_validator = ScriptValidator(yml_path)
                if not script_validator.is_backward_compatible():
                    self._is_valid = False

            elif re.match(IMAGE_REGEX, file_path, re.IGNORECASE):
                image_validator = ImageValidator(file_path)
                if image_validator.is_invalid_image():
                    self._is_valid = False

    def validate_added_files(self, added_files):
        for file_path in added_files:
            print "Validating {}".format(file_path)
            self.validate_scheme(file_path)
            self.validate_version(file_path)

            if self.id_set_validator.is_file_valid_in_set(file_path):
                self._is_valid = False

            self.id_set_validator.check_if_there_is_id_duplicates(file_path)
            if self.id_set_validator.is_invalid_id():
                self._is_valid = False

            if re.match(TEST_PLAYBOOK_REGEX, file_path, re.IGNORECASE):
                if not self.is_test_in_conf_json(file_path):
                    self._is_valid = False

            elif re.match(INTEGRATION_REGEX, file_path, re.IGNORECASE) or \
                    re.match(INTEGRATION_YML_REGEX, file_path, re.IGNORECASE) or \
                    re.match(IMAGE_REGEX, file_path, re.IGNORECASE):

                image_validator = ImageValidator(file_path)
                if image_validator.is_invalid_image():
                    self._is_valid = False

    def check_secrets(self, branch_name):
        """Check if any secrets are found in your changeset.

        Args:
            branch_name (string): The name of the branch you are working on.
        """
        # secrets_found, secrets_found_string = get_secrets(branch_name, self.is_circle)
        # if secrets_found_string:
        #     self._is_valid = False
        #     print_error(secrets_found_string)
        pass

    def validate_committed_files(self, branch_name):
        self.check_secrets(branch_name)

        modified_files, added_files = get_modified_and_added_files(branch_name, self.is_circle)

        self.validate_modified_files(modified_files)
        self.validate_added_files(added_files)

    def validate_all_files(self):
        for regex in CHECKED_TYPES_REGEXES:
            splitted_regex = regex.split(".*")
            directory = splitted_regex[0]
            for root, dirs, files in os.walk(directory):
                print_color("Validating {} directory:".format(directory), LOG_COLORS.GREEN)
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    # skipping hidden files
                    if file_name.startswith('.'):
                        continue

                    print "Validating " + file_name
                    self.validate_scheme(file_path)


def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


def main():
    """
    This script runs both in a local and a remote environment. In a local environment we don't have any
    logger assigned, and then pykwalify raises an error, since it is logging the validation results.
    Therefore, if we are in a local env, we set up a logger. Also, we set the logger's level to critical
    so the user won't be disturbed by non critical loggings
    """
    branches = run_git_command("git branch")
    branch_name_reg = re.search("\* (.*)", branches)
    branch_name = branch_name_reg.group(1)

    parser = argparse.ArgumentParser(description='Utility CircleCI usage')
    parser.add_argument('-c', '--circle', type=str2bool, help='Is CircleCi or not')
    options = parser.parse_args()
    is_circle = options.circle
    if is_circle is None:
        is_circle = False

    print_color("Starting validating files structure", LOG_COLORS.GREEN)
    structure_validator = StructureValidator(is_circle)
    structure_validator.is_valid_conf_json()
    if branch_name != 'master':
        import logging
        logging.basicConfig(level=logging.CRITICAL)

        # validates only committed files
        structure_validator.validate_committed_files(branch_name)
    else:
        # validates all of Content repo directories according to their schemas
        structure_validator.validate_all_files()

    if structure_validator.is_invalid():
        sys.exit(1)

    print_color("Finished validating files structure", LOG_COLORS.GREEN)
    sys.exit(0)


if __name__ == "__main__":
    # main()

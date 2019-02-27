import os
import re
import json
from distutils.version import LooseVersion

from Tests.test_utils import get_script_or_integration_id, collect_ids, print_error
from Tests.scripts.constants import INTEGRATION_REGEX, TEST_PLAYBOOK_REGEX, SCRIPT_JS_REGEX, \
    SCRIPT_REGEX, TEST_SCRIPT_REGEX, INTEGRATION_YML_REGEX, PLAYBOOK_REGEX, SCRIPT_YML_REGEX, SCRIPT_PY_REGEX
from Tests.scripts.update_id_set import get_script_data, get_playbook_data, \
    get_integration_data, get_script_package_data


class IDSetValidator(object):
    """IDSetValidator was designed to make sure we create the id_set.json in the correct way so we can use it later on.

    The id_set.json file is created using the update_id_set.py script. It contains all the data from the various
    executables we have in Content repository - Playbooks/Scripts/Integration. The script extracts the command and
    script names so we will later on will be able to use it in the test filtering we have in our build system.

    Attributes:
        is_circle (bool): whether we are running on circle or local env.
        id_set (dict): Dictionary that hold all the data from the id_set.json file.
        script_set (set): Set of all the data regarding scripts in our system.
        playbook_set (set): Set of all the data regarding playbooks in our system.
        integration_set (set): Set of all the data regarding integrations in our system.
        test_playbook_set (set): Set of all the data regarding test playbooks in our system.
    """
    SCRIPTS_SECTION = "scripts"
    PLAYBOOK_SECTION = "playbooks"
    INTEGRATION_SECTION = "integrations"
    TEST_PLAYBOOK_SECTION = "TestPlaybooks"

    ID_SET_PATH = "./Tests/id_set.json"

    def __init__(self, is_circle, is_test_run=False):
        self.is_circle = is_circle

        if not is_test_run and is_circle:
            self.id_set = self.load_id_set()

            self.script_set = self.id_set[self.SCRIPTS_SECTION]
            self.playbook_set = self.id_set[self.PLAYBOOK_SECTION]
            self.integration_set = self.id_set[self.INTEGRATION_SECTION]
            self.test_playbook_set = self.id_set[self.TEST_PLAYBOOK_SECTION]

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

    def is_valid_in_id_set(self, file_path, obj_data, obj_set):
        """Check if the file is represented correctly in the id_set

        Args:
            file_path (string): Path to the file.
            obj_data (dict): Dictionary that holds the extracted details from the given file.
            obj_set (set): The set in which the file should be located at.

        Returns:
            bool. Whether the file is represented correctly in the id_set or not.
        """
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

        return is_found

    def is_file_valid_in_set(self, file_path):
        """Check if the file is represented correctly in the id_set

        Args:
            file_path (string): Path to the file.

        Returns:
            bool. Whether the file is represented correctly in the id_set or not.
        """
        is_valid = True
        if self.is_circle:  # No need to check on local env because the id_set will contain this info after the commit
            if re.match(PLAYBOOK_REGEX, file_path, re.IGNORECASE):
                playbook_data = get_playbook_data(file_path)
                is_valid = self.is_valid_in_id_set(file_path, playbook_data, self.playbook_set)

            elif re.match(TEST_PLAYBOOK_REGEX, file_path, re.IGNORECASE):
                playbook_data = get_playbook_data(file_path)
                is_valid = self.is_valid_in_id_set(file_path, playbook_data, self.test_playbook_set)

            elif re.match(TEST_SCRIPT_REGEX, file_path, re.IGNORECASE) or \
                    re.match(SCRIPT_REGEX, file_path, re.IGNORECASE):

                script_data = get_script_data(file_path)
                is_valid = self.is_valid_in_id_set(file_path, script_data, self.script_set)

            elif re.match(INTEGRATION_REGEX, file_path, re.IGNORECASE) or \
                    re.match(INTEGRATION_YML_REGEX, file_path, re.IGNORECASE):

                integration_data = get_integration_data(file_path)
                is_valid = self.is_valid_in_id_set(file_path, integration_data, self.integration_set)

            elif re.match(SCRIPT_YML_REGEX, file_path, re.IGNORECASE) or \
                    re.match(SCRIPT_PY_REGEX, file_path, re.IGNORECASE) or \
                    re.match(SCRIPT_JS_REGEX, file_path, re.IGNORECASE):

                yml_path, code = get_script_package_data(os.path.dirname(file_path))
                script_data = get_script_data(yml_path, script_code=code)
                is_valid = self.is_valid_in_id_set(yml_path, script_data, self.script_set)

        return is_valid

    def is_id_duplicated(self, obj_id, obj_data, obj_type):
        """Check if the given ID already exist in the system.

        Args:
            obj_id (string): The new ID we want to add.
            obj_data (dict): Dictionary that holds the extracted details from the given file.
            obj_type (string): the type of the new file.

        Returns:
            bool. Whether the ID already exist in the system or not.
        """
        is_duplicated = False
        dict_value = obj_data.values()[0]
        obj_toversion = dict_value.get('toversion', '99.99.99')
        obj_fromversion = dict_value.get('fromversion', '0.0.0')

        for section, section_data in self.id_set.items():
            for instance in section_data:
                instance_id = instance.keys()[0]
                instance_to_version = instance[instance_id].get('toversion', '99.99.99')
                instance_from_version = instance[instance_id].get('fromversion', '0.0.0')
                if obj_id == instance_id:
                    if section != obj_type:
                        is_duplicated = True
                        break

                    elif obj_fromversion == instance_from_version and obj_toversion == instance_to_version:
                        if instance[instance_id] != obj_data[obj_id]:
                            is_duplicated = True
                            break

                    elif LooseVersion(obj_fromversion) <= LooseVersion(instance_to_version):
                        is_duplicated = True
                        break

        if is_duplicated:
            print_error("The ID {0} already exists, please update the file or update the "
                        "id_set.json toversion field of this id to match the "
                        "old occurrence of this id".format(obj_id))

        return is_duplicated

    def is_file_has_used_id(self, file_path):
        """Check if the ID of the given file already exist in the system.

        Args:
            file_path (string): Path to the file.

        Returns:
            bool. Whether the ID of the given file already exist in the system or not.
        """
        is_used = False
        if self.is_circle:
            if re.match(TEST_PLAYBOOK_REGEX, file_path, re.IGNORECASE):
                obj_type = self.TEST_PLAYBOOK_SECTION
                obj_id = collect_ids(file_path)
                obj_data = get_playbook_data(file_path)

            elif re.match(SCRIPT_REGEX, file_path, re.IGNORECASE) or \
                    re.match(TEST_SCRIPT_REGEX, file_path, re.IGNORECASE):
                obj_type = self.SCRIPTS_SECTION
                obj_id = get_script_or_integration_id(file_path)
                obj_data = get_playbook_data(file_path)

            elif re.match(INTEGRATION_REGEX, file_path, re.IGNORECASE) or \
                    re.match(INTEGRATION_YML_REGEX, file_path, re.IGNORECASE):

                obj_type = self.INTEGRATION_SECTION
                obj_id = get_script_or_integration_id(file_path)
                obj_data = get_playbook_data(file_path)

            elif re.match(PLAYBOOK_REGEX, file_path, re.IGNORECASE):
                obj_type = self.PLAYBOOK_SECTION
                obj_id = collect_ids(file_path)
                obj_data = get_playbook_data(file_path)

            elif re.match(SCRIPT_YML_REGEX, file_path, re.IGNORECASE) or \
                    re.match(SCRIPT_PY_REGEX, file_path, re.IGNORECASE) or \
                    re.match(SCRIPT_JS_REGEX, file_path, re.IGNORECASE):

                yml_path, code = get_script_package_data(os.path.dirname(file_path))
                obj_data = get_script_data(yml_path, script_code=code)

                obj_type = self.SCRIPTS_SECTION
                obj_id = get_script_or_integration_id(yml_path)

            is_used = self.is_id_duplicated(obj_id, obj_data, obj_type)

        return is_used

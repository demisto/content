import os
import re
import json
from distutils.version import LooseVersion

from Tests.test_utils import INTEGRATION_REGEX, print_error, get_from_version, get_json, TEST_PLAYBOOK_REGEX, \
    SCRIPT_REGEX, TEST_SCRIPT_REGEX, INTEGRATION_YML_REGEX, PLAYBOOK_REGEX, SCRIPT_YML_REGEX, SCRIPT_PY_REGEX,\
    SCRIPT_JS_REGEX, get_script_or_integration_id, collect_ids
from Tests.scripts.update_id_set import get_script_data, get_playbook_data, \
    get_integration_data, get_script_package_data


class IDSetValidator(object):
    SCRIPTS_SECTION = "scripts"
    PLAYBOOK_SECTION = "playbooks"
    INTEGRATION_SECTION = "integrations"
    TEST_PLAYBOOK_SECTION = "TestPlaybooks"

    ID_SET_PATH = "./Tests/id_set.json"

    def __init__(self, is_circle, is_test_run=False):
        self._valid_id = True
        self.is_circle = is_circle

        if not is_test_run and is_circle:
            self.id_set = self.load_id_set()

            self.script_set = self.id_set[self.SCRIPTS_SECTION]
            self.playbook_set = self.id_set[self.PLAYBOOK_SECTION]
            self.integration_set = self.id_set[self.INTEGRATION_SECTION]
            self.test_playbook_set = self.id_set[self.TEST_PLAYBOOK_SECTION]

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

        return is_found

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

    def is_id_duplicated(self, obj_id, obj_data, obj_type):
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

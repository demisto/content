import re
import json
from distutils.version import LooseVersion

from Tests.test_utils import *
from Tests.scripts.update_id_set import get_script_data, get_playbook_data, \
    get_integration_data, get_script_package_data


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

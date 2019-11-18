from Tests.scripts.hook_validations.error_constants import Errors
from Tests.scripts.hook_validations.yml_based import YMLBasedValidator
from Tests.test_utils import get_yaml, print_error


class PlaybookValidator(YMLBasedValidator):
    def is_valid_version(self, expected_file_version=-1):
        yaml_dict = get_yaml(self.file_path)
        if yaml_dict.get('version') != -1:
            print_error(Errors.wrong_version(self.file_path, expected_file_version))
            self.is_valid = False

    def is_file_valid(self, validate_rn=True):
        self.is_valid_version()

    def is_context_path_changed(self):
        return False

    def is_backward_compatible(self):
        # TODO
        return True

    def is_changed_subtype(self):
        return False

from Tests.scripts.constants import PYTHON_SUBTYPES, Errors
from Tests.scripts.hook_validations.base_validator import BaseValidator
from Tests.test_utils import print_error, server_version_compare, get_dockerimage45


class ScriptValidator(BaseValidator):
    """ScriptValidator is designed to validate the correctness of the file structure we enter to content repo. And
        also try to catch possible Backward compatibility breaks due to the preformed changes.
    """

    def is_valid_version(self):
        # type: () -> bool
        if self.current_file.get('commonfields', {}).get('version') != self.DEFAULT_VERSION:
            print_error(Errors.wrong_version(self.file_path))
            return False
        return True

    @classmethod
    def _is_sub_set(cls, supposed_bigger_list, supposed_smaller_list):
        # type: (list, list) -> bool
        """Check if supposed_smaller_list is a subset of the supposed_bigger_list"""
        for check_item in supposed_smaller_list:
            if check_item not in supposed_bigger_list:
                return False
        return True

    def is_backward_compatible(self):
        # type: () -> bool
        """Check if the script is backward compatible."""
        if not self.old_file:
            return True

        is_breaking_backwards = [
            self.is_docker_image_changed(),
            self.is_context_path_changed(),
            self.is_added_required_args(),
            self.is_arg_changed(),
            self.is_there_duplicates_args(),
            self.is_changed_subtype()
        ]

        # Add sane-doc-report exception
        # Sane-doc-report uses docker and every fix/change requires a docker tag change,
        # thus it won't be backwards compatible.
        # All other tests should be False (i.e. no problems)
        if self.file_path == 'Scripts/SaneDocReport/SaneDocReport.yml':
            return not any(is_breaking_backwards[1:])
        return not any(is_breaking_backwards)

    def is_valid_script(self):
        # type: () -> bool
        """Check whether the Integration is valid or not, update the _is_valid field to determine that"""
        is_script_valid = any([
            self.is_valid_subtype()
        ])

        return is_script_valid

    @classmethod
    def _get_arg_to_required_dict(cls, script_json):
        """Get a dictionary arg name to its required status.

        Args:
            script_json (dict): Dictionary of the examined script.

        Returns:
            dict. arg name to its required status.
        """
        arg_to_required = {}
        args = script_json.get('args', [])
        for arg in args:
            arg_to_required[arg.get('name')] = arg.get('required', False)
        return arg_to_required

    def is_changed_subtype(self):
        """Validate that the subtype was not changed."""
        type_ = self.current_file.get('type')
        if type_ == 'python':
            subtype = self.current_file.get('subtype')
            if self.old_file:
                old_subtype = self.old_file.get('subtype', "")
                if old_subtype and old_subtype != subtype:
                    print_error(Errors.breaking_backwards_subtype(self.file_path))
                    return True
        return False

    def is_valid_subtype(self):
        """Validate that the subtype is python2 or python3."""
        type_ = self.current_file.get('type')
        if type_ == 'python':
            subtype = self.current_file.get('subtype')
            if subtype not in PYTHON_SUBTYPES:
                print_error(Errors.wrong_subtype(self.file_path))
                return False

        return True

    def is_added_required_args(self):
        """Check if required arg were added."""
        current_args_to_required = self._get_arg_to_required_dict(self.current_file)
        old_args_to_required = self._get_arg_to_required_dict(self.old_file)

        for arg, required in current_args_to_required.items():
            if required:
                if (arg not in old_args_to_required) or \
                        (arg in old_args_to_required and required != old_args_to_required[arg]):
                    print_error(Errors.added_required_fields(self.file_path, arg))
                    return True
        return False

    def is_there_duplicates_args(self):
        # type: () -> bool

        """Check if there are duplicated arguments."""
        args = [arg['name'] for arg in self.current_file.get('args', [])]
        if len(args) != len(set(args)):
            return True
        return False

    def is_arg_changed(self):
        # type: () -> bool
        """Check if the argument has been changed."""
        current_args = [arg['name'] for arg in self.current_file.get('args', [])]
        old_args = [arg['name'] for arg in self.old_file.get('args', [])]

        if not self._is_sub_set(current_args, old_args):
            print_error(Errors.breaking_backwards_arg_changed(self.file_path))
            return True
        return False

    def is_context_path_changed(self):
        # type: () -> bool
        """Check if the context path as been changed."""
        current_context = [output['contextPath'] for output in self.current_file.get('outputs', [])]
        old_context = [output['contextPath'] for output in self.old_file.get('outputs', [])]

        if not self._is_sub_set(current_context, old_context):
            print_error(Errors.breaking_backwards_context(self.file_path))
            return True
        return False

    def is_docker_image_changed(self):
        # type: () -> bool
        """Check if the docker image as been changed."""
        # Unnecessary to check docker image only on 5.0 and up
        if server_version_compare(self.old_file.get('fromversion', '0'), '5.0.0') < 0:
            old_docker = get_dockerimage45(self.old_file)
            new_docker = get_dockerimage45(self.current_file)
            if old_docker != new_docker:
                print_error(Errors.breaking_backwards_docker(self.file_path, old_docker, new_docker))
                return True
        return False

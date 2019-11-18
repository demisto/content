import os
import yaml
import requests

from Tests.scripts.constants import CONTENT_GITHUB_LINK, PYTHON_SUBTYPES, SCRIPT_REGEX, SCRIPT_YML_REGEX
from Tests.scripts.hook_validations.yml_based import YMLBasedValidator
from Tests.test_utils import print_error, print_warning, get_yaml
from error_constants import Errors

# disable insecure warnings
requests.packages.urllib3.disable_warnings()


class ScriptValidator(YMLBasedValidator):
    """ScriptValidator is designed to validate the correctness of the file structure we enter to content repo. And
        also try to catch possible Backward compatibility breaks due to the preformed changes.
    """

    scheme_name = 'script'

    regexes = [
        SCRIPT_REGEX,
        SCRIPT_YML_REGEX,

    ]

    def is_file_valid(self, **kwargs):
        super(ScriptValidator, self).is_file_valid()

    def is_backward_compatible(self):
        """Check if the script is backward compatible."""
        if not self.old_file:
            return True

        backwards_checks = [
            self.is_docker_image_changed(),
            self.is_context_path_changed(),
            self.is_added_required_args(),
            self.is_arg_changed(),
            self.is_there_duplicate_args(),
            self.is_changed_subtype()
        ]

        # Add sane-doc-report exception
        # Sane-doc-report uses docker and every fix/change requires a docker tag change,
        # thus it won't be backwards compatible.
        # All other tests should be False (i.e. no problems)
        if self.file_path == 'Scripts/SaneDocReport/SaneDocReport.yml' and not any([backwards_checks[1:]]):
            return True

        is_bc_broke = any(backwards_checks)

        return not is_bc_broke

    def is_valid_script(self):
        """Check whether the Integration is valid or not, update the _is_valid field to determine that"""
        is_script_valid = any([
            self.is_valid_subtype()
        ])

        return is_script_valid

    def get_arg_to_required_dict(self, json_object, args='args'):
        return super(ScriptValidator, self).get_arg_to_required_dict(json_object, args)

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
                print_error("The subtype for our yml files should be either python2 or python3, "
                            "please update the file {}.".format(self.file_path))
                return False
        return True

    def is_added_required_args(self):
        """Check if required arg were added."""
        current_args_to_required = self.get_arg_to_required_dict(self.current_file)
        old_args_to_required = self.get_arg_to_required_dict(self.old_file)

        for arg, required in current_args_to_required.items():
            if required:
                if (arg not in old_args_to_required) or \
                        (arg in old_args_to_required and required != old_args_to_required[arg]):
                    print_error("You've added required args in the script file '{}', the field is '{}'".format(
                        self.file_path, arg))
                    return True

        return False

    def is_there_duplicate_args(self):
        """Check if there are duplicated arguments."""
        args = [arg['name'] for arg in self.current_file.get('args', [])]
        duplicates = self.find_duplicates(args)
        if duplicates:
            print_error(Errors.duplicate_arg_in_script(duplicates, self.file_path))
            return True
        return False

    def is_arg_changed(self):
        """Check if the argument has been changed."""
        current_args = [arg['name'] for arg in self.current_file.get('args', [])]
        old_args = [arg['name'] for arg in self.old_file.get('args', [])]

        if not self._is_sub_set(current_args, old_args):
            print_error(Errors.breaking_backwards_arg_changed(self.file_path))
            return True
        return False

    def is_context_path_changed(self):
        """Check if the context path as been changed."""
        current_context = [output['contextPath'] for output in self.current_file.get('outputs', [])]
        old_context = [output['contextPath'] for output in self.old_file.get('outputs', [])]

        if not self._is_sub_set(current_context, old_context):
            print_error(Errors.breaking_backwards_context(self.file_path))
            return True
        return False

    def is_docker_image_changed(self):
        """Check if the docker image as been changed."""
        return super(ScriptValidator, self).is_docker_image_changed()

    def is_valid_scheme(self):
        super(ScriptValidator, self)._is_scheme_valid(self.scheme_name)

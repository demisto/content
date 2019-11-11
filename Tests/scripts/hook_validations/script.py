import os
import yaml
import requests

from Tests.scripts.constants import CONTENT_GITHUB_LINK, PYTHON_SUBTYPES
from Tests.scripts.hook_validations.yml_based import YMLBasedValidator
from Tests.test_utils import print_error, print_warning, get_yaml, server_version_compare
from error_constants import Errors

# disable insecure warnings
requests.packages.urllib3.disable_warnings()


class ScriptValidator(YMLBasedValidator):
    """ScriptValidator is designed to validate the correctness of the file structure we enter to content repo. And
        also try to catch possible Backward compatibility breaks due to the preformed changes.

    Attributes:
       file_path (str): the path to the file we are examining at the moment.
       current_script (dict): Json representation of the current script from the branch.
       old_script (dict): Json representation of the current script from master.
    """

    def __init__(self, file_path, is_added_file, is_renamed, check_git=True, old_file_path=None,
                 old_git_branch='master'):
        super(ScriptValidator, self).__init__(file_path, is_added_file, is_renamed)
        self.current_script = {}
        self.old_script = {}

        if check_git:
            self.current_script = get_yaml(file_path)
            # The replace in the end is for Windows support
            if old_file_path:
                git_hub_path = os.path.join(CONTENT_GITHUB_LINK, old_git_branch, old_file_path).replace("\\", "/")
            else:
                git_hub_path = os.path.join(CONTENT_GITHUB_LINK, old_git_branch, file_path).replace("\\", "/")
            try:
                res = requests.get(git_hub_path, verify=False)
                res.raise_for_status()
                self.old_script = yaml.safe_load(res.content)
            except Exception as e:
                print_warning(Errors.breaking_backwards_no_old_script(e))

    def is_backward_compatible(self):
        """Check if the script is backward compatible."""
        if not self.old_script:
            return True

        backwards_checks = [
            self.is_docker_image_changed(),
            self.is_context_path_changed(),
            self.is_added_required_args(),
            self.is_arg_changed(),
            self.is_there_duplicates_args(),
            self.is_changed_subtype()
        ]

        # Add sane-doc-report exception
        # Sane-doc-report uses docker and every fix/change
        # requires a docker tag change, thus it won't be
        # backwards compatible.
        # All other tests should be False (i.e. no problems)
        sane_doc_checks = all([not c for c in backwards_checks[1:]])
        if sane_doc_checks and \
                self.file_path == 'Scripts/SaneDocReport/SaneDocReport.yml':
            return True

        is_bc_broke = any(backwards_checks)

        return not is_bc_broke

    def is_valid_script(self):
        """Check whether the Integration is valid or not, update the _is_valid field to determine that"""
        is_script_valid = any([
            self.is_valid_subtype()
        ])

        return is_script_valid

    def _get_arg_to_required_dict(self, json_object, args='args'):
        return super(ScriptValidator, self)._get_arg_to_required_dict(json_object, 'args')

    def is_changed_subtype(self):
        """Validate that the subtype was not changed."""
        type_ = self.current_script.get('type')
        if type_ == 'python':
            subtype = self.current_script.get('subtype')
            if self.old_script:
                old_subtype = self.old_script.get('subtype', "")
                if old_subtype and old_subtype != subtype:
                    print_error("Possible backwards compatibility break, You've changed the subtype"
                                " of the file {}".format(self.file_path))
                    return True
        return False

    def is_valid_subtype(self):
        """Validate that the subtype is python2 or python3."""
        type_ = self.current_script.get('type')
        if type_ == 'python':
            subtype = self.current_script.get('subtype')
            if subtype not in PYTHON_SUBTYPES:
                print_error("The subtype for our yml files should be either python2 or python3, "
                            "please update the file {}.".format(self.file_path))
                return False

        return True

    def is_added_required_args(self):
        """Check if required arg were added."""
        current_args_to_required = self._get_arg_to_required_dict(self.current_script)
        old_args_to_required = self._get_arg_to_required_dict(self.old_script)

        for arg, required in current_args_to_required.items():
            if required:
                if (arg not in old_args_to_required) or \
                        (arg in old_args_to_required and required != old_args_to_required[arg]):
                    print_error("You've added required args in the script file '{}', the field is '{}'".format(
                        self.file_path, arg))
                    return True

        return False

    def is_there_duplicates_args(self):
        """Check if there are duplicated arguments."""
        args = [arg['name'] for arg in self.current_script.get('args', [])]
        if len(args) != len(set(args)):
            return True

        return False

    def is_arg_changed(self):
        """Check if the argument has been changed."""
        current_args = [arg['name'] for arg in self.current_script.get('args', [])]
        old_args = [arg['name'] for arg in self.old_script.get('args', [])]

        if not self._is_sub_set(current_args, old_args):
            print_error("Possible backwards compatibility break, You've changed the name of an arg in "
                        "the file {}, please undo.".format(self.file_path))
            return True

        return False

    def is_context_path_changed(self):
        """Check if the context path as been changed."""
        current_context = [output['contextPath'] for output in self.current_script.get('outputs', [])]
        old_context = [output['contextPath'] for output in self.old_script.get('outputs', [])]

        if not self._is_sub_set(current_context, old_context):
            print_error(Errors.breaking_backwards_context(self.file_path))
            return True
        return False

    def is_docker_image_changed(self):
        """Check if the docker image as been changed."""
        # Unnecessary to check docker image only on 5.0 and up
        if server_version_compare(self.old_script.get('fromversion', '0'), '5.0.0') < 0:
            if self.old_script.get('dockerimage', "") != self.current_script.get('dockerimage', ""):
                print_error(Errors.breaking_backwards_docker(self.file_path))
                return True

        return False

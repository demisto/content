import os
import yaml
import requests

from Tests.scripts.constants import CONTENT_GITHUB_MASTER_LINK
from Tests.test_utils import print_error, get_yaml

# disable insecure warnings
requests.packages.urllib3.disable_warnings()


class ScriptValidator(object):
    """ScriptValidator is designed to validate the correctness of the file structure we enter to content repo. And
        also try to catch possible Backward compatibility breaks due to the preformed changes.

    Attributes:
       file_path (str): the path to the file we are examining at the moment.
       current_script (dict): Json representation of the current script from the branch.
       old_script (dict): Json representation of the current script from master.
    """

    def __init__(self, file_path, check_git=True, old_file_path=None):
        self.file_path = file_path
        self.current_script = {}
        self.old_script = {}

        if check_git:
            self.current_script = get_yaml(file_path)
            # The replace in the end is for Windows support
            if old_file_path:
                git_hub_path = os.path.join(CONTENT_GITHUB_MASTER_LINK, old_file_path).replace("\\", "/")
            else:
                git_hub_path = os.path.join(CONTENT_GITHUB_MASTER_LINK, file_path).replace("\\", "/")

            try:
                file_content = requests.get(git_hub_path, verify=False).content
                self.old_script = yaml.safe_load(file_content)
            except Exception as e:
                print(str(e))
                print_error("Could not find the old script please make sure that you did not break "
                            "backward compatibility")

    @classmethod
    def _is_sub_set(cls, supposed_bigger_list, supposed_smaller_list):
        """Check if supposed_smaller_list is a subset of the supposed_bigger_list"""
        for check_item in supposed_smaller_list:
            if check_item not in supposed_bigger_list:
                return False

        return True

    def is_backward_compatible(self):
        """Check if the script is backward compatible."""
        if not self.old_script:
            return True

        is_bc_broke = any([
            self.is_context_path_changed(),
            self.is_docker_image_changed(),
            self.is_added_required_args(),
            self.is_arg_changed(),
            self.is_there_duplicates_args(),
            self.is_invalid_subtype()
        ])

        return not is_bc_broke

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

    def is_invalid_subtype(self):
        """Validate that the subtype is python2 or python3."""
        type_ = self.current_script.get('type')
        if type_ == 'python':
            subtype = self.current_script.get('subtype')
            if not subtype or subtype not in ['python3', 'python2']:
                print_error("The subtype for our yml files should be either python2 or python3, "
                            "please update the file {}.".format(self.current_script.get('name')))
                return True
            if self.old_script:
                old_subtype = self.old_script.get('subtype', "")
                if len(old_subtype) > 0 and old_subtype != subtype:
                    print_error("Possible backwards compatibility break, You've changed the subtype"
                                " of the file {}".format(self.file_path))
                    return True
        return False

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
            print_error("Possible backwards compatibility break, You've changed the context in the file {0},"
                        " please undo.".format(self.file_path))
            return True

        return False

    def is_docker_image_changed(self):
        """Check if the docker image as been changed."""
        if self.old_script.get('dockerimage', "") != self.current_script.get('dockerimage', ""):
            print_error("Possible backwards compatibility break, You've changed the docker for the file {}"
                        " this is not allowed.".format(self.file_path))
            return True

        return False

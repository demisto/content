import os
import yaml
import requests

from Tests.test_utils import print_error, get_yaml

# disable insecure warnings
requests.packages.urllib3.disable_warnings()


class ScriptValidator(object):
    """ScriptValidator is designed to validate the correctness of the file structure we enter to content repo. And
        also try to catch possible Backward compatibility breaks due to the preformed changes.

    Attributes:
       _is_valid (bool): the attribute which saves the valid/in-valid status of the current file.
       file_path (str): the path to the file we are examining at the moment.
       current_script (dict): Json representation of the current script from the branch.
       old_script (dict): Json representation of the current script from master.
    """
    CONTENT_GIT_HUB_LINK = "https://raw.githubusercontent.com/demisto/content/master/"

    def __init__(self, file_path, check_git=True, old_file_path=None):
        self._is_valid = True
        self.file_path = file_path
        self.current_script = {}
        self.old_script = {}

        if check_git:
            self.current_script = get_yaml(file_path)
            # The replace in the end is for Windows support
            if old_file_path:
                git_hub_path = os.path.join(self.CONTENT_GIT_HUB_LINK, old_file_path).replace("\\", "/")
            else:
                git_hub_path = os.path.join(self.CONTENT_GIT_HUB_LINK, file_path).replace("\\", "/")

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
        self.is_arg_changed()
        self.is_context_path_changed()
        self.is_docker_image_changed()
        self.is_there_duplicates_args()

        return self._is_valid

    def is_there_duplicates_args(self):
        """Check if there are duplicated arguments."""
        args = [arg['name'] for arg in self.current_script.get('args', [])]
        if len(args) != len(set(args)):
            self._is_valid = False
            return True

        return False

    def is_arg_changed(self):
        """Check if the argument has been changed."""
        current_args = [arg['name'] for arg in self.current_script.get('args', [])]
        old_args = [arg['name'] for arg in self.old_script.get('args', [])]

        if not self._is_sub_set(current_args, old_args):
            print_error("Possible backwards compatibility break, You've changed the name of an arg in "
                        "the file {}, please undo.".format(self.file_path))
            self._is_valid = False
            return True

        return False

    def is_context_path_changed(self):
        """Check if the context path as been changed."""
        current_context = [output['contextPath'] for output in self.current_script.get('outputs', [])]
        old_context = [output['contextPath'] for output in self.old_script.get('outputs', [])]

        if not self._is_sub_set(current_context, old_context):
            print_error("Possible backwards compatibility break, You've changed the context in the file {0},"
                        " please undo.".format(self.file_path))
            self._is_valid = False
            return True

        return False

    def is_docker_image_changed(self):
        """Check if the docker image as been changed."""
        if self.old_script.get('dockerimage', "") != self.current_script.get('dockerimage', ""):
            print_error("Possible backwards compatibility break, You've changed the docker for the file {}"
                        " this is not allowed.".format(self.file_path))
            self._is_valid = False
            return True

        return False

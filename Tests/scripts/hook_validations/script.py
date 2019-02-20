import re
import yaml

from Tests.test_utils import print_error, run_git_command


class ScriptValidator(object):
    def __init__(self, file_path, check_git=True):
        self._is_valid = True

        self.file_path = file_path
        if check_git:
            self.change_string = run_git_command("git diff HEAD {0}".format(self.file_path))
            with open(file_path, 'r') as file_data:
                self.yaml_data = yaml.safe_load(file_data)

    def is_backward_compatible(self):
        self.is_arg_changed()
        self.is_context_path_changed()
        self.is_docker_image_changed()
        self.is_there_duplicates_args()

        return self._is_valid

    def is_there_duplicates_args(self):
        args = self.yaml_data.get('args', [])
        existing_args = []
        for arg in args:
            arg_name = arg['name']
            if arg_name not in existing_args:
                existing_args.append(arg_name)

            else:
                self._is_valid = False
                return True

        return False

    def is_arg_changed(self):
        deleted_args = re.findall("-([ ]+)?- name: (.*)", self.change_string)
        added_args = re.findall("\+([ ]+)?- name: (.*)", self.change_string)

        deleted_args = [arg[1] for arg in deleted_args]
        added_args = [arg[1] for arg in added_args]

        for added_arg in added_args:
            if added_arg in deleted_args:
                deleted_args.remove(added_arg)

        if deleted_args:
            print_error("Possible backwards compatibility break, You've changed the name of a command or its arg in"
                        " the file {0} please undo, the line was:{1}".format(self.file_path,
                                                                             "\n".join(deleted_args)))
            self._is_valid = False
            return True

        return False

    def is_context_path_changed(self):
        deleted_args = re.findall("-([ ]+)?- contextPath: (.*)", self.change_string)
        added_args = re.findall("\+([ ]+)?- contextPath: (.*)", self.change_string)

        deleted_args = [arg[1] for arg in deleted_args]
        added_args = [arg[1] for arg in added_args]

        for added_arg in added_args:
            if added_arg in deleted_args:
                deleted_args.remove(added_arg)

        if deleted_args:
            print_error("Possible backwards compatibility break, You've changed the context in the file {0} please "
                        "undo, the line was:{1}".format(self.file_path, "\n".join(deleted_args)))
            self._is_valid = False
            return True

        return False

    def is_docker_image_changed(self):
        is_docker_added = re.search("\+([ ]+)?dockerimage: .*", self.change_string)
        is_docker_deleted = re.search("-([ ]+)?dockerimage: .*", self.change_string)
        if is_docker_added or is_docker_deleted:
            print_error("Possible backwards compatibility break, You've changed the docker for the file {}"
                        " this is not allowed.".format(self.file_path))
            self._is_valid = False
            return True

        return False

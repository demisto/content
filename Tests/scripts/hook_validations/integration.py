from Tests.scripts.constants import PYTHON_SUBTYPES, INTEGRATION_CATEGORIES
from Tests.test_utils import print_error, get_yaml, print_warning, get_remote_file, server_version_compare, \
    get_dockerimage45


class IntegrationValidator(object):
    """IntegrationValidator is designed to validate the correctness of the file structure we enter to content repo. And
    also try to catch possible Backward compatibility breaks due to the preformed changes.

    Attributes:
       _is_valid (bool): the attribute which saves the valid/in-valid status of the current file.
       file_path (str): the path to the file we are examining at the moment.
       current_integration (dict): Json representation of the current integration from the branch.
       old_integration (dict): Json representation of the current integration from master.
    """

    def __init__(self, file_path, check_git=True, old_file_path=None, old_git_branch='master'):
        self._is_valid = True

        self.file_path = file_path
        if check_git:
            self.current_integration = get_yaml(file_path)

            old_integration_file = old_file_path or file_path
            self.old_integration = get_remote_file(old_integration_file, old_git_branch)

    def is_backward_compatible(self):
        """Check whether the Integration is backward compatible or not, update the _is_valid field to determine that"""
        if not self.old_integration:
            return True

        self.is_changed_context_path()
        self.is_docker_image_changed()
        self.is_added_required_fields()
        self.is_changed_command_name_or_arg()
        self.is_there_duplicate_args()
        self.is_there_duplicate_params()
        self.is_changed_subtype()

        # will move to is_valid_integration after https://github.com/demisto/etc/issues/17949
        self.is_outputs_for_reputations_commands_valid()

        return self._is_valid

    def is_valid_integration(self):
        """Check whether the Integration is valid or not, update the _is_valid field to determine that"""
        self.is_valid_subtype()
        self.is_default_arguments()
        self.is_isarray_arguments()
        self.is_proxy_configured_correctly()
        self.is_insecure_configured_correctly()
        self.is_valid_category()

        return self._is_valid

    def is_valid_beta_integration(self, is_new=False):
        """Check whether the beta Integration is valid or not, update the _is_valid field to determine that"""
        self.is_default_arguments()
        self.is_valid_beta(is_new)
        return self._is_valid

    def is_valid_param(self, param_name, param_display):
        """Check if the given parameter has the right configuration."""
        err_msgs = []
        configuration = self.current_integration.get('configuration', [])
        for configuration_param in configuration:
            configuration_param_name = configuration_param['name']
            if configuration_param_name == param_name:
                if configuration_param['display'] != param_display:
                    err_msgs.append('The display name of the {} parameter should be \'{}\''.format(param_name,
                                                                                                   param_display))
                elif configuration_param.get('defaultvalue', '') != 'false' and configuration_param.get('defaultvalue',
                                                                                                        '') != '':
                    err_msgs.append('The default value of the {} parameter should be \'\''.format(param_name))

                elif configuration_param.get('required', False):
                    err_msgs.append('The required field of the {} parameter should be False'.format(param_name))

                elif configuration_param.get('type') != 8:
                    err_msgs.append('The type field of the {} parameter should be 8'.format(param_name))

        if err_msgs:
            print_error('Received the following error for {} validation:\n{}'.format(param_name, '\n'.join(err_msgs)))
            self._is_valid = False
            return False

        return True

    def is_proxy_configured_correctly(self):
        """Check that if an integration has a proxy parameter that it is configured properly."""
        return self.is_valid_param('proxy', 'Use system proxy settings')

    def is_insecure_configured_correctly(self):
        """Check that if an integration has an insecure parameter that it is configured properly."""
        insecure_field_name = ''
        configuration = self.current_integration.get('configuration', [])
        for configuration_param in configuration:
            if configuration_param['name'] == 'insecure' or configuration_param['name'] == 'unsecure':
                insecure_field_name = configuration_param['name']

        if insecure_field_name:
            return self.is_valid_param(insecure_field_name, 'Trust any certificate (not secure)')

        return True

    def is_valid_category(self):
        """Check that the integration category is in the schema."""
        category = self.current_integration.get('category', None)
        if not category or category not in INTEGRATION_CATEGORIES:
            self._is_valid = False
            print_error("The category '{}' is not in the integration schemas, the valid options are:\n{}".format(
                category, '\n'.join(INTEGRATION_CATEGORIES)))

        return self._is_valid

    def is_default_arguments(self):
        """Check if a reputation command (domain/email/file/ip/url)
            has a default non required argument with the same name

        Returns:
            bool. Whether a reputation command hold a valid argument
        """
        commands = self.current_integration.get('script', {}).get('commands', [])
        for command in commands:
            command_name = command.get('name')
            for arg in command.get('arguments', []):
                arg_name = arg.get('name')
                if command_name in {'file', 'email', 'domain', 'url', 'ip'} and arg_name == command_name:
                    if arg.get('default') is False:
                        self._is_valid = False
                        print_error("The argument '{}' of the command '{}' is not configured as default"
                                    .format(arg_name, command_name))

        return self._is_valid


    def is_isarray_arguments(self):
        """Check if a reputation command's (domain/email/file/ip/url)
            argument of the same name has the 'isArray' attribute set to True

        Returns:
            bool. Whether 'isArray' is True
        """
        reputation_commands = ['file', 'email', 'domain', 'url', 'ip']
        commands = self.current_integration.get('script', {}).get('commands', [])
        for command in commands:
            command_name = command.get('name')
            if command_name in reputation_commands:
                for arg in command.get('arguments', []):
                    arg_name = arg.get('name')
                    if arg_name == command_name:
                        if arg.get('isArray') is False:
                            self._is_valid = False
                            print_error("The argument '{}' of the command '{}' is not configured with 'isArray' set to True"
                                        .format(arg_name, command_name))
        return self._is_valid


    def is_outputs_for_reputations_commands_valid(self):
        """Check if a reputation command (domain/email/file/ip/url)
            has the correct DBotScore outputs according to the context standard
            https://github.com/demisto/content/blob/master/docs/context_standards/README.MD

        Returns:
            bool. Whether a reputation command holds valid outputs
        """
        context_standard = "https://github.com/demisto/content/blob/master/docs/context_standards/README.MD"
        commands = self.current_integration.get('script', {}).get('commands', [])
        for command in commands:
            command_name = command.get('name')
            # look for reputations commands
            if command_name in ['domain', 'email', 'file', 'ip', 'url']:
                context_outputs_paths = set()
                context_outputs_descriptions = set()
                for output in command.get('outputs', []):
                    context_outputs_paths.add(output.get('contextPath'))
                    context_outputs_descriptions.add(output.get('description'))

                # validate DBotScore outputs and descriptions
                dbot_score = {
                    'DBotScore.Indicator': 'The indicator that was tested.',
                    'DBotScore.Type': 'The indicator type.',
                    'DBotScore.Vendor': 'The vendor used to calculate the score.',
                    'DBotScore.Score': 'The actual score.'
                }
                missing_outputs = set()
                missing_descriptions = set()
                for dbot_score_output in dbot_score:
                    if dbot_score_output not in context_outputs_paths:
                        missing_outputs.add(dbot_score_output)
                        self._is_valid = False
                    else:  # DBot Score output path is in the outputs
                        if dbot_score.get(dbot_score_output) not in context_outputs_descriptions:
                            missing_descriptions.add(dbot_score_output)
                            # self._is_valid = False - Do not fail build over wrong description

                if missing_outputs:
                    print_error("The DBotScore outputs of the reputation command {} aren't valid. Missing: {}."
                                " Fix according to context standard {} "
                                .format(command_name, missing_outputs, context_standard))
                if missing_descriptions:
                    print_warning("The DBotScore description of the reputation command {} aren't valid. Missing: {}."
                                  " Fix according to context standard {} "
                                  .format(command_name, missing_descriptions, context_standard))

                # validate the IOC output
                command_to_output = {
                    'domain': {'Domain.Name'},
                    'file': {'File.MD5', 'File.SHA1', 'File.SHA256'},
                    'ip': {'IP.Address'},
                    'url': {'URL.Data'}
                }
                reputation_output = command_to_output.get(command_name)
                if reputation_output and not reputation_output.intersection(context_outputs_paths):
                    self._is_valid = False
                    print_error("The outputs of the reputation command {} aren't valid. The {} outputs is missing"
                                "Fix according to context standard {} "
                                .format(command_name, reputation_output, context_standard))

        return self._is_valid

    def is_valid_subtype(self):
        """Validate that the subtype is python2 or python3."""
        type_ = self.current_integration.get('script', {}).get('type')
        if type_ == 'python':
            subtype = self.current_integration.get('script', {}).get('subtype')
            if subtype not in PYTHON_SUBTYPES:
                print_error("The subtype for our yml files should be either python2 or python3, "
                            "please update the file {}.".format(self.current_integration.get('name')))
                self._is_valid = False

        return self._is_valid

    def is_changed_subtype(self):
        """Validate that the subtype was not changed."""
        type_ = self.current_integration.get('script', {}).get('type')
        if type_ == 'python':
            subtype = self.current_integration.get('script', {}).get('subtype')
            if self.old_integration:
                old_subtype = self.old_integration.get('script', {}).get('subtype', "")
                if old_subtype and old_subtype != subtype:
                    print_error("Possible backwards compatibility break, You've changed the subtype"
                                " of the file {}".format(self.file_path))
                    self._is_valid = False

        return self._is_valid

    def is_valid_beta(self, is_new=False):
        """Validate that that beta integration has correct beta attributes"""

        if not all([self._is_display_contains_beta(), self._has_beta_param()]):
            self._is_valid = False
        if is_new:
            if not all([self._id_has_no_beta_substring(), self._name_has_no_beta_substring()]):
                self._is_valid = False

    def _id_has_no_beta_substring(self):
        """Checks that 'id' field dose not include the substring 'beta'"""
        common_fields = self.current_integration.get('commonfields', {})
        integration_id = common_fields.get('id', '')
        if 'beta' in integration_id.lower():
            print_error(
                "Field 'id' should NOT contain the substring \"beta\" in a new beta integration. "
                "please change the id in the file {}".format(self.file_path))
            return False

        return True

    def _name_has_no_beta_substring(self):
        """Checks that 'name' field dose not include the substring 'beta'"""
        name = self.current_integration.get('name', '')
        if 'beta' in name.lower():
            print_error("Field 'name' should NOT contain the substring \"beta\" in a new beta integration. "
                        "please change the id in the file {}".format(self.file_path))
            return False

        return True

    def _has_beta_param(self):
        """Checks that integration has 'beta' field with value set to true"""
        beta = self.current_integration.get('beta', False)
        if not beta:
            print_error("Beta integration yml file should have the field \"beta: true\", but was not found"
                        " in the file {}".format(self.file_path))
        return beta

    def _is_display_contains_beta(self):
        """Checks that 'display' field includes the substring 'beta'"""
        display = self.current_integration.get('display', '')
        if 'beta' not in display.lower():
            print_error(
                "Field 'display' in Beta integration yml file should include the string \"beta\", but was not found"
                " in the file {}".format(self.file_path))
            return False

        return True

    def is_there_duplicate_args(self):
        """Check if a command has the same arg more than once

        Returns:
            bool. True if there are duplicates, False otherwise.
        """
        commands = self.current_integration.get('script', {}).get('commands', [])
        for command in commands:
            arg_list = []
            for arg in command.get('arguments', []):
                if arg in arg_list:
                    self._is_valid = False
                    print_error("The argument '{}' of the command '{}' is duplicated in the integration '{}', "
                                "please remove one of its appearances "
                                "as we do not allow duplicates".format(arg, command['name'],
                                                                       self.current_integration.get('name')))
                else:
                    arg_list.append(arg)

        return not self._is_valid

    def is_there_duplicate_params(self):
        """Check if the integration has the same param more than once

        Returns:
            bool. True if there are duplicates, False otherwise.
        """
        configurations = self.current_integration.get('configuration', [])
        param_list = []
        for configuration_param in configurations:
            param_name = configuration_param['name']
            if param_name in param_list:
                self._is_valid = False
                print_error("The parameter '{}' of the "
                            "integration '{}' is duplicated, please remove one of its appearances as we do not "
                            "allow duplicated parameters".format(param_name,
                                                                 self.current_integration.get('name')))
            else:
                param_list.append(param_name)

        return not self._is_valid

    @staticmethod
    def _get_command_to_args(integration_json):
        """Get a dictionary command name to it's arguments.

        Args:
            integration_json (dict): Dictionary of the examined integration.

        Returns:
            dict. command name to a list of it's arguments.
        """
        command_to_args = {}
        commands = integration_json.get('script', {}).get('commands', [])
        for command in commands:
            command_to_args[command['name']] = {}
            for arg in command.get('arguments', []):
                command_to_args[command['name']][arg['name']] = arg.get('required', False)

        return command_to_args

    @staticmethod
    def is_subset_dictionary(new_dict, old_dict):
        """Check if the new dictionary is a sub set of the old dictionary.

        Args:
            new_dict (dict): current branch result from _get_command_to_args
            old_dict (dict): master branch result from _get_command_to_args

        Returns:
            bool. Whether the new dictionary is a sub set of the old dictionary.
        """
        for arg, required in old_dict.items():
            if arg not in new_dict.keys():
                return False

            if required != new_dict[arg] and new_dict[arg]:
                return False

        for arg, required in new_dict.items():
            if arg not in old_dict.keys() and required:
                return False

        return True

    def is_changed_command_name_or_arg(self):
        """Check if a command name or argument as been changed.

        Returns:
            bool. Whether a command name or argument as been changed.
        """
        current_command_to_args = self._get_command_to_args(self.current_integration)
        old_command_to_args = self._get_command_to_args(self.old_integration)

        for command, args_dict in old_command_to_args.items():
            if command not in current_command_to_args.keys() or \
                    not self.is_subset_dictionary(current_command_to_args[command], args_dict):
                print_error("Possible backwards compatibility break, You've changed the name of a command or its arg in"
                            " the file {0} please undo, the command was:\n{1}".format(self.file_path, command))
                self._is_valid = False
                return True

        return False

    @staticmethod
    def _is_sub_set(supposed_bigger_list, supposed_smaller_list):
        """Check if supposed_smaller_list is a subset of the supposed_bigger_list"""
        for check_item in supposed_smaller_list:
            if check_item not in supposed_bigger_list:
                return False

        return True

    def _get_command_to_context_paths(self, integration_json):
        """Get a dictionary command name to it's context paths.

        Args:
            integration_json (dict): Dictionary of the examined integration.

        Returns:
            dict. command name to a list of it's context paths.
        """
        command_to_context_list = {}
        commands = integration_json.get('script', {}).get('commands', [])
        for command in commands:
            context_list = []
            if not command.get('outputs', []):
                continue

            for output in command.get('outputs', []):
                command_name = command['name']
                try:
                    context_list.append(output['contextPath'])
                except KeyError:
                    print_error('Invalid context output for command {}. Output is {}'.format(command_name, output))
                    self._is_valid = False

            command_to_context_list[command['name']] = sorted(context_list)

        return command_to_context_list

    def is_changed_context_path(self):
        """Check if a context path as been changed.

        Returns:
            bool. Whether a context path as been changed.
        """
        current_command_to_context_paths = self._get_command_to_context_paths(self.current_integration)
        old_command_to_context_paths = self._get_command_to_context_paths(self.old_integration)

        for old_command, old_context_paths in old_command_to_context_paths.items():
            if old_command in current_command_to_context_paths.keys() and \
                    not self._is_sub_set(current_command_to_context_paths[old_command],
                                         old_context_paths):
                print_error("Possible backwards compatibility break, You've changed the context in the file {0} please "
                            "undo, the command is:\n{1}".format(self.file_path, old_command))
                self._is_valid = False
                return True

        return False

    @staticmethod
    def _get_field_to_required_dict(integration_json):
        """Get a dictionary field name to its required status.

        Args:
            integration_json (dict): Dictionary of the examined integration.

        Returns:
            dict. Field name to its required status.
        """
        field_to_required = {}
        configuration = integration_json.get('configuration', [])
        for field in configuration:
            field_to_required[field.get('name')] = field.get('required', False)

        return field_to_required

    def is_added_required_fields(self):
        """Check if required field were added."""
        current_field_to_required = self._get_field_to_required_dict(self.current_integration)
        old_field_to_required = self._get_field_to_required_dict(self.old_integration)

        for field, required in current_field_to_required.items():
            if (field not in old_field_to_required.keys() and required) or \
                    (required and field in old_field_to_required.keys() and required != old_field_to_required[field]):
                print_error("You've added required fields in the integration "
                            "file '{}', the field is '{}'".format(self.file_path, field))
                self._is_valid = False
                return True

        return False

    def is_docker_image_changed(self):
        """Check if the Docker image was changed or not."""
        # Unnecessary to check docker image only on 5.0 and up
        if server_version_compare(self.old_integration.get('fromversion', '0'), '5.0.0') < 0:
            old_docker = get_dockerimage45(self.old_integration.get('script', {}))
            new_docker = get_dockerimage45(self.current_integration.get('script', {}))
            if old_docker != new_docker:
                print_error("Possible backwards compatibility break, You've changed the docker for the file {}"
                            " this is not allowed. Old: {}. New: {}".format(self.file_path, old_docker, new_docker))
                self._is_valid = False
                return True

        return False

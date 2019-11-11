class Errors(object):
    @staticmethod
    def wrong_filename(filepath, file_type):
        return '"{}" is not a valid {} filename.'.format(filepath, file_type)

    @staticmethod
    def wrong_version(file_path, expected="-1"):
        return "The version for our files should always be -1, please update the file {}.".format(file_path,
                                                                                                  expected)

    @staticmethod
    def missing_outputs(command_name, missing_outputs, context_standard):
        return "The DBotScore outputs of the reputation command {} aren't valid. Missing: {}. " \
               "Fix according to context standard {} ".format(command_name, missing_outputs, context_standard)

    @staticmethod
    def missing_dbot_description(command_name, missing_descriptions, context_standard):
        return "The DBotScore description of the reputation command {} aren't valid. Missing: {}. " \
               "Fix according to context standard {} ".format(command_name, missing_descriptions, context_standard)

    @staticmethod
    def missing_reputation(command_name, reputation_output, context_standard):
        return "The outputs of the reputation command {} aren't valid. The {} outputs is missing. " \
               "Fix according to context standard {} ".format(command_name, reputation_output, context_standard)

    @staticmethod
    def wrong_subtype(file_name):
        return "The subtype for our yml files should be either python2 or python3, " \
               "please update the file {}.".format(file_name)

    @staticmethod
    def breaking_backwards_subtype(file_path):
        return "Possible backwards compatibility break, You've changed the subtype " \
               "of the file {}".format(file_path)

    @staticmethod
    def beta_in_str(file_path, field):
        return "Field '{}' should NOT contain the substring \"beta\" in a new beta integration. " \
               "please change the id in the file {}".format(field, file_path)

    @classmethod
    def beta_in_id(cls, file_path):
        return cls.beta_in_str(file_path, 'id')

    @classmethod
    def beta_in_name(cls, file_path):
        return cls.beta_in_str(file_path, 'name')

    @staticmethod
    def duplicate_command(arg, command, integration_name):
        return "The argument '{}' of the command '{}' is duplicated in the integration '{}', " \
               "please remove one of its appearances as we do not allow duplicates".format(arg, command,
                                                                                           integration_name)

    @staticmethod
    def duplicate_param(param_name, current_integration):
        return "The parameter '{}' of the " \
               "integration '{}' is duplicated, please remove one of its appearances as we do not " \
               "allow duplicated parameters".format(param_name, current_integration)

    @staticmethod
    def breaking_backwards_no_old_script(e):
        return "{}\nCould not find the old file please make sure that you did not break " \
               "backward compatibility".format(str(e))

    @staticmethod
    def breaking_backwards_context(file_path):
        return "Possible backwards compatibility break, You've changed the context in the file {}," \
               " please undo.".format(file_path)

    @staticmethod
    def breaking_backwards_command(file_path, old_command):
        return "Possible backwards compatibility break, You've changed the context in the file {0} please " \
               "undo, the command is:\n{1}".format(file_path, old_command)

    @staticmethod
    def breaking_backwards_docker(file_path):
        return "Possible backwards compatibility break, You've changed the docker for the file {}" \
               " this is not allowed.".format(file_path)

    @staticmethod
    def added_required_fields(file_path, field):
        return "You've added required fields in the file '{}', the field is '{}'".format(file_path, field)

    @staticmethod
    def from_version_modified_after_rename():
        return "fromversion might have been modified, please make sure it hasn't changed."

    @staticmethod
    def from_version_modified(file_path):
        return "You've added fromversion to an existing file in the system, this is not allowed, please undo. " \
               "the file was {}.".format(file_path)

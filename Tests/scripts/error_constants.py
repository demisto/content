class Errors(object):
    BACKWARDS = "Possible backwards compatibility break"

    @staticmethod
    def wrong_filename(filepath, file_type):
        return '{} is not a valid {} filename.'.format(filepath, file_type)

    @staticmethod
    def wrong_path(filepath):
        return "{} is not a valid filepath.".format(filepath)

    @staticmethod
    def wrong_version(file_path, expected="-1"):
        return "{}: The version for our files should always be {}, please update the file.".format(expected, file_path)

    @staticmethod
    def wrong_version_reputations(file_path, object_id, version):
        return "{} Reputation object with id {} must have version {}".format(file_path, object_id, version)

    @staticmethod
    def dbot_invalid_output(file_path, command_name, missing_outputs, context_standard):
        return "{}: The DBotScore outputs of the reputation command {} aren't valid. Missing: {}. " \
               "Fix according to context standard {} ".format(file_path, command_name, missing_outputs, context_standard)

    @staticmethod
    def dbot_invalid_description(file_path, command_name, missing_descriptions, context_standard):
        return "{}: The DBotScore description of the reputation command {} aren't valid. Missing: {}. " \
               "Fix according to context standard {} "\
            .format(file_path, command_name, missing_descriptions, context_standard)

    @staticmethod
    def missing_reputation(file_path, command_name, reputation_output, context_standard):
        return "{}: The outputs of the reputation command {} aren't valid. The {} outputs is missing. " \
               "Fix according to context standard {} "\
            .format(file_path, command_name, reputation_output, context_standard)

    @staticmethod
    def wrong_subtype(file_name):
        return "{}: The subtype for our yml files should be either python2 or python3, " \
               "please update the file.".format(file_name)

    @staticmethod
    def beta_in_str(file_path, field):
        return "{}: Field '{}' should NOT contain the substring \"beta\" in a new beta integration. " \
               "please change the id in the file.".format(field, file_path)

    @classmethod
    def beta_in_id(cls, file_path):
        return cls.beta_in_str(file_path, 'id')

    @classmethod
    def beta_in_name(cls, file_path):
        return cls.beta_in_str(file_path, 'name')

    @staticmethod
    def duplicate_arg_in_file(script_path, arg, command_name=None):
        err_msg = "{}: The argument '{}' is duplicated".format(script_path, arg)
        if command_name:
            err_msg += " in '{}'.format(command_name)".format(command_name)
        err_msg += ", please remove one of its appearances."
        return err_msg

    @staticmethod
    def duplicate_param(param_name, file_path):
        return "{}: The parameter '{}' of the " \
               "file is duplicated, please remove one of its appearances.".format(file_path, param_name)

    @staticmethod
    def added_required_fields(file_path, field):
        return "You've added required fields in the file '{}', the field is '{}'".format(file_path, field)

    @staticmethod
    def from_version_modified_after_rename():
        return "fromversion might have been modified, please make sure it hasn't changed."

    @staticmethod
    def from_version_modified(file_path):
        return "{}: You've added fromversion to an existing file in the system, this is not allowed, please undo.".format(
            file_path)

    @classmethod
    def breaking_backwards_no_old_script(cls, e):
        return "{}\n{}, Could not find the old file.".format(cls.BACKWARDS, str(e))

    @classmethod
    def breaking_backwards_subtype(cls, file_path):
        return "{}: {}, You've changed the subtype, please undo.".format(file_path, cls.BACKWARDS)

    @classmethod
    def breaking_backwards_context(cls, file_path):
        return "{}: {}, You've changed the context in the file," \
               " please undo.".format(file_path, cls.BACKWARDS)

    @classmethod
    def breaking_backwards_command(cls, file_path, old_command):
        return "{}: {}, You've changed the context in the file,please " \
               "undo. the command is:\n{}".format(file_path, cls.BACKWARDS, old_command)

    @classmethod
    def breaking_backwards_docker(cls, file_path, old_docker, new_docker):
        return "{}: {}, You've changed the docker for the file," \
               " this is not allowed. Old: {}, New: {} ".format(file_path, cls.BACKWARDS, old_docker, new_docker)

    @classmethod
    def breaking_backwards_arg_changed(cls, file_path):
        return "{}: {}, You've changed the name of an arg in " \
               "the file, please undo.".format(file_path, cls.BACKWARDS)

    @classmethod
    def breaking_backwards_command_arg_changed(cls, file_path, command):
        return "{}: {}, You've changed the name of a command or its arg in" \
               " the file, please undo, the command was:\n{}".format(file_path, cls.BACKWARDS, command)

    @staticmethod
    def no_beta_in_display(file_path):
        return "{} :Field 'display' in Beta integration yml file should include the string \"beta\", but was not found" \
               " in the file.".format(file_path)

    @staticmethod
    def id_might_changed():
        return "ID might have changed, please make sure to check you have the correct one."

    @staticmethod
    def id_changed(file_path):
        return "{}: You've changed the ID of the file, please undo.".format(file_path)

    @staticmethod
    def file_id_contains_slashes():
        return "File's ID contains slashes - please remove."

    @staticmethod
    def missing_release_notes(file_path, rn_path):
        return '{}:  is missing releaseNotes, Please add it under {}'.format(file_path, rn_path)

    @staticmethod
    def display_param(param_name, param_display):
        return 'The display name of the {} parameter should be \'{}\''.format(param_name, param_display)

    @staticmethod
    def wrong_file_extension(file_extension, accepted_extensions):
        return "File extension {} is not valid. accepted {}".format(file_extension, accepted_extensions)

    @staticmethod
    def might_need_release_notes(file_path):
        return "{}: You might need RN in file, please make sure to check that.".format(file_path)

    @staticmethod
    def unknown_file(file_path):
        return "{}:  File type is unknown, check it out.".format(file_path)

    @staticmethod
    def wrong_default_argument(file_path, arg_name, command_name):
        return "{}: The argument '{}' of the command '{}' is not configured as default" \
            .format(file_path, arg_name, command_name)

    @staticmethod
    def wrong_display_name(param_name, param_display):
        return 'The display name of the {} parameter should be \'{}\''.format(param_name, param_display)

    @staticmethod
    def wrong_default_parameter(param_name):
        return 'The default value of the {} parameter should be \'\''.format(param_name)

    @staticmethod
    def wrong_required_value(param_name):
        return 'The required field of the {} parameter should be False'.format(param_name)

    @staticmethod
    def wrong_required_type(param_name):
        return 'The type field of the {} parameter should be 8'.format(param_name)

    @staticmethod
    def beta_field_not_found(file_path):
        return "{}: Beta integration yml file should have the field \"beta: true\", but was not found in the file." \
            .format(file_path)

    @staticmethod
    def no_default_arg(file_path, command_name):
        return "{}: Could not find default argument {} in command {}".format(file_path, command_name, command_name)

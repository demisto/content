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
    def duplicate_arg_in_file(arg, script_path):
        return "{}: The argument '{}' is duplicated in the file, " \
               "please remove one of its appearances.".format(str(arg), script_path)

    @staticmethod
    def duplicate_arg_in_integration(arg, command, integration_name):
        return "The argument '{}' of the command '{}' is duplicated in the integration '{}', " \
               "please remove one of its appearances.".format(str(arg), command, integration_name)

    @staticmethod
    def duplicate_param(param_name, current_integration):
        return "The parameter '{}' of the " \
               "integration '{}' is duplicated, please remove one of its appearances as we do not " \
               "allow duplicated parameters".format(param_name, current_integration)

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
    def breaking_backwards_docker(cls, file_path):
        return "{}: {}, You've changed the docker for the file," \
               " this is not allowed.".format(file_path, cls.BACKWARDS)

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

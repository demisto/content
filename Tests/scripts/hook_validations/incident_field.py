"""
This module is designed to validate the correctness of incident field entities in content.
"""
from Tests.test_utils import print_error, get_json, get_remote_file


class IncidentFieldValidator(object):
    """IncidentFieldValidator is designed to validate the correctness of the file structure we enter to content repo.
    And also try to catch possible Backward compatibility breaks due to the performed changes.

    Attributes:
       file_path (str): the path to the file we are examining at the moment.
       current_incident_field (dict): Json representation of the current incident field from the branch.
       old_incident_field (dict): Json representation of the current incident field from master.
    """

    def __init__(self, file_path, check_git=True, old_file_path=None, old_git_branch='master'):
        self.file_path = file_path
        self.current_incident_field = {}
        self.old_incident_field = {}

        if check_git:
            self.current_incident_field = get_json(file_path)
            if old_file_path:
                self.old_incident_field = get_remote_file(old_file_path, old_git_branch)
            else:
                self.old_incident_field = get_remote_file(file_path, old_git_branch)

    def is_backward_compatible(self):
        """Check whether the Incident Field is backward compatible or not, update the _is_valid field to determine that
        """
        if not self.old_incident_field:
            return True

        is_bc_broke = any([
            # in the future, add BC checks here
        ])

        return not is_bc_broke

    def is_valid(self):
        """Check whether the Incident Field is valid or not"""
        is_incident_field_valid = all([
            self.is_valid_name(),
            self.is_valid_content_flag(),
            self.is_valid_system_flag(),
        ])

        return is_incident_field_valid

    def is_valid_name(self):
        """Validate that the name and cliName does not contain any potential incident synonyms."""
        name = self.current_incident_field.get('name', '')
        cli_name = self.current_incident_field.get('cliName', '')
        bad_words = {'incident', 'case', 'alert', 'event', 'play', 'ticket', 'issue'}
        whitelisted_field_names = {
            'XDR Alert Count',
            'XDR High Severity Alert Count',
            'XDR Medium Severity Alert Count',
            'XDR Low Severity Alert Count',
            'XDR Incident ID'
        }
        for word in bad_words:
            if name in whitelisted_field_names:
                continue

            if word in name.lower() or word in cli_name.lower():
                print_error("The word {} cannot be used as a name/cliName, "
                            "please update the file {}.".format(word, self.file_path))
                return False

        return True

    def is_valid_content_flag(self):
        """Validate that field is marked as content."""
        is_valid_flag = self.current_incident_field.get('content') is True
        if not is_valid_flag:
            print_error("The content key must be set to true, please update the file '{}'".format(self.file_path))

        return is_valid_flag

    def is_valid_system_flag(self):
        """Validate that field is not marked as system."""
        is_valid_flag = self.current_incident_field.get('system', False) is False
        if not is_valid_flag:
            print_error("The system key must be set to false, please update the file '{}'".format(self.file_path))

        return is_valid_flag

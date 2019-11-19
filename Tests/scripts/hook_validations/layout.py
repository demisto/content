from Tests.scripts.constants import LAYOUT_REGEX, PACKS_LAYOUTS_REGEX
from Tests.scripts.hook_validations.error_constants import Errors
from Tests.scripts.hook_validations.json_based import JSONBasedValidator
from Tests.test_utils import checked_type, get_json, print_error


class LayoutValidator(JSONBasedValidator):
    regexes = [
        LAYOUT_REGEX,
        PACKS_LAYOUTS_REGEX
    ]

    def __init__(self, file_path, *args, **kwargs):
        self.file_path = file_path
        self.current_file = get_json(self.file_path)
        super(LayoutValidator, self).__init__(file_path, *args, **kwargs)

    def is_file_valid(self, **kwargs):
        super(LayoutValidator, self).is_file_valid()
        if not checked_type(self.file_path, self.regexes):
            print_error(Errors.wrong_filename(self.file_path, 'layout'))
            self.is_valid = False
        if not self.is_valid_version():
            print_error(Errors.wrong_version(self.file_path, "-1"))
        self.is_valid_scheme()
        self.is_valid_version()
        return self.is_valid

    def is_valid_version(self, expected_file_version=-1):
        """Validate that the layout file has version of -1."""
        is_version_correct = self.current_file.get('layout', {}).get('version') == expected_file_version
        if not is_version_correct:
            self.is_valid = False
            return False
        return True

    def is_valid_scheme(self, matching_regex='layout'):
        """Validate the file scheme according to the scheme we have saved in SCHEMAS_PATH.

        Args:
            matching_regex (str): the regex we want to compare the file with.

        Returns:
            bool. Whether the scheme is valid on self.file_path.
        """
        super(LayoutValidator, self).is_valid_scheme(matching_regex)

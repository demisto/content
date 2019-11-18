from Tests.scripts.constants import LAYOUT_REGEX, PACKS_LAYOUTS_REGEX
from Tests.scripts.hook_validations.error_constants import Errors
from Tests.scripts.hook_validations.json_based import JSONBasedValidator
from Tests.test_utils import checked_type, get_json


class LayoutValidator(JSONBasedValidator):
    def is_valid_version(self):
        pass

    regexes = [
        LAYOUT_REGEX,
        PACKS_LAYOUTS_REGEX
    ]

    def __init__(self, file_path, *args, **kwargs):
        self.file_path = file_path
        self.is_file_valid()
        super(LayoutValidator, self).__init__(file_path, *args, **kwargs)

    def is_file_valid(self):
        if not checked_type(self.file_path, self.regexes):
            raise TypeError(Errors.wrong_filename(self.file_path, 'layout'))
        json_data = get_json(self.file_path)
        if not self._is_valid_version(json_data):
            raise ValueError(Errors.wrong_version(self.file_path, "-1"))

    @staticmethod
    def _is_valid_version(json_dict):
        """Validate that the layout file has version of -1."""
        layout = json_dict.get('layout')
        return layout.get('version') != -1

    def is_scheme_valid(self, matching_regex='layout'):
        """Validate the file scheme according to the scheme we have saved in SCHEMAS_PATH.

        Args:
            matching_regex (str): the regex we want to compare the file with.

        Returns:
            bool. Whether the scheme is valid on self.file_path.
        """
        super(LayoutValidator, self).is_scheme_valid(matching_regex)
import glob

from Tests.test_utils import re, print_error, os, get_yaml
from Tests.scripts.constants import INTEGRATION_REGEX


class DescriptionValidator(object):
    """DescriptionValidator was designed to make sure we provide a detailed description properly.

    Attributes:
        file_path (string): Path to the checked file.
        _is_valid (bool): the attribute which saves the valid/in-valid status of the current file.
    """

    def __init__(self, file_path):
        self._is_valid = True

        self.file_path = file_path

    def is_valid(self):
        self.is_duplicate_description()

        return self._is_valid

    def is_duplicate_description(self):
        """Check if the integration has a non-duplicate description ."""
        is_description_in_yml = False
        is_description_in_package = False
        package_path = None
        md_file_path = None
        if not re.match(INTEGRATION_REGEX, self.file_path, re.IGNORECASE):
            package_path = os.path.dirname(self.file_path)
            try:
                md_file_path = glob.glob(os.path.join(os.path.dirname(self.file_path), '*.md'))[0]
            except IndexError:
                print_error("No description file was found in the package {}."
                            " Consider adding one.".format(package_path))
            if md_file_path:
                is_description_in_package = True

        data_dictionary = get_yaml(self.file_path)

        if not data_dictionary:
            return is_description_in_package

        if data_dictionary.get('detaileddescription'):
            is_description_in_yml = True

        if is_description_in_package and is_description_in_yml:
            self._is_valid = False
            print_error("A description was found both in the package and in the yml, "
                        "please update the package {}.".format(package_path))
            return False

        return True

import glob

from Tests.test_utils import re, print_error, print_warning, os, get_yaml
from Tests.scripts.constants import INTEGRATION_REGEX, BETA_INTEGRATION_REGEX, BETA_INTEGRATION_DISCLAIMER


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

    def is_valid_beta_description(self):
        """Check if beta disclaimer exists in detailed description"""
        data_dictionary = get_yaml(self.file_path)
        description_in_yml = data_dictionary.get('detaileddescription', '') if data_dictionary else ''

        if not re.match(BETA_INTEGRATION_REGEX, self.file_path, re.IGNORECASE):
            package_path = os.path.dirname(self.file_path)
            try:
                md_file_path = glob.glob(os.path.join(os.path.dirname(self.file_path), '*_description.md'))[0]
            except IndexError:
                self._is_valid = False
                print_error("No detailed description file was found in the package {}. Please add one,"
                            " and make sure it includes the beta disclaimer note."
                            "It should contain the string in constant"
                            "\"BETA_INTEGRATION_DISCLAIMER\"".format(package_path))
                return False

            with open(md_file_path) as description_file:
                description = description_file.read()
            if BETA_INTEGRATION_DISCLAIMER not in description:
                self._is_valid = False
                print_error("Detailed description in beta integration package {} "
                            "dose not contain the beta disclaimer note. "
                            "It should contain the string in constant"
                            " \"BETA_INTEGRATION_DISCLAIMER\".".format(package_path))
                return False
            else:
                return True
        elif BETA_INTEGRATION_DISCLAIMER not in description_in_yml:
            self._is_valid = False
            print_error("Detailed description field in beta integration {} "
                        "dose not contain the beta disclaimer note."
                        "It should contain the string in constant"
                        " \"BETA_INTEGRATION_DISCLAIMER\".".format(self.file_path))
            return False
        return True

    def is_duplicate_description(self):
        """Check if the integration has a non-duplicate description ."""
        is_description_in_yml = False
        is_description_in_package = False
        package_path = None
        md_file_path = None
        if not re.match(INTEGRATION_REGEX, self.file_path, re.IGNORECASE) \
                and not re.match(BETA_INTEGRATION_REGEX, self.file_path, re.IGNORECASE):
            package_path = os.path.dirname(self.file_path)
            try:
                md_file_path = glob.glob(os.path.join(os.path.dirname(self.file_path), '*_description.md'))[0]
            except IndexError:
                print_warning("No detailed description file was found in the package {}."
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

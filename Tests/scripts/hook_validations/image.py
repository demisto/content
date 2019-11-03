import glob
import base64

from Tests.test_utils import re, print_error, os, get_yaml
from Tests.scripts.constants import IMAGE_REGEX, INTEGRATION_REGEX, INTEGRATION_YML_REGEX, DEFAULT_IMAGE_BASE64


class ImageValidator(object):
    """ImageValidator was designed to make sure we use images within the permitted limits.

    Attributes:
        file_path (string): Path to the checked file.
        _is_valid (bool): the attribute which saves the valid/in-valid status of the current file.
    """
    IMAGE_MAX_SIZE = 10 * 1024  # 10kB

    def __init__(self, file_path):
        self._is_valid = True

        if re.match(INTEGRATION_REGEX, file_path, re.IGNORECASE):
            self.file_path = file_path
        else:
            if re.match(INTEGRATION_YML_REGEX, file_path, re.IGNORECASE):
                try:
                    self.file_path = glob.glob(os.path.join(os.path.dirname(file_path), '*.png'))[0]
                except IndexError:
                    self._is_valid = False
                    print_error("You've created/modified a package but failed to provide an image as a .png file, "
                                "please add an image in order to proceed.")

    def is_valid(self):
        """Validate that the image exists and that it is in the permitted size limits."""
        if self._is_valid is False:  # In case we encountered an IndexError in the init - we don't have an image
            return self._is_valid

        is_existing_image = False
        self.oversize_image()
        if '.png' not in self.file_path:
            is_existing_image = self.is_existing_image()
        if is_existing_image:
            self.is_not_default_image()

        return self._is_valid

    def oversize_image(self):
        """Check if the image if over sized, bigger than IMAGE_MAX_SIZE"""
        if re.match(IMAGE_REGEX, self.file_path, re.IGNORECASE):
            if os.path.getsize(self.file_path) > self.IMAGE_MAX_SIZE:  # disable-secrets-detection
                print_error("{} has too large logo, please update the logo to be under 10kB".format(self.file_path))
                self._is_valid = False

        else:
            data_dictionary = get_yaml(self.file_path)

            if not data_dictionary:
                return

            image = data_dictionary.get('image', '')

            if ((len(image) - 22) / 4.0) * 3 > self.IMAGE_MAX_SIZE:  # disable-secrets-detection
                print_error("{} has too large logo, please update the logo to be under 10kB".format(self.file_path))
                self._is_valid = False

    def is_existing_image(self):
        """Check if the integration has an image."""
        is_image_in_yml = False
        is_image_in_package = False

        data_dictionary = get_yaml(self.file_path)

        if not data_dictionary:
            return False

        if data_dictionary.get('image'):
            is_image_in_yml = True

        if not re.match(INTEGRATION_REGEX, self.file_path, re.IGNORECASE):
            package_path = os.path.dirname(self.file_path)
            if is_image_in_yml:
                print_error("You have added an image in the yml "
                            "file, please update the package {}".format(package_path))
                return False
            image_path = glob.glob(package_path + '/*.png')
            if image_path:
                is_image_in_package = True

        if not (is_image_in_package or is_image_in_yml):
            print_error("You have failed to add an image in the yml/package for {}".format(self.file_path))
            self._is_valid = False
            return False

        return True

    def is_not_default_image(self):
        """Check if the image is the default one"""
        if re.match(IMAGE_REGEX, self.file_path, re.IGNORECASE):
            with open(self.file_path, 'r') as image:
                image_data = image.read()
                encoded_image = base64.b64encode(image_data)
                if encoded_image == DEFAULT_IMAGE_BASE64:  # disable-secrets-detection
                    print_error("{} is the default image, please change to the "
                                "integration image.".format(self.file_path))
                    self._is_valid = False
                    return False
                else:
                    return True

        else:
            data_dictionary = get_yaml(self.file_path)

            if not data_dictionary:
                self._is_valid = False
                return False

            image = data_dictionary.get('image', '')

            if not image:
                self._is_valid = False
                return False

            image_split = image.split('base64,')
            if image_split and len(image_split) == 2:
                if image_split[1] == DEFAULT_IMAGE_BASE64:  # disable-secrets-detection
                    print_error("{} is the default image, please add the integration image.".format(self.file_path))
                    self._is_valid = False
                    return False
                else:
                    return True
            else:
                self._is_valid = False
                return False


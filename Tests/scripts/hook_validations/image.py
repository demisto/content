import glob
from Tests.test_utils import *


class ImageValidator(object):
    IMAGE_MAX_SIZE = 10 * 1024  # 10kB

    def __init__(self, file_path):
        self.file_path = file_path
        self._is_valid = True

    def is_invalid_image(self):
        return not self._is_valid

    def validate(self):
        self.oversize_image()
        if '.png' not in self.file_path:
            self.is_existing_image()

    def oversize_image(self):
        if re.match(IMAGE_REGEX, self.file_path, re.IGNORECASE):
            if os.path.getsize(self.file_path) > self.IMAGE_MAX_SIZE:  # disable-secrets-detection
                print_error("{} has too large logo, please update the logo to be under 10kB".format(self.file_path))
                self._is_valid = False

        else:
            data_dictionary = get_json(self.file_path)
            image = data_dictionary.get('image', '')

            if ((len(image) - 22) / 4.0) * 3 > self.IMAGE_MAX_SIZE:  # disable-secrets-detection
                print_error("{} has too large logo, please update the logo to be under 10kB".format(self.file_path))
                self._is_valid = False

    def is_existing_image(self):
        is_image_in_yml = False
        is_image_in_package = False
        if get_json(self.file_path).get('image'):
            is_image_in_yml = True

        if not re.match(INTEGRATION_REGEX, self.file_path, re.IGNORECASE):
            package_path = os.path.dirname(self.file_path)
            image_path = glob.glob(package_path + '/*.png')
            if image_path:
                if is_image_in_yml:
                    print_error("You have added an image both in the package and in the yml "
                                "file, please update the package {}".format(package_path))
                    return False

                is_image_in_package = True

        if not (is_image_in_package or is_image_in_yml):
            print_error("You have failed to add an image in the yml/package for {}".format(self.file_path))

        return is_image_in_package or is_image_in_yml

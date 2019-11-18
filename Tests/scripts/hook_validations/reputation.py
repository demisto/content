import os

from Tests.scripts.hook_validations.error_constants import Errors
from Tests.scripts.hook_validations.json_based import JSONBasedValidator
from Tests.test_utils import get_json, print_error


class ReputationValidator(JSONBasedValidator):
    scheme_name = 'reputation'

    def is_valid_scheme(self):
        super(ReputationValidator, self)._is_scheme_valid(self.scheme_name)

    def is_file_valid(self, validate_rn=True):
        super(ReputationValidator, self).is_file_valid(validate_rn=validate_rn)

    def is_valid_version(self):
        json_dict = get_json(self.file_path)
        is_valid = True
        reputations = json_dict.get('reputations')
        for reputation in reputations:
            internal_version = reputation.get('version')
            if internal_version != -1:
                object_id = reputation.get('id')
                err_str = '{} with id {}.f'.format(self.file_path, object_id)
                print_error(Errors.wrong_version(err_str, -1))
                is_valid = False

        return is_valid

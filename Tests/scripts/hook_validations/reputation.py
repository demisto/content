from Tests.scripts.hook_validations.json_based_validator import JSONBasedValidator
from Tests.test_utils import print_error


class ReputationValidator(JSONBasedValidator):
    def is_valid_version(self):
        # type: () -> bool
        """Validate that the reputations file as version of -1."""
        is_valid = True
        reputations = self.current_file.get('reputations')
        for reputation in reputations:
            internal_version = reputation.get('version')
            if internal_version != -1:
                object_id = reputation.get('id')
                print_error("Reputation object with id {} must have version -1".format(object_id))
                is_valid = False
                self.is_valid = False
        return is_valid

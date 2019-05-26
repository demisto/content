from Tests.scripts.hook_validations.conf_json import ConfJsonValidator


WITH_DESCRIPTION = {
    "test": "description"
}
MISSING_DESCRIPTION = {
    "test": "",
    "test2": "description"
}
TESTS_SECTION = [
    {
        "playbookID": "siri"
    },
    {
        "playbookID": "alexa"
    }
]


def test_conf_json_description():
    validator = ConfJsonValidator()

    assert validator.is_valid_description_in_conf_dict(checked_dict=WITH_DESCRIPTION), \
        "The conf validator couldn't find the description in the dictionary"


def test_conf_json_description_not_given():
    validator = ConfJsonValidator()

    assert validator.is_valid_description_in_conf_dict(checked_dict=MISSING_DESCRIPTION) is False, \
        "The conf validator couldn't find the missing description in the dictionary"


def test_the_missing_existence_of_added_test_in_conf_json():
    validator = ConfJsonValidator()

    validator.conf_data = {
        "tests": TESTS_SECTION
    }

    assert validator.is_test_in_conf_json(file_id="cortana") is False, \
        "The conf validator didn't catch that the test is missing"


def test_the_existence_of_added_test_in_conf_json():
    validator = ConfJsonValidator()

    validator.conf_data = {
        "tests": TESTS_SECTION
    }

    assert validator.is_test_in_conf_json(file_id="alexa"), \
        "The conf validator didn't catch the test although it exists in the test list"


def test_is_valid_conf_json_sanity_check():
    validator = ConfJsonValidator()

    validator.conf_data = {
        "skipped_tests": WITH_DESCRIPTION,
        "skipped_integrations": WITH_DESCRIPTION,
        "unmockable_integrations": WITH_DESCRIPTION,
    }

    assert validator.is_valid_conf_json(), \
        "The conf validator didn't find the description sections although they exist"


def test_is_valid_conf_json_negative_sanity_check():
    validator = ConfJsonValidator()

    validator.conf_data = {
        "skipped_tests": WITH_DESCRIPTION,
        "skipped_integrations": MISSING_DESCRIPTION,
        "unmockable_integrations": MISSING_DESCRIPTION
    }

    assert validator.is_valid_conf_json() is False, \
        "The conf validator didn't find the missing description sections although they don't exist"

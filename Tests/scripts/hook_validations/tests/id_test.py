from Tests.scripts.hook_validations.id import IDSetValidator


def test_validness_in_set():
    validator = IDSetValidator(is_circle=False, is_test_run=True)

    obj_data = {
        "test": {
            "name": "test"
        }
    }
    obj_set = [
        obj_data,
    ]

    assert validator.is_valid_in_id_set(file_path="test", obj_data=obj_data, obj_set=obj_set), \
        "The id validator couldn't find id as valid one"


def test_obj_not_found_in_set():
    validator = IDSetValidator(is_circle=False, is_test_run=True)

    obj_data = {
        "test": {
            "name": "test"
        }
    }
    actual_obj_set = {
        "test": {
            "name": "test",
            "fromversion": "1.2.2"
        }
    }
    obj_set = [
        actual_obj_set,
    ]

    assert validator.is_valid_in_id_set(file_path="test", obj_data=obj_data, obj_set=obj_set) is False, \
        "The id validator couldn't find id as valid one"


def test_obj_data_mismatch_in_set():
    validator = IDSetValidator(is_circle=False, is_test_run=True)

    obj_data = {
        "test": {
            "name": "test"
        }
    }
    actual_obj_set = {
        "test": {
            "name": "not test",
        }
    }
    obj_set = [
        actual_obj_set,
    ]

    assert validator.is_valid_in_id_set(file_path="test", obj_data=obj_data, obj_set=obj_set) is False, \
        "The id validator couldn't find id as valid one"

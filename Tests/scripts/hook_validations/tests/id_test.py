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


def test_duplicated_id_same_set():
    validator = IDSetValidator(is_circle=False, is_test_run=True)

    obj_data = {
        "test": {
            "name": "test"
        }
    }
    actual_obj_set = {
        "test": {
            "name": "test",
        }
    }
    obj_set = [
        actual_obj_set,
    ]

    validator.id_set = {
        "testing_set": obj_set
    }
    assert validator.is_id_duplicated(obj_id="test", obj_data=obj_data, obj_type="testing_set") is False, \
        "The id validator found the id as duplicated although it is not"


def test_duplicated_id_different_set():
    validator = IDSetValidator(is_circle=False, is_test_run=True)

    obj_data = {
        "test": {
            "name": "test"
        }
    }
    actual_obj_set = {
        "test": {
            "name": "test",
        }
    }
    obj_set = [
        actual_obj_set,
    ]

    validator.id_set = {
        "not_testing_set": obj_set
    }
    assert validator.is_id_duplicated(obj_id="test", obj_data=obj_data, obj_type="testing_set"), \
        "The id validator couldn't find id as duplicated one(In different sets)"


def test_duplicated_id_with_same_versioning_diff_data():
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

    validator.id_set = {
        "not_testing_set": obj_set
    }
    assert validator.is_id_duplicated(obj_id="test", obj_data=obj_data, obj_type="testing_set"), \
        "The id validator couldn't find id as duplicated one(In different sets)"


def test_duplicated_id_with_diff_versioning():
    validator = IDSetValidator(is_circle=False, is_test_run=True)

    obj_data = {
        "test": {
            "name": "test",
            "fromversion": "1.0.0"
        }
    }
    actual_obj_set = {
        "test": {
            "name": "test",
            "toversion": "2.0.0"
        }
    }
    obj_set = [
        actual_obj_set,
    ]

    validator.id_set = {
        "testing_set": obj_set
    }
    assert validator.is_id_duplicated(obj_id="test", obj_data=obj_data, obj_type="testing_set"), \
        "The id validator couldn't find id as duplicated one(In different sets)"

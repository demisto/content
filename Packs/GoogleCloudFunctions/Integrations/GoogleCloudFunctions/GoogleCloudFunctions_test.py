import pytest
from GoogleCloudFunctions import set_default_project_id


test_set_default_project_id():


def test_format_parameters():
    from GoogleCloudFunctions import format_parameters
    parameters_to_check = "key:value , name: lastname, onemorekey : to test "
    result = format_parameters(parameters_to_check)
    assert result == '{"key": "value", "name": "lastname", "onemorekey": "to test"}'

    bad_parameters = "oh:no,bad"
    with pytest.raises(ValueError):
        format_parameters(bad_parameters)

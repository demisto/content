import pytest
from GoogleCloudFunctions import resolve_default_project_id


@pytest.mark.parametrize('project, credentials_json, expected_output,expected_exception', [
    ("some-project-id", {"credentials_json": {"type": "service_account", "project_id": "some-project-id"}},
     "some-project-id", None),
    (None, {"credentials_json": {"type": "service_account", "project_id": "some-project-id"}}, "some-project-id", None),
    ("some-project-id", {"credentials_json": {"type": "service_account"}}, "some-project-id", None),
    (None, {"credentials_json": {"type": "service_account"}}, None, SystemExit)

])
def test_resolve_default_project_id(project, credentials_json, expected_output, expected_exception):
    credentials_json = credentials_json.get('credentials_json')
    if expected_exception is None:
        assert resolve_default_project_id(project, credentials_json) == expected_output
    else:
        with pytest.raises(SystemExit):
            assert resolve_default_project_id(project, credentials_json) == expected_output


def test_format_parameters():
    from GoogleCloudFunctions import format_parameters
    parameters_to_check = "key:value , name: lastname, onemorekey : to test "
    result = format_parameters(parameters_to_check)
    assert result == '{"key": "value", "name": "lastname", "onemorekey": "to test"}'

    bad_parameters = "oh:no,bad"
    with pytest.raises(ValueError):
        format_parameters(bad_parameters)

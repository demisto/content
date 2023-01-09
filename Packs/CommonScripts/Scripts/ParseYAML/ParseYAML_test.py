
import pytest


def test_load_yaml():
    """
    Given:
        - A YAML string
    When:
        - load_yaml function is called
    Then:
        - Ensure the function returns the correct python data structure
    """
    from ParseYAML import load_yaml
    assert load_yaml("a: 1") == {"a": 1}


def test_load_and_parse_yaml_command_fail():
    """
    Given:
        - An empty Yaml string
    When:
        - load_and_parse_yaml_command function is called
    THen:
        - Raise ValueError
    """
    from ParseYAML import load_and_parse_yaml_command
    with pytest.raises(ValueError):
        load_and_parse_yaml_command({"string": ""})


def test_load_and_parse_yaml_command():
    """
    Given:
        - A Yaml string
    When:
        - load_and_parse_yaml_command function is called
    THen:
        - Ensure the function returns the correct CommandResults object
    """
    from ParseYAML import load_and_parse_yaml_command
    result = load_and_parse_yaml_command({"string": "a: 1"})
    assert result.outputs == {"a": 1}

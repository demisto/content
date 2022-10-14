from JiraCreateIssueExample import add_additional_args, get_known_args_from_input, get_additional_args_from_input, DEFAULT_ARGS
import pytest


@pytest.mark.parametrize("input,expected", [
    ({DEFAULT_ARGS[0]: "system down"}.items(), {"summary": "system down"}),
    ({DEFAULT_ARGS[0]: "system down", "unknown_key": "some key"}.items(), {"summary": "system down"}),
    ({"unknown_key": "some key"}.items(), {})
])
def test_get_known_args_from_input(input, expected):

    """
    Given:
        - A dictionary view with Jira fields
    When:
        - 1 known argument key is supplied
        - 1 known argument key is supplied, 1 unknown argument key is supplied
        - 0 known arguments are supplied,  1 unknown argument key is supplied

    Then:
        - dict with known argument key is returned
        - dict with known argument key is returned
        - empty dict
    """

    args = get_known_args_from_input(input)

    assert isinstance(args, dict)
    assert args == expected


@pytest.mark.parametrize("input,expected", [
    ({DEFAULT_ARGS[0]: "system down"}.items(), {}),
    ({DEFAULT_ARGS[0]: "system down", "unknown_key": "some key"}.items(), {"unknown_key": "some key"}),
    ({"unknown_key": "some key"}.items(), {"unknown_key": "some key"})
])
def test_get_additional_args_from_input(input, expected):
    """
    Given:
        - A dictionary view with Jira fields
    When:
        - 1 unknown argument key is supplied
        - 1 unknown argument key is supplied, 1 known argument key is supplied
        - 1 known arguments are supplied, 0 unknown argument key is supplied

    Then:
        - empty dict
        - dict with unknown argument key is returned
        - dict with unknown argument key is returned
    """

    args = get_additional_args_from_input(input)

    assert isinstance(args, dict)
    assert args == expected


@pytest.mark.parametrize("known,additional,expected", [
    ({DEFAULT_ARGS[0]: "system down"}, None, {DEFAULT_ARGS[0]: "system down"}),
    ({DEFAULT_ARGS[0]: "system down"}, {"unknown_key": "some key"},
        {'issueJSON': '{"unknown_key": "some key"}', DEFAULT_ARGS[0]: "system down"}),
])
def test_add_additional_args(known, additional, expected):
    """
    Given:
        - 2 dictionaries of known and unknown keys
    When:
        - 1 known dict, no unknown dicts
        - 1 known dict and one unknown dict

    Then:
        - dict with known argument key is returned
        - dict with known argument and unknown keys returned
    """

    args = add_additional_args(known, additional)

    if additional:
        assert "issueJSON" in args.keys()

    assert isinstance(args, dict)
    assert args == expected

#!/usr/bin/env python3
import pytest
from typing import Any
from utils import (
    get_env_var,
    EnvVariableError,
    get_content_reviewers,
    CONTRIBUTION_REVIEWERS_KEY,
    CONTRIBUTION_SECURITY_REVIEWER_KEY,
    TIM_REVIEWER_KEY,
    DOC_REVIEWER_KEY,
    get_doc_reviewer
)


class TestGetEnvVar:
    def test_no_env_var(self):
        """
        Scenario: Try getting an environment variable

        Given
        - Using the 'get_env_var' function

        When
        - The environment variable does not exist
        - No 'default_val' argument was passed when the function was called

        Then
        - Ensure a 'EnvVariableError' exception is raised
        """
        with pytest.raises(EnvVariableError):
            get_env_var('MADE_UP_ENV_VARIABLE')

    def test_empty_env_var(self, monkeypatch):
        """
        Scenario: Try getting an environment variable

        Given
        - Using the 'get_env_var' function

        When
        - The environment variable's value is an empty string
        - No 'default_val' argument was passed when the function was called

        Then
        - Ensure a 'EnvVariableError' exception is raised
        """
        monkeypatch.setenv('MADE_UP_ENV_VARIABLE', '')
        with pytest.raises(EnvVariableError):
            get_env_var('MADE_UP_ENV_VARIABLE')

    def test_no_env_var_with_default(self):
        """
        Scenario: Try getting an environment variable

        Given
        - Using the 'get_env_var' function

        When
        - The environment variable does not exist
        - The 'default_val' argument was passed with a value of 'TIMOTHY'

        Then
        - Ensure 'TIMOTHY' is returned from the function
        """
        default_val = 'TIMOTHY'
        env_var_val = get_env_var('MADE_UP_ENV_VARIABLE', default_val)
        assert env_var_val == default_val

    def test_empty_env_var_with_default(self, monkeypatch):
        """
        Scenario: Try getting an environment variable

        Given
        - Using the 'get_env_var' function

        When
        - The environment variable's value is an empty string
        - The 'default_val' argument was passed with a value of 'TIMOTHY'

        Then
        - Ensure 'TIMOTHY' is returned from the function
        """
        monkeypatch.setenv('MADE_UP_ENV_VARIABLE', '')
        default_val = 'TIMOTHY'
        env_var_val = get_env_var('MADE_UP_ENV_VARIABLE', default_val)
        assert env_var_val == default_val

    def test_existing_env_var(self, monkeypatch):
        """
        Scenario: Try getting an environment variable

        Given
        - Using the 'get_env_var' function

        When
        - The environment variable's value is 'LEROY JENKINS'
        - No 'default_val' argument was passed when the function was called

        Then
        - Ensure 'LEROY JENKINS' is returned from the function
        """
        monkeypatch.setenv('MADE_UP_ENV_VARIABLE', 'LEROY JENKINS')
        env_var_val = get_env_var('MADE_UP_ENV_VARIABLE')
        assert env_var_val == 'LEROY JENKINS'

    def test_existing_env_var_with_default(self, monkeypatch):
        """
        Scenario: Try getting an environment variable

        Given
        - Using the 'get_env_var' function

        When
        - The environment variable's value is 'LEROY JENKINS'
        - The 'default_val' argument was passed with a value of 'TIMOTHY'

        Then
        - Ensure 'LEROY JENKINS' is returned from the function
        """
        monkeypatch.setenv('MADE_UP_ENV_VARIABLE', 'LEROY JENKINS')
        default_val = 'TIMOTHY'
        env_var_val = get_env_var('MADE_UP_ENV_VARIABLE', default_val)
        assert env_var_val == 'LEROY JENKINS'


@pytest.mark.parametrize(
    'content_roles,expected_content_reviewers,expected_security_reviewer, expected_tim_reviewer',
    [
        ({
            CONTRIBUTION_REVIEWERS_KEY: ["cr1", "cr2", "cr3", "cr4"],
            CONTRIBUTION_SECURITY_REVIEWER_KEY: "sr1",
            TIM_REVIEWER_KEY: "tr1",
            "CONTRIBUTION_TL": "tl1",
            "ON_CALL_DEVS": ["ocd1", "ocd2"]
        }, ["cr1", "cr2", "cr3", "cr4"], "sr1", "tr1")
    ]
)
def test_get_content_reviewers(
    content_roles: dict[str, Any],
    expected_content_reviewers: list[str],
    expected_security_reviewer: str,
    expected_tim_reviewer: str
):
    """
    Test retrieval of content and security reviewers.

    Given:
        - A ``dict[str, Any]``

    When:
        - 4 content reviewers and 1 security reviewers provided

    Then:
        - 4 content reviewers and 1 security reviewer added
    """

    actual_content_reviewers, actual_security_reviewer, actual_tim_reviewer = get_content_reviewers(content_roles)
    assert actual_content_reviewers == expected_content_reviewers
    assert actual_security_reviewer == expected_security_reviewer
    assert actual_tim_reviewer == expected_tim_reviewer


@pytest.mark.parametrize(
    'content_roles',
    [
        ({
            CONTRIBUTION_REVIEWERS_KEY: [],
            CONTRIBUTION_SECURITY_REVIEWER_KEY: "sr1",
        }),
        ({
            CONTRIBUTION_REVIEWERS_KEY: ["cr1", "cr2"],
            CONTRIBUTION_SECURITY_REVIEWER_KEY: None,
        }),
        ({
            CONTRIBUTION_REVIEWERS_KEY: ["cr1", "cr2"],
            CONTRIBUTION_SECURITY_REVIEWER_KEY: "",
        }),
        ({
            CONTRIBUTION_REVIEWERS_KEY: "sr1",
            CONTRIBUTION_SECURITY_REVIEWER_KEY: "cr1",
        }),
        ({
            CONTRIBUTION_SECURITY_REVIEWER_KEY: ["sr1"],
        }),
        ({
            CONTRIBUTION_REVIEWERS_KEY: ["cr1"],
        }),
        ({
            "CONTRIBUTION_TL": "tl1",
            "ON_CALL_DEVS": ["ocd1", "ocd2"]
        })
    ]
)
def test_exit_get_content_reviewers(
    content_roles: dict[str, Any]
):
    """
    Test retrieval of content and security reviewers when the file/`dict`
    has unexpected/incorrect structure.

    Given:
        - A ``dict[str, Any]``

    When:
        - Case A: An empty contribution reviewers `list` is supplied.
        - Case B: An undefined security reviewer is supplied.
        - Case C: An empty security reviewer is supplied.
        - Case D: A `str` is supplied for the contribution reviewers.
        - Case E: No contribution reviewers key is supplied.
        - Case F: No security reviewer key is supplied.
        - Case G: No security reviewer key nor contribution reviewers key is supplied.

    Then:
        - Case A-G: Result in `sys.exit(1)`.
    """

    with pytest.raises(SystemExit) as e:
        get_content_reviewers(content_roles)
        assert e.type == SystemExit
        assert e.value.code == 1


@pytest.mark.parametrize(
    'content_roles,expected_doc_reviewer',
    [
        ({
            "CONTRIBUTION_REVIEWERS": ["cr1", "cr2", "cr3", "cr4"],
            "CONTRIBUTION_SECURITY_REVIEWER": "sr1",
            "CONTRIBUTION_TL": "tl1",
            "ON_CALL_DEVS": ["ocd1", "ocd2"],
            DOC_REVIEWER_KEY: "dr1"
        }, "dr1")
    ]
)
def test_get_doc_reviewer(
    content_roles: dict[str, Any],
    expected_doc_reviewer: str
):
    """
    Test retrieval of doc reviewer.

    Given:
        - A ``dict[str, Any]``

    When:
        - Case A: 4 content reviewers and 1 security reviewers provided, 1 doc reviewer
        - Case B: There's no ``DOC_REVIEWER`` key in `dict`.

    Then:
        - Case A: 1 doc reviewer returned.
        - Case B: `None`.
    """

    actual_doc_reviewer = get_doc_reviewer(content_roles)
    assert actual_doc_reviewer == expected_doc_reviewer


@pytest.mark.parametrize(
    'content_roles',
    [
        ({
            DOC_REVIEWER_KEY: [],
        }),
        ({
            "CONTRIBUTION_REVIEWERS": ["cr1", "cr2"],
        }),
        ({
            DOC_REVIEWER_KEY: ""
        }),
        ({
            DOC_REVIEWER_KEY: None
        })
    ]
)
def test_exit_get_doc_reviewer(
    content_roles: dict[str, Any]
):
    """
    Test retrieval of content and security reviewers when the file/`dict`
    has unexpected/incorrect structure.
    Given:
        - A ``dict[str, Any]``
    When:
        - Case A: Document reviewer specified as an array/list.
        - Case B: Document reviewer key is not specified.
        - Case C: Document reviewer is empty.
        - Case D: Document reviewer is undefined.
    Then:
        - Case A-G: Result in `sys.exit(1)`.
    """

    with pytest.raises(ValueError) as e:
        get_doc_reviewer(content_roles)
        assert e.type == ValueError

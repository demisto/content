#!/usr/bin/env python3
import pytest
from utils import get_env_var, EnvVariableError


class TestGetEnvVar(object):
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

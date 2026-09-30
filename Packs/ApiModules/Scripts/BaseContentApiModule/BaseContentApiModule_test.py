"""Unit tests for BaseContentApiModule.

This module tests the base classes provided by BaseContentApiModule:
- ContentBaseModel: Pydantic model with user-friendly validation
- BaseParams: Base parameters with common connection settings
- BaseExecutionConfig: Centralized execution configuration
"""

import pytest
from pydantic import Field
from BaseContentApiModule import ContentBaseModel, BaseParams, BaseExecutionConfig
from CommonServerPython import DemistoException


class TestContentBaseModel:
    """Test ContentBaseModel validation and error formatting."""

    def test_valid_model(self):
        """Test that valid data creates a model successfully."""

        class TestModel(ContentBaseModel):
            name: str
            age: int

        model = TestModel(name="John", age=30)
        assert model.name == "John"
        assert model.age == 30

    def test_invalid_model_raises_demisto_exception(self):
        """Test that invalid data raises DemistoException with formatted errors."""

        class TestModel(ContentBaseModel):
            name: str
            age: int

        with pytest.raises(DemistoException) as exc_info:
            TestModel(name="John", age="invalid")

        error_message = str(exc_info.value)
        assert "Invalid Inputs:" in error_message
        assert "age:" in error_message

    def test_model_str_representation(self):
        """Test that model string representation uses aliases."""

        class TestModel(ContentBaseModel):
            internal_name: str = Field(alias="externalName")

        model = TestModel(externalName="test")
        assert "externalName" in str(model)

    def test_extra_fields_ignored(self):
        """Test that extra fields are ignored per Config."""

        class TestModel(ContentBaseModel):
            name: str

        model = TestModel(name="John", extra_field="ignored")
        assert model.name == "John"
        assert not hasattr(model, "extra_field")


class TestBaseParams:
    """Test BaseParams common connection settings."""

    def test_default_values(self):
        """Test that default values are set correctly."""
        params = BaseParams()
        assert params.insecure is False
        assert params.proxy is False
        assert params.verify is True

    def test_verify_property(self):
        """Test that verify property returns inverse of insecure."""
        params_secure = BaseParams(insecure=False)
        assert params_secure.verify is True

        params_insecure = BaseParams(insecure=True)
        assert params_insecure.verify is False

    def test_inheritance(self):
        """Test that BaseParams can be inherited."""

        class CustomParams(BaseParams):
            api_key: str

        params = CustomParams(api_key="test-key", insecure=True, proxy=True)
        assert params.api_key == "test-key"
        assert params.insecure is True
        assert params.proxy is True
        assert params.verify is False


class TestBaseExecutionConfig:
    """Test BaseExecutionConfig centralized configuration."""

    def test_command_property(self, mocker):
        """Test that command property returns the current command."""
        mocker.patch("demistomock.command", return_value="test-module")
        mocker.patch("demistomock.params", return_value={})
        mocker.patch("demistomock.args", return_value={})
        mocker.patch("demistomock.getLastRun", return_value={})

        config = BaseExecutionConfig()
        assert config.command == "test-module"

    def test_raw_params_stored(self, mocker):
        """Test that raw params are stored correctly."""
        test_params = {"url": "https://api.example.com", "api_key": "test"}
        mocker.patch("demistomock.command", return_value="test-module")
        mocker.patch("demistomock.params", return_value=test_params)
        mocker.patch("demistomock.args", return_value={})
        mocker.patch("demistomock.getLastRun", return_value={})

        config = BaseExecutionConfig()
        assert config._raw_params == test_params

    def test_raw_args_stored(self, mocker):
        """Test that raw args are stored correctly."""
        test_args = {"limit": 10, "severity": "high"}
        mocker.patch("demistomock.command", return_value="my-command")
        mocker.patch("demistomock.params", return_value={})
        mocker.patch("demistomock.args", return_value=test_args)
        mocker.patch("demistomock.getLastRun", return_value={})

        config = BaseExecutionConfig()
        assert config._raw_args == test_args

    def test_last_run_for_fetch_commands(self, mocker):
        """Test that last_run is retrieved for fetch commands."""
        test_last_run = {"offset": 100}
        mocker.patch("demistomock.command", return_value="fetch-incidents")
        mocker.patch("demistomock.params", return_value={})
        mocker.patch("demistomock.args", return_value={})
        mocker.patch("demistomock.getLastRun", return_value=test_last_run)

        config = BaseExecutionConfig()
        assert config._raw_last_run == test_last_run

    def test_assets_last_run_for_fetch_assets(self, mocker):
        """Test that assets_last_run is retrieved for fetch-assets command."""
        test_assets_last_run = {"stage": "assets", "offset": 50}
        mocker.patch("demistomock.command", return_value="fetch-assets")
        mocker.patch("demistomock.params", return_value={})
        mocker.patch("demistomock.args", return_value={})
        mocker.patch("demistomock.getLastRun", return_value={})
        mocker.patch("demistomock.getAssetsLastRun", return_value=test_assets_last_run)

        config = BaseExecutionConfig()
        assert config._raw_assets_last_run == test_assets_last_run

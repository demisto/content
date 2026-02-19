"""Base Content API Module

This module provides base classes for building robust Cortex integrations with:
- User-friendly validation error formatting via Pydantic models
- Common connection settings (proxy, SSL verification)
- Centralized execution configuration to minimize redundant system calls

Classes:
    ContentBaseModel: Base Pydantic model with enhanced validation error formatting
    BaseParams: Base class for integration parameters with common connection settings
    BaseExecutionConfig: Centralized entry point holding command, params, args, and last_run
"""

from pydantic import BaseModel, ValidationError, Extra  # pylint: disable=no-name-in-module

import demistomock as demisto
from CommonServerPython import *


class ContentBaseModel(BaseModel):
    """Base Pydantic model with user-friendly validation error formatting.

    INTEGRATION DEVELOPER TIP:
    This base class enhances Pydantic's default validation by:
    1. Catching ValidationError exceptions
    2. Formatting them in a user-friendly way
    3. Raising `DemistoException` with clear error messages

    All parameter and argument models should inherit from this class to provide
    consistent, readable error messages to users when validation fails.
    """

    def __init__(self, **data):
        try:
            super().__init__(**data)
        except ValidationError as e:
            # Format errors in a user-friendly way
            error_messages = []
            for error in e.errors():
                field = error["loc"][0] if error["loc"] else "unknown"
                msg = error["msg"]
                error_messages.append(f"- {field}: {msg}")

            raise DemistoException("Invalid Inputs:\n" + "\n".join(error_messages)) from e

    def __str__(self):
        return str(self.dict(by_alias=True))

    def __repr__(self):
        return str(self.dict(by_alias=True))

    class Config:
        extra = Extra.ignore
        allow_population_by_field_name = True


class BaseParams(ContentBaseModel):
    """Base class for integration parameters with common connection settings.

    INTEGRATION DEVELOPER TIP:
    This class provides common parameters that most integrations need:
    - insecure: Whether to skip SSL certificate verification
    - proxy: Whether to use system proxy settings
    - verify: Computed property that returns the inverse of insecure

    Your integration's parameter class should inherit from this to get these
    common settings automatically.
    """

    insecure: bool = False
    proxy: bool = False

    @property
    def verify(self) -> bool:
        """Return SSL verification setting (inverse of insecure).

        Returns:
            bool: True if SSL certificates should be verified, False otherwise.
        """
        return not self.insecure


class BaseExecutionConfig:
    """Centralized entry point for the integration that holds command, params, args, and last_run.

    This class encapsulates all the information needed to execute a command, including:
    - command: The command being executed
    - params: Integration parameters (validated via Pydantic)
    - args: Command-specific arguments (different per command, validated via Pydantic)
    - last_run: State from when the previous fetch ended (for fetch commands)
    """

    def __init__(self):
        # INTEGRATION DEVELOPER TIP:
        # Centralize all your `demisto` class usages in the `ExecutionConfig`
        # class constructor and create an instance of the class *once* in the
        # `main` function to avoid redundant system calls. Access the required
        # configurations as validated and type-safe properties.
        self._raw_command: str = demisto.command()
        self._raw_params: dict = demisto.params()
        self._raw_args: dict = demisto.args()
        self._raw_last_run: dict = demisto.getLastRun() if self._raw_command in FETCH_COMMANDS else {}
        self._raw_assets_last_run: dict = demisto.getAssetsLastRun() if self._raw_command == "fetch-assets" else {}

    @property
    def command(self) -> str:
        """Get the current command being executed.

        Returns:
            str: The command name (e.g., 'test-module', 'ip', 'fetch-incidents').
        """
        return self._raw_command

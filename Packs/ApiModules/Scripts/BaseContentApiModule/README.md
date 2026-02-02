# BaseContentApiModule

Base classes for building robust Cortex integrations with user-friendly validation, common connection settings, and centralized execution configuration.

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Classes](#classes)
  - [ContentBaseModel](#contentbasemodel)
  - [BaseParams](#baseparams)
  - [BaseExecutionConfig](#baseexecutionconfig)
- [Complete Integration Example](#-complete-integration-example)
- [API Reference](#api-reference)

---

## Overview

This API module provides foundational classes that integrations can use to:
- Validate configuration parameters and command arguments with user-friendly error messages.
- Manage common connection settings (proxy, SSL verification)
- Centralize execution configuration to minimize redundant system calls

These classes work seamlessly with `ContentClient` from `ContentClientApiModule` to provide a complete foundation for building production-ready integrations.

---

## Key Features

| Feature | Description |
|---------|-------------|
| **User-Friendly Validation** | Pydantic-based validation with clear, actionable error messages |
| **Common Connection Settings** | Standardized proxy and SSL verification parameters |
| **Centralized Configuration** | Single entry point for command, params, args, and last_run |
| **Type Safety** | Full type hints and validation for integration parameters |
| **Minimal Boilerplate** | Reduce redundant `demisto` class calls |

---

## Installation

Import the module in your integration:

```python
from BaseContentApiModule import *
```

---

## Quick Start

### Minimal Example

```python
from BaseContentApiModule import ContentBaseModel, BaseParams, BaseExecutionConfig
from pydantic import AnyUrl

# Define your integration parameters
class MyIntegrationParams(BaseParams):
    url: AnyUrl
    api_key: str
    max_fetch: int = 50

# Define command arguments
class MyCommandArgs(ContentBaseModel):
    limit: int = 10
    severity: str

# Create execution configuration
class MyExecutionConfig(BaseExecutionConfig):
    @property
    def params(self) -> MyIntegrationParams:
        return MyIntegrationParams(**self._raw_params)
    
    @property
    def my_command_args(self) -> MyCommandArgs:
        return MyCommandArgs(**self._raw_args)

# Use in main function
def main():
    execution = MyExecutionConfig()
    params = execution.params  # Validated parameters
    
    if execution.command == "my-command":
        args = execution.my_command_args  # Validated arguments
        # Execute command logic...
```

---

## Classes

### ContentBaseModel

Base Pydantic model with enhanced validation error formatting.

#### Features

- Catches `ValidationError` exceptions from Pydantic
- Formats validation errors in a user-friendly way
- Raises `DemistoException` with clear, readable error messages
- Ignores extra fields automatically
- Supports field aliases for parameter name mapping

#### Usage

```python
from BaseContentApiModule import ContentBaseModel
from pydantic import Field

class MyArgs(ContentBaseModel):
    """Arguments for my-command."""
    
    name: str
    age: int
    email: str | None = None
    is_active: bool = Field(default=True, alias="isActive")

# Valid usage
args = MyArgs(name="John", age=30, isActive=False)

# Invalid usage - raises DemistoException with clear message
try:
    args = MyArgs(name="John", age="invalid")
except DemistoException as e:
    # Error message: "Invalid Inputs:\n- age: value is not a valid integer"
    print(str(e))
```

#### String Representation

```python
args = MyArgs(name="John", age=30, isActive=False)
print(str(args))  # Uses aliases: {'name': 'John', 'age': 30, 'isActive': False}
```

---

### BaseParams

Base class for integration parameters with common connection settings.

#### Attributes

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `insecure` | `bool` | `False` | Whether to skip SSL certificate verification |
| `proxy` | `bool` | `False` | Whether to use system proxy settings |
| `verify` | `bool` (property) | `not insecure` | SSL verification setting (computed) |

#### Usage

```python
from BaseContentApiModule import BaseParams
from pydantic import AnyUrl, Field

class MyIntegrationParams(BaseParams):
    """Integration parameters with validation.
    
    Attributes:
        url: API base URL (trailing slash removed automatically).
        api_key: API key for authentication.
        max_fetch: Maximum incidents per fetch.
    """
    # proxy and insecure are already defined in BaseParams
    url: AnyUrl
    api_key: str
    max_fetch: int = Field(default=50, ge=1, le=1000)
    
    @validator('url', allow_reuse=True)
    def clean_url(cls, v):
        """Remove trailing slash from URL."""
        return v.rstrip('/')

# Usage
params = MyIntegrationParams(
    url="https://api.example.com/",
    api_key="secret-key",
    max_fetch=100,
    insecure=True,
    proxy=False
)

print(params.url)     # "https://api.example.com" (trailing slash removed)
print(params.verify)  # False (inverse of insecure)
```

---

### BaseExecutionConfig

Centralized entry point for integration execution that holds command, params, args, and last_run.

#### Features

- Encapsulates all information needed to execute a command
- Centralizes `demisto` class usages to avoid redundant system calls
- Provides type-safe access to configuration via properties
- Automatically retrieves last_run for fetch commands
- Supports both regular fetch and fetch-assets commands

#### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `_raw_command` | `str` | The command being executed |
| `_raw_params` | `dict` | Raw integration parameters dictionary |
| `_raw_args` | `dict` | Raw command arguments dictionary |
| `_raw_last_run` | `dict` | State from previous fetch execution |
| `_raw_assets_last_run` | `dict` | State from previous fetch-assets execution |

#### Usage

```python
from BaseContentApiModule import BaseExecutionConfig, BaseParams, ContentBaseModel

class MyIntegrationParams(BaseParams):
    url: str
    api_key: str

class MyCommandArgs(ContentBaseModel):
    limit: int = 10

class MyLastRun(ContentBaseModel):
    offset: int = 0
    last_id: str | None = None

class MyExecutionConfig(BaseExecutionConfig):
    """Centralized execution configuration for MyIntegration."""
    
    @property
    def params(self) -> MyIntegrationParams:
        """Get validated integration parameters."""
        return MyIntegrationParams(**self._raw_params)
    
    @property
    def my_command_args(self) -> MyCommandArgs:
        """Get validated arguments for my-command."""
        return MyCommandArgs(**self._raw_args)
    
    @property
    def last_run(self) -> MyLastRun:
        """Get validated last run state for fetch commands."""
        return MyLastRun(**self._raw_last_run)

# Use in main function
def main():
    execution = MyExecutionConfig()
    
    # Access command name
    command = execution.command
    
    # Access validated parameters (only called once)
    params = execution.params
    
    # Route to command functions
    if command == "my-command":
        args = execution.my_command_args
        # Execute command...
    elif command == "fetch-incidents":
        last_run = execution.last_run
        # Execute fetch...
```

---

## 🔧 Complete Integration Example

Here's a complete example of a production-ready integration using BaseContentApiModule with ContentClient:

```python
from BaseContentApiModule import ContentBaseModel, BaseParams, BaseExecutionConfig
from ContentClientApiModule import ContentClient, BearerTokenAuthHandler, RetryPolicy
from pydantic import AnyUrl, Field, validator
import demistomock as demisto
from CommonServerPython import *


# ===== Parameters =====

class Credentials(ContentBaseModel):
    password: str


class MyIntegrationParams(BaseParams):
    """Integration parameters with validation."""
    
    url: AnyUrl
    credentials: Credentials
    max_fetch: int = Field(default=50, ge=1, le=1000)
    severity: str = "high"
    
    @validator('url', allow_reuse=True)
    def clean_url(cls, v):
        """Remove trailing slash from URL."""
        return v.rstrip('/')


# ===== Command Arguments =====

class GetAlertsArgs(ContentBaseModel):
    """Arguments for get-alerts command."""
    
    limit: int = Field(default=10, ge=1, le=100)
    severity: str | None = None


class LastRun(ContentBaseModel):
    """State management for fetch-incidents."""
    
    offset: int = 0
    last_id: str | None = None
    
    def set(self):
        """Save state for next fetch."""
        demisto.setLastRun(self.dict(by_alias=True))


# ===== Execution Configuration =====

class MyExecutionConfig(BaseExecutionConfig):
    """Centralized execution configuration."""
    
    @property
    def params(self) -> MyIntegrationParams:
        return MyIntegrationParams(**self._raw_params)
    
    @property
    def get_alerts_args(self) -> GetAlertsArgs:
        return GetAlertsArgs(**self._raw_args)
    
    @property
    def last_run(self) -> LastRun:
        return LastRun(**self._raw_last_run)


# ===== Client =====

class MyIntegrationClient(ContentClient):
    """Client for MyIntegration API."""
    
    def __init__(self, params: MyIntegrationParams):
        super().__init__(
            base_url=params.url,
            verify=params.verify,
            proxy=params.proxy,
            auth_handler=BearerTokenAuthHandler(token=params.credentials.password),
            retry_policy=RetryPolicy(max_attempts=3),
            diagnostic_mode=is_debug_mode(),
            client_name="MyIntegration"
        )
    
    def get_alerts(self, limit: int, severity: str | None = None) -> list[dict]:
        """Fetch alerts from the API."""
        params = {"limit": limit}
        if severity:
            params["severity"] = severity
        return self.get("/api/v1/alerts", params=params)


# ===== Commands =====

def get_alerts_command(client: MyIntegrationClient, args: GetAlertsArgs) -> CommandResults:
    """Execute get-alerts command."""
    alerts = client.get_alerts(limit=args.limit, severity=args.severity)
    
    return CommandResults(
        outputs_prefix="MyIntegration.Alert",
        outputs_key_field="id",
        outputs=alerts,
        readable_output=tableToMarkdown("Alerts", alerts)
    )

def test_module(client: MyIntegrationClient) -> str:
    """Test the integration connection."""
    try:
        client.get_alerts(limit=1)
        return "ok"
    except Exception as e:
        return f"Test failed: {str(e)}"


# ===== Main =====

def main():
    execution = MyExecutionConfig()
    command = execution.command
    
    try:
        params = execution.params
        client = MyIntegrationClient(params)
        
        if command == "test-module":
            return_results(test_module(client))
        
        elif command == "my-integration-get-alerts":
            args = execution.get_alerts_args
            return_results(get_alerts_command(client, args))

        else:
            raise NotImplementedError(f"Command {command} not implemented")
    
    except Exception as e:
        demisto.error(f"Error executing {command}: {str(e)}")
        return_error(str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
```

---

## API Reference

### ContentBaseModel

Base Pydantic model with user-friendly validation error formatting.

#### Methods

| Method | Description |
|--------|-------------|
| `__init__(**data)` | Initialize model with validation |
| `__str__()` | String representation using aliases |
| `__repr__()` | Representation using aliases |
| `dict(by_alias=True)` | Convert to dictionary |

#### Configuration

| Setting | Value | Description |
|---------|-------|-------------|
| `extra` | `Extra.ignore` | Ignore extra fields not defined in model |
| `allow_population_by_field_name` | `True` | Allow both field names and aliases |

#### Example

```python
from BaseContentApiModule import ContentBaseModel
from pydantic import Field, validator

class MyModel(ContentBaseModel):
    name: str
    age: int = Field(ge=0, le=150)
    email: str | None = None
    is_active: bool = Field(default=True, alias="isActive")
    
    @validator('email')
    def validate_email(cls, v):
        if v and '@' not in v:
            raise ValueError('Invalid email format')
        return v

# Valid usage
model = MyModel(name="John", age=30, isActive=False)

# Invalid usage - clear error message
try:
    model = MyModel(name="John", age=200)
except DemistoException as e:
    # Error: "Invalid Inputs:\n- age: ensure this value is less than or equal to 150"
    pass
```

---

### BaseParams

Base class for integration parameters with common connection settings.

#### Attributes

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `insecure` | `bool` | `False` | Skip SSL certificate verification |
| `proxy` | `bool` | `False` | Use system proxy settings |
| `verify` | `bool` (property) | `not insecure` | SSL verification (computed) |

#### Example

```python
from BaseContentApiModule import BaseParams
from pydantic import AnyUrl, Field, validator

class MyIntegrationParams(BaseParams):
    """Integration parameters with validation.
    
    Attributes:
        url: API base URL.
        api_key: API key for authentication.
        max_fetch: Maximum incidents per fetch (1-1000).
    """
    url: AnyUrl
    api_key: str
    max_fetch: int = Field(default=50, ge=1, le=1000)
    
    @validator('url', allow_reuse=True)
    def clean_url(cls, v):
        """Remove trailing slash from URL."""
        return v.rstrip('/')
    
    @validator('max_fetch', allow_reuse=True)
    def validate_max_fetch(cls, v):
        """Ensure max_fetch is within limits."""
        if v > 1000:
            raise ValueError("max_fetch must not exceed 1000")
        return v

# Usage
params = MyIntegrationParams(
    url="https://api.example.com/",
    api_key="secret",
    max_fetch=100,
    insecure=True
)

print(params.url)     # "https://api.example.com"
print(params.verify)  # False
```

---

### BaseExecutionConfig

Centralized entry point for integration execution.

#### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `_raw_command` | `str` | Current command being executed |
| `_raw_params` | `dict` | Raw integration parameters |
| `_raw_args` | `dict` | Raw command arguments |
| `_raw_last_run` | `dict` | State from previous fetch |
| `_raw_assets_last_run` | `dict` | State from previous fetch-assets |

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `command` | `str` | Current command name |

#### Example

```python
from BaseContentApiModule import BaseExecutionConfig, BaseParams, ContentBaseModel

class MyParams(BaseParams):
    url: str
    api_key: str

class MyCommandArgs(ContentBaseModel):
    limit: int = 10
    severity: str | None = None

class MyLastRun(ContentBaseModel):
    offset: int = 0

class MyExecutionConfig(BaseExecutionConfig):
    """Centralized configuration for MyIntegration."""
    
    @property
    def params(self) -> MyParams:
        """Get validated integration parameters."""
        return MyParams(**self._raw_params)
    
    @property
    def my_command_args(self) -> MyCommandArgs:
        """Get validated arguments for my-command."""
        return MyCommandArgs(**self._raw_args)
    
    @property
    def last_run(self) -> MyLastRun:
        """Get validated last run state."""
        return MyLastRun(**self._raw_last_run)

# Usage in main function
def main():
    execution = MyExecutionConfig()
    
    # Single call to demisto.command()
    command = execution.command
    
    # Single call to demisto.params() with validation
    params = execution.params
    
    # Route to commands
    if command == "my-command":
        # Single call to demisto.args() with validation
        args = execution.my_command_args
        # Execute command...
    
    elif command == "fetch-incidents":
        # Single call to demisto.getLastRun() with validation
        last_run = execution.last_run
        # Execute fetch...
```

---

## Dependencies

- **pydantic**: Data validation and settings management
- **CommonServerPython**: Cortex XSOAR/XSIAM utilities
- **demistomock**: Offline testing support

---

## Best Practices

1. **Always inherit from ContentBaseModel** for parameter and argument classes to get user-friendly error messages
2. **Use BaseParams** as the base for integration parameters to get common connection settings
3. **Create one ExecutionConfig instance** in main() to minimize redundant system calls
4. **Define properties** in your ExecutionConfig subclass for each command's arguments
5. **Use validators** to add custom validation logic and data cleaning
6. **Document your models** with docstrings and type hints for better IDE support

---

## Integration Example

See the Hello World v2 integration for a complete example of using these base classes in a production integration.

---

## Related Modules

- **ContentClientApiModule**: High-performance HTTP client with retry logic, rate limiting, and authentication
- **CommonServerPython**: Core utilities and helper functions for Cortex integrations

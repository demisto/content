# ruff: noqa: F401,N805
import asyncio
import json
import time
import traceback

from datetime import datetime, timedelta, UTC
from enum import Enum
from typing import Any
from collections.abc import Awaitable
from pydantic import AnyUrl, Field, SecretStr, validator, root_validator  # pylint: disable=no-name-in-module

import demistomock as demisto

from CommonServerPython import *
from CommonServerUserPython import *

from ContentClientApiModule import *
from BaseContentApiModule import *

# region Intro

"""Unified HelloWorldV2 Integration for Cortex XSOAR and XSIAM

This integration demonstrates how to build a unified integration using Python 3. Follow the documentation links below
and ensure that the integration follows the Code Conventions and passes the Linting phase.

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

When building a reusable integration, significant effort must be placed in the design. We recommend filling out a
Design Document template that allows you to capture Use Cases, Requirements, and Inputs/Outputs.

Example Design document for this Integration (HelloWorldV2):
https://docs.google.com/document/d/1wETtBEKg37PHNU8tYeB56M1LE314ux086z3HFeF_cX0


HelloWorld API
--------------

The HelloWorld API is a simple API that demonstrates a realistic use case for an integration.

This API has a few basic functions, including:

- Alerts - Returns mocked alerts and allows you to search based on a number of parameters, such as severity. It can
  also return a single alert by ID. This is used to create new alerts in XSOAR by using the `fetch-incidents` command,
  which is invoked every minute by default.

- IP Reputation - Returns a mock lookup response of the IP address given as well as a reputation score (from 0 to 100)
  that is used to determine whether the entity is malicious. This endpoint is called by the reputation command `ip`
  that runs automatically every time an indicator is extracted in Cortex. As a design best practice, it is important
  to map and document the mapping between a score in the original API format (0 to 100 in this case) to a score in
  Cortex format (0 to 3). This score is called `DBotScore`, and is returned in the context to allow automated handling
  of indicators based on their reputation.
  More information: https://xsoar.pan.dev/docs/integrations/dbot

- Create Note - Demonstrates how to run commands that do not return instant data. The API provides a command that
  simulates creating a new entity in the API. This can be used for endpoints that take longer than a few seconds to
  complete with the GenericPolling mechanism to implement the job polling loop. The results can be returned in JSON or
  attachment file format.
  Info on GenericPolling: https://xsoar.pan.dev/docs/playbooks/generic-polling

This integration also has a `say-hello` command for backward compatibility that does not connect to an API and just
returns a `Hello {name}` string, where name is the input value provided.


Integration File Structure
--------------------------

An integration usually consists of the following parts:
- Imports
- Constants
- Parameter Validation Model
- Client Class
- Argument Validation Models and Command Functions
- Execution Configuration Class
- Main Function and Entrypoint


Imports
-------

Here you can import Python modules you need for your integration. If you need a module that is not part of the default
Docker images, you can add a custom one. More details: https://xsoar.pan.dev/docs/integrations/docker

There are also internal imports that are used by integrations:
- demistomock (imported as demisto): allows your code to work offline for testing. The actual `demisto` module is
  provided at runtime when the code runs on the tenant.
- CommonServerPython.py: contains a set of helper functions, base classes and other useful components that will make
  your integration code easier to maintain.
- CommonServerUserPython.py: includes a set of user-defined commands that are specific to a tenant. Do not use it for
  integrations that are meant to be shared externally.
- BaseContentApiModule: contains base classes and utilities for parameter validation, execution configuration, and
  system capabilities detection.
- ContentClientApiModule: contains a high-performance async-first HTTP client for automation commands and event or
  incident fetching.

These imports are automatically loaded at runtime within the script runner, so you shouldn't modify them.

Constants
---------

Usually some constants that do not require user parameters or inputs, such as the default API entry point for your
service, or the maximum number of alerts to fetch every time.

Use enums to group multiple possible values of a configuration parameter or a command argument.


Parameter Validation Model
--------------------------

Define a Pydantic model that inherits from `BaseParams` to parse, validate, and clean integration configuration
parameters. This model should include all parameters defined in the integration YML file, such as connection settings,
fetch configuration, and advanced options.


Client Class
------------

We recommend using a Client class to wrap all the code that needs to interact with your API. Moreover, we recommend,
when possible, to inherit from the new `ContentClient` class, defined in `ContentClientApiModule.py`. This class
already handles a lot of the work, such as system proxy settings, SSL certificate verification, and exception handling
for HTTP errors.

Note that the Client class should NOT contain any Cortex tenant-specific code, i.e., it should not use anything in the
`demisto` class (functions such as `demisto.args()` or `demisto.results()`) or even `return_results`, `return_error`,
or `CommandResults`. You will use the Command Functions to handle inputs and outputs.

When calling an API, use methods like `ContentClient.get` and `ContentClient.post` and return the raw API response to
the calling function (usually a Command function).

Ideally, there should be one client method per API endpoint.

Look at the code and the comments of this specific class to better understand the implementation details.


Argument Validation Models and Command Functions
-------------------------------------------------

For each command, define a Pydantic model that inherits from `ContentBaseModel` to parse, validate, and clean command
arguments. Then implement the corresponding command function that uses the validated arguments.

Command functions perform the mapping between inputs and outputs to the Client class functions inputs and outputs. As a
best practice, they should not contain calls to `demisto.args()`, `demisto.results()`, `return_error`, and
`demisto.command()` as those should be handled through the `main()` function. However, in command functions, use
`demisto` or `CommonServerPython.py` artifacts, such as `demisto.debug()` or the `CommandResults` class and the
`Common.*` classes. Usually, one command function is used per command, in addition to `test-module`, and, if supported
in the integration, `fetch-incidents`, `fetch-events`, and `fetch-indicators`. Each command function should invoke one
specific function of the Client class.

Command functions, when invoked through a command, usually return data using the `CommandResults` class, which is then
passed to `return_results()` in the `main()` function. `return_results()` is defined in `CommonServerPython.py` to
return the data to the War Room. `return_results()` actually wraps `demisto.results()`. You should never use
`demisto.results()` directly.

Sometimes you will need to return values in a format that is not compatible with `CommandResults` (for example files):
in that case you must return a data structure that is then passed to `return_results()`.

In any case, you should never call `return_results()` directly from the command functions.

When you create the CommandResults object in command functions, you usually pass some types of data:

- Human Readable: usually in Markdown format. This is what is presented to the analyst in the War Room. You can use
  `tableToMarkdown()`, defined in `CommonServerPython.py`, to convert lists and dicts to Markdown and pass it to
  `return_results()` using the `readable_output` argument, or the `return_results()` function will call
  `tableToMarkdown()` automatically for you.

- Context Output: this is the machine-readable data, JSON-based, that XSOAR can parse and manage in the Playbooks or
  Incident's War Room. The Context Output fields should be defined in your integration YML file and are important
  during the design phase. Make sure you define the format and follow best practices. You can use `demisto-sdk
  json-to-outputs` to autogenerate the YML file outputs section. Context output is passed as the `outputs` argument in
  `demisto_results()`, and the prefix (i.e., `HelloWorld.Alert`) is passed via the `outputs_prefix` argument.

More information on Context Outputs, Standards, DBotScore, and demisto-sdk:
https://xsoar.pan.dev/docs/integrations/code-conventions#outputs
https://xsoar.pan.dev/docs/integrations/context-and-outputs
https://xsoar.pan.dev/docs/integrations/context-standards
https://xsoar.pan.dev/docs/integrations/dbot
https://github.com/demisto/demisto-sdk/blob/master/demisto_sdk/commands/json_to_outputs/README.md

Also, when you write data in the Context, you want to make sure that if you return updated information for an entity,
to update it and not append to the list of entities (i.e., in HelloWorld you want to update the status of an existing
`HelloWorld.Alert` in the context when you retrieve it, rather than adding a new one if you already retrieved it). To
update data in the Context, you can define which is the key attribute to use, such as (using the example):
`outputs_key_field='alert_id'`. This means that you are using the `alert_id` key to determine whether to add a new
entry in the context or update an existing one that has the same ID. You can look at the examples to understand how it
works. More information here:
https://xsoar.pan.dev/docs/integrations/context-and-outputs
https://xsoar.pan.dev/docs/integrations/code-conventions#outputs
https://xsoar.pan.dev/docs/integrations/dt

- Raw Output: this is usually the raw result from your API and is used for troubleshooting purposes or for invoking
  your command from Automation Scripts. If not specified, `return_results()` will use the same data as `outputs`.


Execution Configuration Class
------------------------------

Define an Execution Configuration class that inherits from `BaseExecutionConfig` to provide a centralized entrypoint for
the integration. This class holds the currently-executed command, configuration parameters, command arguments, and fetch
last run state. It provides properties that return validated instances of the parameter and argument models, making it
easy to access validated data throughout the integration. This pattern centralizes validation logic and provides type
safety when accessing integration parameters and command arguments.


Main Function and Entrypoint
-----------------------------

The `main()` function takes care of reading the integration parameters via the `demisto.params()` function, initializes
the Client class, and checks the different options provided to `demisto.commands()` to invoke the correct command
function, passing to it `demisto.args()` and returning the data to `return_results()`. If implemented, `main()` also
invokes the function `fetch_incidents()` with the right parameters and passes the outputs to the `demisto.incidents()`
function. `main()` also catches exceptions and returns an error message via `return_error()`.

The entrypoint checks whether the `__name__` variable is `__main__`, `__builtin__` (for Python 2), or `builtins` (for
Python 3) and then calls the `main()` function. Just keep this convention.

"""

# endregion

# region Constants

MOCK_ALERT = (
    '"id": {id}, "severity": "{severity}", "user": "{user}", "action": "{action}", "date": "{date}", "status": "{status}"'
)

MOCK_ASSET = '"id": {id}, "name": "{name}", "type": "{asset_type}", "status": "{status}", "created": "{created}"'

MOCK_VULN = (
    '"id": {id}, "cve_id": "{cve_id}", "severity": "{severity}", "description": "{description}", "published": "{published}"'
)

BASE_CONTEXT_OUTPUT_PREFIX = "HelloWorld"  # Context outputs from all commands will have this prefix


class PollingDefaults(int, Enum):
    INTERVAL_SECONDS = 30
    TIMEOUT_SECONDS = 60 * 10  # 10 minutes


class EventsDatasetConfigs(str, Enum):
    VENDOR = "Hello"
    PRODUCT = "WorldV2"
    TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
    TIME_KEY = "_time"
    SOURCE_LOG_TYPE_KEY = "source_log_type"


class AssetsDatasetConfigs(str, Enum):
    VENDOR = "Hello_WorldV2"
    PRODUCT = "Assets"


class VulnerabilitiesDatasetConfigs(str, Enum):
    VENDOR = "Hello_WorldV2"
    PRODUCT = "Vulnerabilities"


class FetchAssetsStages(str, Enum):
    """HelloWorld sequential stages for fetching assets and vulnerabilities."""

    ASSETS = "assets"
    VULNS = "vulnerabilities"


class HelloWorldSeverity(str, Enum):
    """HelloWorld severity options matching the YML configuration parameter options."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def all_values(cls) -> list[str]:
        """Get the string values of all enum members.

        Returns:
            list[str]: The values of the enum class members.
        """
        return [member.value for member in cls]

    @classmethod
    def convert_to_incident_severity(cls, raw_severity: str) -> int:
        """
        Convert HelloWorld API severity to Cortex XSOAR incident severity.

        Maps the HelloWorld alert severity levels ('low', 'medium', 'high', 'critical')
        to Cortex XSOAR incident severity integers (1-4).

        Args:
            raw_severity (str): Severity as returned from the HelloWorld API.

        Returns:
            int: Cortex XSOAR incident severity (0-4).
        """
        # INTEGRATION DEVELOPER TIP:
        # It is important to document the mapping between the API's severity
        # format and XSOAR's severity format. This mapping should be consistent
        # across the integration and clearly documented for users.
        mapping = {
            cls.LOW.value: IncidentSeverity.LOW,
            cls.MEDIUM.value: IncidentSeverity.MEDIUM,
            cls.HIGH.value: IncidentSeverity.HIGH,
            cls.CRITICAL.value: IncidentSeverity.CRITICAL,
            None: IncidentSeverity.UNKNOWN,
        }
        return mapping.get(raw_severity, IncidentSeverity.UNKNOWN)


DUMMY_VALID_API_KEY = "dummy-key"  # to mock API errors

CAN_SEND_EVENTS = is_xsiam() or is_platform()

# endregion

# region Parameters


class Credentials(ContentBaseModel):
    """Credentials model for API authentication."""

    # username field omitted because `hiddenusername: true` in YML
    password: SecretStr


class HelloWorldParams(BaseParams):
    # Connection parameters (`proxy` and `insecure` are already in `BaseParams`)
    url: AnyUrl
    credentials: Credentials

    # Fetch events / incidents parameters
    is_fetch_events: bool | None = Field(default=False, alias="isFetchEvents")  # access via abstracted `is_fetch` property
    is_fetch_incidents: bool | None = Field(default=False, alias="isFetch")
    first_fetch: str = "3 days"  # access via abstracted and normalized `first_fetch_time` property
    max_events_fetch: int = Field(default=1000, alias="max_events_fetch")  # access via abstracted `max_fetch` property
    max_incidents_fetch: int = Field(default=10, alias="max_incidents_fetch")
    severity: HelloWorldSeverity = HelloWorldSeverity.HIGH

    # Fetch assets parameter
    is_fetch_assets: bool | None = Field(default=False, alias="isFetchAssets")

    # Advanced parameters
    threshold_ip: int = 65
    integration_reliability: str = Field(default=DBotScoreReliability.C, alias="integrationReliability")

    @property
    def api_key(self):
        return self.credentials.password

    @property
    def first_fetch_time(self) -> str:
        """Convert first_fetch to ISO 8601 timestamp string."""
        if CAN_SEND_EVENTS:
            demisto.debug("[Param validation] Setting first fetch internally to last 1 minute.")
            return (datetime.now(tz=UTC) - timedelta(minutes=1)).isoformat()
        else:
            return cast(datetime, arg_to_datetime(self.first_fetch)).isoformat()

    @property
    def is_fetch(self) -> bool | None:
        """Abstract getter and validator the 'Fetch incidents / events' parameters, depending on system capabilities."""
        return self.is_fetch_events if CAN_SEND_EVENTS else self.is_fetch_incidents

    @property
    def max_fetch(self) -> int:
        """Abstract getter and validator the 'Maximum per fetch' parameters, depending on system capabilities."""
        if CAN_SEND_EVENTS:
            max_fetch_cap = 100000
            max_fetch = self.max_events_fetch
        else:
            max_fetch = self.max_incidents_fetch
            max_fetch_cap = 200

        if max_fetch > max_fetch_cap:
            demisto.debug(f"[Param validation] Lowered configured {max_fetch=} to {max_fetch_cap=}.")
            return max_fetch_cap

        return max_fetch

    @validator("url", allow_reuse=True)
    def clean_url(cls, v):  # pylint: disable=no-self-argument
        """Remove trailing forward slash from the 'URL' parameter"""
        return v.rstrip("/")


# endregion

# region Auth & Client


class HelloWorldAuthHandler(APIKeyAuthHandler):
    """Custom authentication handler for API key-based authentication for HelloWorldV2.

    INTEGRATION DEVELOPER TIP:
    You may define your custom `AuthHandler` if needed or use any of the
    included ones in `ContentClientApiModule` such as `APIKeyAuthHandler`,
    `BearerTokenAuthHandler`, or `BasicAuthHandler`.
    """

    def __init__(self, api_key: SecretStr):
        """Initialize the authentication handler.

        Args:
            api_key (SecretStr): The API key for authentication.
        """

        super().__init__(key=api_key.get_secret_value(), header_name="X-HelloWorld-API-Key")
        self.validate_api_key()

    def validate_api_key(self) -> None:
        """Validate the API key.

        Raises:
            DemistoException: If the API key is invalid.
        """
        if self.key != DUMMY_VALID_API_KEY:
            # Simulate failed authentication
            raise DemistoException("Invalid Credentials. Please verify your API key.")


class HelloWorldClient(ContentClient):
    """
    HelloWorld client that extends `ContentClient` for API interactions.

    This client inherits from `ContentClient` to leverage built-in retry logic,
    rate limit handling, authentication, and thread safety.
    It adds HelloWorld-specific methods for mock / dummy API responses.
    For real API calls, see the `send_example_api_request` method.
    """

    def __init__(self, params: HelloWorldParams):
        """Initialize HelloWorld client with ContentClient capabilities.

        Args:
            params (HelloWorldParams): Integration parameters.
        """
        # Initialize parent ContentClient
        auth_handler = HelloWorldAuthHandler(params.api_key)
        super().__init__(
            base_url=params.url,
            verify=params.verify,
            proxy=params.proxy,
            auth_handler=auth_handler,
            client_name="HelloWorldV2Client",
            diagnostic_mode=is_debug_mode(),  # enable if commands are run with `debug-mode=true`
        )

    def send_example_api_request(self, item_id: str | int, params: dict) -> dict:
        """Example of calling a real specific API endpoint using ContentClient.

        Args:
            item_id (str | int): The ID of the item to retrieve.
            params (dict): Query parameters for the API request.

        Returns:
            dict: The API response.
        """
        # INTEGRATION DEVELOPER TIP:
        # For real API calls, use the inherited HTTP verb methods, for example:
        # - `self.get(endpoint, params)` for GET requests
        # - `self.post(endpoint, json_body)` for POST requests
        # Alternatively, call the legacy "_http_request" method:
        # - `self._http_request("GET", url_suffix=endpoint, params=params)`
        return self.get(url_suffix=f"/api/endpoint/{item_id}", params=params)

    def get_ip_reputation(self, ip: str) -> dict[str, Any]:
        """Get IP reputation (dummy response for demonstration purposes).

        For real API calls, see the `send_example_api_request` method.

        Args:
            ip (str): IP address to get the reputation for.

        Returns:
            dict[str, Any]: Dictionary containing the dummy IP reputation as it should be returned from the API.
        """
        mocked_response = {
            "attributes": {
                "as_owner": "EMERALD-ONION",
                "asn": 396507,
                "continent": "NA",
                "country": "US",
                "jarm": ":jarm:",
                "last_analysis_stats": {"harmless": 72, "malicious": 5, "suspicious": 2, "timeout": 0, "undetected": 8},
                "last_modification_date": 1613300914,
                "network": ":cidr:",
                "regional_internet_registry": "ARIN",
                "reputation": -4,
                "tags": [],
                "total_votes": {"harmless": 0, "malicious": 1},
                "whois_date": 1611870274,
            },
            "id": ip,
            "links": {"self": f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"},
            "type": "ip_address",
        }

        return mocked_response

    def say_hello(self, name: str) -> str:
        """Return a greeting string.

        Args:
            name (str): Name to append to the 'Hello' string.

        Returns:
            str: String containing 'Hello {name}'.
        """
        # INTEGRATION DEVELOPER TIP:
        # In a real implementation, you would make an HTTP request here using ContentClient:
        # endpoint = "/api/v1/hello"
        # data = {"name": name}
        # # If API response type is not JSON, specify the suitable type
        # resp_type = "text"  # Use any of the following: 'json', 'text', 'content', 'response', 'xml'
        # return self.post(endpoint, json_data=data, resp_type=resp_type)

        return f"Hello {name}"

    def get_alert_list(self, limit: int, severity: HelloWorldSeverity | None = None, start_time: str | None = None) -> list[dict]:
        """Get a list of alerts (dummy response for demonstration purposes).

        For real API calls, see the `send_example_api_request` method.

        Args:
            limit (int): The number of items to generate.
            severity (HelloWorldSeverity | None): The severity value of the items returned.
            start_time (str | None): ISO 8601 timestamp to fetch alerts from (inclusive).

        Returns:
            list[dict]: Dummy data of items as it would be returned from the API.
        """
        # INTEGRATION DEVELOPER TIP:
        # In a real implementation, you would make an HTTP request here using ContentClient:
        # endpoint = "/api/v1/alerts"
        # # Use `assign_params` to remove potentially "empty" values (e.g. severity, start_time)
        # params = assign_params(
        #   limit=limit,
        #   severity=severity,
        #   start_time=start_time,
        # )
        # return self.get(endpoint, params=params)

        # Assume API returns results from the last 24 hours if start_time is not specified
        base_time = arg_to_datetime(start_time) or (datetime.now(tz=UTC) - timedelta(hours=24))

        mock_response: list[dict] = []
        for mock_number in range(limit):
            mock_alert_time = base_time + timedelta(seconds=mock_number)
            mock_alert_id = int(mock_alert_time.timestamp())
            is_even = mock_alert_id % 2 == 0
            item = MOCK_ALERT.format(
                id=mock_alert_id,
                severity=severity.value if severity else "",
                date=mock_alert_time.isoformat(),
                action="Testing",
                status="Success" if is_even else "Error",
                user="userA@test.com" if is_even else "userB@test.com",
            )
            dict_item = json.loads("{" + item + "}")
            mock_response.append(dict_item)

        return mock_response

    def get_alert(self, alert_id: int) -> dict:
        """Get a specific alert by ID (dummy response for demonstration purposes).

        For real API calls, see the `send_example_api_request` method.

        Args:
            alert_id (int): The alert ID to retrieve.

        Returns:
            dict: Dummy data of the alert as it would be returned from the API.
        """
        # INTEGRATION DEVELOPER TIP:
        # In a real implementation, you would make an HTTP request here using ContentClient:
        # endpoint = f"/api/v1/alerts/{alert_id}"
        # return self.get(endpoint)

        item = MOCK_ALERT.format(
            id=alert_id,
            severity=HelloWorldSeverity.LOW.value,
            date=datetime(2023, 9, 14, 11, 30, 39, 882955).isoformat(),
            status="Testing",
        )
        return json.loads("{" + item + "}")

    def create_note(self, alert_id: int, comment: str) -> dict:
        """Create a new note in an alert.

        For real API calls, see the `send_example_api_request` method.

        Args:
            alert_id (int): The alert ID to add a note to.
            comment (str): The text comment to add to the alert as a note.

        Returns:
            dict: The summary of the newly created note from the API response.
        """
        # INTEGRATION DEVELOPER TIP:
        # In a real implementation, you would make an HTTP request here using ContentClient:
        # endpoint = f"/api/v1/notes/{alert_id}"
        # data = {"comment": comment}
        # return self.post(endpoint, json_data=data)

        return {"status": "success", "msg": f"Note was created for alert #{alert_id} successfully with comment: {comment}"}

    def submit_job(self) -> dict[str, str]:
        """Submit a new job to the API.

        For real API calls, see the `send_example_api_request` method.

        Returns:
            dict[str, str]: The summary of the newly created job.
        """
        # INTEGRATION DEVELOPER TIP:
        # In a real implementation, you would make an HTTP request here using ContentClient:
        # endpoint = "/api/v1/jobs/config-refresh"
        # return self.post(endpoint)
        return {"id": "abc-123", "status": "submitted", "type": "HelloWorldRefreshConfig"}

    def get_job_status(self, job_id: str) -> dict[str, str]:
        """Get the status of a job.

        For real API calls, see the `send_example_api_request` method.

        Args:
            job_id (str): The job ID to check status for.

        Returns:
            dict[str, str]: The status of the job.
        """
        # INTEGRATION DEVELOPER TIP:
        # In a real implementation, you would make an HTTP request here using ContentClient:
        # endpoint = f"/api/v1/jobs/{job_id}/status"
        # return self.get(endpoint)
        return {"id": job_id, "status": "complete"}

    def get_job_result(self, job_id: str) -> dict[str, str]:
        """Get the finished result of a job.

        For real API calls, see the `send_example_api_request` method.

        Args:
            job_id (str): The job ID to get results for.

        Returns:
            dict[str, str]: The end result of the job.
        """
        # INTEGRATION DEVELOPER TIP:
        # In a real implementation, you would make an HTTP request here using ContentClient:
        # endpoint = f"/api/v1/jobs/{job_id}/result"
        # return self.get(endpoint)
        return {"id": job_id, "msg": "The configuration has successfully been updated."}

    def get_assets(self, limit: int, id_offset: int = 0) -> dict[str, Any]:
        """Get a list of assets (dummy response for demonstration purposes).

        For real API calls, see the `send_example_api_request` method.

        Args:
            limit (int): The number of assets to retrieve.
            id_offset (int): The ID of the last fetched asset for pagination.

        Returns:
            dict[str, Any]: Dummy data of assets as it would be returned from the API.
        """
        # INTEGRATION DEVELOPER TIP:
        # In a real implementation, you would make an HTTP request here using ContentClient:
        # endpoint = "/api/v1/assets"
        # params = {"limit": limit, "offset": id_offset}
        # return self.get(endpoint, params=params)

        mock_assets: list[dict] = []
        asset_types = ["server", "database", "storage", "network"]
        for mock_number in range(limit):
            asset_id = id_offset + mock_number + 1
            asset_creation_time = datetime(2024, 1, 15) + timedelta(hours=mock_number)
            asset = MOCK_ASSET.format(
                id=asset_id,
                name=f"{asset_types[mock_number % len(asset_types)].capitalize()}-{mock_number + 1:02d}",
                asset_type=asset_types[mock_number % len(asset_types)],
                status="active",
                created=asset_creation_time.isoformat(),
            )
            asset_dict = json.loads("{" + asset + "}")
            mock_assets.append(asset_dict)

        # Assume our environment has no more assets batches after offset = 5000
        mock_has_more_data = bool(id_offset < 5000)
        mock_response = {"has_more": mock_has_more_data, "data": mock_assets}
        return mock_response

    def get_vulnerabilities(self, limit: int, id_offset: int = 0) -> dict[str, Any]:
        """Get a list of vulnerabilities (dummy response for demonstration purposes).

        For real API calls, see the `send_example_api_request` method.

        Args:
            limit (int): The number of vulnerabilities to retrieve.
            id_offset (int): The ID of the last fetched vulnerability for pagination.

        Returns:
            dict[str, Any]: Dummy data of vulnerabilities as it would be returned from the API.
        """
        # INTEGRATION DEVELOPER TIP:
        # In a real implementation, you would make an HTTP request here using ContentClient:
        # endpoint = "/api/v1/vulnerabilities"
        # params = {"limit": limit, "offset": id_offset}
        # return self.get(endpoint, params=params)

        mock_vulns: list[dict] = []
        severities = HelloWorldSeverity.all_values()
        descriptions = [
            "Remote code execution vulnerability",
            "SQL injection vulnerability",
            "Cross-site scripting vulnerability",
            "Information disclosure vulnerability",
        ]
        for mock_number in range(limit):
            vuln_id = id_offset + mock_number + 1
            vuln_published_time = datetime(2026, 1, 15) + timedelta(hours=mock_number)
            vuln = MOCK_VULN.format(
                id=vuln_id,
                cve_id=f"CVE-MOCK-{mock_number + 1:04d}",
                severity=severities[mock_number % len(severities)],
                description=descriptions[mock_number % len(descriptions)],
                published=vuln_published_time.isoformat(),
            )
            vuln_dict = json.loads("{" + vuln + "}")
            mock_vulns.append(vuln_dict)

        # Assume our environment has a limited number of vulnerabilities that can all be fetched in one requested
        mock_has_more_data = False
        mock_response = {"has_more": mock_has_more_data, "data": mock_vulns}
        return mock_response

    def log_optional_diagnostic_report(self) -> None:
        """Log diagnostic report for troubleshooting if diagnostic mode is enabled."""
        # INTEGRATION DEVELOPER TIP:
        # Adding diagnostic logs can help with troubleshooting bugs and common issues (authentication issues)

        if not self._diagnostic_mode:
            demisto.debug("[Client] Diagnostic mode is disabled. Skipping generating diagnostic report.")
            return

        try:
            report = self.get_diagnostic_report()
            demisto.debug(f"[Client] Diagnostic Report: {json.dumps(report.__dict__, default=str, indent=2)}")
            self.logger.log_metrics_summary()
        except Exception as e:
            demisto.debug(f"Failed to generate diagnostic report: {e}")


# endregion

# region test-module


def test_module(client: HelloWorldClient, params: HelloWorldParams) -> str:
    """Test API connectivity and authentication.

    When 'ok' is returned, it indicates the integration works as expected and the connection to the
    service is successful. Raises exceptions if something goes wrong.

    Args:
        client (HelloWorldClient): HelloWorld client to use.
        params (HelloWorldParams): Validated integration parameters containing configuration settings.

    Returns:
        str: 'ok' if test passed; anything else will raise an exception and fail the test.
    """

    # INTEGRATION DEVELOPER TIP
    # Client class should raise the exceptions, but if the test fails
    # the exception text is printed to the UI.
    # If you have some specific errors you want to capture (i.e. auth failure)
    # you should catch the exception here and return a string with a more
    # readable output (for example return 'Authentication Error, API Key
    # invalid').
    # The tenant will treat anything other than 'ok' as an error
    try:
        demisto.debug("[Testing] Testing API connectivity")
        client.say_hello(name="Test")
        demisto.debug("[Testing] API connectivity test passed")

        if params.is_fetch:
            demisto.debug("[Testing] Testing fetch flow.")
            fetch_alerts(
                client,
                max_fetch=1,
                last_run=HelloWorldLastRun(),
                severity=params.severity,
                first_fetch_time=params.first_fetch_time,
                should_push=False,
            )
            demisto.debug("[Testing] Fetch flow test passed")

        if params.is_fetch_assets:
            demisto.debug("[Testing] Testing fetch assets flow.")
            fetch_assets(client, last_run=HelloWorldAssetsLastRun(), should_push=False)
            demisto.debug("[Testing] Fetch assets flow test passed")

    except ContentClientAuthenticationError as e:
        demisto.error(f"[Testing] Authentication failed. Got error={e}.")
        return "AuthenticationError: make sure API Key is correctly set."

    demisto.debug("[Testing] All tests passed.")
    return "ok"


# endregion

# region helloworld-say-hello


class HelloworldSayHelloArgs(ContentBaseModel):
    """Arguments for helloworld-say-hello command."""

    name: str


def say_hello_command(client: HelloWorldClient, args: HelloworldSayHelloArgs) -> CommandResults:
    """Execute helloworld-say-hello command.

    Args:
        client (HelloWorldClient): HelloWorld client to use.
        args (HelloworldSayHelloArgs): Validated command arguments containing:
            - name: The name to use in the greeting message.

    Returns:
        CommandResults: CommandResults object containing the hello world message.
    """

    # INTEGRATION DEVELOPER TIP
    # In this case 'name' is an argument set in the HelloWorldV2.yml file as mandatory,
    # so Pydantic will validate it's present before the function is called.
    # The validation happens automatically when HelloworldSayHelloArgs is instantiated.

    # Call the Client function and get the raw response
    result = client.say_hello(name=args.name)

    # Create the human readable output.
    # It will  be in markdown format - https://www.markdownguide.org/basic-syntax/
    # More complex output can be formatted using `tableToMarkDown()` defined
    # in `CommonServerPython.py`
    readable_output = f"## {result}"

    # More information about Context:
    # https://xsoar.pan.dev/docs/integrations/context-and-outputs
    # We return a `CommandResults` object, and we want to pass a custom
    # markdown here, so the argument `readable_output` is explicit. If not
    # passed, `CommandResults`` will do a `tableToMarkdown()` do the data
    # to generate the readable output.
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.Hello",
        outputs_key_field="name",
        outputs={"name": args.name},
    )


# endregion

# region fetch-incidents / fetch-events


class HelloWorldLastRun(ContentBaseModel):
    """State management for fetch-incidents and fetch-events commands.

    Ensures no data is missed or duplicated between invocations.
    """

    # ISO 8601 timestamp of the last fetched alert
    start_time: str | None = None
    # List of alert IDs from the last fetch time to prevent duplicates
    last_alert_ids: list[int] = []

    def set(self):
        """Save the current state for the next fetch-incidents or fetch-events execution."""
        last_run = json.loads(self.json(by_alias=True))  # Ensure last run a JSON serializable object
        demisto.debug(f"[Last Run] Setting {last_run=}.")
        demisto.setLastRun(last_run)


def format_as_incidents(
    alerts: list[dict[str, Any]],
    id_field: str,
    occurred_field: str,
    severity_field: str,
    custom_fields_mapping: dict | None = None,
) -> list[dict[str, Any]]:
    """Format alerts as XSOAR incidents.

    Args:
        alerts (list[dict[str, Any]]): List of alert dictionaries from the API.
        id_field (str): The field name in the alert to use as the incident ID.
        occurred_field (str): The field name in the alert to use as the occurred time.
        severity_field (str): The field name in the alert to use for severity.
        custom_fields_mapping (dict | None): Optional mapping for custom fields.

    Returns:
        list[dict[str, Any]]: List of incidents formatted for XSOAR.
    """
    custom_fields_mapping = custom_fields_mapping or {}
    return [
        {
            "name": f"XSOAR Test Alert #{alert[id_field]}",
            "occurred": alert[occurred_field],
            "rawJSON": json.dumps(alert),
            "type": "Hello World Alert",  # Map to a specific XSOAR incident type
            "severity": HelloWorldSeverity.convert_to_incident_severity(raw_severity=alert[severity_field]),
            "CustomFields": {
                field_name: demisto.get(custom_fields_mapping, field_value)
                for field_name, field_value in custom_fields_mapping.items()
            },
        }
        for alert in alerts
    ]


def create_incidents(alerts: list[dict]) -> None:
    """Format alerts as incidents and create them in XSOAR.

    Args:
        alerts (list[dict]): List of alert dictionaries from the API.

    Returns:
        None
    """
    demisto.debug(f"[Create incidents] Formatting and creating {len(alerts)} XSOAR incidents.")
    incidents = format_as_incidents(alerts, id_field="id", occurred_field="date", severity_field="severity")
    demisto.incidents(incidents)
    demisto.debug(f"[Create incidents] Successfully created {len(incidents)} XSOAR incidents.")


def format_as_events(
    alerts: list[dict[str, Any]],
    time_field: str,
) -> list[dict[str, Any]]:
    """Format alerts as XSIAM events.

    Args:
        alerts (list[dict[str, Any]]): List of alert dictionaries from the API.
        time_field (str): The field name in the audit to use as the event time.

    Returns:
        list[dict[str, Any]]: List of events formatted for XSIAM.
    """
    events: list[dict[str, Any]] = []
    for alert in alerts:
        event = alert.copy()
        if raw_event_time := event.get(time_field):
            event_time = cast(datetime, arg_to_datetime(raw_event_time))
            event[EventsDatasetConfigs.TIME_KEY.value] = event_time.strftime(EventsDatasetConfigs.TIME_FORMAT.value)
        # Important to declare source log type, especially if multiple event types are fetched
        event[EventsDatasetConfigs.SOURCE_LOG_TYPE_KEY.value] = "Alert"
        events.append(event)
    return events


def create_events(alerts: list[dict]) -> None:
    """Format alerts and send them to XSIAM.

    Args:
        alerts (list[dict]): List of alert dictionaries from the API.
    """
    demisto.debug(f"[Create events] Formatting and sending {len(alerts)} XSIAM events.")
    events = format_as_events(alerts, time_field="date")
    send_events_to_xsiam(
        events=events,
        vendor=EventsDatasetConfigs.VENDOR.value,
        product=EventsDatasetConfigs.PRODUCT.value,
        client_class=ContentClient,
    )
    demisto.debug(f"[Create events] Successfully sent {len(events)} XSIAM events.")


async def get_alert_list(
    client: HelloWorldClient,
    start_time: str | None,
    severity: HelloWorldSeverity,
    limit: int,
    should_push: bool,
    last_alert_ids: list[int] | None = None,
) -> list[dict]:
    """Fetch raw alerts from the API in batches and optionally create XSOAR incidents or XSIAM events.

    INTEGRATION DEVELOPER TIP:
    This function fetches events from the API in batches. When running on XSIAM, it uses asyncio to
    concurrently fetch the next alerts batch while pushing the formatted events to XSIAM to improve
    performance and scalability.

    Args:
        client (HelloWorldClient): HelloWorld client instance for API calls.
        start_time (str | None): ISO 8601 timestamp to fetch alerts from (inclusive).
        severity (HelloWorldSeverity): Severity filter for alerts.
        limit (int): Maximum total number of alerts to fetch.
        should_push (bool): Whether to create incidents (XSOAR) or events (XSIAM).
        last_alert_ids (list[int] | None): Optional list of alert IDs from the last fetch time to prevent duplicates.

    Returns:
        list[dict]: List of unique alerts fetched.
    """
    demisto.debug(f"[Get alert list] Starting to fetch alerts with {severity=}, {start_time=}, and {limit=}.")

    unique_alerts: list[dict] = []
    async_push_tasks: list[Awaitable] = []
    current_start_time: str | None = start_time
    all_fetched_ids: set[int] = set(last_alert_ids or [])

    while len(unique_alerts) < limit:
        # Send API request
        remaining_alerts_count = limit - len(unique_alerts)
        batch_limit = min(500, remaining_alerts_count)
        demisto.debug(f"[Get alert list] Request alerts batch using {current_start_time=} and {batch_limit=}.")
        alerts_batch = client.get_alert_list(limit=batch_limit, start_time=current_start_time, severity=severity)

        # Deduplicate alerts
        unique_alerts_batch: list[dict] = []
        for alert in alerts_batch:
            alert_id = alert["id"]
            if alert["id"] in all_fetched_ids:
                demisto.debug(f"[Get alert list] Skipping duplicate {alert_id=}.")
                continue
            unique_alerts.append(alert)
            unique_alerts_batch.append(alert)
            all_fetched_ids.add(alert_id)

        # Create XSOAR incidents / XSIAM events
        if should_push and unique_alerts_batch:
            if CAN_SEND_EVENTS:
                demisto.debug(f"[Get alert list] Creating {len(unique_alerts_batch)} XSIAM events asynchronously.")
                async_push_tasks.append(asyncio.to_thread(create_events, unique_alerts_batch))
            else:
                demisto.debug(f"[Get alert list] Creating {len(unique_alerts_batch)} XSOAR incidents synchronously.")
                create_incidents(unique_alerts_batch)

        # Stop if we have reached the limit
        if len(unique_alerts) >= limit:
            demisto.debug(f"[Get alert list] Reached {limit=}. Breaking...")
            break

        # Stop if the returned alerts count is less than the requested batch limit (no more new alerts are currently available)
        if len(alerts_batch) < batch_limit:
            demisto.debug("[Get alert list] No more alerts currently available for fetching. Breaking...")
            break

        # Update start_time to the last alert's time for next batch
        current_start_time = alerts_batch[-1]["date"]

    if async_push_tasks:
        demisto.debug(f"[Get alert list] Awaiting to finish sending all {len(unique_alerts)} XSIAM events.")
        await asyncio.gather(*async_push_tasks)

    demisto.debug(f"[Get alert list] Finished fetching {len(unique_alerts)} alerts with {severity=}, {start_time=}, {limit=}.")
    return unique_alerts


def fetch_alerts(
    client: HelloWorldClient,
    last_run: HelloWorldLastRun,
    severity: HelloWorldSeverity,
    max_fetch: int,
    first_fetch_time: str,
    should_push: bool = True,
) -> HelloWorldLastRun:
    """Retrieve new alerts and format them as XSOAR incidents or XSIAM events.

    Args:
        client (HelloWorldClient): HelloWorld client to use.
        last_run (HelloWorldLastRun): State from the last fetch.
        severity (HelloWorldSeverity): Severity of the alerts to search for.
        max_fetch (int): Maximum number of alerts per fetch.
        first_fetch_time (str): ISO 8601 timestamp for first fetch if no last_run exists.
        should_push (bool): Whether to create incidents (XSOAR) or events (XSIAM).

    Returns:
        HelloWorldLastRun: Next run state for the next fetch.
    """
    start_time = last_run.start_time or first_fetch_time
    last_alert_ids = last_run.last_alert_ids
    demisto.debug(
        f"[Fetch Alerts] Starting fetch alerts with {severity=}, {start_time=}, and {last_alert_ids=} using {max_fetch=}."
    )

    alerts = asyncio.run(
        get_alert_list(
            client,
            start_time=start_time,
            severity=severity,
            limit=max_fetch,
            should_push=should_push,
            last_alert_ids=last_alert_ids,
        )
    )
    if not alerts:
        demisto.debug(f"[Fetch Alerts] No new alerts found. Keeping {start_time=}.")
        return last_run

    next_start_time = alerts[-1]["date"]
    latest_alert_ids = [alert["id"] for alert in alerts if alert["date"] == next_start_time]
    next_run = HelloWorldLastRun(start_time=next_start_time, last_alert_ids=latest_alert_ids)

    demisto.debug(f"[Fetch Alerts] Completed, fetched {len(alerts)} HelloWorld alerts. Updating {next_start_time=}.")
    return next_run


# endregion

# region fetch-assets


class HelloWorldAssetsLastRun(ContentBaseModel):
    """State management for fetch-assets command.

    Ensures no data is missed or duplicated between fetch invocations.
    """

    # Save the `stage` to denote the type of data to be fetched (assets or vulnerabilities)
    stage: FetchAssetsStages = FetchAssetsStages.ASSETS
    # The ID of the last fetched asset/vulnerability to use for offsetting
    id_offset: int = 0
    # Keep a running total of fetched assets/vulnerabilities
    cumulative_count: int = 0
    # ID of snapshot in the dataset. Persist if ingestion is ongoing, reset once ingestion is done
    snapshot_id: str | None = None
    # `nextTrigger` instructs the server when to trigger the next fetch invocation
    next_trigger_in_seconds: str | None = Field(default=None, alias="nextTrigger")
    # `type` indicates to the server that the next fetch invocation is of type "assets" (1), not "events" (0)
    trigger_type: int = Field(default=1, alias="type")

    def set(self):
        """Save the current state for the next fetch-assets execution."""
        assets_last_run = json.loads(self.json(by_alias=True))  # Ensure last run a JSON serializable object
        demisto.debug(f"[Assets Last Run] Setting {assets_last_run=}.")
        demisto.setAssetsLastRun(assets_last_run)


def generate_unix_timestamp() -> str:
    """Generate the current Unix timestamp in milliseconds.

    Used as `snapshot_id` in the assets/vulnerabilities datasets.

    Returns:
        str: The current time in milliseconds since the Unix epoch, rounded to the nearest integer
             and converted to a string.
    """
    return str(round(time.time() * 1000))


def fetch_assets(
    client: HelloWorldClient,
    last_run: HelloWorldAssetsLastRun,
    should_push: bool = True,
) -> HelloWorldAssetsLastRun:
    """Retrieve assets and vulnerabilities in sequential batched stages and send to XSIAM.

    INTEGRATION DEVELOPER TIP:
    This function implements a two-stage batched fetching approach:

    Stage 1 (ASSETS): Fetch all assets in batches until has_more=False
    Stage 2 (VULNS): Fetch all vulnerabilities in batches until has_more=False

    The workflow:
    1. Generate snapshot_id on first run (when stage=ASSETS and offset=0)
    2. Fetch data in batches using offset for pagination
    3. Send each batch to XSIAM with should_update_module_health=False
    4. Track cumulative_count across all batches
    5. When has_more=False, move to next stage or complete
    6. Update module health only when both stages complete
    7. Use nextTrigger to control immediate continuation vs. scheduled interval

    Args:
        client (HelloWorldClient): HelloWorld client to use.
        last_run (HelloWorldAssetsLastRun): State from the previous fetch-assets execution.
        should_push (bool): Whether to create assets in XSIAM.

    Returns:
        HelloWorldAssetsLastRun: Next run state for the next fetch-assets execution.
    """
    current_fetch_stage: FetchAssetsStages = last_run.stage
    current_data_type: str = current_fetch_stage.value
    last_offset: int = last_run.id_offset
    last_cumulative_count: int = last_run.cumulative_count
    # Generate a new `snapshot_id` if starting fresh (first fetch)
    last_snapshot_id: str = last_run.snapshot_id or generate_unix_timestamp()
    batch_limit = 1000

    demisto.debug(
        f"[Fetch assets] Starting to fetch with {current_fetch_stage=}, {last_offset=}, "
        f"{last_cumulative_count=}, {last_snapshot_id=}."
    )

    # Call the relevant client method based on the `current_fetch_stage`
    if current_fetch_stage is FetchAssetsStages.ASSETS:
        demisto.debug(f"[Fetch assets] Fetching assets batch with {last_offset=} and {batch_limit=}.")
        response = client.get_assets(limit=batch_limit, id_offset=last_offset)
        dataset_vendor = AssetsDatasetConfigs.VENDOR.value
        dataset_product = AssetsDatasetConfigs.PRODUCT.value

    else:
        demisto.debug(f"[Fetch assets] Fetching vulnerabilities batch with {last_offset=} and {batch_limit=}.")
        response = client.get_vulnerabilities(limit=batch_limit, id_offset=last_offset)
        dataset_vendor = VulnerabilitiesDatasetConfigs.VENDOR.value
        dataset_product = VulnerabilitiesDatasetConfigs.PRODUCT.value

    # Parse raw API response
    demisto.debug(f"[Fetch assets] Parsing raw response of {current_data_type} API.")
    data = response.get("data", [])
    has_more = response.get("has_more", False)

    batch_count = len(data)
    demisto.debug(f"[Fetch assets] Parsed raw response of {current_data_type} API. Got {batch_count} items, {has_more=}.")

    # Determine how to send items to XSIAM vendor/product dataset based on pulled type

    # INTEGRATION DEVELOPER TIP:
    # Pay special attention to the variables used when calling `send_data_to_xsiam`:
    # If no more remaining data available to fetch:
    #   - Report the actual (cumulative) count of items fetched to indicate to the server that pulling is complete
    #   - Update the integration instance heath status with the total count of pulled data on the tenant UI
    # Otherwise:
    #   - Report "1" items fetched to indicate to the server that pulling is ongoing (i.e. snapshot is not yet complete)
    #   - Do *NOT* update the the integration instance heath status to avoid showing a partial count of pulled data

    reported_items_count = 1 if has_more else (last_cumulative_count + batch_count)
    update_health_module = not has_more
    if should_push:
        demisto.debug(
            f"[Fetch assets] Starting to send {batch_count} {current_data_type} to XSIAM with "
            f"{last_snapshot_id=} and {reported_items_count=}."
        )
        send_data_to_xsiam(
            data=data,
            vendor=dataset_vendor,
            product=dataset_product,
            data_type=ASSETS,  # use "assets" data type even if pulling vulnerabilities
            items_count=reported_items_count,
            snapshot_id=last_snapshot_id,
            should_update_health_module=update_health_module,  # Update health only when all assets / vulnerabilities are fetched
            client_class=ContentClient,
        )
        demisto.debug(
            f"[Fetch assets] Successfully sent {batch_count} {current_data_type} to XSIAM with "
            f"{last_snapshot_id=} and {reported_items_count=}."
        )

    # Determine next state based on `has_more` and `current_fetch_stage`

    # INTEGRATION DEVELOPER TIP:
    # Pay special attention to the variables used when setting `assets_next_run`:
    # If no more remaining data available to fetch:
    #   - Retain the same `snapshot_id` and `fetch_stage`
    #   - Increment the `offset` by the `batch_count`
    #   - Set `nextTrigger` = 1 to immediately trigger the next fetch-assets invocation
    # Otherwise:
    #   - Generate a new `snapshot_id`.
    #   - Move on to the next `fetch_stage`
    #   - Reset the `offset` back to 0
    #   - Set `nextTrigger` = 1 *ONLY* if the `current_fetch_stage` is not the last one (vulnerabilities)
    if has_more:
        next_snapshot_id = last_snapshot_id
        next_fetch_stage = current_fetch_stage
        next_offset = last_offset + batch_count
        next_cumulative_count = last_cumulative_count + batch_count
        next_trigger_in_seconds = "1"
        demisto.debug(
            f"[Fetch assets] More {current_data_type} available. Setting {next_offset=}, "
            f"{next_fetch_stage=}, {next_trigger_in_seconds=}."
        )

    else:
        # Generate new snapshot ID and reset offset since no more remaining data to fetch as part of
        # the current stage
        next_snapshot_id = generate_unix_timestamp()
        next_offset = 0
        next_cumulative_count = 0
        if current_fetch_stage is FetchAssetsStages.ASSETS:
            # First stage (assets) finished, send immediate server trigger to move on to second stage
            # (vulnerabilities)
            next_fetch_stage = FetchAssetsStages.VULNS
            next_trigger_in_seconds = "1"

        else:
            # Second stage (vulnerabilities) finished, trigger first stage (assets) based on the
            # configured assets fetch interval
            next_fetch_stage = FetchAssetsStages.ASSETS
            next_trigger_in_seconds = None

    assets_next_run = HelloWorldAssetsLastRun(
        stage=next_fetch_stage,
        id_offset=next_offset,
        cumulative_count=next_cumulative_count,
        snapshot_id=next_snapshot_id,
        nextTrigger=next_trigger_in_seconds,
    )

    demisto.debug(f"[Fetch assets] Completed. Fetched {batch_count} {current_data_type}. Set {assets_next_run=}.")

    return assets_next_run


# endregion

# region ip reputation


class IpArgs(ContentBaseModel):
    """Arguments for ip command."""

    ip: str | list[str]  # Can be single IP or comma-separated list
    threshold: int | None = None

    @property
    def ips(self):
        """Returns list of IPs."""
        # Reputation commands usually support multiple inputs (i.e. arrays), so
        # they can be invoked once in Cortex. In case the API supports a single
        # IP at a time, we will cycle this for all the members of the array.
        # We use argToList(), implemented in CommonServerPython.py to automatically
        # return a list of a single element even if the provided input is a scalar.
        ips_list = argToList(self.ip) or []

        valid_ips = []
        invalid_ips = []
        for ip in ips_list:
            if not is_ip_valid(ip, accept_v6_ips=True):  # check IP's validity
                invalid_ips.append(ip)
                demisto.error(f"[Args validation] Invalid IP {ip=}, skipping")
            else:
                valid_ips.append(ip)
        if not valid_ips:
            raise ValueError(f"[Args validation] No valid IP(s) specified. Found invalid IPs: {', '.join(invalid_ips)}.")
        return valid_ips


def ip_reputation_command(client: HelloWorldClient, args: IpArgs, params: HelloWorldParams) -> list[CommandResults]:
    """Execute ip reputation command for a list of IPs.

    Args:
        client (HelloWorldClient): HelloWorld client to use.
        args (IpArgs): Validated command arguments containing IP addresses and optional threshold.
        params (HelloWorldParams): Integration parameters containing default threshold and reliability.

    Returns:
        list[CommandResults]: List of CommandResults objects containing IP reputation data.
    """
    # It's a good practice to document the threshold you use to determine
    # if a score is malicious in your integration documentation.
    # Thresholds should also be possible to override, as in this case,
    # where threshold is an actual argument of the command.
    threshold = args.threshold or params.threshold_ip
    demisto.debug(f"[IP Reputation] Processing {len(args.ips)} IPs {threshold=}")

    # Initialize an empty list of CommandResults to return
    # each CommandResult will contain context standard for IP
    command_results: list[CommandResults] = []

    for ip in args.ips:
        demisto.debug(f"[IP Reputation] Getting reputation for {ip=}")
        ip_data = client.get_ip_reputation(ip)
        ip_data["ip"] = ip

        # This is an example of creating relationships in reputation commands. We will create
        # relationships between indicators only in case that the API returns information about the
        # relationship between two indicators.
        # See https://xsoar.pan.dev/docs/integrations/generic-commands-reputation#relationships

        relationships_list = []
        links = ip_data.get("links", {}).get("self", "")
        for link in links:
            relationships_list.append(
                EntityRelationship(
                    entity_a=ip,
                    entity_a_type=FeedIndicatorType.IP,
                    name="related-to",
                    entity_b=link,
                    entity_b_type=FeedIndicatorType.URL,
                    brand="HelloWorld",
                )
            )

        # We can use demisto.get to get nested values from dict.
        reputation = cast(int, arg_to_number(demisto.get(ip_data, "attributes.reputation", defaultParam=0)))

        # HelloWorld score to XSOAR reputation mapping
        # See: https://xsoar.pan.dev/docs/integrations/dbot
        # We are using Common.DBotScore as macros to simplify
        # the mapping.

        if reputation == 0:
            score = Common.DBotScore.NONE  # unknown
        elif reputation < threshold / 2:
            score = Common.DBotScore.BAD  # bad
        elif reputation < threshold:
            score = Common.DBotScore.SUSPICIOUS  # suspicious
        else:
            score = Common.DBotScore.GOOD  # good

        # The context is bigger here than other commands, as it consists in 3
        # parts: the vendor-specific context (HelloWorld), the standard-context
        # (IP) and the DBotScore.
        # More information:
        # https://xsoar.pan.dev/docs/integrations/context-and-outputs
        # https://xsoar.pan.dev/docs/integrations/context-standards
        # https://xsoar.pan.dev/docs/integrations/dbot
        # Also check the HelloWorld Design Document

        # Create the DBotScore structure first using the Common.DBotScore class.
        dbot_score = Common.DBotScore(
            indicator=ip,
            indicator_type=DBotScoreType.IP,
            integration_name="HelloWorld",
            score=score,
            malicious_description=f"Hello World returned reputation {reputation}",
            reliability=params.integration_reliability,
        )

        # Create the IP Standard Context structure using Common.IP and add
        # dbot_score to it.
        ip_standard_context = Common.IP(ip=ip, asn=ip_data.get("asn"), dbot_score=dbot_score, relationships=relationships_list)

        # INTEGRATION DEVELOPER TIP
        # In the integration specific Context output (HelloWorld.IP) in this
        # example you want to provide a lot of information as it can be used
        # programmatically from within Cortex XSOAR in playbooks and commands.
        # On the other hand, this API is way to verbose, so we want to select
        # only certain keys to be returned in order not to clog the context
        # with useless information. What to actually return in the context and
        # to define as a command output is subject to design considerations.

        # INTEGRATION DEVELOPER TIP
        # To generate the Context Outputs on the YML use `demisto-sdk`'s
        # `json-to-outputs` option.

        # Define which fields we want to exclude from the context output as they are too verbose.
        # We will use attributes key separately. Just make sure to keep the whole response somewhere.
        ip_context_excluded_fields = ["whois", "attributes"]
        ip_data_outputs = {k: ip_data[k] for k in ip_data if k not in ip_context_excluded_fields}

        # In this case we want to use an custom markdown to specify the table title,
        # but otherwise `CommandResults()` will call `tableToMarkdown()`
        #  automatically.

        readable_attributes = tableToMarkdown("Attributes", ip_data["attributes"], is_auto_json_transform=True)
        readable_output = tableToMarkdown("IP (Sample Data)", ip_data_outputs)
        readable_output += readable_attributes

        # INTEGRATION DEVELOPER TIP
        # The output key will be `HelloWorld.IP`, using `ip` as the key field.
        # `indicator` is used to provide the context standard (IP)
        command_results.append(
            CommandResults(
                readable_output=readable_output,
                raw_response=ip_data,
                outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.IP",
                outputs_key_field="ip",
                outputs=ip_data_outputs,
                indicator=ip_standard_context,
                relationships=relationships_list,
            )
        )
    return command_results


# endregion

# region helloworld-alert-list


class HelloworldAlertListArgs(ContentBaseModel):
    """Arguments for helloworld-alert-list command."""

    alert_id: int | None = None
    limit: int = 10
    severity: HelloWorldSeverity | None = None

    @root_validator(allow_reuse=True)
    def check_alert_id_or_severity(cls, values: dict):  # pylint: disable=no-self-argument
        has_alert_id = bool(values.get("alert_id"))
        has_severity = bool(values.get("severity"))

        if not (has_alert_id ^ has_severity):
            raise ValueError("Either 'alert_id' or 'severity' arguments need to be provided.")
        return values


def alert_list_command(client: HelloWorldClient, args: HelloworldAlertListArgs) -> CommandResults:
    """Execute helloworld-alert-list command.

    Args:
        client (HelloWorldClient): HelloWorld client to use.
        args (HelloworldAlertListArgs): Validated command arguments containing:
            - alert_id: Optional alert ID to retrieve a specific alert.
            - severity: Optional severity filter for alerts (required if alert_id is not provided).
            - limit: Optional maximum number of results to return.

    Returns:
        CommandResults: CommandResults object containing alert data.
    """
    # Pagination params. See https://xsoar.pan.dev/docs/integrations/code-conventions#pagination-in-integration-commands
    demisto.debug(f"[Alerts list] Fetching alerts using {args.alert_id=}, {args.severity=}, and {args.limit=}.")

    if args.alert_id:  # If alert_id is provided, we only need one call to API and pagination is not needed.
        demisto.debug(f"[Alerts list] Fetching single alert {args.alert_id=}")
        full_res = client.get_alert(args.alert_id)
        full_res = [full_res] if isinstance(full_res, dict) else full_res

    elif args.severity:  # At this point, severity must be set (validated in __init__)
        demisto.debug(f"[Alerts list] Fetching alerts by severity {args.severity=} {args.limit=}")
        full_res = client.get_alert_list(limit=args.limit, severity=args.severity)

    demisto.debug(f"[Alerts list] Fetched {len(full_res)} alerts")
    readable_output = tableToMarkdown("Items List (Sample Data)", full_res)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.Alert",
        outputs_key_field="id",
        outputs=full_res,
    )


# endregion

# region helloworld-get-events


class HelloWorldGetEventsArgs(ContentBaseModel):
    """Arguments for helloworld-get-events command."""

    severity: HelloWorldSeverity
    start_time: str | None = None
    limit: int = 10
    should_push_events: bool = False

    @validator("start_time", allow_reuse=True)
    def validate_start_time(cls, v) -> str | None:  # pylint: disable=no-self-argument
        """Convert start_time to ISO 8601 timestamp string."""
        if v:
            return cast(datetime, arg_to_datetime(v)).isoformat()  # Raises ValueError / AttributeError if invalid
        return None

    @validator("should_push_events", allow_reuse=True)
    def validate_should_push_events(cls, v):  # pylint: disable=no-self-argument
        """Ensure should_push_events is valid for the current tenant."""
        should_push_events = argToBoolean(v)
        if should_push_events and not CAN_SEND_EVENTS:
            raise ValueError("[Args validation] 'should_push_events' is not supported on this tenant.")
        return should_push_events


def get_events_command(client: HelloWorldClient, args: HelloWorldGetEventsArgs) -> CommandResults:
    """Execute helloworld-get-events command.

    This demonstrates on-demand data collection, which is useful for commands that need to retrieve
    datasets from APIs.

    Args:
        client (HelloWorldClient): HelloWorld client to use.
        args (HelloWorldGetEventsArgs): Validated command arguments containing severity, start_time, limit,
                                        and should_push_events.

    Returns:
        CommandResults: CommandResults with collected events.
    """
    demisto.debug(f"[Get events] Getting events {args.severity=}, {args.start_time=}, and {args.limit=}.")

    # Fetch events using the simplified approach
    events = asyncio.run(
        get_alert_list(
            client=client,
            start_time=args.start_time,
            severity=args.severity,
            limit=args.limit,
            should_push=args.should_push_events,
        )
    )

    demisto.debug(f"[Get events] Fetched {len(events)} events")
    return CommandResults(readable_output=tableToMarkdown("HelloWorld Events", events))


# endregion

# region helloworld-alert-note-create


class HelloworldAlertNoteCreateArgs(ContentBaseModel):
    """Arguments for helloworld-alert-note-create command."""

    alert_id: int
    note_text: str

    @validator("alert_id", allow_reuse=True)
    def validate_alert_id(cls, v):  # pylint: disable=no-self-argument
        """Ensure alert_id is a valid positive integer."""
        if v is None or v <= 0:
            raise ValueError("[Args validation] Please provide a valid 'alert_id' argument (must be positive).")
        return v


def alert_note_create_command(client: HelloWorldClient, args: HelloworldAlertNoteCreateArgs) -> CommandResults:
    """Execute helloworld-alert-note-create command.

    Args:
        client (HelloWorldClient): HelloWorld client to use.
        args (HelloworldAlertNoteCreateArgs): Validated command arguments containing:
            - alert_id: The ID of the alert to add a note to (must be a positive integer).
            - note_text: The text content of the note to create.

    Returns:
        CommandResults: CommandResults object containing the note creation result.
    """
    demisto.debug(f"[Create note] Creating note for {args.alert_id=}")
    res_data = client.create_note(alert_id=args.alert_id, comment=args.note_text)

    demisto.debug(f"[Create note] Successfully created note for {args.alert_id=}")
    return CommandResults(
        readable_output="Note was created successfully.",
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.Note",
        outputs_key_field="id",
        outputs=res_data,
    )


# endregion

# region helloworld-job-submit


class HelloWorldJobSubmitArgs(ContentBaseModel):
    """Arguments for helloworld-job-submit command."""

    interval_in_seconds: int = PollingDefaults.INTERVAL_SECONDS
    timeout_in_seconds: int = PollingDefaults.TIMEOUT_SECONDS


def job_submit_command(client: HelloWorldClient, args: HelloWorldJobSubmitArgs) -> CommandResults:
    """Execute helloworld-job-submit command and initiate polling.

    This command demonstrates the polling pattern for long-running operations. It submits a job to
    the remote API and returns a ScheduledCommand to poll for completion.

    Args:
        client (HelloWorldClient): HelloWorld client to use.
        args (HelloWorldJobSubmitArgs): Validated command arguments containing polling interval and timeout.

    Returns:
        CommandResults: CommandResults with ScheduledCommand for polling.
    """
    demisto.debug("[Job submit] Submitting job to API")

    # Submit the job
    job_data = client.submit_job()
    job_id = job_data.get("id")

    if not job_id:
        demisto.error("[Job submit] No job ID returned from API")
        raise DemistoException("No job ID returned from API")

    demisto.debug(f"[Job submit] Successfully submitted {job_id=}")

    # Calculate polling parameters
    polling_interval = args.interval_in_seconds
    polling_timeout = args.timeout_in_seconds

    demisto.debug(f"[Job submit] Initiating polling {job_id=} {polling_interval=} {polling_timeout=}")

    # Prepare arguments for the polling command
    poll_args = {"job_id": job_id, **dict(args)}
    readable = f"Successfully submitted {job_id=}. Polling initiated, checking every {polling_interval} seconds."

    return CommandResults(
        readable_output=readable,
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.Job",
        outputs_key_field="id",
        outputs=job_data,
        scheduled_command=ScheduledCommand(
            command="helloworld-job-poll",
            args=poll_args,
            next_run_in_seconds=polling_interval,
            timeout_in_seconds=polling_timeout,
        ),
    )


# endregion

# region helloworld-job-poll


class HelloWorldJobPollArgs(ContentBaseModel):
    """Arguments for helloworld-job-poll command."""

    job_id: str
    interval_in_seconds: int = PollingDefaults.INTERVAL_SECONDS
    timeout_in_seconds: int = PollingDefaults.TIMEOUT_SECONDS


@polling_function(
    name="helloworld-job-poll",
    interval=PollingDefaults.INTERVAL_SECONDS,
    timeout=PollingDefaults.TIMEOUT_SECONDS,
)
def job_poll_command(args: HelloWorldJobPollArgs | dict, client: HelloWorldClient) -> PollResult:
    """Poll the HelloWorld service for job status until complete.

    Periodically checks the job status and returns the final result when complete.

    Polling Flow:
    1. Status Check: Queries the job status (submitted/running/complete).
    2. Polling Continuation: If not complete, schedules the next poll.
    3. Final Result: If complete, fetches the job result.
    4. Result Compilation: Returns final CommandResults with job data.

    Args:
        args (HelloWorldJobPollArgs): Validated arguments containing 'job_id' and polling parameters.
        client (HelloWorldClient): The configured HelloWorldClient instance.

    Returns:
        PollResult: Contains polling status and final results if complete.
    """
    if isinstance(args, dict):
        args = HelloWorldJobPollArgs(**args)

    job_id = args.job_id
    polling_interval = args.interval_in_seconds

    demisto.debug(f"[Job polling] Polling for {job_id=} with {polling_interval=}.")

    # Check job status
    status_response = client.get_job_status(job_id)

    status = status_response.get("status", "")
    demisto.debug(f"[Job polling] Job status for {job_id=} {status=}")

    # Check if job is complete
    if status == "complete":
        demisto.debug(f"[Job polling] Job complete {job_id=}. Returning final result...")

        # Fetch the final job result
        job_result = client.get_job_result(job_id)

        # Create readable output
        readable = tableToMarkdown(
            f"HelloWorld Job {job_id} - Complete",
            job_result,
            headers=["id", "msg"],
            headerTransform=string_to_table_header,
        )

        final_results = CommandResults(
            readable_output=readable,
            outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.Job",
            outputs_key_field="id",
            outputs=job_result,
        )

        demisto.debug(f"[Job polling] Polling finished successfully {job_id=}")

        return PollResult(
            response=final_results,
            continue_to_poll=False,
            partial_result=CommandResults(readable_output=f"Job {job_id} completed successfully."),
        )

    # Job is still running - continue polling
    else:
        demisto.debug(f"[Job polling] Job still running {job_id=} {status=}, scheduling next poll in {polling_interval}s")

        readable = f"Scheduling next check in {polling_interval} seconds for {job_id=}."
        status_update = CommandResults(
            readable_output=readable,
            outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.Job",
            outputs_key_field="id",
            outputs={"id": job_id, "status": status},
        )

        return PollResult(
            response=None,
            args_for_next_run=dict(args),
            continue_to_poll=True,
            partial_result=status_update,
        )


# endregion

# region helloworld-get-assets


class HelloWorldGetAssetsArgs(ContentBaseModel):
    """Arguments for helloworld-get-assets command."""

    limit: int = 10


def get_assets_command(client: HelloWorldClient, args: HelloWorldGetAssetsArgs) -> CommandResults:
    """Execute helloworld-get-assets command.

    Args:
        client (HelloWorldClient): HelloWorld client to use.
        args (HelloWorldGetAssetsArgs): Validated command arguments containing:
            - limit: Maximum number of assets to retrieve.

    Returns:
        CommandResults: CommandResults object containing asset data.
    """
    demisto.debug(f"[Get assets] Fetching assets with {args.limit=}")

    # Fetch assets from the API
    raw_response = client.get_assets(limit=args.limit)
    assets = raw_response.get("data", [])

    demisto.debug(f"[Get assets] Fetched {len(assets)} assets")
    readable_output = tableToMarkdown("HelloWorld Assets", assets)

    return CommandResults(readable_output=readable_output)


# endregion

# region helloworld-get-vulnerabilities


class HelloWorldGetVulnerabilitiesArgs(ContentBaseModel):
    """Arguments for helloworld-get-vulnerabilities command."""

    limit: int = 10


def get_vulnerabilities_command(client: HelloWorldClient, args: HelloWorldGetVulnerabilitiesArgs) -> CommandResults:
    """Execute helloworld-get-vulnerabilities command.

    Args:
        client (HelloWorldClient): HelloWorld client to use.
        args (HelloWorldGetVulnerabilitiesArgs): Validated command arguments containing:
            - limit: Maximum number of vulnerabilities to retrieve.

    Returns:
        CommandResults: CommandResults object containing vulnerability data.
    """
    demisto.debug(f"[Get vulnerabilities] Fetching vulnerabilities with {args.limit=}")

    # Fetch vulnerabilities from the API
    raw_response = client.get_vulnerabilities(limit=args.limit)
    vulnerabilities = raw_response.get("data", [])

    demisto.debug(f"[Get vulnerabilities] Fetched {len(vulnerabilities)} vulnerabilities")
    readable_output = tableToMarkdown("HelloWorld Vulnerabilities", vulnerabilities)

    return CommandResults(readable_output=readable_output)


# endregion

# region ExecutionConfig


class HelloWorldExecutionConfig(BaseExecutionConfig):
    """Extends BaseExecutionConfig to leverage a centralized entrypoint.

    Holds the currently-executed command, configuration parameters, command arguments, and fetch last
    run state.
    """

    @property
    def params(self) -> HelloWorldParams:
        """Get validated integration parameters.

        Returns:
            HelloWorldParams: Validated integration parameters with all configuration settings.
        """
        return HelloWorldParams(**self._raw_params)

    @property
    def ip_args(self) -> IpArgs:
        """Get validated arguments for the ip command.

        Returns:
            IpArgs: Validated arguments containing IP addresses and threshold.
        """
        return IpArgs(**self._raw_args)

    @property
    def get_events_args(self) -> HelloWorldGetEventsArgs:
        """Get validated arguments for the helloworld-get-events command.

        Returns:
            HelloWorldGetEventsArgs: Validated arguments containing severity, offset, limit, and
                                     should_push_events.
        """
        return HelloWorldGetEventsArgs(**self._raw_args)

    @property
    def alert_list_args(self) -> HelloworldAlertListArgs:
        """Get validated arguments for the helloworld-alert-list command.

        Returns:
            HelloworldAlertListArgs: Validated arguments containing alert_id, limit, and severity.
        """
        return HelloworldAlertListArgs(**self._raw_args)

    @property
    def alert_note_create_args(self) -> HelloworldAlertNoteCreateArgs:
        """Get validated arguments for the helloworld-alert-note-create command.

        Returns:
            HelloworldAlertNoteCreateArgs: Validated arguments containing alert_id and note_text.
        """
        return HelloworldAlertNoteCreateArgs(**self._raw_args)

    @property
    def say_hello_args(self) -> HelloworldSayHelloArgs:
        """Get validated arguments for the helloworld-say-hello command.

        Returns:
            HelloworldSayHelloArgs: Validated arguments containing name.
        """
        return HelloworldSayHelloArgs(**self._raw_args)

    @property
    def job_submit_args(self) -> HelloWorldJobSubmitArgs:
        """Get validated arguments for the helloworld-job-submit command.

        Returns:
            HelloWorldJobSubmitArgs: Validated arguments containing polling interval and timeout.
        """
        return HelloWorldJobSubmitArgs(**self._raw_args)

    @property
    def job_poll_args(self) -> HelloWorldJobPollArgs:
        """Get validated arguments for the helloworld-job-poll command.

        Returns:
            HelloWorldJobPollArgs: Validated arguments containing job_id, interval, and timeout.
        """
        return HelloWorldJobPollArgs(**self._raw_args)

    @property
    def get_assets_args(self) -> HelloWorldGetAssetsArgs:
        """Get validated arguments for the helloworld-get-assets command.

        Returns:
            HelloWorldGetAssetsArgs: Validated arguments containing limit.
        """
        return HelloWorldGetAssetsArgs(**self._raw_args)

    @property
    def get_vulnerabilities_args(self) -> HelloWorldGetVulnerabilitiesArgs:
        """Get validated arguments for the helloworld-get-vulnerabilities command.

        Returns:
            HelloWorldGetVulnerabilitiesArgs: Validated arguments containing limit.
        """
        return HelloWorldGetVulnerabilitiesArgs(**self._raw_args)

    @property
    def last_run(self) -> HelloWorldLastRun:
        """Get the last_run state for fetch-incidents or fetch-events commands.

        Returns:
            HelloWorldLastRun: State from the previous fetch execution.
        """
        return HelloWorldLastRun(**self._raw_last_run)

    @property
    def assets_last_run(self) -> HelloWorldAssetsLastRun:
        """Get the last_run state for fetch-assets command.

        Returns:
            HelloWorldAssetsLastRun: State from the previous fetch-assets execution.
        """
        return HelloWorldAssetsLastRun(**self._raw_assets_last_run)


# endregion

# region Main


def main() -> None:  # pragma: no cover
    """Parse and validate configuration parameters and command arguments, then run commands."""
    execution = HelloWorldExecutionConfig()
    command = execution.command

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as `demisto.debug()`, `demisto.info()`,
    # etc. to print information in the engine runner logs. You can set the log
    # level in the integration instance configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging

    demisto.debug(f"[Main] Starting to execute {command=}.")
    client = None
    try:
        params = execution.params
        client = HelloWorldClient(params)

        match execution.command:
            case "test-module":
                # This is the call made when pressing the integration Test button.
                return_results(test_module(client, params))

            case "ip":
                # Validate command arguments, such as the validity of `ip` addresses
                ip_args = execution.ip_args
                # Run command and get its results
                return_results(ip_reputation_command(client, ip_args, params))

            case "fetch-incidents" | "fetch-events":
                # Implement command(s) that are invoked when fetch is enabled in the integration instance configuration
                # Get last_run from the last time was invoked
                demisto.debug("[Main] Starting fetch")
                last_run = execution.last_run
                next_run = fetch_alerts(
                    client,
                    last_run,
                    severity=params.severity,
                    max_fetch=params.max_fetch,
                    first_fetch_time=params.first_fetch_time,
                )
                # Save next_run for the next time fetch is invoked
                next_run.set()
                demisto.debug("[Main] fetch completed")

            case "fetch-assets":
                # Implement fetch-assets command that is invoked when fetch is enabled in the integration instance configuration
                demisto.debug("[Main] Starting fetch-assets")
                # Get last_run from the last time fetch-assets was invoked
                assets_last_run = execution.assets_last_run
                # Fetch assets and vulnerabilities in sequential batched stages
                assets_next_run = fetch_assets(client, assets_last_run)
                # Save next_run for the next time fetch-assets is invoked
                assets_next_run.set()
                demisto.debug("[Main] fetch-assets completed")

            case "helloworld-get-events":
                # Validate command arguments
                get_events_args = execution.get_events_args
                # Run command and get a list of events and its results
                results = get_events_command(client, get_events_args)
                return_results(results)

            case "helloworld-get-assets":
                # Validate command arguments
                get_assets_args = execution.get_assets_args
                # Run command and get its results
                return_results(get_assets_command(client, get_assets_args))

            case "helloworld-get-vulnerabilities":
                # Validate command arguments
                get_vulnerabilities_args = execution.get_vulnerabilities_args
                # Run command and get its results
                return_results(get_vulnerabilities_command(client, get_vulnerabilities_args))

            case "helloworld-alert-list":
                # Validate command arguments, such as the existence of `alert_id` or `severity`
                alert_list_args = execution.alert_list_args
                # Run command and get its results
                return_results(alert_list_command(client, alert_list_args))

            case "helloworld-alert-note-create":
                # Validate command arguments, such as `alert_id` > 0
                alert_note_create_args = execution.alert_note_create_args
                # Run command and get its results
                return_results(alert_note_create_command(client, alert_note_create_args))

            case "helloworld-say-hello":
                # Validate command arguments, such as mandatory `name` string
                say_hello_args = execution.say_hello_args
                # Run command and get its results
                return_results(say_hello_command(client, say_hello_args))

            case "helloworld-job-submit":
                # Submit a job and initiate polling
                job_submit_args = execution.job_submit_args
                # Run command and get its results
                return_results(job_submit_command(client, job_submit_args))

            case "helloworld-job-poll":
                # Periodically polls the status of a process being executed on a remote host.
                # When the process execution is done, the final result is returned and polling stops.
                job_poll_args = execution.job_poll_args
                # Run command, schedule next polling run, and return final result when complete
                return_results(job_poll_command(job_poll_args, client))

            case _:
                raise NotImplementedError(f"Command {command} is not implemented")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(f"[Main] Failed to execute {command=}: {str(e)}. {traceback.format_exc()}")
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")

    finally:
        demisto.debug(f"[Main] Generating diagnostic report after executing {command=}.")
        if client:
            client.log_optional_diagnostic_report()


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

# endregion

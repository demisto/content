## Overview

This is the Hello World v2 integration for getting started.

## Configure Hello World v2 in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g., https://api.dummy-example.com) | Default is https://api.dummy-example.com. | True |
| API Key |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Score threshold for IP reputation command | The minimum HelloWorld score required to mark an IP as malicious \(0-100\). Default is 65. | False |
| Source Reliability | Reliability of the source providing the intelligence data. Possible values are: A+ - 3rd party enrichment, A - Completely reliable, B - Usually reliable, C - Fairly reliable, D - Not usually reliable, E - Unreliable, F - Reliability cannot be judged. Default is C - Fairly reliable. | False |
| First fetch time | The time from which to start fetching alerts. Supports relative time \(e.g., "3 hours ago"\) or ISO 8601 format \(e.g., "2025-12-01T00:00:00Z"\). Default is 3 days. | False |
| Severity of alerts to fetch | Possible values are: low, medium, high, critical. Default is high. | False |
| Fetch incidents | Fetch HelloWorld alerts as incidents in Cortex XSOAR. Supported in Cortex XSOAR only. | False |
| Incident type | | False |
| Maximum number of incidents per fetch | Default is 10. Supported in Cortex XSOAR only. | False |
| Fetch events | Fetch HelloWorld alerts as events in Cortex XSIAM. Supported in Cortex XSIAM only. | False |
| Maximum number of events per fetch | Default is 1000. Supported in Cortex XSIAM only. | False |
| Fetch assets and vulnerabilities |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### helloworld-say-hello

***
Prints hello to a specified name.

#### Base Command

`helloworld-say-hello`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the person you want to say hello to. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.Hello.name | String | The greeting message returned by the command. |

#### Command example

```!helloworld-say-hello name="Dbot"```

#### Context Example

```json
{
    "HelloWorld": {
        "Hello": {
            "name": "Dbot"
        }
    }
}
```

#### Human Readable Output

>## Hello Dbot

### helloworld-alert-list

***
Lists example alerts as they would appear in a fetch operation.

#### Base Command

`helloworld-alert-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Filter the fetch by alert ID. If not specified, all alert IDs will be retrieved. | Optional |
| limit | How many alerts to fetch. Default is 10. | Optional |
| severity | The severity by which to filter the alerts. Possible values are: low, medium, high, critical. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.alert.id | Number | The ID of the alert. |
| HelloWorld.alert.name | String | The name of the alert. |
| HelloWorld.alert.severity | String | The severity of the alert. |
| HelloWorld.alert.date | Date | The date of the alert occurrence. |
| HelloWorld.alert.status | String | The status of the alert. |

#### Command example

```!helloworld-alert-list limit="3" severity="low"```

#### Context Example

```json
{
    "HelloWorld": {
        "Alert": [
            {
                "date": "2023-09-14T11:30:39.882955",
                "id": 1,
                "name": "XSOAR Test Alert #1",
                "severity": "low",
                "status": "Testing"
            },
            {
                "date": "2023-09-14T11:30:39.882955",
                "id": 2,
                "name": "XSOAR Test Alert #2",
                "severity": "low",
                "status": "Testing"
            },
            {
                "date": "2023-09-14T11:30:39.882955",
                "id": 3,
                "name": "XSOAR Test Alert #3",
                "severity": "low",
                "status": "Testing"
            }
        ]
    }
}
```

#### Human Readable Output

>### Items List (Sample Data)
>
>|date|id|name|severity|status|
>|---|---|---|---|---|
>| 2023-09-14T11:30:39.882955 | 1 | XSOAR Test Alert #1 | low | Testing |
>| 2023-09-14T11:30:39.882955 | 2 | XSOAR Test Alert #2 | low | Testing |
>| 2023-09-14T11:30:39.882955 | 3 | XSOAR Test Alert #3 | low | Testing |

#### Command example

```!helloworld-alert-list alert_id=2```

#### Context Example

```json
{
    "HelloWorld": {
        "Alert": {
            "date": "2023-09-14T11:30:39.882955",
            "id": 2,
            "name": "XSOAR Test Alert #2",
            "severity": "low",
            "status": "Testing"
        }
    }
}
```

#### Human Readable Output

>### Items List (Sample Data)
>
>|date|id|name|severity|status|
>|---|---|---|---|---|
>| 2023-09-14T11:30:39.882955 | 2 | XSOAR Test Alert #2 | low | Testing |

### helloworld-alert-note-create

***
Create a note in the API.

#### Base Command

`helloworld-alert-note-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert ID to add the note to. | Required |
| note_text | The text to add to the note. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.Note.status | String | The note creation status. |
| HelloWorld.Note.msg | String | The message from the note creation response. |

#### Command example

```!helloworld-alert-note-create alert_id=2 note_text=test```

#### Context Example

```json
{
    "HelloWorld": {
        "Note": {
            "msg": "Note was created for alert #2 successfully with comment: test",
            "status": "success"
        }
    }
}
```

#### Human Readable Output

>Note was created successfully.

### ip

***
The returned IP information and reputation.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IPs. | Required |
| threshold | The score threshold used to determine if an IP is malicious. If not provided, the default threshold from the instance configuration is used. Default is 65. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| HelloWorld.IP.asn | String | The autonomous system name \(ASN\) for the IP address. |
| HelloWorld.IP.asn_cidr | String | The network routing prefix in CIDR notation associated with the ASN. |
| HelloWorld.IP.asn_country_code | String | The two letter ISO country code associated with the ASN. |
| HelloWorld.IP.asn_date | Date | The date the ASN was assigned. |
| HelloWorld.IP.asn_description | String | The ASN description. |
| HelloWorld.IP.asn_registry | String | The registry the ASN belongs to. |
| HelloWorld.IP.entities | String | Entities associated to the IP. |
| HelloWorld.IP.ip | String | The actual IP address. |
| HelloWorld.IP.network.cidr | String | The network CIDR for the IP address. |
| HelloWorld.IP.network.country | String | The country of the IP address. |
| HelloWorld.IP.network.end_address | String | The last IP address of the CIDR. |
| HelloWorld.IP.network.events.action | String | The specific action recorded for the network \(for example, registration or modification\). |
| HelloWorld.IP.network.events.actor | Unknown | The actor \(identifier or entity name\) that performed the recorded action on the network. |
| HelloWorld.IP.network.events.timestamp | String | The date and time the event occurred. |
| HelloWorld.IP.network.handle | String | The unique registry identifier assigned to the network block. |
| HelloWorld.IP.network.ip_version | String | The IP address version. |
| HelloWorld.IP.network.links | String | Links associated to the IP address. |
| HelloWorld.IP.network.name | String | The name of the network. |
| HelloWorld.IP.network.notices.description | String | The description of the notice. |
| HelloWorld.IP.network.notices.links | Unknown | A list of URLs providing additional information or documentation related to the network notice. |
| HelloWorld.IP.network.notices.title | String | The title of a specific notice related to the network. |
| HelloWorld.IP.network.parent_handle | String | The unique registry identifier of the parent network from which this block was allocated. |
| HelloWorld.IP.network.raw | Unknown | Additional raw data for the network. |
| HelloWorld.IP.network.remarks | Unknown | Additional remarks for the network. |
| HelloWorld.IP.network.start_address | String | The first IP address of the CIDR. |
| HelloWorld.IP.network.status | String | The network status. |
| HelloWorld.IP.network.type | String | The type of the network. |
| HelloWorld.IP.query | String | The IP address that was queried. |
| HelloWorld.IP.raw | Unknown | Additional raw data for the IP address. |
| HelloWorld.IP.score | Number | The reputation score from HelloWorld for this IP \(0 to 100, where higher is worse\). |
| IP.Address | String | The IP address. |
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. |
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. |
| IP.ASN | String | The autonomous system name for the IP address. |
| IP.Relationships.EntityA | string | The source of the relationship. |
| IP.Relationships.EntityB | string | The destination of the relationship. |
| IP.Relationships.Relationship | string | The name of the relationship. |
| IP.Relationships.EntityAType | string | The relationship source type. |
| IP.Relationships.EntityBType | string | The relationship destination type. |

#### Command example

```!ip ip="8.8.8.8"```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "8.8.8.8",
        "Reliability": "C - Fairly reliable",
        "Score": 3,
        "Type": "ip",
        "Vendor": "HelloWorld"
    },
    "HelloWorld": {
        "IP": {
            "id": "x.x.x.x",
            "ip": "8.8.8.8",
            "links": {
                "self": "https://www.virustotal.com/api/v3/ip_addresses/x.x.x.x"
            },
            "type": "ip_address"
        }
    },
    "IP": {
        "Address": "8.8.8.8",
        "Malicious": {
            "Description": "Hello World returned reputation -4",
            "Vendor": "HelloWorld"
        },
        "Relationships": [
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "h",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "x",
                "EntityBType": "URL",
                "Relationship": "related-to"
            }
        ]
    }
}
```

#### Human Readable Output

>### IP (Sample Data)
>
>|id|ip|links|type|
>|---|---|---|---|
>| x.x.x.x | 8.8.8.8 | self: https:<span>//</span>www.virustotal.com/api/v3/ip_addresses/x.x.x.x | ip_address |
>
>### Attributes
>
>|as_owner|asn|continent|country|jarm|last_analysis_stats|last_modification_date|network|regional_internet_registry|reputation|tags|total_votes|whois_date|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| EMERALD-ONION | 396507 | NA | US | :jarm: | ***harmless***: 72<br/>***malicious***: 5<br/>***suspicious***: 2<br/>***timeout***: 0<br/>***undetected***: 8 | 1613300914 | :cidr: | ARIN | -4 |  | ***harmless***: 0<br/>***malicious***: 1 | 1611870274 |

### helloworld-get-events

***
Retrieves alerts from the HelloWorld API. Use this command for development and debugging only, as it may produce duplicate events, exceed API rate limits, or disrupt the fetch mechanism.

#### Base Command

`helloworld-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| severity | The severity by which to filter the alerts. Possible values are: low, medium, high, critical. | Required |
| start_time | The time from which to start fetching alerts. Supports relative time \(e.g., "3 hours ago"\) or ISO 8601 format \(e.g., "2025-12-01T00:00:00Z"\). | Optional |
| limit | Maximum number of alerts to retrieve. Default is 10. | Optional |
| should_push_events | Whether to push events to Cortex XSIAM \(for Cortex XSIAM tenants only\). Possible values are: true, false. Default is false. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!helloworld-get-events severity="low" limit=3```

#### Human Readable Output

>### HelloWorld Events
>
>| id | severity | user | action | date | status |
>| --- | --- | --- | --- | --- | --- |
>| 1 | low | userB@test.com | Testing | 2023-09-14T11:30:39.882955 | Error |
>| 2 | low | userA@test.com | Testing | 2023-09-14T11:30:39.883955 | Success |
>| 3 | low | userB@test.com | Testing | 2023-09-14T11:30:39.884955 | Error |

### helloworld-job-submit

***
Submits a job to the HelloWorld API and polls for completion. Used for asynchronous APIs and long-running operations.

#### Base Command

`helloworld-job-submit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| interval_in_seconds | Interval in seconds between each poll. Default is 30. | Optional |
| timeout_in_seconds | Timeout in seconds until polling stops. Default is 600. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.Job.id | String | The ID of the submitted job. |
| HelloWorld.Job.status | String | The current status of the job. |
| HelloWorld.Job.type | String | The type of job submitted. |
| HelloWorld.Job.msg | String | Message from the completed job. |

#### Command example

```!helloworld-job-submit```

#### Context Example

```json
{
    "HelloWorld": {
        "Job": {
            "id": "abc-123",
            "msg": "The configuration has successfully been updated.",
            "status": "complete",
            "type": "HelloWorldRefreshConfig"
        }
    }
}
```

#### Human Readable Output

>### HelloWorld Job abc-123 - Complete
>
>|id|msg|
>|---|---|
>| abc-123 | The configuration has successfully been updated. |

### helloworld-get-assets

***
Retrieves resources and assets in the HelloWorld environment.

#### Base Command

`helloworld-get-assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of assets to retrieve. Default is 10. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!helloworld-get-assets limit=3```

#### Human Readable Output

>### HelloWorld Assets
>
>| id | name | type | status | created |
>| --- | --- | --- | --- | --- |
>| 1 | Server-01 | server | active | 2024-01-15T10:00:00 |
>| 2 | Database-01 | database | active | 2024-01-16T11:30:00 |
>| 3 | Storage-01 | storage | active | 2024-01-17T09:15:00 |

### helloworld-get-vulnerabilities

***
Retrieves vulnerabilities found in the HelloWorld environment.

#### Base Command

`helloworld-get-vulnerabilities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of vulnerabilities to retrieve. Default is 10. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!helloworld-get-vulnerabilities limit=3```

#### Human Readable Output

>### HelloWorld Vulnerabilities
>
>| id | cve_id | severity | description | published |
>| --- | --- | --- | --- | --- |
>| 1 | CVE-MOCK-0001 | critical | Remote code execution vulnerability | 2026-01-10T08:00:00 |
>| 2 | CVE-MOCK-0002 | high | SQL injection vulnerability | 2026-01-12T14:30:00 |
>| 3 | CVE-MOCK-0003 | medium | Cross-site scripting vulnerability | 2026-01-14T16:45:00 |

---

## Developer Guide

This section documents the key architectural patterns and code features in Hello World v2 and provides guidelines for building robust Cortex integrations.

### Key Patterns and Features

| **Feature** | **Description** |
| --- | --- |
| Robust User Input Validation | Type-safe configuration parameter and command argument validation with user-friendly error messages. |
| Modern API Client | Uses the `ContentClient`, which provides enhanced reliability, observability, and developer experience features. |
| Polling / Scheduled Commands | Commands that can schedule the future execution of other commands; suitable for periodically checking the status of a long-running external process or asynchronous task. |
| Centralized Execution Configuration | A centralized object for commands, configuration params, command arguments, and fetch last run state to minimize redundant system calls. |
| Dual Fetch Incidents / Events Support | A Unified flow for fetching Cortex XSOAR incidents and Cortex XSIAM events. |
| Fetch Assets and Vulnerabilities Support | A flow for fetching a current snapshot of an environment's resources and vulnerabilities in Cortex XSIAM. |
| Structured Logging | A consistent, prefix-based Python f-string format that captures specific variable context, ensuring messages are easily searchable and facilitate efficient debugging of the execution flow. |

### How to Build an Integration

Below is a step-by-step guide on how to build an integration that implements a basic automation command and fetch flow.

1. [Import the Required Modules](#1-import-the-required-modules)
2. [Define a Configuration Parameters Validation Model](#2-define-a-configuration-parameters-validation-model)
3. [Create an API Client Class](#3-create-an-api-client-class)
4. [Implement Standard Automation Command Pattern](#4-implement-standard-automation-command-pattern)
5. [Implement Standard Fetch Flow Pattern](#5-implement-standard-fetch-flow-pattern)
6. [Setup Execution Configuration](#6-setup-execution-configuration)
7. [Define the Main Function](#7-define-the-main-function)

#### 1. Import the Required Modules

At the top of the integration code file, import the required modules. This can include built-in Python modules such as `enum`, `typing`, and `asyncio`, as well as Content-related imports such as `CommonServerPython` and `ContentClientApiModule`.

```python
# Use enumerations to group related constants or define all possible values of configuration parameter or command argument
# For example, severity values: critical, high, moderate, low, unknown
from enum import Enum

# Use `typing` and/or `collections.abc` for defining attribute types in validation models and for type hinting.
from typing import Any
from collections.abc import Awaitable

# Import `CommonServerPython` and `demisto` class, which contain many useful helper and utility functions
from CommonServerPython import *
import demistomock as demisto

# Optionally use `CommonServerUserPython` (for custom integrations) to override constants, functions, and classes defined in `CommonServerPython`
from CommonServerUserPython import *

# Import `ContentClientApiModule` to use the new `ContentClient` class, which contains improved error handling, thread safety, and authentication handling.
from ContentClientApiModule import *

# Add any other required imports depending on your code
from datetime import datetime, UTC, timedelta
```

#### 2. Define a Configuration Parameters Validation Model

Define the schema that corresponds to the configuration parameters in the integration YML file.  
Use Pydantic classes that inherit from `ContentBaseModel` (or its subclasses like `BaseParams`) for robust input validation with user-friendly error messages.

You can use an AI agent to automatically generate models from the configuration parameters defined in the integration YML file.

```python
class Credentials(ContentBaseModel):
    """Credentials model for API authentication."""

    username: str
    password: SecretStr


class MyIntegrationParams(BaseParams):
    """Integration parameters with validation.
    
    Attributes:
        url: API base URL (trailing slash removed automatically).
        credentials: Username and password for API Authentication.
        max_fetch: Maximum incidents per fetch.
    """
    # `proxy` and `insecure` are already defined in `BaseParams`
    url: AnyUrl
    credentials: Credentials
    # Ensure attribute name matches the param `name` field value in the YML
    # To follow Python "snake_case" format, use an `alias` value for mapping to the `camelCase` param name in the YML
    is_fetch: bool | None = Field(default=False, alias="isFetch")  # corresponds to "Fetch incidents" checkbox
    first_fetch: str  = "1 week"
    max_fetch: int = 50

    @property
    def first_fetch_datetime(self) -> datetime:
        """Cast first fetch to a datetime object."""
        return arg_to_datetime(self.first_fetch) or (datetime.now(tz=UTC) - timedelta(weeks=1))

    @validator('url', reuse=True)
    def clean_url(cls, v) -> str:
        """Remove trailing slash from URL."""
        return v.rstrip('/')
    
    @validator('max_fetch', reuse=True)
    def validate_max_fetch(cls, v) -> int:
        """Check that max fetch is not above the permitted value."""
        max_fetch = arg_to_number(v)
        if max_fetch > 1000:
            raise ValueError("The maximum number of incidents per fetch must not be greater than 1000.")
        return max_fetch
```

#### 3. Create an API Client Class

Create a `MyIntegrationClient` class that inherits from `ContentClient` to leverage built-in retry logic, rate limit handling, authentication, and thread safety.

For authentication, define a custom `AuthHandler` if needed or use any of the included ones in `ContentClientApiModule` such as `APIKeyAuthHandler`, `BearerTokenAuthHandler`, or `BasicAuthHandler`.

```python
# Example client class that inherits from ContentClient and adds two integration-specific methods

class MyIntegrationClient(ContentClient):

    def __init__(self, params: HelloWorldParams):
        """Initialize client with ContentClient capabilities.

        Args:
            params (MyIntegrationParams): Validated integration configuration parameters.
        """
        credentials: Credentials = params.credentials
        super().__init__(
            base_url=params.url,
            verify=params.verify,
            proxy=params.proxy,
            auth_handler=BasicAuthHandler(username=credentials.username, password=credentials.password),
            client_name="MyIntegrationClient",
            diagnostic_mode=is_debug_mode(),  # enable if commands are run with `debug-mode=true`
        )

    def get_item_by_id(self, item_id: int) -> dict[str, Any]:
        """Get an item in MyIntegration by its ID.

        Args:
            item_id (int): Item ID.

        Returns:
            dict[str, Any]: Item dictionary.
        """
        endpoint = f"api/items/{item_id}"
        return self.get(endpoint)  # JSON response bodies are decoded by default

    def get_items_list(self, limit: int, start_time: str | None = None) -> list[dict]:
        """Get a list of items in MyIntegration up to the limit.

        Args:
            limit (int): Maximum number of items to return.
            start_time (str | None): Optional start time in ISO 8601 format.

        Returns:
            list[dict]: List of items.
        """
        endpoint = "api/items"
        query_params = assign_params(limit=limit, start_time=start_time)  # use `assign_params` to remove empty values
        return self.get(endpoint, params=query_params)
```

#### 4. Implement Standard Automation Command Pattern

Define an arguments validation model and a command function for each command. Define additional (helper) functions if needed.

You can use an AI agent to automatically generate models from the command arguments defined in the integration YML file.

The code snippet below demonstrates how to implement a ***basic*** automation command.

See the following references for example implementations of more complex commands:

| **Type** | **Example** |
| --- | --- |
| [Polling / scheduled command](https://xsoar.pan.dev/docs/integrations/scheduled-commands) | `helloworld-job-poll` command in Hello World v2 |
| [Generic reputation command](https://xsoar.pan.dev/docs/integrations/generic-commands-reputation) | `ip` command in Hello World v2 |

```python
# Basic automation command example implementation

class MyIntegrationItemListArgs(BaseArgs):
    """Arguments for `my-integration-item-list` command.
    
    Attributes:
        item_id: Optional item ID to retrieve.
        limit: Maximum number of items to retrieve (default: 10).
    """
    item_id: int | None = None
    limit: int = 10


def my_integration_item_list_command(client: MyIntegrationClient, args: MyIntegrationItemListArgs) -> CommandResults:
    """Run `my-integration-item-list` command logic.

    Args:
        client (MyIntegrationClient): An initialized API client instance.
        args (MyIntegrationItemListArgs): Validated command arguments.

    Returns:
        CommandResults: Command results containing context and human-readable outputs.
    """

    if args.item_id:
        items = client.get_item_by_id(item_id=args.item_id)
    else:
        items = client.get_items_list(limit=args.limit)

    return CommandResults(
        outputs_prefix="MyIntegration.Item",  # Context output prefix
        outputs_key_field="id",  # Objects under the defined prefix will be deduplicated according to this field value
        outputs=items,  # The items to return to the context output
        readable_output=tableToMarkDown("My Integration Items", items),  # Human-readable entry to return to the war room
    )
```

#### 5. Implement Standard Fetch Flow Pattern

The code snippet below demonstrates how to implement a ***basic*** `fetch-incidents` flow.

See the following references for example implementations of more complex fetch flows:

| **Type** | **Example** |
| --- | --- |
| Unified Cortex XSOAR fetch incidents and Cortex XSIAM fetch events | `fetch-incidents` and `fetch-events` commands, respectively, in Hello World v2 |
| Cortex XSIAM fetch assets flow | `fetch-assets` command in Hello World v2 |
| Fetch indicators | `fetch-indicators` command in Hello World Feed |

```python
# Basic fetch-incidents example implementation

class MyIntegrationLastRun(BaseLastRun):
    """State management for fetch-incidents.
    
    Attributes:
        start_time: ISO 8601 timestamp of the last fetched item.
        last_item_ids: List of item IDs from the last fetch time to prevent duplicates.
    """
    start_time: str | None = None
    last_item_ids: list[int] = []


def fetch_incidents(
    client: MyIntegrationClient,
    last_run: MyIntegrationLastRun,
    max_fetch: int,
    first_fetch_datetime: datetime,
) -> MyIntegrationLastRun:
    """Fetch new items as incidents.

    Args:
        client (MyIntegrationClient): An initialized API client instance.
        last_run (MyIntegrationLastRun): Last run state from previous fetch invocation.
        max_fetch (int): Maximum number of incidents to fetch.
        first_fetch_datetime (datetime): Date from which to start fetching incidents.
    """
    default_batch_limit: int = 100
    start_time: str = last_run.start_time or first_fetch_datetime.isoformat()
    last_item_ids: list[int] = last_run.last_item_ids

    unique_items: list[dict] = []

    while len(unique_items) < max_fetch:
        # Send requests in batches to avoid exceeding the API's maximum `limit` value
        remaining_count = max_fetch - len(unique_items)
        batch_limit = min(default_batch_limit, remaining_count)
        items = client.get_items_list(limit=batch_limit, start_time=start_time)

        # Deduplication logic
        for item in items:
            if item["id"] in last_item_ids:
                continue
            unique_items.append(item)
    
    if unique_items:
        start_time = unique_items[-1]["time"]
        last_item_ids = [item["id"] for item in unique_items if item["time"] == start_time]
    
        # Formatting and incident creation logic
        incidents = format_as_incidents(unique_items)
        demisto.createIncidents(incidents)  # create incidents

    return MyIntegrationLastRun(start_time=start_time, last_item_ids=last_item_ids)
```

#### 6. Setup Execution Configuration

Inherits from the `BaseExecutionConfig` class in `BaseContentApiModule` to centralize command execution context, prevent redundant system calls (via the `demisto` class), and provide type-safe access to configuration parameters, command arguments, and fetch last run state.

```python
class MyIntegrationExecutionConfig(BaseExecutionConfig):

    @property
    def params(self) -> MyIntegrationItemListArgs:
        return MyIntegrationItemListArgs(**self._raw_params)

    @property
    def item_list_args(self) -> MyIntegrationItemListArgs:
        """Get validated arguments for `my-integration-item-list` command."""
        return MyIntegrationItemListArgs.get(**self._raw_args)

    @property
    def last_run(self) -> MyIntegrationLastRun:
        """Get validated last run object for `fetch-incidents` flow."""
        return MyIntegrationLastRun(**self._raw_last_run)
```

#### 7. Define the Main Function

Define and implement a `main()` function, which would serve as the entrypoint into the integration logic.

This function should initialize the Execution Configuration and API Client classes and route to the implemented command functions.

```python
def main():
    execution = ExecutionConfig()
    command: str = execution.command
    client = None

    try:
        params: MyIntegrationParams = execution.params
        client = MyIntegrationClient(params)

        # Ensure the integration implements connection / configuration testing logic
        if command == "test-module":
            return_results(my_integration_test_module(client, params))
        
        # Route to automation command
        elif command == "my-integration-item-list":
            args = execution.item_list_args
            return_results(my_integration_item_list_command(client, args))
        
        elif command == "fetch-incidents":
            last_run = execution.last_run
            next_run = fetch_incidents(client, last_run, max_fetch=params.max_fetch, first_fetch_datetime=params.first_fetch_datetime)
            next_run.set()

        else:
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
```

### AI Agent Prompts

#### Uplift an Existing Integration

```
Update the logic in MyIntegration.py to follow the style of HelloWorldV2.py.

REFERENCE DOCUMENTATION
- The ContentClientApiModule README.md file
- The "Developer Guide" section in the HelloWorldV2 README.md file
- The HelloWorldV2.py code file

FOCUS AREAS
Focus on implementing key features <including fetch if relevant> and avoid common pitfalls, as documented.

REQUIREMENTS
- Maintain backward compatibility with existing YML configuration parameters and command arguments (Do not add any new commands and keep existing ones)
- Preserve all integration-specific logic (authentication methods, API quirks, data transformations)
- Include consistent debug and diagnostic logging that captures specific variable context
- Pass type checking with Pydantic validation models
- Follow the region-based organization from HelloWorldV2

Make sure to update the unit test to match the new code in MyIntegration.py in the style of HelloWorldV2_test.py. Mock API responses and helper functions where needed.
Update the API Module dependencies and Docker image in MyIntegration.yml to match HelloWorldV2.yml
```

#### Create a New Integration

```
Create a new integration called MyIntegration available in the <xsoar|marketplacev2|platform> marketplaces with supported modules <...> and support level <xsoar|partner|community|...> inside my <new|existing> MyPack pack.

REFERENCE DOCUMENTATION
- The ContentClientApiModule README.md file
- The "Developer Guide" section in the HelloWorldV2 README.md file
- The HelloWorldV2.py code file

FOCUS AREAS
Focus on implementing key features <including fetch if relevant> and avoid common pitfalls, as documented.

API DETAILS
- Base URL: <https://api.example.com>
- Authentication: <OAuth2|Basic|API Key|Custom>
- Rate Limits: <X requests per minute/hour>

CONFIGURATION PARAMETERS 
For each parameter, define in YML and include in the parameter validation model:
1. **Required** `url` - "Server URL" (type: 0, default: https://api.example.com)
2. **Required** `credentials` - "Client ID/Client Secret" (type: 9)
3. **Optional** `proxy` - "Use system proxy settings" (type: 8, inherited from BaseParams)
4. **Optional** `insecure` - "Trust any certificate" (type: 8, inherited from BaseParams)
5. **Optional** `<param_name>` - "<Display Name>" (type: <0-16>, default: <value>)
6. Add more parameters as needed with clear descriptions

COMMANDS TO IMPLEMENT
For each command, define: YML configuration, argument validation model, command function, and client method.
1. **test-module**: Validate connectivity and authentication
   - No arguments
   - Returns: "ok" on success
2. **<integration-name>-<command-name>**: <Brief description>
   - Arguments:
     - **<Required|Optional>** `<arg_name>`: <description> (Python type: <str|int|bool>, default: <value>)
   - Context Outputs:
     - `<IntegrationName>.<CommandPrefix>.<key>` : <description> (YML type: <string|number|boolean|object>)
   - API Endpoint: <GET|POST|PUT|DELETE> /v1/<endpoint>
   - Request <Params|Body>: <list parameters>
   - Returns: CommandResults with readable markdown table and outputs_prefix="<IntegrationName>.<CommandPrefix>"
3. <Add more commands following the same pattern

REQUIREMENTS
- Ensure matching configuration parameters and command arguments in both the YML and code
- Pass type checking with Pydantic validation models
- Follow the region-based organization from HelloWorldV2
- Include consistent debug and diagnostic logging that captures specific variable context

Make sure to write parameterized unit tests in the style of HelloWorldV2_test.py that check edge cases and cover at least 80% of the code. Mock API responses and helper functions where needed.
Update the API Module dependencies and Docker image in MyIntegration.yml to match HelloWorldV2.yml
```

### Pitfalls to Avoid

Avoid the following where possible to adhere to best practices:

- Do not create an API Client that inherits from `BaseClient` in `CommonServerPython`; inherit from `ContentClient` in `ContentClientApiModule` instead, which is backwards compatible.
- Do not call `demisto.params()` directly; define a `params` property under the `ExecutionConfig` class and use `execution.params` instead.
- Do not forget to define an alias for YML configuration parameter or command argument mapping if the field name in the YML is in the "camelCase" format in the validation models. For example: `snake_case_name: str = Field(alias="camelCaseName")`.
- Do not skip defining a custom Pydantic `@validator` function for specific field(s) under the validation model for complex validation logic.
- Do not forget to call `client.log_optional_diagnostic_report()` in `finally` block of the `main()` function.
- Do not forget to accommodate all tenant types if the integration supports multiple marketplaces. For example `send_events_to_xsiam` is not supported on Cortex XSOAR tenants.

## Additional Resources

- [Python Integration Development Guide and Code Standards](https://xsoar.pan.dev/docs/integrations/code-conventions)
- [Reputation Commands and DBotScore Documentation](https://xsoar.pan.dev/docs/integrations/dbot)
- [Pydantic 1.10 Documentation](https://docs.pydantic.dev/1.10/)
- [Python Type Hints](https://docs.python.org/3/library/typing.html)

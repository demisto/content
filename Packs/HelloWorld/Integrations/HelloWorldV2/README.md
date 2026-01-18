## Overview

This is the Hello World v2 integration for getting started.

## Configure Hello World v2 in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g., https://api.xsoar-example.com) |  | True |
| API Key |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Score threshold for IP reputation command | Set this to determine the HelloWorld score that will determine if an IP is malicious \(0-100\). | False |
| Source Reliability | Reliability of the source providing the intelligence data. | False |
| Fetch incidents | Fetch HelloWorld alerts as incidents in Cortex XSOAR. Supported in Cortex XSOAR only. | False |
| Maximum number of incidents per fetch | Default value is 10. Supported in Cortex XSOAR only. | False |
| Fetch events | Fetch HelloWorld alerts as events in Cortex XSIAM. Supported in Cortex XSIAM only. | False |
| Maximum number of events per fetch | Default value is 1000. Supported in Cortex XSIAM only. | False |
| Severity of alerts to fetch | Possible values are: low, medium, high, critical. Default value is high. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### helloworld-say-hello

***
Hello command - prints hello to anyone.

#### Base Command

`helloworld-say-hello`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of whom you want to say hello to. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| hello | String | Should be Hello \*\*something\*\* here. |

#### Command example

```!helloworld-say-hello name="Hello Dbot"```

#### Context Example

```json
{
    "hello": "Hello Hello Dbot"
}
```

#### Human Readable Output

>## Hello Hello Dbot

### helloworld-alert-list

***
Lists the example alerts as it would be fetched from the API.

#### Base Command

`helloworld-alert-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Filter by alert item ID. If not provided, all IDs will be retrieved. | Optional |
| limit | How many alerts to fetch. Default is 10. | Optional |
| severity | The severity by which to filter the alerts. | Optional |

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
Example of creating a new item in the API.

#### Base Command

`helloworld-alert-note-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert's ID to add the note to. | Required |
| note_text | The comment to add to the note. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.Note.status | String | The status of the note creation. |
| HelloWorld.Note.msg | String | Message from the note creation response. |

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
Return IP information and reputation.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IPs. | Optional |
| threshold | If the IP has a reputation above the threshold, then the IP is defined as malicious. If a threshold not set, then threshold from the instance configuration is used. Default is 65. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| HelloWorld.IP.asn | String | The autonomous system name for the IP address. |
| HelloWorld.IP.asn_cidr | String | The ASN CIDR. |
| HelloWorld.IP.asn_country_code | String | The ASN country code. |
| HelloWorld.IP.asn_date | Date | The date on which the ASN was assigned. |
| HelloWorld.IP.asn_description | String | The ASN description. |
| HelloWorld.IP.asn_registry | String | The registry the ASN belongs to. |
| HelloWorld.IP.entities | String | Entities associated to the IP. |
| HelloWorld.IP.ip | String | The actual IP address. |
| HelloWorld.IP.network.cidr | String | Network CIDR for the IP address. |
| HelloWorld.IP.network.country | Unknown | The country of the IP address. |
| HelloWorld.IP.network.end_address | String | The last IP address of the CIDR. |
| HelloWorld.IP.network.events.action | String | The action that happened on the event. |
| HelloWorld.IP.network.events.actor | Unknown | The actor that performed the action on the event. |
| HelloWorld.IP.network.events.timestamp | String | The timestamp when the event occurred. |
| HelloWorld.IP.network.handle | String | The handle of the network. |
| HelloWorld.IP.network.ip_version | String | The IP address version. |
| HelloWorld.IP.network.links | String | Links associated to the IP address. |
| HelloWorld.IP.network.name | String | The name of the network. |
| HelloWorld.IP.network.notices.description | String | The description of the notice. |
| HelloWorld.IP.network.notices.links | Unknown | Links associated with the notice. |
| HelloWorld.IP.network.notices.title | String | Title of the notice. |
| HelloWorld.IP.network.parent_handle | String | Handle of the parent network. |
| HelloWorld.IP.network.raw | Unknown | Additional raw data for the network. |
| HelloWorld.IP.network.remarks | Unknown | Additional remarks for the network. |
| HelloWorld.IP.network.start_address | String | The first IP address of the CIDR. |
| HelloWorld.IP.network.status | String | Status of the network. |
| HelloWorld.IP.network.type | String | The type of the network. |
| HelloWorld.IP.query | String | IP address that was queried. |
| HelloWorld.IP.raw | Unknown | Additional raw data for the IP address. |
| HelloWorld.IP.score | Number | Reputation score from HelloWorld for this IP \(0 to 100, where higher is worse\). |
| IP.Address | String | IP address. |
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. |
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. |
| IP.ASN | String | The autonomous system name for the IP address. |
| IP.Relationships.EntityA | string | The source of the relationship. |
| IP.Relationships.EntityB | string | The destination of the relationship. |
| IP.Relationships.Relationship | string | The name of the relationship. |
| IP.Relationships.EntityAType | string | The type of the source of the relationship. |
| IP.Relationships.EntityBType | string | The type of the destination of the relationship. |

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
Retrieves alerts from the HelloWorld API. Can optionally push events to XSIAM when running on XSIAM tenants.

#### Base Command

`helloworld-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| severity | The severity by which to filter the alerts. Possible values are: low, medium, high, critical. | Required |
| offset | The alert ID (offset) from which to start retrieving. Default is 0. | Optional |
| limit | Maximum number of alerts to retrieve. Default is 10. | Optional |
| should_push_events | Whether to push events to XSIAM (only works on XSIAM tenants). Possible values are: true, false. Default is false. | Optional |

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
Submits a job to the HelloWorld API and polls for completion. This command demonstrates the polling pattern for long-running operations.

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

---

## Developer Guide

This section documents the key architectural patterns and code features in HelloWorldV2 that demonstrate best practices for building robust Cortex XSOAR/XSIAM integrations.

### Table of Contents

- [Key Features](#key-features)
- [Architecture Overview](#architecture-overview)
- [Pydantic Models for Validation](#pydantic-models-for-validation)
- [ExecutionConfig Pattern](#executionconfig-pattern)
- [Last Run State Management](#last-run-state-management)
- [Severity Mapping](#severity-mapping)
- [Logging Best Practices](#logging-best-practices)
- [Command Implementation Patterns](#command-implementation-patterns)
- [Complete Integration Example](#complete-integration-example)

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Pydantic Validation** | Type-safe parameter and argument validation with user-friendly error messages |
| **ExecutionConfig Pattern** | Centralized entry point management for command, params, args, and state |
| **Property-Based Args** | Type-safe command argument access via dedicated properties |
| **Dual Fetch Support** | Separate implementations for XSOAR incidents and XSIAM events |
| **State Management** | Robust last_run handling with dedicated classes for each fetch type |
| **Severity Mapping** | Enum-based severity conversion with clear documentation |
| **Structured Logging** | Consistent logging format with contextual information |
| **Generic Polling** | Built-in support for long-running operations |

---

## Architecture Overview

HelloWorldV2 follows a layered architecture:

```
┌─────────────────────────────────────────────────────┐
│                 main() Function                     │
│  - Initializes ExecutionConfig                      │
│  - Initializes HelloWorldClient                     │
│  - Routes to command functions                      │
└─────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│             ExecutionConfig Class                   │
│  - Holds command, params, args, last_run            │
│  - Provides type-safe property access               │
│  - Validates inputs via Pydantic models             │
└─────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│               Command Functions                     │
│  - Access args via ExecutionConfig properties       │
│  - Call HelloWorldClient methods                    │
│  - Return CommandResults                            │
└─────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│             HelloWorldClient Class                  │
│  - Inherits from ContentClient                      │
│  - Implements API calls                             │
│  - Returns raw data (no integration logic)          │
└─────────────────────────────────────────────────────┘
```

---

## Pydantic Models for Validation

HelloWorldV2 uses Pydantic for robust input validation with user-friendly error messages.

You can use an AI agent to automatically generate models from the YML file.

### Parameter Model Example

```python
class HelloWorldParams(BaseParams):
    """Integration parameters with validation.
    
    Attributes:
        url: API base URL (trailing slash removed automatically).
        api_key: API authentication key (stored securely).
        max_incidents_fetch: Maximum incidents per fetch for XSOAR (default: 10).
        max_events_fetch: Maximum events per fetch for XSIAM (default: 1000).
        severity: Alert severity filter for fetch-incidents.
    """
    
    url: str
    api_key: Credentials  # Assume `Credentials` Pydantic model already defined in the code
    max_incidents_fetch: int = 10
    max_events_fetch: int = 1000
    severity: HelloWorldSeverity = HelloWorldSeverity.LOW
    
    @validator('url')
    def clean_url(cls, v):
        """Remove trailing slash from URL."""
        return v.rstrip('/')
```

### Argument Model Example

```python
class HelloWorldAlertListArgs(BaseArgs):
    """Arguments for helloworld-alert-list command.
    
    Attributes:
        alert_id: Optional alert ID to retrieve.
        limit: Maximum number of alerts to return (default: 10).
        severity: Optional severity filter.
    """
    
    alert_id: int | None = None
    limit: int = 10
    severity: HelloWorldSeverity | None = None
```

### Usage in Commands

```python
def alert_list_command(client: Client, args: HelloWorldAlertListArgs) -> CommandResults:
    # Args are already validated and type-safe
    if args.alert_id:
        alerts = client.get_alert(args.alert_id)
    else:
        alerts = client.get_alert_list(
            limit=args.limit,
            severity=args.severity.value if args.severity else None
        )
    
    return CommandResults(
        outputs_prefix="HelloWorld.Alert",
        outputs_key_field="id",
        outputs=alerts
    )
```

---

## ExecutionConfig Pattern

The `ExecutionConfig` class centralizes command execution context, prevents redundant system calls (via the `demisto` class), and provides type-safe access to configuration parameters, command arguments, and fetch last run state.

### Core Concept

```python
class ExecutionConfig:
    """Centralized execution configuration for command handling.
    Attributes:
        command: The command being executed.
        params: Raw configuration parameters.
        args: Raw command arguments dictionary.
        last_run: Raw state from previous fetch.
    """
    
    def __init__(self):
        self._command: str = demisto.command()
        self._params: dict = demisto.params()
        self._args: dict = demisto.args()
        self._last_run: dict = demisto.getLastRun()
```

### Property-Based Argument Access

Each command has a dedicated property that returns validated arguments:

```python
    @property
    def alert_list_args(self) -> HelloWorldAlertListArgs:
        """Get validated arguments for helloworld-alert-list command."""
        return HelloWorldAlertListArgs.get(**self.args)

    @property
    def ip_args(self) -> HelloWorldIPArgs:
        """Get validated arguments for ip command."""
        return HelloWorldIPArgs.get(**self.args)

    @property
    def get_events_args(self) -> HelloWorldGetEventsArgs:
        """Get validated arguments for helloworld-get-events command."""
        return HelloWorldGetEventsArgs.get(**self.args)
```

Similarly, for command, configuration parameter, and fetch last run state:

```python
    @property
    def command(self) -> str:
        """Get called command name."""
        return self._command

    @property
    def params(self) -> HelloWorldParams:
        """Get validated params."""
        return HelloWorldParams(**self._params)
    
    @property
    def events_last_run(self) -> HelloWorldEventsLastRun:
        """Get validated fetch last run object."""
        return HelloWorldEventsLastRun(**self._last_run)
```

### Benefits

1. **Type Safety**: Arguments are validated and typed
2. **Centralization**: All execution context in one place
3. **Reusability**: Easy to pass to command functions
4. **Testability**: Simple to mock for unit tests
5. **Discoverability**: IDE autocomplete for all properties

### Usage Example

```python
def main():
    execution = ExecutionConfig()
    params: HelloWorldParams = execution.params
    client = HelloWorldClient(params)
    
    # Route to command
    if command == "helloworld-alert-list":
        args = execution.alert_list_args
        return_results(alert_list_command(client, args))
    elif command == "ip":
        args = execution.ip_args
        return_results(ip_reputation_command(client, args))
```

---

## Last Run State Management

HelloWorldV2 uses dedicated classes for managing fetch state, ensuring type safety and clear structure.

### Events Last Run (Cortex XSIAM)

```python
class HelloWorldEventsLastRun(BaseLastRun):
    """State management for fetch-events (XSIAM).
    
    Attributes:
        audit_start_time: ISO 8601 timestamp of the last fetched event.
        last_audit_ids: List of event IDs from the last fetch time to prevent duplicates.
    """
    audit_start_time: str = "1 minute"  # by default, start fetching events from the last minute
    last_audit_ids: list = []
```

### Incidents Last Run (Cortex XSOAR)

```python
class HelloWorldIncidentsLastRun(BaseLastRun):
    """State management for fetch-incidents (XSOAR).
    
    Attributes:
        alert_start_id: The ID of the last fetched alert.
    """
    alert_start_id: int = 0
```

### Usage in Fetch Commands

```python
def fetch_incidents(client: Client, last_run: HelloWorldIncidentsLastRun, max_fetch: int, severity: HelloWorldSeverity) -> tuple[dict, list[dict]]:
    """Fetch incidents for XSOAR."""
    # Fetch new alerts
    alerts = client.get_alert_list_for_fetch(
        limit=max_fetch,
        last_id=last_run.alert_start_id,
        severity=severity.value,
    )
    
    # Process alerts into incidents
    incidents = format_as_incidents(alerts)
    # Create incidents
    demisto.createIncidents(incidents)
    # Update last run
    last_run.alert_start_id = max(alerts, key=lambda alert: alert["id"])["id"]
    last_run.set()
    return
```

---

## Logging Best Practices

HelloWorldV2 uses consistent, structured logging throughout the codebase.

### Logging Format

All log message are Python f-strings that follow the pattern:

```python
demisto.debug(f"[PREFIX] Message {variable=}.")
```

### Examples

```python
# In fetch_incidents
demisto.debug(f"[Main] Starting fetch-incidents with {max_results=}, {severity=}")
demisto.debug(f"[Client] Fetched {len(alerts)} alerts from API")
demisto.debug(f"[Deduplication] Found {num_duplicates} duplicate alerts to skip")
demisto.debug(f"[Formatting] Returning {len(incidents)} incidents")
```

### Benefits

1. **Searchability**: Easy to grep logs with a specific prefix
2. **Context**: Variable names and values clearly shown
3. **Debugging**: Trace execution flow through logs
4. **Consistency**: Same format across all log statements

---

## Command Implementation Patterns

### Standard Command Pattern

```python
def command_name_command(client: Client, args: IntegrationNameCommandArgs) -> CommandResults:
    """Command description.
    
    Args:
        client: ServiceName API client.
        args: Validated command arguments.
        
    Returns:
        CommandResults with outputs and readable output.
    """
    # 2. Call client method
    data = client.api_method(
        param1=args.param1,
        param2=args.param2
    )
    
    # 3. Return results
    return CommandResults(
        outputs_prefix="IntegrationName.Entity",  # prefix of context outputs
        outputs_key_field="id",  # for deduplicating context outputs under the same prefix
        outputs=data,  # context outputs
        readable_output=tableToMarkdown("Title", data)  # human-readable output appearing in playground / war room
    )
```

### Fetch Pattern (Incidents)

```python
def fetch_incidents(
    client: Client,
    config: ExecutionConfig
) -> tuple[dict, list[dict]]:
    """Fetch incidents for XSOAR.
    
    Args:
        client: HelloWorld API client.
        config: Execution configuration.
        
    Returns:
        Tuple of (next_run, incidents).
    """
    # 1. Restore state
    last_run = HelloWorldIncidentsLastRun.get(config.last_run)
    
    # 2. Fetch data
    alerts = client.get_alert_list_for_fetch(
        limit=config.params.max_incidents_fetch,
        last_id=last_run.alert_start_id,
        severity=config.params.severity.value
    )
    
    # 3. Process into incidents
    incidents = []
    for alert in alerts:
        incidents.append({
            "name": alert["name"],
            "occurred": alert["date"],
            "severity": HelloWorldSeverity.convert_to_incident_severity(alert["severity"]),
            "rawJSON": json.dumps(alert)
        })
        last_run.alert_start_id = max(last_run.alert_start_id, alert["id"])
    
    # 4. Return state and incidents
    return last_run.set(), incidents
```

### Fetch Pattern (Events)

```python
def fetch_events(
    client: Client,
    config: ExecutionConfig
) -> tuple[dict, list[dict]]:
    """Fetch events for XSIAM.
    
    Args:
        client: HelloWorld API client.
        config: Execution configuration.
        
    Returns:
        Tuple of (next_run, events).
    """
    # 1. Restore state
    last_run = HelloWorldEventsLastRun.get(config.last_run)
    
    # 2. Determine start time
    if last_run.audit_start_time:
        start_time = dateparser.parse(last_run.audit_start_time)
    else:
        start_time = dateparser.parse("1 hour ago")
    
    # 3. Fetch events
    events = client.get_audit_list_for_fetch(
        limit=config.params.max_events_fetch,
        start_time=start_time,
        last_ids=last_run.last_audit_ids
    )
    
    # 4. Deduplicate
    events, num_dups = dedup_by_ids(events, last_run.last_audit_ids)
    
    # 5. Update state
    if events:
        last_event_time = events[-1]["timestamp"]
        last_run.audit_start_time = last_event_time
        last_run.last_audit_ids = [
            e["id"] for e in events if e["timestamp"] == last_event_time
        ]
    
    # 6. Return state and events
    return last_run.set(), events
```

---

## Complete Integration Example

Here's how all the patterns come together in the `main()` function:

```python
def main() -> None:
    """Main function - parses params and routes commands."""
    
    # 1. Get raw inputs
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    
    try:
        # 2. Validate parameters
        validated_params = HelloWorldParams.get(params)
        
        # 3. Validate API key
        if validated_params.api_key:
            validate_api_key(validated_params.api_key.get_secret_value())
        
        # 4. Create client
        client = Client(
            base_url=validated_params.url,
            verify=validated_params.verify,
            proxy=validated_params.proxy,
            headers={"Authorization": f"Token {validated_params.api_key.get_secret_value()}"}
        )
        
        # 5. Create execution config
        config = ExecutionConfig(
            command=command,
            params=validated_params,
            args=args,
            last_run=demisto.getLastRun()
        )
        
        # 6. Route to command
        demisto.debug(f"[HelloWorld] Executing {command=}")
        
        if command == "test-module":
            return_results(test_module(client, config))
            
        elif command == "fetch-incidents":
            next_run, incidents = fetch_incidents(client, config)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
            
        elif command == "fetch-events":
            next_run, events = fetch_events(client, config)
            demisto.setLastRun(next_run)
            send_events_to_xsiam(events, vendor="HelloWorld", product="API")
            
        elif command == "helloworld-say-hello":
            return_results(say_hello_command(client, config))
            
        elif command == "helloworld-alert-list":
            return_results(alert_list_command(client, config))
            
        elif command == "helloworld-alert-note-create":
            return_results(alert_note_create_command(client, config))
            
        elif command == "ip":
            return_results(ip_reputation_command(client, config))
            
        elif command == "helloworld-get-events":
            return_results(get_events_command(client, config))
            
        elif command == "helloworld-job-submit":
            return_results(job_submit_command(client, config))
            
        elif command == "helloworld-job-poll":
            return_results(job_poll_command(client, config))
            
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
            
    except Exception as e:
        demisto.error(f"[HelloWorld] Failed to execute {command}: {str(e)}")
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
```

### Key Takeaways

1. **Validation First**: Validate all inputs before processing and inherit from `ContentBaseModel` to ensure clearly-presented validation errors.
2. **Centralized Config**: Use `ExecutionConfig` to centralize command execution context and to prevent unnecessary `demisto` system calls.
3. **Type Safety**: Leverage Pydantic 1.10 for type-safe configuration parameters, command arguments, and fetch last run state.
4. **Clear Routing**: Simple `if`/`elif` chain, `match-case` statement, or a mapping `dict` for clear and legible command routing in the `main` function.
5. **Consistent Logging**: Log at key points with consistent Python f-string format. Use log prefixes to aid with log querying.
6. **Error Handling**: Catch all exceptions and return user-friendly errors with diagnostic messages if possible.
7. **Separation of Concerns**: Client handles API calls and returns raw responses, commands functions handle integration-specific logic.

---

## Additional Resources

- [Python Integration Development Guide and Code Standards](https://xsoar.pan.dev/docs/integrations/code-conventions)
- [Reputation Commands and DBotScore Documentation](https://xsoar.pan.dev/docs/integrations/dbot)
- [Pydantic 1.10 Documentation](https://docs.pydantic.dev/1.10/)
- [Python Type Hints](https://docs.python.org/3/library/typing.html)

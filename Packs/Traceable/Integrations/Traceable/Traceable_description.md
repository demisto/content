# Traceable AI API Security Platform Integration
## Overview
Traceable Platform monitors Application APIs and detects Threat Activities. These Threat Events consist of the details about the Threat Activity, the Actor performing the threat activity and the Request/Response Payloads.

With this integration, an Incident can be raised in Cortex Xsoar when an Event is detected by Traceable Platform. This enables the Security Teams to orchestrate actions through Cortex Xsoar with meaningful information about the detected Threat Activities.

## Setup
To use the integration the following mandatory parameters need to be set:
|Parameter Name|Default Value|Description|
|------|------|------|
|Traceable Platform URL|https://api.traceable.ai|URL of Traceable Platform API Endpoint.|
|API Token|-|API Token. Used for Authenticating against the Traceable Platform|

The API Token can be generated as described in the [Traceable Documentation](https://docs.traceable.ai/docs/public-apis#step-1-%E2%80%93-copy-the-platform-api-token)

## Customize Event/Activity Collection
The following parameters can be used to customize what Events should be exported from the Traceable Platform and brought over into Xsoar as Security Incidents.

|Parameter name|Type|Required (Yes/No)|Default Value|Description|
|------|------|------|------|------|
|First fetch timestamp (<number> <time unit>, e.g., 12 hours, 7 days)|Short Text|No|7 days|Duration in the past to query the Events when querying for the first time.|
|Query Return Limit|Short Text|No|100|Number of records to return from Platform per query|
|Comma Separated Environment List To Process|Long Text|No|-|Comma separated list of environments to query.|
|Security Score Category|Multi Select|No|CRITICAL, HIGH, MEDIUM|Security Score Category to query|
|Threat Category|Multi Select|No|Malicious Activities, API Abuse, Malicious Sources|Threat Categories to query|
|IP Reputation Level|Multi Select|No|CRITICAL, HIGH, MEDIUM|IP Reputations to query|
|IP Abuse Velocity|Multi Select|No|CRITICAL, HIGH, MEDIUM|IP Abuse Velocity to query|
|IP Location Type|Multi Select|No|-|IP Location Type to query|

## Incident Types
The integration generates _Exploit_ type of Inidents.

## Official Traceable Documentation
[https://docs.traceable.ai/](https://docs.traceable.ai/)

## Issues?
Reach out to [support@traceable.ai](mailto:support@traceable.ai)
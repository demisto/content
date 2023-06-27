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
|Trust any certificate (not secure)|false|Trust any SSL certificate while connecting to Platform API Endpoint|
|Use system proxy settings|false|Use the system proxy setup using the environment variables `http_proxy`/`https_proxy`|

The API Token can be generated as described in the [Traceable Documentation](https://docs.traceable.ai/docs/public-apis#step-1-%E2%80%93-copy-the-platform-api-token)

## Customize Event/Activity Collection
The following parameters can be used to customize what Events should be exported from the Traceable Platform and brought over into Xsoar as Security Incidents.

|Parameter name|Type|Required (Yes/No)|Default Value|Description|
|------|------|------|------|------|
|First fetch timestamp|Short Text|No|1 days|Duration in the past to query the Events when querying for the first time.|
|max_fetch|Short Text|No|100|Number of records to return from Platform per query|
|span_fetch_threadpool|Short Text|No|10|Number of threads to use for querying `spans` in parallel|
|Comma Separated Environment List To Process|Long Text|No|-|Comma separated list of environments to query.|
|Security Score Category|Multi Select|No|CRITICAL, HIGH, MEDIUM|Security Score Category to query|
|Threat Category|Multi Select|No|Malicious Activities, API Abuse, Malicious Sources|Threat Categories to query|
|IP Reputation Level|Multi Select|No|CRITICAL, HIGH, MEDIUM|IP Reputations to query|
|IP Abuse Velocity|Multi Select|No|CRITICAL, HIGH, MEDIUM|IP Abuse Velocity to query|

## Incident Types
The integration generates _Exploit_ type of Inidents.

## Official Traceable Documentation
https://docs.traceable.ai/

## Issues?
Reach out to support@traceable.ai
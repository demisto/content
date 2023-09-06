# Traceable AI API Security Platform Integration
## Overview
Traceable platform monitors application APIs and detects _Threat Events_. These _Threat Events_ consist of the details about the _Threat Activity_, the _Actor_ performing the threat activity and the request/response payloads.

With this integration, an _Incident_ can be raised in Cortex Xsoar when an event is detected by Traceable platform. This enables the security teams to orchestrate actions through Cortex Xsoar with meaningful information about the detected _Threat Activities_.

## Setup
To use the integration the following mandatory parameters need to be set:

|Parameter Name|Default Value|Description|
|------|------|------|
|Traceable Platform API Endpoint URL|https://api.traceable.ai| Base URL of the Traceable platform API endpoint. |
|API Token|-| API token used for authenticating against the Traceable platform. |
|Trust any certificate (not secure)|false| Trust any SSL certificate while connecting to the Traceable platform API endpoint. |
|Use system proxy settings|false| Use the system proxy using the environment variables `http_proxy`/`https_proxy`. |

The API token can be generated as described in the [Traceable Documentation](https://docs.traceable.ai/docs/public-apis#step-1-%E2%80%93-copy-the-platform-api-token)

## Customize Event/Activity Collection
The following parameters can be used to select the events that should be imported from the Traceable platform into Cortex Xsoar as security incidents.

|Parameter name|Type|Required (Yes/No)|Default Value|Description|
|------|------|------|------|------|
|First fetch timestamp|Short text|No|1 days| Duration in the past to query the events, when querying for the first time. |
|max_fetch|Short text|No|100| Number of records to return from Traceable platform per query. |
|span_fetch_threadpool|Short text|No|10| Number of threads to use for querying `spans` in parallel. |
|Comma Separated Environment List To Process|Long text|No|-| Comma separated list of environments to query. |
|Security Score Category|Multi select|No|CRITICAL, HIGH, MEDIUM| `Security Score Category` of the events to be queried. |
|Threat Category|Multi select|No|Malicious Activities, API Abuse, Malicious Sources| `Threat Category` of the events to be queried. |
|IP Reputation Level|Multi select|No|CRITICAL, HIGH, MEDIUM| `IP Reputation Level` of the events to be queried. |
|IP Abuse Velocity|Multi select|No|CRITICAL, HIGH, MEDIUM| `IP Abuse Velocity` of the events to queried. |
|IP Location Type|Multi select|No|-| `IP Location` type of the events to be queried. |
|Traceable Platform Endpoint URL|Long text|No|https://app.traceable.ai| Base URL of the Traceable platform UI endpoint. |
|Ignore Status Codes|Long text|No|400-499| Ignore incidents for attacks failing with these status codes. |
|Incident optional field list|Multi select|No|actorDevice,actorEntityId,actorId,actorScoreCategory,actorSession,anomalousAttribute,apiName,apiUri,category,ipAbuseVelocity,ipReputationLevel,securityEventType,securityScore,serviceId,serviceName,actorScore,threatCategory,type| Optional fields to pull from the Traceable event. |
|Additional API Attributes|Multi select|No|isExternal,isAuthenticated,riskScore,riskScoreCategory,isLearnt| Additional API attributes to query for the affected API in the incident. |

## Incident Types
The integration generates _Exploit_ type of incidents.

## Official Traceable Documentation
https://docs.traceable.ai/

## Issues?
Reach out to support@traceable.ai
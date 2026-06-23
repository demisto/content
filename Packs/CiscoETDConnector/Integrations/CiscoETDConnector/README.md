# Cisco ETD Connector

The Cisco ETD Connector ingests Cisco Email Threat Defense (ETD) Message, Audit, and Connection logs into Cortex XSIAM for security analytics and monitoring.

## Supported Versions

This integration uses the Cisco Email Threat Defense REST API.

## Configure CiscoETDConnector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| ETD API Base URL |  | True |
| ETD API Key |  | True |
| Client ID |  | True |
| Client Secret |  | True |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | Maximum supported value is 30 days | False |
| Max fetch |  | False |
| Fetch Events |  | False |

## Commands

### cisco-etd-get-events

Fetches ETD logs and sends them to Cortex XSIAM.

> Use this command for development and debugging only, as it may produce duplicate events, exceed API rate limits, or disrupt the fetch mechanism.

#### Base Command

`cisco-etd-get-events`

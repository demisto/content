# Cisco ETD Connector

The Cisco ETD Connector ingests Cisco Email Threat Defense (ETD) Message, Audit, and Connection logs into Cortex XSIAM for security analytics, monitoring, and threat investigation.

## Supported Versions

This integration uses the Cisco Email Threat Defense REST API.

## Configure CiscoETDConnector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| ETD API Base URL | Base URL of the Cisco Email Threat Defense API (for example, `https://api.ironport.com`). | Yes |
| ETD API Key | API key used to authenticate requests to Cisco ETD. | Yes |
| Client ID | Cisco ETD OAuth Client ID. | Yes |
| Client Secret | Cisco ETD OAuth Client Secret. | Yes |
| Event Types | Select one or more Cisco ETD log types to ingest (`message`, `audit`, or `connection`). | Yes |
| Max fetch | Maximum number of events to ingest during a single fetch cycle. | No |
| Fetch Events | Enables continuous event collection into Cortex XSIAM. | No |


## Commands

### cisco-etd-get-events

Fetches Cisco ETD logs for the specified time range.

> **Warning:** Use this command for development and debugging only, as it may produce duplicate events, exceed API rate limits, or disrupt the automatic fetch mechanism.

#### Base Command

`cisco-etd-get-events`

#### Input

| **Argument Name**  | **Description**                                                                  | **Required** |
| ------------------ | -------------------------------------------------------------------------------- | ------------ |
| start_time         | Start of the time range in `YYYY-MM-DDTHH` format.                               | Yes          |
| end_time           | End of the time range in `YYYY-MM-DDTHH` format.                                 | Yes          |
| log_type           | One or more ETD log types to retrieve (`message`, `audit`, or `connection`).     | No           |
| limit              | Maximum number of events to return. Default is `100`.                            | No           |
| should_push_events | If set to `true`, pushes the fetched events to Cortex XSIAM. Default is `false`. | No           |

#### Context Output

There is no context output for this command.

### fetch-events

Fetches new Cisco ETD events and ingests them into Cortex XSIAM. This command is used internally by the Event Collector during scheduled fetches and is not intended for manual execution.

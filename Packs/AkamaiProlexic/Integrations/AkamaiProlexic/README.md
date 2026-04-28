Collects DDoS detection critical events and general events from Akamai Prolexic Analytics for Cortex XSIAM.
This integration was integrated and tested with version xx of AkamaiProlexic.

## Configure Akamai Prolexic Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Your Akamai API host \(the value of the "host" field in your .edgerc file\). Example: https://akab-h05tnam3wl42son7nktnlnnx-kbob3i3v.luna.akamaiapis.net | True |
| Contract ID | The policy domain name of the data center or proxy that the events belong to. | True |
| Client Token |  | True |
| Client Secret |  | True |
| Access Token |  | True |
| Account Switch Key | For customers managing more than one account; runs the operation against another account. The Identity and Access Management API provides a list of available account switch keys. | False |
| Event types to fetch |  | True |
| First fetch time | How far back to fetch events on the first run \(e.g., "1 day", "12 hours"\). | False |
| Maximum events per fetch | Per source. Maximum allowed: 10000. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### akamai-prolexic-get-events

***
Manually retrieve events from Akamai Prolexic for development and debugging. May produce duplicate events when used alongside automatic fetching.

#### Base Command

`akamai-prolexic-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of events to retrieve per source. Default is 50. | Optional | 
| event_type | Comma-separated list of event types to retrieve. If empty, uses the integration configuration. Possible values are: Critical Events, Events. | Optional | 
| should_push_events | If true, push retrieved events to Cortex XSIAM. Otherwise only display them. Possible values are: true, false. Default is false. | Required | 

#### Context Output

There is no context output for this command.

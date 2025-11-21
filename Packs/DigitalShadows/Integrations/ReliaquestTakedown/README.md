This is Reliaquest DRP Takedown integration. It enables xsoar user to create and manage takedowns.
This integration was integrated and tested with version 6.9.0 of ReliaquestTakedown.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure ReliaquestTakedown in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| DS SearchLight API URL | Enter the Digital Shadows SearchLight API URL. | True |
| Account ID | Account ID associated with this account. | True |
| API Key | Enter the API Key for this account. | True |
| API Secret | Enter the API Secret for this account. | True |
| Trust any certificate (not secure) | Verify certificate. | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 2 months, 1 years or datetime in "%Y-%m-%d %H:%M:%S" format) | First fetch | False |
| Fetch Limit | The maximum number of takedown to fetch. | True |
| Takedown | This controls how often the integration will perform a fetch takwdown command. | False |
| Incident type |  | False |
| Fetch incidents |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### rq-takedown-create

***
Create takedown command takes brand id, type, target and portal shortcode (optional) and returns the created takedown in response.

#### Base Command

`rq-takedown-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| brand_id | Brand Id. | Required |
| type | Takedown Type. | Required |
| target | Target URL. | Required |
| portal_id | Portal shortcode. | Optional |

#### Context Output

There is no context output for this command.

### rq-takedown-list-brand

***
Returns list of allowed brand details for takedown.

#### Base Command

`rq-takedown-list-brand`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### rq-takedown-create-comment

***
Create comment for a takedown.

#### Base Command

`rq-takedown-create-comment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | Comment for takedown. Default is Investigate the tekedown. | Required |
| takedown_id | Takedown id. Default is UUID. | Required |

#### Context Output

There is no context output for this command.

### rq-takedown-upload-attachment

***
Uploads attachment for takedown.

#### Base Command

`rq-takedown-upload-attachment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | No description provided. | Required |
| takedown_id | No description provided. | Required |

#### Context Output

There is no context output for this command.

### rq-takedown-download-attachment

***
Downloads attachment for takedown.

#### Base Command

`rq-takedown-download-attachment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attachment_id | No description provided. | Required |

#### Context Output

There is no context output for this command.

## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and ReliaquestTakedown corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:

1. Enable *Fetching incidents* in your instance configuration.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and ReliaquestTakedown.

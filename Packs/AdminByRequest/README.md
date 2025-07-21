# Admin By Request

AdminByRequest is a Privileged Access Management (PAM) solution that enables secure, temporary elevation to local admin rights.

<~XSIAM>

## What does this pack contain?

- API Integration.
- Modeling Rules for the following events:
  - Audit Log
  - Request
  - Events

## Configuration on Server Side

### Admin By Request configuration

1. Log into your Admin By Request portal.
2. Navigate to **Settings** -> **Tenant Settings** -> **API Keys** -> **API KEYS**.
3. Click **Add New**
4. Copy and store the generated key,

For more inofrmation use the following guide [here](https://docs.adminbyrequest.com/integrations/public-api.htm).

### Configuration on XSIAM

1. Navigate to **Settings** > **Configuration** > **Data Collection** > **Automation & Feed Integrations**.
2. Search for "Admin By Request" and click **Add Instance**
3. When configuring the API Integration, set the following values:

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| API Key | The API Key allows you to programmatically integrate with the Armis ecosystem. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch events |  | False |
| Event types to fetch | Returns the types of events. Available for Auditlogs, Events, and Requests. | True |
| Maximum number of Auditlog per fetch | Maximum number of audit log entries to retrieve per fetch cycle. Applies only if the "Auditlog" event type is enabled for fetching. | False |
| Maximum number of Events per fetch | Maximum number of events entries to retrieve per fetch cycle. Applies only if the "Events" event type is enabled for fetching. | False |
| Maximum number of Requests per fetch | Maximum number of requests entries to retrieve per fetch cycle. Applies only if the "Requests" event type is enabled for fetching. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### adminbyrequest-get-events

***
Retrieves a list of entries logs events from the AdminByRequest instance.

#### Base Command

`adminbyrequest-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to 'true' in order to create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required |
| event_type | The type of event to fetch. Default is Auditlog. | Optional |
| limit | Returns no more than the specified number of events (for entries of type 'Requests' the default value is 5000). | Optional |
| first_fetch | The UTC date or relative timestamp from when to start fetching incidents. Notice that for event type 'Requests' there is the option to set a start date. Supported formats: N days, N weeks, N months, N years, yyyy-mm-dd. | Optional |

#### Context Output

There is no context output for this command.

### API Limitations

- DO NOT consistently use a high "limit" number or flood the API; otherwise, the account will be automatically throttled.
- Daily quota: 100,000 API calls (approximately 60 calls per minute maximum).

</~XSIAM>

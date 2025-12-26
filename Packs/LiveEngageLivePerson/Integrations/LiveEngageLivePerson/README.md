## LiveEngage LivePerson Integration

This integration collects audit events from the LivePerson LiveEngage platform, which is part of LivePerson's Conversational Cloud. LivePerson's LiveEngage is an AI-powered conversational commerce platform that allows businesses to communicate with customers across multiple digital channels.

This integration uses the LivePerson **Audit Trail API** to fetch audit events related to user changes, skill modifications, agent status, and other administrative activities.

### Prerequisites

Before configuring the integration, you must have the following LivePerson credentials:

1. **Account ID (Site ID):** Your unique LivePerson account identifier.
2. **Client ID and Client Secret:** These are API keys for OAuth 2.0 authentication. You can typically generate these in your LivePerson admin console under **Manage > APIs**.
3. **Authorization Server URL:** This is the base URL for the LivePerson authentication service, which is specific to your account's region. The integration uses this URL to dynamically discover the correct Event API domain for your account.

Common Authorization Server URLs by region:

* **APAC:** `sy.sentinel.liveperson.net`
* **EMEA:** `lo.sentinel.liveperson.net`
* **US:** `va.sentinel.liveperson.net`

Contact LivePerson support if you are unsure of your account's specific URLs.

### Configure the Integration on XSIAM

Follow these steps to configure the integration:

1. Navigate to **Settings > Integrations > API Keys**.
2. Find and select **LiveEngage LivePerson**.
3. Click **Add instance** to create and configure a new integration instance.

#### Parameters

Fill in the parameters as follows:

| Parameter | Description | Required |
| --- | --- | --- |
| **Authorization Server URL** | The base URL of the authorization server (e.g., `sy.sentinel.liveperson.net`). Do not include `https://`. The integration uses this to find the correct Event API domain. | True |
| **Account ID** | Your LivePerson site ID (account\_id). | True |
| **Client ID and Client Secret** | The Client ID (identifier) and Client Secret (password) for OAuth 2.0 authentication. | True |
| **Fetch events** | Select this to enable the collection of audit events. | False |
| **Maximum number of events per fetch** | The maximum number of audit trail events to pull in a single fetch. The API's maximum is 500 per call; the integration will loop to retrieve this total. | False |
| **Trust any certificate (not secure)** | Select this to bypass SSL certificate validation. Not recommended for production environments. | False |
| **Use system proxy settings** | Select this to route integration traffic through the XSIAM proxy. | False |

4. Click **Test** to validate the settings.
5. Click **Save & Exit**.

### Commands

You can execute the following command from the XSIAM CLI, as part of an automation, or in a playbook.

#### `liveperson-get-events`

Manually fetches LivePerson audit events for debugging and investigation. This command is used for developing/debugging and is to be used with caution as it can create events, leading to event duplication and exceeding API request limits.

##### Input (Arguments)

| Argument | Description | Default |
| --- | --- | --- |
| `limit` | The maximum number of events to return. | `50` |
| `start_time` | The start time to fetch events from (e.g., '3 days ago', '2023-10-25T10:00:00Z'). | `3 days` |
| `should_push_events` | If `true`, pushes the fetched events to XSIAM. Use `false` for debugging to prevent event duplication. | `false` |

##### Context Output (Outputs)

This command returns a `LivePerson.Event` object for each event fetched.

| Path | Description | Type |
| --- | --- | --- |
| `LivePerson.Event.changeDate` | Timestamp of the event. | String |
| `LivePerson.Event.accountId` | Account ID associated with the event. | String |
| `LivePerson.Event.objectType` | The type of object that was changed (e.g., 'USER', 'SKILL'). | String |
| `LivePerson.Event.element` | The name or identifier of the element that was changed. | String |
| `LivePerson.Event.changeType` | Type of change (e.g., 'UPDATE', 'CREATE', 'DELETE'). | String |
| `LivePerson.Event.userId` | ID of the user who performed the action. | String |
| `LivePerson.Event.changedBy` | Full name or identifier of the user who performed the action. | String |

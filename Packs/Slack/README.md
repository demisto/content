## Overview

Send messages and notifications to your Slack team and integrate with Slack's services to execute create, read, update, and delete operations for employee lifecycle processes.

## What does this pack do?

<~XSOAR>

- Mirrors the investigation between Slack and the Cortex XSOAR War Room.
</~XSOAR>
- Sends a message to a user, group, or channel.
- Archives a Slack channel.
- Sends a file to a user, channel, or group.
- Sets the topic for a channel.
- Creates a channel in Slack.
- Invites users to join a channel.
- Removes users from the specified channel.
- Renames a channel in Slack.
- Gets details about a specified user.
- Returns the integration context as a file (for debugging purposes only).

- As part of this pack, you will get a playbook that investigates failed login events.
<~XSIAM>
- Data normalization capabilities:
  - Rules for parsing and modeling Slack audit logs that are ingested via the event collector into Cortex XSIAM.
  - The ingested Slack logs can be queried in XQL Search using the *`slack_slack_raw`* dataset.

## Supported log categories

| Category | Category Display Name |
|:---------|:----------------------|
| [Audit Logs](https://api.slack.com/admins/audit-logs) | Slack Audit Logs |

### Supported timestamp formats

- Unix epoch timestamp.

***

## Data Collection

### Slack Side

**Note**: The Audit Logs API is only available to Slack workspaces on an **Enterprise Grid** plan. This integration will **not** work for workspaces on a Free, Standard, or Business+ plan.

#### Obtain a User Token

The following steps must be done by the **Owner** of the Enterprise Grid organization:

1. **Create a Slack app:**
    Navigate to the [Slack App creation page](https://api.slack.com/apps?new_app=1). Click **Create App** to proceed to the settings page.

2. **Configure Permissions:**
    From the left navigation bar, select **OAuth & Permissions**.
   Scroll down to the **Scopes** section and add the `auditlogs:read` User Token Scope to your app.

3. **Activate Distribution:**
    - From the left navigation bar, select **Manage Distribution**.
    - Ensure all sections under **Share Your App with Other Workspaces** are checked (green), then click **Activate Public Distribution**.
    - Under **Share Your App with Your Workspace**, copy the **Sharable URL**. Paste this into a browser to initiate the OAuth handshake.
    - **Critical:** Check the dropdown in the upper right of the installation page. **You must install the app on the Enterprise Grid organization**, not an individual workspace within the organization.
4. **Retrieve Token:**
    Once the OAuth flow is complete, you will receive an OAuth token (starting with `xoxp-`) that authorizes access to the Audit Logs API.

### Cortex XSIAM Side - Slack Event Collector

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

#### Configuration Parameters

 | **Parameter** | **Description** | **Required** |
 | --- | --- | --- |
 | **Server URL** | Slack API server URL. | True |
 | **User Token** | OAuth token starting with `xoxp-`. | True |
 | **Max Events per Fetch** | The maximum number of audit logs to retrieve per fetch cycle. | False |
 | **First Fetch Time Interval** | Date from which to start fetching data (Data is not available prior to March 2018). | False |
 | **Trust Any Certificate** | Skip SSL certificate verification (insecure). | False |
 | **Use System Proxy** | Use the configured system proxy settings. | False |

</~XSIAM>

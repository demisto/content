This integration fetches alerts from iManage Threat Manager, an AI-driven security solution that uses machine learning to detect unusual user behavior, prevent data loss, and ensure compliance.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex.

## Configure iManage Threat Manager in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Should be in format https://&lt;your-instance&gt;.tm-cloudimanage.com | True |
| User Name | Username for user sign-in authentication. Required for Get Addressable Alerts and Get Detect And Protect Alerts. | Conditional |
| Password | Password for user sign-in authentication. Required for Get Addressable Alerts and Get Detect And Protect Alerts. | Conditional |
| Token | Application token for API token authentication. Required for Behavior Analytics alerts. | Conditional |
| Secret | Application secret for API token authentication. Required for Behavior Analytics alerts. | Conditional |
| Fetch events | Whether to fetch events. | False |
| Events types to fetch | Select which event types to fetch: Behavior Analytics alerts, Get Addressable Alerts, Get Detect And Protect Alerts. Default is Behavior Analytics alerts. | False |
| Maximum number of events per type | Default and maximum is 900 events to fetch for each type. | False |
| Trust any certificate (not secure) | Use SSL secure connection or not. | False |
| Use system proxy settings | Use proxy settings for connection or not. | False |

## iManage Threat Manager Authentication

The integration supports two authentication methods:

### Application Token Authentication (for Behavior Analytics alerts)


To generate an application token and secret from the Threat Manager admin console:

1. In iManage Threat Manager, browse to **Configuration** > **System** > **Application Tokens for Utility Access**.
2. Select **New Token**. The New Token dialog opens.
3. In the **Token Name** field, enter a unique name for this application token.
4. Select the **Export Alert List** permission.
5. In **Token Expiry Time in minutes**, enter the number of minutes before this token becomes invalid.
   - By default, application tokens expire after 1400 minutes (1 day). The maximum value is 525600 (365 days).
6. Select **Generate Token**.
7. The New Token dialog shows the generated application token and secret.

**Note:** The Integrations Manager role is required to generate an application token. If a user with the Integration Manager role is made inactive or the role is removed, all existing application tokens created by that user become inactive.

### User Sign-in Authentication (for Get Addressable Alerts and Get Detect And Protect Alerts)

Use your iManage Threat Manager username and password. This provides a similar level of access to what the user would have in the admin console.

**Important:** These alert types cannot be accessed through application token authentication and require user credentials.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### imanage-threat-manager-get-events

***
Gets events from iManage Threat Manager. Manual command to fetch and display events. This command is used for developing/debugging and is to be used with caution, as it can create events, leading to events duplication and exceeding the API request limitation.

#### Base Command

`imanage-threat-manager-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command creates events; otherwise, it only displays them. Possible values are true and false. The default value is false. | Required |
| event_type | Type of events to fetch. Possible values are: Behavior Analytics alerts, Get Addressable Alerts, Get Detect And Protect Alerts. Default is Behavior Analytics alerts. | Optional |
| limit | Maximum number of results to return. Default is 50. | Optional |
| from_date | Start date from which to get events. Supports ISO format or natural language (e.g., "7 days ago", "1 hour ago"). Default is 1 hour ago. | Optional |
| to_date | End date until which to get events. Supports ISO format or natural language (e.g., "now", "30 minutes ago"). Default is now. | Optional |

#### Context Output

There is no context output for this command.


## Rate Limits
#TODO improve
To avoid throttling:
- **Recommended:** Once per day per enabled user
- Avoid frequent polling
- Monitor usage to stay within limits

## Additional Information

- **Timezone:** All timestamps are in UTC

## iManage Threat Manager

Fetch and manage security alerts from iManage Threat Manager.

## Credentials Required by Event Type

iManage Threat Manager supports different authentication methods depending on the event type you want to fetch:

- **Behavior Analytics alerts**: Requires **Token** and **Secret** credentials
- **Addressable Alerts**: Requires **User Name** and **Password** credentials
- **Detect And Protect Alerts**: Requires **User Name** and **Password** credentials


## Authentication and Authorization

The Integrations Manager role is required to generate an application token.

If a user (with the Integration Manager role) is made inactive through iManage Work, or the Integration Manager role is removed from a user, all existing application tokens created by that user become inactive.

### Authentication using an API token and secret

To generate an application token and secret from the Threat Manager admin console:

1. In iManage Threat Manager, browse to **Configuration** > **System** > **Application Tokens for Utility Access**.
2. Select **New Token**. The New Token dialog opens.
3. In the **Token Name** field, enter a unique name for this application token.
4. Select the **Export Alert List** permission.
5. In **Token Expiry Time in minutes**, enter the number of minutes before this token becomes invalid.
   - By default, application tokens expire after 1400 minutes (1 day). The maximum value is 525600 (365 days).
6. Select **Generate Token**.
7. The New Token dialog shows the generated application token and secret.

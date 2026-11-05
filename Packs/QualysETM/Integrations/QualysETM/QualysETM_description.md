## Qualys Enterprise TruRisk Management (ETM)

### Prerequisites

1. Verify that your Qualys subscription includes the **Enterprise TruRisk Management** module and that API access is enabled. This is a paid feature.
2. Identify the Qualys API Gateway URL of the platform on which your account is hosted, using the [Qualys Platform Identification page](https://www.qualys.com/platform-identification/). Use this URL as the **Server URL** parameter.
3. Obtain the username and password of the Qualys account to use.

### Required Permissions

To call the ETM API, the Qualys user account must have the **API Access** permission in its assigned role. To grant this permission:

1. Log in to the **Qualys Cloud Platform** with an account that has administrator privileges.
2. Select the **Administration** module from the application picker.
3. Click the **Role Management** tab.
4. Locate the role assigned to the user, click the **Quick Actions** menu next to it, and select **Edit**. Alternatively, click **New** > **Role** to create a new role.
5. Click **Permissions** in the left navigation pane.
6. Select the **API Access** checkbox.
7. Click **Save** to apply the changes.
8. If you created a new role, assign it to the user from the **User Management** tab.

For more information, see the [Qualys Administration documentation](https://docs.qualys.com/en/admin/latest/).

## Qualys VMDR Help

### Server URL

The server URL can be found using the [Qualys Platform Identification Guide](https://www.qualys.com/platform-identification/).

### Username and Password

Qualys VMDR uses basic authentication. Qualys user login credentials are needed in order to use this integration.

- If a subscription has multiple users, all users with any user role (except Contact) can be used in setting up an instance of this integration. Each user’s permissions correspond to their assigned user role.

- Qualys user accounts that have been enabled with VIP two-factor authentication can be used with the Qualys API. However, two-factor authentication will _not_ be used when making API requests. Two-factor authentication is only supported when logging into the Qualys GUI.

### Fetch Vulnerabilities Behavior

When configuring the integration instance, selecting the "Fetch by last modified date" option fetches all assets and vulnerabilities from the last 90 days.

To fetch only vulnerabilities by unique QIDs relevant to the assets regardless of the vulnerability modified time, choose the "Fetch by unique QIDs of assets" option.

---
[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/qualys-v2)
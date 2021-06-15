Use the Workday IAM Integration as part of the IAM premium pack.
For more information, please refer to the [Identity Lifecycle Management article](https://xsoar.pan.dev/docs/reference/articles/identity-lifecycle-management).

## Configure Workday IAM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Workday IAM.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Credentials | | False |
| Workday Report URL | | True |
| Fetch Limit \(Recommended less than 200\) | | False |
| Fetch incidents | Whether or not to fetch events from Workday report. Enable only when all required configurations are set properly. | False |
| Incident type | | False |
| Trust any certificate \(not secure\) | | False |
| Use system proxy settings | | False |
| Mapper \(incoming\) | Used to map Workday report entries to XSOAR indicators format. | False |
| Sync user profiles on first run | If checked, the first fetch won't trigger incidents but all of the User Profile indicators will be created. | False |
| Fetch Samples | If checked, five sample events will be created. | False |
| Dates Format in Workday Report | | False |
| Deactivation date field | Select the field that determines when to trigger a termination incident for deactivated employees. | False |
| Number of days before hire date to sync hires | Determines when employees are synced from Workday, i.e., when are the User Profile in XSOAR, and the users in the applications, created. Set to 0 to sync hires on their hire date. Leave empty to sync the hires immediately. | False |
| Number of days before hire date to enable Active Directory account | Determines when to enable the Active Directory accounts for employees. Set to 0 to enable the Active Directory accounts on their hire date. Leave empty to enable the accounts immediately. Note that this is effective only when the employees are already synced to XSOAR, so you should set a number lower, or equal to, the value in the *Number of days before hire date to sync hires* parameter. | False |

4. Click **Test** to validate the connection.

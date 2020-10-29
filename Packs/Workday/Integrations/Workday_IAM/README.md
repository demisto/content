Use the Workday IAM Integration as part of the IAM premium pack.
This integration was integrated and tested with version xx of Workday IAM
## Configure Workday IAM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Workday IAM.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| credentials | Username | False |
| report_url | Workday Report URL | True |
| max_fetch | Fetch Limit \(Recommended less than 200\) | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| mapper_in | Mapper \(incoming\) | False |
| first_run | Sync user profiles on first run | False |

4. Click **Test** to validate the URLs, token, and connection.

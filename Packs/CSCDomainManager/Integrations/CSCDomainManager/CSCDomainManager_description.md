## Configure CSCDomainManager on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CSCDomainManager.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Base URL | The endpoint URL | True |
    | Token | The token to use for connection | True |
    | API Key | The API Key to use for connection | True |
    | Source Reliability | Reliability of the source providing the intelligence data. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Access and Security
 Customers request access through their CSC service team.  Their service team will gather the details for
the service account that will be used to access the API; and
the API administrator(s) (one or more authorized client users) who will manage the credentials through our CSCDomainManagerSM web portal.
 
Please see attached API guide for reference.
 
CSC generates the API key and creates the service account, with requested permissions, that will be used to access the API.
 
The client API administrator then logs into our CSCDomainManagerSM at https://weblogin.cscglobal.com to retrieve the key and generate the bearer token for the API service account.

Tokens  expire after 30 consecutive days of no activity and will be needed to refresh.
Refresh token example:

curl --location --request PUT '<URL>/dbs/api/v2/token/refresh' \
--header 'apikey:XXXXXXXXXXXXXXXX' \
--header 'Authorization: XXXXXXXXXXXXXXXXX'

1. Name: Give a name to the integration instance.
2. Base URL: Enter the endpoint URL.
3. Token: Enter the token.
4. API Key: Enter the API key.

## Access and Security
You request access through the CSC service team. The service team will gather the details for the service account that will be used to access the API, and the API administrator(s) (one or more authorized client users) who will manage the credentials through the CSCDomainManagerSM web portal.
 
Please see attached API guide for reference.
 
CSC generates the API key and creates the service account, with requested permissions, that will be used to access the API.
 
The client API administrator then logs into the CSCDomainManagerSM at https://weblogin.cscglobal.com to retrieve the key and generate the bearer token for the API service account.

The API administrator(s) (one or more authorized client users) who will manage the credentials through the CSCDomainManagerSM web portal.

### Token Refresh
Token will expire after 30 consecutive days of no activity, you can reactive it by using the [token refresh endpoint](https://www.cscglobal.com/cscglobal/docs/dbs/domainmanager/api-v2/#/token/put_token_refresh).

### For more information
- [Visit the CSC website](https://www.cscdbs.com/)
- [See the api page](https://www.cscglobal.com/cscglobal/docs/dbs/domainmanager/api-v2/#/)
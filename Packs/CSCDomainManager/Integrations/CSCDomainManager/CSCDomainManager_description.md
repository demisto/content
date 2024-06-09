## Access and Security
Customers request access through their CSC service team.  Their service team will gather the details for
the service account that will be used to access the API, and
the API administrator(s) (one or more authorized client users) who will manage the credentials through the CSCDomainManagerSM web portal.
 
Please see attached API guide for reference.
 
CSC generates the API key and creates the service account, with requested permissions, that will be used to access the API.
 
The client API administrator then logs into the CSCDomainManagerSM at https://weblogin.cscglobal.com to retrieve the key and generate the bearer token for the API service account.

Tokens expire after 30 consecutive days of no activity and will need to be refreshed.
Refresh token example:

The API administrator(s) (one or more authorized client users) who will manage the credentials through the CSCDomainManagerSM web portal.

# Refresh token example:
curl --location --request PUT '<YOUR_URL>/dbs/api/v2/token/refresh' \
--header 'apikey:XXXXXXXXXXXXXXXX' \
--header 'Authorization: XXXXXXXXXXXXXXXXX'

# For more information
- [Visit the CSC website](https://www.cscdbs.com/)
- [See the api page](https://www.cscglobal.com/cscglobal/docs/dbs/domainmanager/api-v2/#/)
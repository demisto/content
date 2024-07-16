## Carbon Black Cloud Endpoint Standard V3
 
*Carbon Black Cloud Endpoint Standard is the new name for the product formerly called CB Defense.*

### Create Access Levels and API Keys

This integration uses two rest APIs with two different permissions, one for the policy commands and another for the rest all commands. Therefore, in addition to creating a Live Response API key and API secret key for the policy commands, you also need to create a custom API key and a custom API secret key for the rest all commands, with a custom access level.

#### Create a Custom Access Level

1. In the Carbon Black Cloud console, go to **Settings** > **API Access** > **Access Levels** tab.
2. Open the *Add Access Level* panel. 
3. Give the access level a unique name (you will need this for creating your API Key) and a description.
4. In the table, scroll down until you see your API service category. Configure the required permissions. Some service categories have multiple
   permissions that can be configured.

#### Create an API Key

1. In the Carbon Black Cloud console, go to **Settings** > **API Access** > **API Keys** tab.
2. Select **Add API Key** from the far right.
3. Give the API key a unique name, and select the appropriate access level. If you select
   "Custom", you will need to choose the Access Level you created in the *Create a Custom Access Level* section.
4. Click **Save**. You will be provided with your API key credentials:
   - API Secret Key
   - API Key
 
   Click [here](https://developer.carbonblack.com/reference/carbon-black-cloud/authentication) for more information about authentication.

### Set the API keys
#### If you use credentials:
   - Username => api key & password => secret api key
   - The first credentials is for **Custom** api access level (all commands except the policies commands), the second credentials is for **Live Response** access level (the policies commands)

#### If you don't use credentials:
   - api key => api key & password => secret api key
   
### Create a Carbon Black Query

Carbon Black Cloud Endpoint Standard uses Advanced Search Queries to query for events and processes. Click [here](https://developer.carbonblack.com/resources/query_overview.pdf) for more information
about Advanced Search Queries.

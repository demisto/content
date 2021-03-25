## Carbon Black Cloud Endpoint Standard

*Carbon Black Cloud Endpoint Standard is the new name for the product formerly called CB Defense.*

### Create Access Levels and API Keys

There are two versions of the API - V3 and V6. V6 includes all the APIs except for the Policy APIs. Therefore, in addition to creating an API key and API secret key, you also need to create a custom API key and a custom API secret key for the policy related commands.
Click [here](https://developer.carbonblack.com/reference/carbon-black-cloud/cb-defense/latest/rest-api) for more information about the versions.

#### Create a Custom Access Level

1. In the Carbon Black Cloud console, go to **Settings** > **API Access** > **Access Levels** tab.
2. Open the *Add Access Level* panel. 
2. Give the access level a unique name (you will need this for creating your API Key) and a description.
3. In the table, scroll down until you see your API service category. Configure the required permissions. Some service categories have multiple
   permissions that can be configured.

#### Create an API Key

1. In the Carbon Black Cloud console, go to **Settings** > **API Access** > **API Keys** tab.
2. Select **Add API Key** from the far right.
3. Give the API key a unique name, and select the appropriate access level. If you select
   "Custom", you will need to choose the Access Level you created in [Create a Custom Access Level](#create-a-custom-access-level).
4. Click **Save**. You will be provided with your API key credentials:
   - API Secret Key
   - API Key
 
   Click [here](https://developer.carbonblack.com/reference/carbon-black-cloud/authentication) for more information about authentication.

### Create a Carbon Black Query

Carbon Black Cloud Endpoint Standard uses Advanced Search Queries to query for events and processes. Click [here](https://developer.carbonblack.com/resources/query_overview.pdf) for more information
about Advanced Search Queries.

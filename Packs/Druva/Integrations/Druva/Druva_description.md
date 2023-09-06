Important: The integration is applicable to customers using Realize Ransomware Recovery module with inSync and Phoenix on Druva Public Cloud

We recommend familiarizing yourself with the content before you begin to use the APIs.

Druva APIs are built around REST and support the following:

- JSON formatted requests and responses
- Standard HTTP Verbs/Methods
- Standard HTTP Error Codes

The following steps are involved in API integration:

- Create API Credentials from the [Druva Cloud Platform Console](https://login.druva.com/)
- Encode the API Credentials to [Base64](https://www.base64encode.org/)
- Request and receive Access Token using the Base64 encoded API Credentials
- Use the Access Token to make API calls.

API credentials can be created and managed from Druva Cloud Platform Console. Refer [Create and Manage API Credentials](https://docs.druva.com/Druva_Cloud_Platform/Integration_with_Druva_APIs/Create_and_Manage_API_Credentials#Create_new_credentials) to learn API credentials management.

Please connect to our [Developer portal](https://developer.druva.com/docs) to learn more about our APIs

Important: The API Credentials which is a combination of the Client ID and Secret Key are equivalent to user name and password. One can access all the Druva APIs and in turn, access the data stored within Druva products. It is strongly recommended not to share the Client ID and Secret Key with unauthorized sources.
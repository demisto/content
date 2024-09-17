## HPE Aruba Central Help

### How to generate Client ID and Secret

In order for the collector to access the Aruba Central API, it must first be added as an application in the Aruba Central API gateway. Doing so will generate unique client id and secret to be used for authentication. Here are the steps to do so:

- Go to the Aruba Central portal and navigate to **Accounts Home** -> **Global Settings** -> **API Gateway**.
- Admin users: navigate to the **System Apps & Tokens** tab.
  Non-admin users: navigate to the **My Apps & Tokens** tab.
- Click **+ Add Apps & Tokens**
- Fill in the required details and click **Generate**
- Once created, the new credentials can be viewed in the **My Apps & Tokens** tab

See [Creating Application & Token](https://developer.arubanetworks.com/hpe-aruba-networking-central/docs/api-gateway-creating-application-token) for more details.
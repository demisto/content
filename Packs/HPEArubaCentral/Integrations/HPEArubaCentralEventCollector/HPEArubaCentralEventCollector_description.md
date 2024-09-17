## HPE Aruba Central Help

### How to generate Client ID and Secret

In order for the collector to access the Aruba Central API, it must first be added as an application in the Aruba Central API gateway. Doing so will generate a unique pair of client id and secret to be used for authentication. Here are the steps to do so:

1. Go to the Aruba Central portal and navigate to **Accounts Home** -> **Global Settings** -> **API Gateway**.

- Admin users:
  - Navigate to **System Apps & Tokens**.
- Non-admin users:
  - Navigate to **My Apps & Tokens**.

2. Click **+ Add Apps & Tokens**
3. Fill in the required details and click **Generate**
4. Once created, the new credentials can be viewed in the **My Apps & Tokens** tab

See [Creating Application & Token](https://developer.arubanetworks.com/hpe-aruba-networking-central/docs/api-gateway-creating-application-token) for more details.
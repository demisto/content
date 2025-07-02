# Endpoint Central Cloud Domains

Endpoint Central cloud is hosted at multiple data centers, and therefore available on different domains. There are several domains for Endpoint Central Cloud APIs, so you can use the one that is applicable to you.

| Data Centre  | Domain | EndpointCentral Server URI                 |
|-------------:|:-------|:-------------------------------------------|
| United States| .com   | https://endpointcentral.manageengine.com   |
| Europe       | .eu    | https://endpointcentral.manageengine.eu    |
| India        | .in    | https://endpointcentral.manageengine.in    |
| Australia    | .com.au| https://endpointcentral.manageengine.com.au|
| China        | .cn    | https://endpointcentral.manageengine.cn    |
| Japan        | .jp    | https://endpointcentral.manageengine.jp    |
| Canada       | .ca    | https://endpointcentral.manageengine.ca    |

The APIs on this page are intended for organizations hosted on the **.com** domain. If your organization is on a different domain, replace “.com” with the appropriate domain for the API endpoints before using them.  
Note: You can also find out which domain you’re accessing by checking the URL while logged in to Endpoint Central.

## Setting Up the Instance

### Step 1: Generate Client ID and Client Secret

1. Register your application as a new client by accessing the developer console.
2. Choose Self client as application type.
3. After choosing the client type, provide the required details and click 'Create'. On successful registration, you will be provided with a set of OAuth 2.0 credentials such as `Client_ID` and `Client_Secret` that will be only known to Zoho and your application. (Do not share this credentials anywhere).

### Step 2: Authorization by generating the grant token

After generating `Client_ID` and `Client_Secret`, a grant code has to be generated.
Self Client Method - For Self Client type.

- After registration, click the `Self Client` method available on the Applications list.
- Enter a valid scope: DesktopCentralCloud.Admin.READ

Click Create to generate `Code`.

## Testing the configuration

To test the configuration, run the !manage-engine-test command instead of using the Test button.

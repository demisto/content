#To read the integration's description and authentication instructions more conveniently, you are  welcome to browse them here:
https://xsoar.pan.dev/docs/reference/integrations/microsoft-management-activity-api-(O365/Azure-Events)

Microsoft Cloud App Security is a Cloud Access Security Broker that supports various deployment modes including log collection, 
API connectors, and reverse proxy. It provides rich visibility, control over data travel, 
and sophisticated analytics to identify and combat cyberthreats across all your Microsoft and third-party cloud services.

## Grant Demisto Authorization in Microsoft Cloud App Security API
To allow us to access Microsoft Management Activity API you will be required to give us authorization to access it.

1. To grant authorization, click the [HERE](https://oproxy.demisto.ninja/ms-management-api).
2. After you click the link, click the **Start Authorization Process** button.
3. When prompted, accept the Microsoft authorization request for the required permissions.
You will get an ID, Token, and Key, which you need to enter in the corresponding fields when configuring an integration instnace..

## Self-Deployed Configuration
1. Enter the following URL.
Note that CLIENT_ID and REDIRECT_URI should be replaced by your own client ID and redirect URI, accordingly.
https://login.windows.net/common/oauth2/authorize?response_type=code&resource=https://manage.office.com&client_id=CLIENT_ID&redirect_uri=REDIRECT_URI
2. When prompted, accept the Microsoft authorization request for the required permissions.
3. The URL will change and will have the following structure:
SOME_PREFIX?code=AUTH_CODE&session_state=SESSION_STATE
Take the AUTH_CODE (without the “code=” prefix) and enter it to the instance configuration under the “Authentication” code section.
Moreover, enter your client secret as the “Key” parameter and your client ID as the “ID” parameter. 
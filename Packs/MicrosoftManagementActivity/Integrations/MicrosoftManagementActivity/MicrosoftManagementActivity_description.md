To read the integration's description and authentication instructions more conveniently, you are  welcome to browse them here:
https://xsoar.pan.dev/docs/reference/integrations/microsoft-management-activity-api-(O365/Azure-Events)

Microsoft Management Activity API (O365/Azure Events) should be used to retrieve content records from the various Microsoft Management Activity content types.
Through the integration you can subscribe to new content types or stop your subscription, list the available content of each content type, and most importantly - fetch new content records from content types of your choice as Demisto incidents.

## Grant Demisto Authorization in Microsoft Management Activity API
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

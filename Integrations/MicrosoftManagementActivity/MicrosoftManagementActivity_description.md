Microsoft Management Activity API (O365/Azure Events) should be used to retrieve content records from the various Microsoft Management Activity content types.
Through the integration you can subscribe to new content types or stop your subscription, list the available content of each content type, and most importantly - fetch new content records from content types of your choice as Demisto incidents.

To allow us to access Microsoft Management Activity API you will be required to give us authorization to access it.
That could be achieved by clicking on the following [link](https://oproxy.demisto.ninja/ms-management-api).
As you click the link, you will see a button that states “Start Authorization Process”.
Please click it, and then you will be prompted with a Microsoft authorization request with the required permissions - accept it.
Then, you will receive your ID, Token and Key - please enter those to your integration configuration as you configure an instance.

Alternatively, for a self-deployed configuration, please enter the following URL.
Note that CLIENT_ID and REDIRECT_URI should be replaced by your own client ID and redirect URI, accordingly.
https://login.windows.net/common/oauth2/authorize?response_type=code&resource=https://manage.office.com&client_id=CLIENT_ID&redirect_uri=REDIRECT_URI
As you enter the link, you will be prompted with a Microsoft authorization request - accept it.
The URL will then change, and will have the following structure:
SOME_PREFIX?code=AUTH_CODE&session_state=SESSION_STATE
Take the AUTH_CODE (without the “code=” prefix) and enter it to the instance configuration under the “Authentication” code section.
Moreover, enter your client secret as the “Key” parameter and your client ID as the “ID” parameter. 

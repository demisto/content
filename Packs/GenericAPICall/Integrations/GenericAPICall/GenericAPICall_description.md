
## GenericAPICall Integration

This integration provides a method for executing HTTP API calls to specific API endpoints used in one-off scenarios not covered by other XSOAR integrations. This integration supports unauthenticated and authenticated API calls over HTTPS, using API key and basic HTTP authentication methods.

## Configuration Parameters

 - ***Name*** - Integration instance name
 - ***Base Server URL*** - The base server URL for the API endpoint without the trailing slash (**/**)
 - ***Username*** - Username for HTTP basic authentication.
		 - Leave blank when using an API key
 - ***Password/API Key*** - The password (when using HTTP basic authentication) or API key to use for API calls with this integration instance
 - ***API call is authenticated*** - Check this box if API calls to this endpoint require authentication (**Default**: False)
 - ***API key supplied in header*** - Check this box if API key or authentication credentials are provided as part of the HTTP header (**Default**: False)
		 - Unchecking this box will pass the API key as a parameter in the URL (**&apiKey=KEY_HERE**)
 - ***Authentication Header*** - The value to use to identify the API key field as part of the HTTP header or API Key parameter in the URL
		 - **Header example**: { 'AUTHENICATION_HEADER_HERE': 'API_KEY_HERE' }
		 - **Parameterized example**: &AUTHENTICATION_HEADER=API_KEY_HERE
 - **Use system proxy settings** - Leverage the proxy settings configured on the XSOAR server
 - **Trust any certificate (not secure)** - Bypass SSL certificate verification (Default: 
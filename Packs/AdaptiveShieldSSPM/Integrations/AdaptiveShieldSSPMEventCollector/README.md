Adaptive Shield SSPM fetches security check events from Adaptive Shield and sends them to Cortex XSIAM.

## Configure Adaptive Shield SSPM in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Account ID | The Adaptive Shield account ID. Can be retrieved from the List Accounts endpoint or from your user settings in the Adaptive Shield dashboard \(API tab\). | True |
| API Key |  | True |
| Fetch events |  | False |
| The maximum number of Security Checks per fetch | The maximum number of Security Checks per fetch. The default is 5000. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Configuration steps

A valid API key is required to send any request.

**Generate API Key**

An API key is required for every request sent to Adaptive Shield's API.

1. In your Adaptive Shield dashboard navigate to your user profile
2. Click the API tab
3. Click "Generate a new key"
4. Set a key name, and click "Create"


Symantec Endpoint Security Event Collector for Cortex XSIAM.

## Configure Symantec Endpoint Security on Cortex XSIAM

1. Navigate to Settings > Configurations > Data Collection > Automations & Feed Integrations.
2. Search for Symantec Endpoint Security.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | OAuth credential | True |
    | Stream ID | True |
    | Channel ID | True |
    | Fetch interval in seconds | True |
    | Use system proxy settings | False |
    | Trust any certificate (not secure) | False |

4. Click **Test** to validate the URLs, token, and connection.


### To generate a token for the ***Token*** parameter:

1. Log in to the Symantec Endpoint Security console.
2. Click **Integration** > **Client Applications**.
3. Choose `Add Client Application`.
4. Choose a name for the application, then click `Add`. The client application details screen will appear.
5. Click `⋮` and select `Client Secret`.
6. Click the ellipsis and select **Client Secret**.
7. Click the `copy` icon next to `OAuth Credentials`.

For more information on obtaining *OAuth Credentials*, refer to [this documentation](https://apidocs.securitycloud.symantec.com/#/doc?id=ses_auth) or watch [this video](https://youtu.be/d7LRygRfDLc?si=NNlERXtfzv4LjpsB).

**Note:** 

- No need to generate the bearer token, the integration uses the provided `OAuth Credentials` to generate one.
- The `test_module` test checks only the validity of the `OAuth credential` parameter and does not validate the `Channel ID` and `Stream ID` parameters.
- Fetching events that occurred at a specific time may be delayed due to delays in event ingestion on Symantec's side.
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
### symantec-ses-reset-integration-context

***
Reset Integration context. By default, resetting the integration context only resets the `next_fetch` field in the integration context.

**Note:**
By default, resetting the integration context only resets the `next_fetch` field in the integration context,  
This means that the next fetch call will be performed without the `next` parameter, but events will still be filtered, preventing duplicate events from being ingested.  

When using the `delete_all=true` argument, the entire `integration_context` is deleted. This means that the API call will be performed without the `next` parameter, and duplicate events may be ingested into the system.
#### Base Command

`symantec-ses-reset-integration-context`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| delete_all | Whether delete all integration context, default, false. Possible values are: true, false. | Optional | 

#### Context Output

There is no context output for this command.


### Troubleshooting
In case where the integration has been disabled for an extended period, it is recommended to run the command `symantec-ses-reset-integration-context` without the `delete_all` argument. This will ensure that the `next` parameter stored in the `integration_context` is cleared,  
This means that the fetch process will run without the `next` parameter and retrieve all available events from the stream. However, events will still be filtered based on the last retrieved event timestamp.

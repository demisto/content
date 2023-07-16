To begin fetching events from Okta Auth0 API you need to have a machine to machine (M2M) application in your Auth0 UI. In the M2M application you can find your client ID and secret to configure the instance.

### Create an Okta Auth0 API M2M application
1. Access OneLogin as an account owner or administrator.
2. In the side bar go to **Applications** > **Applications**.
3. Click **Create Application**, choose **Machine to Machine Applications** and click **Create**.
4. Select the authorized API URL you want to use in the instance.
5. To fetch the logs, choose the permission `read:logs`.
6. Click **Authorize**.
7. In the created application under the **Quick Start** tab locate the client credentials to use to configure the integration instance.

**Note**: To fetch the Auth0 logs you need to set the permission `read:logs` in the M2M application.

For more information about how to register M2M apps, see the [Auth0 documentation](https://auth0.com/docs/get-started/auth0-overview/create-applications/machine-to-machine-apps).


### Log Data Retention
Important: Your Auth0 log retention period depends on your subscription level.

| Plan | Log Retention |
| --- | --- |
| Starter | 1 day|
| B2C Essentials | 2 days |
| B2C Professional | 10 days |
| B2B Essentials | 10 days |
| B2B Professional | 10 days |
| Enterprise | 30 days |

**Note from Auth0**: Auth0 does not provide real-time logs for your tenant. While we do our best to index events as they arrive, you may see some delays.

For more information see [this](https://auth0.com/docs/deploy-monitor/logs/log-data-retention)
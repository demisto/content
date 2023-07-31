Please configure only one of the following fields:

1. Cloud ID - Used for Jira Cloud instance.
2. OnPrem - Leave the Cloud ID empty, and fill in the rest of the fields.

For both instances, it is advised to use the `https://oproxy.demisto.ninja/authcode` **Callback URL**. The oproxy url is a client side only web page which provides an easy interface to copy the obtained auth code from the authorization response to the integration configuration in the authorization flow steps. Optionally: if you don't want to use the oproxy url, you may use a localhost url on a port which is not used locally on your machine. For example: <http://localhost:9004>. You will then need to copy the code from the url address bar in the response.

**Notes**:

1. Authentication is done using OAuth 2.0.
2. OAuth 2.0 works for Jira OnPrem 8.22 and above.

### Cloud authentication

Go to your [Developer console](https://developer.atlassian.com/console/myapps/) page, and choose the App you want to integrate with your instance. It must be of type OAuth 2.0. For creating a new app with type OAuth 2.0, click **Create** and choose **OAuth 2.0 integration** and follow the steps.

#### Callback URL

1. Go to the **Authorization** tab, and click **Add** on the authorization with type of OAuth 2.0 (3LO).
2. Insert a **Callback URL**.

#### Client ID, Client Secret

1. Go to the **Settings** tab.
2. Copy the **Client ID** and **Secret** to the Client ID and Client Secret fields, respectively.

#### Cloud ID

Go to your [Admin page](https://admin.atlassian.com/), click the **Products** tab on the top banner and choose the appropriate site under **Sites and Products** on the left side bar. Your Cloud ID will appear in the URL:
`https://admin.atlassian.com/s/{cloud_id}/users`

#### Cloud Scopes

The integration uses the *offline_access* scope, in order to retrieve refresh tokens.

##### Classic Scopes

* read:jira-work
* read:jira-user
* write:jira-work

#### Granular Scopes

* read:jql:jira
* read:issue-details:jira
* write:board-scope:jira-software
* read:board-scope:jira-software
* read:sprint:jira-software
* read:epic:jira-software
* write:sprint:jira-software

### OnPrem authentication

1. Log in to Jira as a user with `Jira Administrator` permissions.
2. Click the Jira Administration tab (the gear icon found in the top right corner) and click **Applications**.
3. To create a new `Application link`, which will be used to integrate Cortex XSOAR with Jira:
    a. Click **Application links** under `Integrations`, found on the left side menu.
    b. Click **Create link** and choose **External application** with the **Incoming** direction.
4. Fill in the required details as explained in the page and choose the permission **Write**.
5. Once the link is created, you will be able to see `Client ID`, and the `Client secret`, which are required in the configuration screen. Copy these values and paste them into the respective fields in the configuration screen.

#### OnPrem Scopes

Write

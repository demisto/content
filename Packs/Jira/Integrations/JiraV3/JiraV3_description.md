Please configure only one of the following fields:

1. Cloud ID - Used for Jira Cloud instance.
2. OnPrem - Leave the Cloud ID empty, and fill in the rest of the fields.

### Cloud authentication

Go to your [Developer console](https://developer.atlassian.com/console/myapps/) page, and choose the App you want to integrate with your instance, it must be of type OAuth 2.0. For creating a new app with type OAuth 2.0, press the Create button and choose `OAuth 2.0 integration`, and follow the steps.

#### Callback URL

Go to the `Authorization` tab, and press on the `Configure` button of the authorization with type of OAuth 2.0 (3LO), and copy the content of the `Callback URL`.

#### Client ID, Client Secret

Go to the `Settings` tab, and copy the `Client ID`, and `Secret` to the Client ID, and Client Secret fields, respectively.

#### Cloud ID

Go to your [Admin page](https://admin.atlassian.com/), and choose the `Jira Software` product by pressing the three dots and choosing `Manage users`, after that, your Cloud ID will be shown in the url:
`https://admin.atlassian.com/s/{cloud_id}/users`
(if you do not have it, then press on `Products` and the then add the `Jira Software` product to your products list)

#### Cloud Scopes

The integration uses the *offline_access* scope, in order to retrieve refresh tokens

##### Classic Scopes

* read:jira-work
* read:jira-user
* write:jira-work
* read:jql:jira

#### Granular Scopes

* read:issue-details:jira
* write:board-scope:jira-software
* read:board-scope:jira-software
* read:sprint:jira-software
* read:epic:jira-software
* write:sprint:jira-software

### OnPrem authentication

Log in to Jira as a user with `Jira Administrator` permissions, then click on the Jira Administration tab (the gear icon found in the top right corner), and press on `Applications`. For creating a new `Application link`, which will be used to integrate XSOAR with Jira, press on `Application links` under `Integrations`, found on the left side menu, then press on `Create link`, and choose `External application`, with the `Incoming` direction.
Fill in the required details as explained in the page, and on permissions, choose the permission `Write`.
Once the link is created, you will be able to see `Client ID`, and the `Client secret`, which are required in the configuration screen, copy them into the respective fields.

#### OnPrem Scopes

* Write

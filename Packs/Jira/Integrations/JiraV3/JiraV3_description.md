Please configure only one of the following fields:

1. Cloud ID - Used for Jira Cloud instance.
2. Server URL - Used for Jira On Prem instance.

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

## Cisco Webex Event Collector Help


### Cisco Webex Event Collector collects three types of events.
* Admin Audit Events.
* Security Audit Events (user sign-in and sign-out data). See [Fetch security audits](#Fetch-security-audit) more information about these events.
* Events.

### Users and Clients
In order to fetch all types of events 2 users and 2 applications must be created where each application is associated with one user.
In addition, each application should be defined with a specific scope as follows.

#### Create two users
1. Admin user
2. Compliance officer user

Click [here](https://developer.webex.com/) to create and manage the users.

#### Create two clients
1. Admin client (for `Admin Audit Events` and `Security Audit Events`) associated with the admin user defined and the `audit:events_read` scope.
2. Compliance Officer client (for `Events`) associated with the compliance officer user defined and the `spark-compliance:events_read` scope.

Click [here](https://developer.webex.com/my-apps) to create and manage the applications.


### Each client needs three parameters:
* client ID.
* client secret.
* client redirect URI.

_Note:  The Admin client needs a fourth parameter: `organization ID`._\
Run [this](https://developer.webex.com/docs/api/v1/organizations/list-organizations) HTTP request (login with admin credentials) to get the organization ID.

![get_organization_id](../../doc_files/get_organization_id.png)

### Authentication flow (Oauth)

Each application (admin and compliance officer) should be authenticated with the following 3 commands.
Each command (of the following three commands) has an argument called **user**, which can be set to `admin` or `compliance officer`.
In order to receive all events, You must run all three commands twice, once with `admin` as your **user** argument value and once with `compliance officer` as your **user** argument value.

1. Run the ***cisco-webex-oauth-start*** command with the **user** argument - you will be prompted to sign in to Cisco Webex with your username and password. (make sure you sign in with the same user as you defined in the user argument `admin` or `compliance officer`). You will then be redirected to the `redirect URI` you defined in the application. The URL will contain a query parameter called `code`. The value of this query parameter will be used in the next command. 
2. Run the ***cisco-webex-oauth-complete*** command with the **user** and **code** arguments The **user** argument should be set to the same value as in the previous command (`admin` or `compliance officer`). The **code** argument should be set to the value returned in the code query parameter from the previous command.
3. Run the ***cisco-webex-oauth-test*** command with the **user** argument. The **user** argument should be set to the same value as in the previous command (`admin` or `compliance officer`) to ensure connectivity to Cisco Webex.

### Fetch Security Audits  

This API requires Full Admin permissions.  

To fetch security audit events, the **Pro Pack** must be installed on the Webex instance. Additionally, the **Allow user authentication data** setting must be enabled:  

1. Go to **Management** > **Organization Settings**.  
2. In the **User authentication data** section, toggle **Allow user authentication data** ON.  
For more details, refer to the [official documentation.](https://help.webex.com/en-us/article/pf66vg/Log-and-analyze-user-sign-ins-and-sign-outs)

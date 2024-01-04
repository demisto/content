## Cisco Webex Event Collector Help


### Cisco Webex Event Collector collects three types of events.
* Admin Audit Events.
* Security Audit Events (user sign-in and sign-out data).
* Events.

### Users and Clients
In order to fetch all types of events 2 users and 2 applications must be created where each application is associated with one user.
In addition, each application should be defined with a specific scope as follows.

#### Create two users
1. Admin user
2. Compliance officer user

[click here to create and managed your users](https://developer.webex.com/?????)

#### Crete two clients
1. Admin client (for `Admin Audit Events` and `Security Audit Events`) associated with the admin user defined with teh `audit:events_read` scope.
2. Compliance Officer client (for `Events`) associated with the compliance officer user defined with teh `spark-compliance:events_read` scope.

[click here to create and managed your applications](https://developer.webex.com/my-apps)


### Each client needs three parameters:
* client ID.
* client secret.
* client redirect URI.

_Note:  The Admin client needs a fourth parameter: `organization ID`._\
Run [this](https://developer.webex.com/docs/api/v1/organizations/list-organizations) HTTP request (login with admin credentials) to get the organization ID.
![get_organization_id](../../doc_files/get_organization_id.png)

### Authentication flow (Oauth)

Each application should be authenticated with the following 3 commands.

1. Run the ***cisco-webex-auth-start*** command - you will be prompted to open the page https://microsoft.com/devicelogin and enter the generated code.
2. Run the ***cisco-webex-auth-complete*** command.
3. Run the ***cisco-webex-test*** command to ensure connectivity to Microsoft. 



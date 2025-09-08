ManageEngine Endpoint Central is a unified endpoint management (UEM) platform that allows businesses to manage and secure their IT infrastructure from a single console. It offers a comprehensive suite of features for managing servers, desktops, laptops, and mobile devices, including automated patching, security management, and remote troubleshooting.

# Manage Engine

ManageEngine Endpoint Central is a unified endpoint management (UEM) platform that allows businesses to manage and secure their IT infrastructure from a single console. It offers a comprehensive suite of features for managing servers, desktops, laptops, and mobile devices, including automated patching, security management, and remote troubleshooting.

<~XSIAM>

## What does this pack contain?

- Rest API Log collection for audit events
- Modeling rules for audit events

## Endpoint Central Cloud Domains

Endpoint Central cloud is hosted at multiple data centers, and therefore available on different domains. There are several domains for Endpoint Central Cloud APIs, so you can use the one that is applicable to you.

| Data Centre  | Domain | EndpointCentral Server URI                 |
|-------------:|:-------|:-------------------------------------------|
| United States| .com   | https://endpointcentral.manageengine.com   |
| Europe       | .eu    | https://endpointcentral.manageengine.eu    |
| India        | .in    | https://endpointcentral.manageengine.in    |
| Australia    | .com.au| https://endpointcentral.manageengine.com.au|
| China        | .cn    | https://endpointcentral.manageengine.cn    |
| Japan        | .jp    | https://endpointcentral.manageengine.jp    |
| Canada       | .ca    | https://endpointcentral.manageengine.ca    |

The APIs on this page are intended for organizations hosted on the **.com** domain. If your organization is on a different domain, replace “.com” with the appropriate domain for the API endpoints before using them.  
Note: You can also find out which domain you’re accessing by checking the URL while logged in to Endpoint Central.

## Setting Up the Instance

### Step 1: Generate Client ID and Client Secret

1. Register your application as a new client by accessing the developer console.
2. Choose Self client as application type.
3. After choosing the client type, provide the required details and click 'Create'. On successful registration, you will be provided with a set of OAuth 2.0 credentials such as `Client_ID` and `Client_Secret` that will be only known to Zoho and your application. (Do not share this credentials anywhere).

For more information use the following guide [here](https://www.manageengine.com/products/desktop-central/api/cloud_index.html).

### Step 2: Authorization by generating the grant token

After generating `Client_ID` and `Client_Secret`, a grant code has to be generated.
Self Client Method - For Self Client type.

- After registration, click the `Self Client` method available on the Applications list.
- Enter a valid scope: DesktopCentralCloud.Admin.READ

Click Create to generate `Code`.

## Testing the configuration

To test the configuration, run the !manage-engine-test command instead of using the Test button.

## Configure ManageEngine in Cortex

| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| Client ID | True |
| Client Secret | True |
| Code | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Max number of audit events per fetch | False |
| Fetch events | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### manage-engine-test

***
Tests connectivity of the server.

#### Base Command

`manage-engine-test`

### manage-engine-get-events

***
Manual command to fetch events and display them.

#### Base Command

`manage-engine-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events. Otherwise, it will only display them. Used for debugging purposes.| Required |
| limit              | Maximum number of results to return.                                                                       | Optional |
| start_date         | Date from which to get events, For example '2018-11-06T08:56:41.000Z'.                                         | Optional |
| end_date           | Date to which to get events , For example '2018-11-06T08:56:41.000Z'.                                          | Optional |

#### Context Output

There is no context output for this command.

</~XSIAM>

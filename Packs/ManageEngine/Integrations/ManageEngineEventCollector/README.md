# Endpoint Central Cloud Domains

Endpoint Central cloud is hosted at multiple data centers, and therefore available on different domains. There are 7 different domains for Endpoint central cloud APIs, so you can use the one that is applicable to you.


| Data Centre    | Domain | EndpointCentral Server URI                        | Zoho Accounts Server URI              |
|---------------:|:-------|:--------------------------------------------------|:--------------------------------------|
| United States  | .com   | https://endpointcentral.manageengine.com          | https://accounts.zoho.com             |
| Europe         | .eu    | https://endpointcentral.manageengine.eu           | https://accounts.zoho.eu              |
| India          | .in    | https://endpointcentral.manageengine.in           | https://accounts.zoho.in              |
| Australia      | .com.au| https://endpointcentral.manageengine.com.au       | https://accounts.zoho.com.au          |
| China          | .cn    | https://endpointcentral.manageengine.cn           | https://accounts.zoho.cn              |
| Japan          | .jp    | https://endpointcentral.manageengine.jp           | https://accounts.zoho.jp              |
| Canada         | .ca    | https://endpointcentral.manageengine.ca           | https://accounts.zohoone.ca           |

The APIs on this page are intended for organizations hosted on the **.com** domain. If your organization is on a different domain, replace “.com” with the appropriate domain for the API endpoints before using them.  
Note: You can also find out which domain you’re accessing by checking the URL while logged in to Endpoint Central.


## Setting Up the Instance

### Step 1: Generate Client ID and Client Secret

1. Register your application as a new client by accessing the developer console.
2. Choose `Client Type` that suits your application type.
3. After choosing the client type, provide the required details and click 'Create'. On successful registration, you will be provided with a set of OAuth 2.0 credentials such as `Client_ID` and `Client_Secret` that will be only known to Zoho and your application. (Do not share this credentials anywhere).

### Step 2: Authorization by generating the grant token

After generating `Client_ID` and `Client_Secret`, a grant code has to be generated. 
Self Client Method - For Self Client type.
- After registration, click the `Self Client` method available on the Applications list.
- Enter a valid scope: DesktopCentralCloud.Admin.READ
Click Create to generate `code`


## Configure ManageEngineEventCollector in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| Client ID | True |
| Client Secret | True |
| Password | True |
| Code | True |
| Password | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Max number of audit events per fetch | False |
| Fetch events | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### manage-engine-get-events

***
Gets events from ManageEngine.

#### Base Command

`manage-engine-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum number of results to return. | Required | 
| start_date | Date from which to get events. | Optional | 
| end_date | Date to which to get events. | Optional | 

#### Context Output

There is no context output for this command.

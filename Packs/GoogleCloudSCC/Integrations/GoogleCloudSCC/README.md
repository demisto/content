Security Command Center is a security and risk management platform for Google Cloud. Security Command Center enables you to understand your security and data attack surface by providing asset inventory and discovery, identifying vulnerabilities and threats, and helping you mitigate and remediate risks across an organization. This integration helps you to perform tasks related to findings and assets.
This integration was integrated and tested with version v1 of GoogleCloudSCC.

## Detailed Description
This integration uses Pub/Sub to fetch the incidents. To set up the initial parameters of Google SCC in Cortex XSOAR, please follow the below instructions -

### Scope
We need to provide the below mentioned OAuth scope to execute the commands: https://www.googleapis.com/auth/cloud-platform.
 
### Create a Service Account
1. Go to the [Google documentation](https://developers.google.com/identity/protocols/OAuth2ServiceAccount#creatinganaccount) and follow the procedure mentioned in the _Creating a Service Account_ section. After you create a service account, a Service Account Private Key file is downloaded. You will need this file when configuring an instance of the integration.
2. Grant the Security Command Center admin permission to the Service Account to enable the Service Account to perform certain Google Cloud API commands.
3. In Cortex XSOAR, configure an instance of the Google Cloud Security Command Center integration. For the Service Account Private Key parameter, add the Service Account Private Key file contents (JSON).

### Steps to configure workload identity federation:
1. Follow the [steps](https://cloud.google.com/iam/docs/configuring-workload-identity-federation) to construct a workload identity pool and a workload identity pool provider to leverage workload identity federation.
2. Navigate to the '[Granting external identities permission to impersonate a service account](https://cloud.google.com/iam/docs/using-workload-identity-federation#impersonate)' section.
3. Follow the step-1 mentioned in the [Google documentation](https://cloud.google.com/iam/docs/using-workload-identity-federation#generate-automatic) to create a credential file for external identities. The contents of the downloaded file should be given into the 'Service Account Configuration' parameter.
    
    ### Prerequisite for accessing Google services from AWS:
    1. [Create an IAM AWS Role.](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#create-iam-role)
    2. [Attach the IAM role to EC2 instance.](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#attach-iam-role)
    
    ### Prerequisite for accessing Google services from Azure:
    1. [Create an Azure AD application and service principal.](https://docs.microsoft.com/en-au/azure/active-directory/develop/howto-create-service-principal-portal#register-an-application-with-azure-ad-and-create-a-service-principal)
    2. Set an **Application ID URI** for the application.
    3. [Create a managed identity](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/how-manage-user-assigned-managed-identities?pivots=identity-mi-methods-azp). Note the Object ID of the managed identity. You need it later when you configure impersonation.
    4. [Assign the managed identity](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/qs-configure-portal-windows-vm#user-assigned-managed-identity) to a virtual machine or another resource that runs your application.

### Getting your Organization ID
The Organization ID is a unique identifier for an organization and is automatically created when your organization resource is created.
1. To get the Organization ID for your organization, follow the steps mentioned in Google documentation provided [here](https://cloud.google.com/resource-manager/docs/creating-managing-organization#retrieving_your_organization_id).
2. To get your Organization ID using the Cloud Console, [Go to the Cloud Console](https://console.cloud.google.com/) and at the top of the page, click the project selection drop-down list and __from the Select__ window that appears, click the organization drop-down list and select the organization you want.
3. On the right side, click __More__, then click __Settings__. The __Settings__ page displays your organization's ID.

### Getting your Project ID
When we create a new project or for an existing project, Project ID generates for that project. To get the Project ID and the Project number, you can follow the same instructions provided above for getting Organization ID. For more details, You can follow the instructions provided in Google documentation [here](https://cloud.google.com/resource-manager/docs/creating-managing-projects).

### Getting Subscription ID from Pub/Sub
To fetch incidents using Google Pub/Sub, we need to configure Pub/Sub first. This [Google documentation](https://cloud.google.com/pubsub/docs/quickstart-console) will help setting up Pub/Sub prerequisites for creating a subscription.
1. To add a subscription, we need to have a topic first. So after you create a topic, go to the menu for the topic and click on __Create subscription__ and it will take you to the _Add new subscription_ page.
2. Type a name for the subscription and leave the delivery type as __Pull__.
3. Set the Message retention duration to retain unacknowledged messages for a specified duration. If the checkbox of _Retain acknowledged messages_ is enabled, acknowledged messages are retained for the same duration. It is recommended to keep maximum possible value for Message retention so messages can be retained inside subscription until they are pulled.
4. Set the Acknowledgement deadline for pub/sub to wait for the subscriber to acknowledge receipt before resending the message. Minimum recommended value for Acknowledgement deadline is 300 seconds for this integration.
5. Apply the other settings as required and click on the CREATE button.
6. Once the subscription is created, it will take you to the Subscriptions page, where you can see the Subscription ID for the subscription you just created. 

### Setting up finding notifications
* Enable the Security Command Center API notifications feature. Notifications send information to a Pub/Sub topic to provide findings updates and new findings within minutes. Set up the notifications as per [Google Documentation](https://cloud.google.com/security-command-center/docs/how-to-notifications) available and get SCC data in Cortex XSOAR. 
* The basic parameters required for setting up pub/sub notifications are ORGANIZATION_ID, PUBSUB_TOPIC, DESCRIPTION and FILTER.
* Before creating a pub/sub notification, make sure to check the filter parameters using __google-cloud-scc-finding-list__ command provided in this integration. The total size applicable for the filter provided can be checked using _Total retrieved findings_ available inside the command results section. A maximum of 200 findings per minute is recommended.

## Configure GoogleCloudSCC on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for GoogleCloudSCC.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Service Account Configuration | If the application runs on cloud provider (AWS, Azure) use workload identity federation configuration setup file otherwise use service account credential file. | True |
    | Organization ID | Organization ID defines from which organization incidents need to be fetched. | True |
    | Fetch incidents | Enables fetch incident. | False |
    | Project ID | ID of the project to use for fetching incidents. If ID is not provided it will be taken from the provided service account JSON. | False |
    | Subscription ID | ID of subscription from which to fetch incidents. | False |
    | Max Incidents | The maximum number of incidents to fetch every time. | False |
    | Incident type | Type of incident. | False |
    | Trust any certificate (not secure) | Enables to trust on all certificates. | False |
    | Use system proxy settings | Enables system proxy settings. | False |

4. Click **Test** to validate configuration parameter.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### google-cloud-scc-asset-list
***
Lists an organization's assets.


#### Base Command

`google-cloud-scc-asset-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | The filter expression is a list of one or more restrictions combined via logical operators AND and OR.<br/>Parentheses are supported, and OR has higher precedence than AND.Examples include:<br/>1) name<br/>2) securityCenterProperties.resource_name<br/>3) resourceProperties.name<br/>4) securityMarks.marks.marka<br/><br/>The supported operators are:<br/>1) = for all value types.<br/>2) &gt;, &lt;, &gt;=, &lt;= for integer values.<br/>3) :, meaning substring matching, for strings.<br/><br/>The following field and operator combinations are supported:<br/>1) name: =<br/>2) updateTime: =, &gt;, &lt;, &gt;=, &lt;<br/><br/>Example: resourceProperties.displayName="test.com" OR resourceProperties.projectNumber="455757558851"<br/>Use a negated partial match on the empty string to filter based on a property not existing: "-resourceProperties.project=45". | Optional |  
| orderBy | This parameter defines what fields and order to use for sorting.<br/>The string value should be a comma-separated list of fields.<br/>The default sorting order is ascending. To specify descending order for a field, a suffix "desc" should be appended to the field name.<br/>For example: "name desc,resourceProperties.owner".<br/>The following fields are supported for orderBy:<br/>name, updateTime, resourceProperties,  securityMarks.marks,  securityCenterProperties.resource_name,<br/>securityCenterProperties.resource_display_name,  securityCenterProperties.resource_parent, securityCenterProperties.resource_parent_display_name,  securityCenterProperties.resource_project,<br/>securityCenterProperties.resource_project_display_name,  securityCenterProperties.resource_type. | Optional | 
| readTime | Time is used as a reference point when filtering assets. The filter is limited to assets existing at the supplied time and their values are those at that specific time. If not provided, it will take current time. Format: YYYY-MM-ddTHH:mm:ss.sssZ<br/>Example:  2020-07-22T07:10:02.782Z. | Optional | 
| compareDuration | When compareDuration is set, the "stateChange" attribute is updated to indicate whether the asset was added, removed, or remained present during the compareDuration period of time that precedes the readTime. <br/>Possible "stateChange" values when compareDuration is specified:<br/>1) ADDED<br/>2) REMOVED<br/>3) ACTIVE<br/><br/>If compareDuration is not specified, then the only possible stateChange is "UNUSED", <br/>Example value: 3.5s. | Optional |  
| fieldMask | A field mask is used to specify the specific response fields to be listed in the response.<br/>An empty field mask will list all fields. Comma-separated values are supported in this parameter.<br/>Example: "asset.resourceProperties.owner,asset.securityCenterProperties.resourceName". | Optional | 
| pageToken | The value returned by the last response of the google-cloud-scc-asset-list command indicates that this is a continuation of prior assets.list call, and that the system should return the next page of data. | Optional | 
| pageSize | The maximum number of results to return in a single response. The minimum value is 1 and maximum value is 1000. Default is 10. | Optional | 
| resourceType |  This parameter is used to filter assets by resource types by providing a single value or a comma-separated value of resource types. If any resource type is not provided, by default all resource types will be considered for listing assets.The value provided inside resourceType would be applied in the query as a filter parameter for filtering results. Example: cloudfunction, bucket. | Optional | 
| project | This parameter is used to filter assets by the project by providing a single value or a comma-separated value of projects. If any project is not provided, by default all projects will be considered for listing assets. Value provided inside the project would be applied in the query as a filter parameter for filtering results. Example: Automeet, Backstory. | Optional | 
| activeAssetsOnly | This parameter is used to filter assets by their lifeCycleState value by selecting an option from the dropdown. If 'True' is selected the assets having lifeCycleState as 'ACTIVE' will be fetched and if 'False' or no option selected from the dropdown, then assets with all states will be considered for listing assets. The value selected in activeAssetsOnly would be applied in the query as a filter parameter for filtering results. Possible values are: True, False. Default is False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudSCC.Asset.name | String | The relative resource name of the asset. | 
| GoogleCloudSCC.Asset.securityCenterProperties.resourceName | String | The full resource name of the Google Cloud resource this asset represents. | 
| GoogleCloudSCC.Asset.securityCenterProperties.resourceType | String | The type of the Google Cloud resource. | 
| GoogleCloudSCC.Asset.securityCenterProperties.resourceParent | String | The full resource name of the immediate parent of the resource. | 
| GoogleCloudSCC.Asset.securityCenterProperties.resourceProject | String | The full resource name of the project the resource belongs to. | 
| GoogleCloudSCC.Asset.securityCenterProperties.resourceOwners | String | Owners of the Google Cloud resource. | 
| GoogleCloudSCC.Asset.securityCenterProperties.resourceDisplayName | String | The user defined display name for this resource. | 
| GoogleCloudSCC.Asset.securityCenterProperties.resourceParentDisplayName | String | The user defined display name for the parent of this resource. | 
| GoogleCloudSCC.Asset.securityCenterProperties.resourceProjectDisplayName | String | The user defined display name for the project of this resource. | 
| GoogleCloudSCC.Asset.securityCenterProperties.folders.resourceFolder | String | Full resource name of this folder. | 
| GoogleCloudSCC.Asset.securityCenterProperties.folders.resourceFolderDisplayName | String | The user defined display name for this folder. | 
| GoogleCloudSCC.Asset.resourceProperties | Unknown | Resource managed properties. These properties are managed and defined by the Google Cloud resource and cannot be modified by the user. Properties are varying from assets to assets. | 
| GoogleCloudSCC.Asset.securityMarks.name | String | The relative resource name of the SecurityMarks. | 
| GoogleCloudSCC.Asset.securityMarks.marks | String | Mutable user specified security marks belonging to the parent resource. | 
| GoogleCloudSCC.Asset.createTime | String | The time at which the asset was created in the Security Command Center. | 
| GoogleCloudSCC.Asset.updateTime | String | The time at which the asset was last updated, added, or deleted in Security Command Center. | 
| GoogleCloudSCC.Asset.iamPolicy.policyBlob | String | Cloud IAM Policy information associated with the Google Cloud resource described by the Security Command Center asset. | 
| GoogleCloudSCC.Asset.stateChange | String | State change of the asset between the points in time. | 
| GoogleCloudSCC.Asset.readTime | String | Time used for executing the list request. | 
| GoogleCloudSCC.Token.nextPageToken | String | Token to retrieve the next page of results, or empty if there are no more results. | 
| GoogleCloudSCC.Token.name | String | Name of the command. | 


#### Command Example
```!google-cloud-scc-asset-list pageSize="3"```

#### Context Example
```json
{
    "GoogleCloudSCC": {
        "Asset": [
            {
                "createTime": "2020-07-22T07:10:02.782Z",
                "iamPolicy": {
                    "policyBlob": "{\"bindings\":[{\"role\":\"roles/billing.admin\",\"members\":[\"group:gcp-billing-admins@test.com\",\"user:harsh.shah@test.com\",\"user:malhar@test.com\",\"user:shail.rabdu@test.com\"]},{\"role\":\"roles/billing.creator\",\"members\":[\"domain:test.com\",\"group:gcp-billing-admins@test.com\",\"user:harsh.shah@test.com\",\"user:malhar@test.com\",\"user:shail.rabdu@test.com\"]},{\"role\":\"roles/billing.user\",\"members\":[\"group:gcp-organization-admins@test.com\"]},{\"role\":\"roles/browser\",\"members\":[\"user:jignesh.patel@test.com\"]},{\"role\":\"roles/cloudfunctions.serviceAgent\",\"members\":[\"serviceAccount:service-org-595779152576@security-center-api.iam.gserviceaccount.com\"]},{\"role\":\"roles/cloudsql.admin\",\"members\":[\"serviceAccount:service-org-595779152576@security-center-api.iam.gserviceaccount.com\"]},{\"role\":\"roles/cloudsupport.admin\",\"members\":[\"group:gcp-organization-admins@test.com\"]},{\"role\":\"roles/compute.admin\",\"members\":[\"user:jignesh.patel@test.com\"]},{\"role\":\"roles/iam.organizationRoleAdmin\",\"members\":[\"group:gcp-organization-admins@test.com\"]},{\"role\":\"roles/iam.serviceAccountAdmin\",\"members\":[\"user:jignesh.patel@test.com\"]},{\"role\":\"roles/orgpolicy.policyAdmin\",\"members\":[\"group:gcp-organization-admins@test.com\"]},{\"role\":\"roles/owner\",\"members\":[\"user:harsh.shah@test.com\"]},{\"role\":\"roles/pubsub.editor\",\"members\":[\"serviceAccount:scc-test-sa-0908@gscc-demo-0908.iam.gserviceaccount.com\"]},{\"role\":\"roles/resourcemanager.folderAdmin\",\"members\":[\"group:gcp-organization-admins@test.com\"]},{\"role\":\"roles/resourcemanager.organizationAdmin\",\"members\":[\"group:gcp-organization-admins@test.com\",\"user:harsh.shah@test.com\",\"user:it.systems@test.com\",\"user:malhar@test.com\",\"user:shivang.patel@test.com\"]},{\"role\":\"roles/resourcemanager.organizationViewer\",\"members\":[\"group:gcp-billing-admins@test.com\",\"user:shivang.patel@test.com\"]},{\"role\":\"roles/resourcemanager.projectCreator\",\"members\":[\"group:gcp-organization-admins@test.com\",\"user:it.systems@test.com\"]},{\"role\":\"roles/securitycenter.admin\",\"members\":[\"domain:test.com\",\"group:gcp-organization-admins@test.com\",\"serviceAccount:scc-test-sa-0908@gscc-demo-0908.iam.gserviceaccount.com\",\"deleted:serviceAccount:scc-test-sa@gscc-demo.iam.gserviceaccount.com?uid\\u003d111170257821042589392\",\"serviceAccount:scc-test@calcium-vial-280707.iam.gserviceaccount.com\",\"user:jignesh.patel@test.com\",\"user:namrata.haridwari@test.com\",\"user:shivang.patel@test.com\"]},{\"role\":\"roles/securitycenter.serviceAgent\",\"members\":[\"serviceAccount:service-org-595779152576@security-center-api.iam.gserviceaccount.com\"]},{\"role\":\"roles/serviceusage.serviceUsageAdmin\",\"members\":[\"serviceAccount:service-org-595779152576@security-center-api.iam.gserviceaccount.com\"]},{\"role\":\"roles/viewer\",\"members\":[\"serviceAccount:scc-test-sa-0908@gscc-demo-0908.iam.gserviceaccount.com\",\"deleted:serviceAccount:scc-test-sa@gscc-demo.iam.gserviceaccount.com?uid\\u003d111170257821042589392\"]}]}"
                },
                "name": "organizations/595779152576/assets/7180457033309348544",
                "readTime": "2021-02-11T13:51:59.620Z",
                "resourceProperties": {
                    "creationTime": "2017-01-23T08:50:47.212Z",
                    "displayName": "test.com",
                    "lifecycleState": "ACTIVE",
                    "name": "organizations/595779152576",
                    "organizationId": "595779152576",
                    "owner": "{\"directoryCustomerId\":\"C02umwv6u\"}"
                },
                "securityCenterProperties": {
                    "resourceDisplayName": "test.com",
                    "resourceName": "//cloudresourcemanager.googleapis.com/organizations/595779152576",
                    "resourceType": "google.cloud.resourcemanager.Organization"
                },
                "securityMarks": {
                    "marks": {
                        "compressed": "SSH",
                        "LastSeen": "Yesterday"
                    },
                    "name": "organizations/595779152576/assets/7180457033309348544/securityMarks"
                },
                "updateTime": "2021-02-06T11:01:26.317Z"
            },
            {
                "createTime": "2020-12-16T10:05:58.742Z",
                "iamPolicy": {
                    "policyBlob": "{\"bindings\":[{\"role\":\"roles/owner\",\"members\":[\"user:milankumar.thummar@test.com\"]}]}"
                },
                "name": "organizations/595779152576/assets/2994068353411300094",
                "readTime": "2021-02-11T13:51:59.620Z",
                "resourceProperties": {
                    "createTime": "2020-12-16T10:05:54.696Z",
                    "lifecycleState": "ACTIVE",
                    "name": "Calender",
                    "parent": "{\"id\":\"595779152576\",\"type\":\"organization\"}",
                    "projectId": "calender-1608113154215",
                    "projectNumber": "455757558851"
                },
                "securityCenterProperties": {
                    "resourceDisplayName": "calender-1608113154215",
                    "resourceName": "//cloudresourcemanager.googleapis.com/projects/455757558851",
                    "resourceOwners": [
                        "user:milankumar.thummar@test.com"
                    ],
                    "resourceParent": "//cloudresourcemanager.googleapis.com/organizations/595779152576",
                    "resourceParentDisplayName": "test.com",
                    "resourceProject": "//cloudresourcemanager.googleapis.com/projects/455757558851",
                    "resourceProjectDisplayName": "calender-1608113154215",
                    "resourceType": "google.cloud.resourcemanager.Project"
                },
                "securityMarks": {
                    "marks": {
                        "compressed": "SSH",
                        "LastSeen": "Yesterday"
                    },
                    "name": "organizations/595779152576/assets/2994068353411300094/securityMarks"
                },
                "updateTime": "2020-12-16T10:06:00.134Z"
            },
            {
                "createTime": "2019-09-24T02:10:50.766Z",
                "iamPolicy": {
                    "policyBlob": "{\"bindings\":[{\"role\":\"roles/owner\",\"members\":[\"user:heena.vaghela@test.com\"]}]}"
                },
                "name": "organizations/595779152576/assets/14656821127596596302",
                "readTime": "2021-02-11T13:51:59.620Z",
                "resourceProperties": {
                    "createTime": "2019-08-13T06:58:21.574Z",
                    "lifecycleState": "ACTIVE",
                    "name": "Test Proj",
                    "parent": "{\"id\":\"595779152576\",\"type\":\"organization\"}",
                    "projectId": "test-proj-249706",
                    "projectNumber": "265894444436"
                },
                "securityCenterProperties": {
                    "resourceDisplayName": "test-proj-249706",
                    "resourceName": "//cloudresourcemanager.googleapis.com/projects/265894444436",
                    "resourceOwners": [
                        "user:heena.vaghela@test.com"
                    ],
                    "resourceParent": "//cloudresourcemanager.googleapis.com/organizations/595779152576",
                    "resourceParentDisplayName": "test.com",
                    "resourceProject": "//cloudresourcemanager.googleapis.com/projects/265894444436",
                    "resourceProjectDisplayName": "test-proj-249706",
                    "resourceType": "google.cloud.resourcemanager.Project"
                },
                "securityMarks": {
                    "name": "organizations/595779152576/assets/14656821127596596302/securityMarks"
                },
                "updateTime": "2020-04-16T06:09:38.488Z"
            }
        ],
        "Token": {
            "name": "google-cloud-scc-asset-list",
            "nextPageToken": "next-page-token"
        }
    }
}
```

#### Human Readable Output

>### Total retrieved asset(s): 3
>|Name|Project|Resource Name|Resource Type|Resource Owners|Security Marks|
>|---|---|---|---|---|---|
>| [organizations/595779152576/assets/7180457033309348544](https://console.cloud.google.com/security/command-center/assets?organizationId=595779152576&resourceId=organizations/595779152576/assets/7180457033309348544) | organizations/595779152576 | //cloudresourcemanager.googleapis.com/organizations/595779152576 | google.cloud.resourcemanager.Organization |  | compressed: SSH<br/>LastSeen: Yesterday |
>| [organizations/595779152576/assets/2994068353411300094](https://console.cloud.google.com/security/command-center/assets?organizationId=595779152576&resourceId=organizations/595779152576/assets/2994068353411300094) | Calender | //cloudresourcemanager.googleapis.com/projects/455757558851 | google.cloud.resourcemanager.Project | user:milankumar.thummar@test.com | compressed: SSH<br/>LastSeen: Yesterday |
>| [organizations/595779152576/assets/14656821127596596302](https://console.cloud.google.com/security/command-center/assets?organizationId=595779152576&resourceId=organizations/595779152576/assets/14656821127596596302) | Test Proj | //cloudresourcemanager.googleapis.com/projects/265894444436 | google.cloud.resourcemanager.Project | user:heena.vaghela@test.com |  |



### google-cloud-scc-finding-list
***
Lists an organization or source's findings.


#### Base Command

`google-cloud-scc-finding-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| severity | Filter findings by their severity (LOW, MEDIUM, HIGH, CRITICAL). Comma-separated values are supported and if any severity value is not provided, by default all the severities will be considered for listing of findings. Value provided inside severity would be applied in the query as a filter parameter for filtering results. | Optional | 
| category | Filter findings by providing comma-separated values of categories or a single category.<br/>If any category value is not provided, by default all the categories will be considered for listing findings.<br/>Value provided inside the category would be applied in the query as a filter parameter for filtering results.<br/>For Example: anomaly,application. | Optional | 
| sourceTypeId | Filter findings by providing the value of a single source type. If any source type Id value  is not provided, by default all source types will be considered for list findings. Default is -. | Optional | 
| pageSize | The maximum number of results to return in a single response. The minimum value is 1 and maximum value is 1000. Default is 10. | Optional | 
| state | Filter the findings by their state. Can be 'ACTIVE', 'INACTIVE'. Comma-separated values are supported and if any state value is not provided, by default 'ACTIVE' state will be considered for listing of findings. Value provided inside the state would be applied in the query as a filter parameter for filtering results. Default is ACTIVE. | Optional | 
| filter | The filter  expression is a list of one or more restrictions combined via logical operators AND and OR.<br/>Parentheses are supported, and OR has higher precedence than AND.Examples include:<br/>1) name<br/>2) sourceProperties.a_property<br/>3) securityMarks.marks.marka<br/><br/>The supported operators are:<br/>1) = for all value types.<br/>2) &gt;, &lt;, &gt;=, &lt;= for integer values.<br/>3) :, meaning substring matching, for strings.<br/><br/>The following field and operator combinations are supported:<br/>1) name: =<br/>2) parent: =, :<br/>3) resourceName: =, :<br/>4) state: =, :<br/>5) category: =, :<br/>6) externalUri: =, :<br/>7) eventTime: =, &gt;, &lt;, &gt;=, &lt;=<br/>8) severity: =, :<br/>9) findingClass: =<br/><br/>Examples: "sourceProperties.browser="chrome" AND sourceProperties.event_type="proximity""<br/>Use a negated partial match on the empty string to filter based on a property not existing: "-severity=LOW". | Optional |  
| orderBy | This parameter defines what fields and order to use for sorting.<br/>The string value should be a comma separated list of fields. The default sorting order is ascending.<br/>To specify descending order for a field, a suffix " desc" should be appended to the field name.<br/>For example: "name desc,sourceProperties.browser".<br/>Supported fields: name, parent, state, category, resourceName, eventTime, sourceProperties, securityMarks.marks. | Optional | 
| compareDuration | When compareDuration is set, the "stateChange" attribute is updated to indicate whether the finding had its state changed, the finding's state remained unchanged, or if the finding was added in any state during the compareDuration period of time that precedes the readTime. This is the time between (readTime - compareDuration) and readTime.<br/>The results aren't affected if the finding is made inactive and then active again.<br/><br/>Possible "stateChange" values when compareDuration is specified:<br/>1) CHANGED<br/>2) UNCHANGED<br/>3) ADDED<br/>4) REMOVED<br/><br/>If compareDuration is not specified, then the only possible stateChange is "UNUSED".<br/>Example value: "3.5s". | Optional |  
| readTime | Time used as a reference point when filtering findings. The filter is limited to findings existing at the supplied time and their values are those at that specific time. If not provided, it will take current time. <br/>Format: YYYY-MM-ddTHH:mm:ss.sssZ<br/>Example: 2020-07-22T07:10:02.782Z. | Optional | 
| fieldMask | A field mask is used to specify the specific response fields to be listed in the response.<br/>An empty field mask will list all fields. Comma-separated values are supported in this parameter.<br/>Example: "user.displayName,sourceProperties.browser". | Optional | 
| pageToken | The value returned by the last response of a google-cloud-scc-finding-list command indicates that this is a continuation of a prior findings.list call, and that the system should return the next page of data. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudSCC.Finding.name | String | The relative resource name of this finding. | 
| GoogleCloudSCC.Finding.parent | String | The relative resource name of the source the finding belongs to. | 
| GoogleCloudSCC.Finding.resourceName | String | For findings on Google Cloud resources, the full resource name of the Google Cloud resource this finding is for. | 
| GoogleCloudSCC.Finding.state | String | The state of the finding. | 
| GoogleCloudSCC.Finding.category | String | The additional taxonomy group within findings from a given source. | 
| GoogleCloudSCC.Finding.externalUri | String | The URI that, if available, points to a web page outside of Security Command Center where additional information about the finding can be found. | 
| GoogleCloudSCC.Finding.createTime | String | The time at which the finding was created in Security Command Center. | 
| GoogleCloudSCC.Finding.eventTime | String | The time at which the event took place, or when an update to the finding occurred. | 
| GoogleCloudSCC.Finding.resource.name | String | The full resource name of the resource. | 
| GoogleCloudSCC.Finding.resource.parentDisplayName | String | The human readable name of resource's parent. | 
| GoogleCloudSCC.Finding.resource.parentName | String | The full resource name of resource's parent. | 
| GoogleCloudSCC.Finding.resource.projectDisplayName | String | The human readable name of project that the resource belongs to. | 
| GoogleCloudSCC.Finding.resource.projectName | String | The full resource name of the project that the resource belongs to. | 
| GoogleCloudSCC.Finding.resource.folders.resourceFolder | String | Full resource name of this folder. | 
| GoogleCloudSCC.Finding.resource.folders.resourceFolderDisplayName | String | The user defined display name for this folder. | 
| GoogleCloudSCC.Finding.stateChange | String | State change of the finding between the points in time. | 
| GoogleCloudSCC.Finding.sourceProperties | Unknown | Source specific properties. These properties are managed by the source that writes the finding. Properties are varying from finding to finding. | 
| GoogleCloudSCC.Finding.severity | String | Severity of the finding. | 
| GoogleCloudSCC.Finding.securityMarks.name | String | The relative resource name of the SecurityMarks. | 
| GoogleCloudSCC.Finding.securityMarks.marks | String | Mutable user specified security marks belonging to the parent resource. | 
| GoogleCloudSCC.Finding.readTime | String | Time used for executing the list request. | 
| GoogleCloudSCC.Token.nextPageToken | String | Token to retrieve the next page of results, or empty if there are no more results. | 
| GoogleCloudSCC.Token.name | String | Name of the command. | 


#### Command Example
```!google-cloud-scc-finding-list sourceTypeId="-" pageSize="3" state="ACTIVE"```

#### Context Example
```json
{
    "GoogleCloudSCC": {
        "Finding": [
            {
                "category": "page",
                "createTime": "2020-05-15T05:57:46.641Z",
                "eventTime": "2021-02-11T09:33:30.716Z",
                "externalUri": "http://www.fake-url.com",
                "name": "organizations/595779152576/sources/10134421585261057824/findings/00002906967111ea87141217baf6db4d",
                "parent": "organizations/595779152576/sources/10134421585261057824",
                "readTime": "2021-02-11T13:52:10.594Z",
                "resource": {
                    "name": "//cloudresourcemanager.googleapis.com/projects/339295427573",
                    "parentDisplayName": "test.com",
                    "parentName": "//cloudresourcemanager.googleapis.com/organizations/595779152576",
                    "projectDisplayName": "gscc-demo-0908",
                    "projectName": "//cloudresourcemanager.googleapis.com/projects/339295427573"
                },
                "resourceName": "//cloudresourcemanager.googleapis.com/projects/339295427573",
                "securityMarks": {
                    "name": "organizations/595779152576/sources/10134421585261057824/findings/00002906967111ea87141217baf6db4d/securityMarks"
                },
                "sourceProperties": {
                    "access_method": "IPSec",
                    "appcategory": "Technology",
                    "bypass_traffic": "yes",
                    "category": "Technology",
                    "ccl": "unknown",
                    "count": "1",
                    "domain": "www.fake-url.com",
                    "dst_country": "US",
                    "dst_geoip_src": "2",
                    "dst_latitude": 35.7319,
                    "dst_location": "Morganton",
                    "dst_longitude": -81.7091,
                    "dst_region": "North Carolina",
                    "dst_zipcode": "28655",
                    "dstip": "127.0.0.1",
                    "id": "fda1f2cb566f247dac4c4c77",
                    "insertion_epoch_timestamp": "1584069016",
                    "organization_unit": "None",
                    "page": "www.fake-url.com",
                    "page_id": "0",
                    "policy": "Domains",
                    "site": "apple",
                    "src_country": "US",
                    "src_geoip_src": "2",
                    "src_latitude": 37.4073,
                    "src_location": "San Jose",
                    "src_longitude": -121.939,
                    "src_region": "California",
                    "src_zipcode": "95134",
                    "srcip": "127.0.0.1",
                    "ssl_decrypt_policy": "no",
                    "tenant_name": "partners",
                    "timestamp": "1584069012",
                    "traffic_type": "Web",
                    "transaction_id": "0",
                    "type": "page",
                    "ur_normalized": "127.0.0.1",
                    "url": "www.fake-url.com",
                    "user": "127.0.0.1",
                    "user_generated": "yes",
                    "userip": "127.0.0.1"
                },
                "state": "ACTIVE"
            },
            {
                "category": "page",
                "createTime": "2020-05-30T15:19:49.539Z",
                "eventTime": "2021-02-11T07:21:45.317Z",
                "name": "organizations/595779152576/sources/10134421585261057824/findings/00002ccaa28911ea9d221217baf6db4d",
                "parent": "organizations/595779152576/sources/10134421585261057824",
                "readTime": "2021-02-11T13:52:10.594Z",
                "resource": {
                    "name": "//cloudresourcemanager.googleapis.com/projects/339295427573",
                    "parentDisplayName": "test.com",
                    "parentName": "//cloudresourcemanager.googleapis.com/organizations/595779152576",
                    "projectDisplayName": "gscc-demo-0908",
                    "projectName": "//cloudresourcemanager.googleapis.com/projects/339295427573"
                },
                "resourceName": "//cloudresourcemanager.googleapis.com/projects/339295427573",
                "securityMarks": {
                    "name": "organizations/595779152576/sources/10134421585261057824/findings/00002ccaa28911ea9d221217baf6db4d/securityMarks"
                },
                "state": "ACTIVE"
            },
            {
                "category": "page",
                "createTime": "2020-05-30T02:41:01.848Z",
                "eventTime": "2020-03-16T01:38:52Z",
                "externalUri": "http://www.fake-url.com",
                "name": "organizations/595779152576/sources/10134421585261057824/findings/000031c6a21f11ea9d221217baf6db4d",
                "parent": "organizations/595779152576/sources/10134421585261057824",
                "readTime": "2021-02-11T13:52:10.594Z",
                "resource": {
                    "name": "//cloudresourcemanager.googleapis.com/projects/339295427573",
                    "parentDisplayName": "test.com",
                    "parentName": "//cloudresourcemanager.googleapis.com/organizations/595779152576",
                    "projectDisplayName": "gscc-demo-0908",
                    "projectName": "//cloudresourcemanager.googleapis.com/projects/339295427573"
                },
                "resourceName": "//cloudresourcemanager.googleapis.com/projects/339295427573",
                "securityMarks": {
                    "name": "organizations/595779152576/sources/10134421585261057824/findings/000031c6a21f11ea9d221217baf6db4d/securityMarks"
                },
                "sourceProperties": {
                    "access_method": "IPSec",
                    "app": "LinkedIn",
                    "appcategory": "Social",
                    "bypass_traffic": "yes",
                    "category": "Social",
                    "cci": "65",
                    "ccl": "medium",
                    "count": "1",
                    "domain": "www.fake-url.com",
                    "dst_country": "US",
                    "dst_geoip_src": "1",
                    "dst_latitude": 37.368889,
                    "dst_location": "Sunnyvale",
                    "dst_longitude": -122.035278,
                    "dst_region": "California",
                    "dst_timezone": "N/A",
                    "dst_zipcode": "N/A",
                    "dstip": "127.0.0.1",
                    "id": "567a33f799d411dab82da23e",
                    "insertion_epoch_timestamp": "1584322739",
                    "organization_unit": "None",
                    "page": "www.fake-url.com",
                    "page_id": "0",
                    "policy": "No_Decrypt",
                    "site": "Linkedin",
                    "src_country": "US",
                    "src_geoip_src": "2",
                    "src_latitude": 37.4073,
                    "src_location": "San Jose",
                    "src_longitude": -121.939,
                    "src_region": "California",
                    "src_zipcode": "95134",
                    "srcip": "127.0.0.1",
                    "ssl_decrypt_policy": "yes",
                    "tenant_name": "partners",
                    "timestamp": "1584322732",
                    "traffic_type": "CloudApp",
                    "transaction_id": "0",
                    "type": "page",
                    "ur_normalized": "127.0.0.1",
                    "url": "www.fake-url.com",
                    "user": "127.0.0.1",
                    "user_generated": "yes",
                    "userip": "127.0.0.1"
                },
                "state": "ACTIVE"
            }
        ],
        "Token": {
            "name": "google-cloud-scc-finding-list",
            "nextPageToken": "next-page-token"
        }
    }
}
```

#### Human Readable Output

>### Total retrieved finding(s): 3
>|Name|Category|Resource Name|Finding Class|Event Time|Create Time|Security Marks|
>|---|---|---|---|---|---|---|
>| [organizations/595779152576/sources/10134421585261057824/findings/00002906967111ea87141217baf6db4d](https://console.cloud.google.com/security/command-center/findings?organizationId=595779152576&resourceId=organizations/595779152576/sources/10134421585261057824/findings/00002906967111ea87141217baf6db4d) | page | //cloudresourcemanager.googleapis.com/projects/339295427573 | THREAT | February 11, 2021 at 09:33:30 AM | May 15, 2020 at 05:57:46 AM | { "name": "wrench", "count": "3" } |
>| [organizations/595779152576/sources/10134421585261057824/findings/00002ccaa28911ea9d221217baf6db4d](https://console.cloud.google.com/security/command-center/findings?organizationId=595779152576&resourceId=organizations/595779152576/sources/10134421585261057824/findings/00002ccaa28911ea9d221217baf6db4d) | page | //cloudresourcemanager.googleapis.com/projects/339295427573 | THREAT | February 11, 2021 at 07:21:45 AM | May 30, 2020 at 03:19:49 PM | { "name": "wrench", "count": "3" } |
>| [organizations/595779152576/sources/10134421585261057824/findings/000031c6a21f11ea9d221217baf6db4d](https://console.cloud.google.com/security/command-center/findings?organizationId=595779152576&resourceId=organizations/595779152576/sources/10134421585261057824/findings/000031c6a21f11ea9d221217baf6db4d) | page | //cloudresourcemanager.googleapis.com/projects/339295427573 | THREAT | March 16, 2020 at 01:38:52 AM | May 30, 2020 at 02:41:01 AM | { "name": "wrench", "count": "3" } |



### google-cloud-scc-finding-update
***
Update an organization's or source's finding.


#### Base Command

`google-cloud-scc-finding-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The relative resource name of the finding.<br/>Format: organizations/{organization_id}/sources/{source_id}/finding/{findingId}<br/>Example: organizations/595779152576/sources/14801394649435054450/findings/bc5a86da657611ebb979005056a5924e. | Required | 
| eventTime | Time at which the event took place. By default UTC current time will be taken if no value is provided in eventTime.<br/>Format: YYYY-MM-ddTHH:mm:ss.sssZ<br/>Example: 2020-07-22T07:10:02.782Z, 2014-10-02T15:01:23.045123456Z. | Optional | 
| severity | Related severity of the finding. Possible values are: LOW, MEDIUM, HIGH, CRITICAL. | Optional | 
| externalUri | URI that points to a web page outside of Cloud SCC (Security Command Center) where additional information about the finding can be found. | Optional | 
| sourceProperties | Source specific properties. These properties are managed by the source that writes the finding. For example "key1=val1,key2=val2". | Optional | 
| updateMask | A updateMask argument supports single or comma-separated fields that need to be updated/deleted. A updateMask is automatically generated in the backend for the specific arguments provided in the command and only those values will be updated. To delete attributes/properties, add those keys in updateMask without specifying those fields individually in the command arguments. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudSCC.Finding.name | String | The relative resource name of this finding. | 
| GoogleCloudSCC.Finding.parent | String | The relative resource name of the source the finding belongs to. | 
| GoogleCloudSCC.Finding.resourceName | String | For findings on Google Cloud resources, the full resource name of the Google Cloud resource this finding is for. | 
| GoogleCloudSCC.Finding.state | String | The state of the finding. | 
| GoogleCloudSCC.Finding.category | String | The additional taxonomy group within findings from a given source. | 
| GoogleCloudSCC.Finding.externalUri | String | The URI that, if available, points to a web page outside of Security Command Center where additional information about the finding can be found. | 
| GoogleCloudSCC.Finding.createTime | String | The time at which the finding was created in Security Command Center. | 
| GoogleCloudSCC.Finding.eventTime | String | The time at which the event took place, or when an update to the finding occurred. | 
| GoogleCloudSCC.Finding.sourceProperties | Unknown | Source specific properties. These properties are managed by the source that writes the finding. Properties are varying from finding to finding. | 
| GoogleCloudSCC.Finding.severity | String | Severity of the finding. | 
| GoogleCloudSCC.Finding.securityMarks.name | String | The relative resource name of the SecurityMarks. | 
| GoogleCloudSCC.Finding.securityMarks.marks | String | Mutable user specified security marks belonging to the parent resource. | 


#### Command Example
```!google-cloud-scc-finding-update name="organizations/595779152576/sources/10134421585261057824/findings/00002906967111ea87141217baf6db4d"```

#### Context Example
```json
{
    "GoogleCloudSCC": {
        "Finding": {
            "category": "page",
            "createTime": "2020-05-15T05:57:46.641Z",
            "eventTime": "2021-02-11T13:52:25.986162Z",
            "externalUri": "http://www.fake-url.com",
            "name": "organizations/595779152576/sources/10134421585261057824/findings/00002906967111ea87141217baf6db4d",
            "parent": "organizations/595779152576/sources/10134421585261057824",
            "resourceName": "//cloudresourcemanager.googleapis.com/projects/339295427573",
            "securityMarks": {
                "name": "organizations/595779152576/sources/10134421585261057824/findings/00002906967111ea87141217baf6db4d/securityMarks"
            },
            "sourceProperties": {
                "access_method": "IPSec",
                "appcategory": "Technology",
                "bypass_traffic": "yes",
                "category": "Technology",
                "ccl": "unknown",
                "count": "1",
                "domain": "www.fake-url.com",
                "dst_country": "US",
                "dst_geoip_src": "2",
                "dst_latitude": 35.7319,
                "dst_location": "Morganton",
                "dst_longitude": -81.7091,
                "dst_region": "North Carolina",
                "dst_zipcode": "28655",
                "dstip": "127.0.0.1",
                "id": "fda1f2cb566f247dac4c4c77",
                "insertion_epoch_timestamp": "1584069016",
                "organization_unit": "None",
                "page": "www.fake-url.com",
                "page_id": "0",
                "policy": "Domains",
                "site": "apple",
                "src_country": "US",
                "src_geoip_src": "2",
                "src_latitude": 37.4073,
                "src_location": "San Jose",
                "src_longitude": -121.939,
                "src_region": "California",
                "src_zipcode": "95134",
                "srcip": "127.0.0.1",
                "ssl_decrypt_policy": "no",
                "tenant_name": "partners",
                "timestamp": "1584069012",
                "traffic_type": "Web",
                "transaction_id": "0",
                "type": "page",
                "ur_normalized": "127.0.0.1",
                "url": "www.fake-url.com",
                "user": "127.0.0.1",
                "user_generated": "yes",
                "userip": "127.0.0.1"
            },
            "state": "ACTIVE"
        }
    }
}
```

#### Human Readable Output

>### The finding has been updated successfully.
>|Name|State|Category|Event Time|Create Time|External Uri|Resource Name|
>|---|---|---|---|---|---|---|
>| [organizations/595779152576/sources/10134421585261057824/findings/00002906967111ea87141217baf6db4d](https://console.cloud.google.com/security/command-center/findings?organizationId=595779152576&resourceId=organizations/595779152576/sources/10134421585261057824/findings/00002906967111ea87141217baf6db4d) | ACTIVE | page | February 11, 2021 at 01:52:25 PM | May 15, 2020 at 05:57:46 AM | [http://www.fake-url.com](http://www.fake-url.com) | //cloudresourcemanager.googleapis.com/projects/339295427573 |


### google-cloud-scc-asset-resource-list
***
Lists cloud asset's resources.


#### Base Command

`google-cloud-scc-asset-resource-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| parent | Name of the organization or project the assets belong to. Organization Id provided in the Integration Configuration will be taken by default, if no value is provided to the parent.<br/><br/>Format: "organizations/[organization-number]" (such as "organizations/123"), "projects/[project-id]" (such as "projects/my-project-id"), or "projects/[project-number]" (such as "projects/12345"). | Optional | 
| assetTypes | This parameter is used to filter assets by asset types by providing a single value or a comma-separated value of asset types.<br/>For example: "compute.googleapis.com/Disk".<br/><br/>Regular expression is also supported. <br/>For example:<br/>1) "compute.googleapis.com.*" resources whose asset type starts with "compute.googleapis.com".<br/>2) ".*Instance" resources whose asset type ends with "Instance".<br/>3) ".*Instance.*" resources whose asset type contains "Instance". | Optional | 
| pageSize | The maximum number of results to return in a single response. The minimum value is 1 and maximum value is 1000. Default is 10. | Optional | 
| pageToken | The nextPageToken returned from the previous scc-asset-resource-list command response, or unspecified for the first  scc-asset-resource-list command. It is a continuation of a prior scc-asset-resource-list call, and the API should return the next page of assets. | Optional | 
| readTime | Time used as a reference point when filtering assets. This can only be set to a timestamp between the current time and the current time minus 35 days (inclusive). If not provided, it will take current time. <br/><br/>Format:<br/>(&lt;number&gt; &lt;time unit&gt;, e.g., "12 hours ago", "7 days ago", "1 week", "1 month") or (&lt;date&gt; &lt;time&gt;, e.g. "yyyy-mm-ddTHH-MM-SS") or ( "YYYY-MM-ddTHH:mm:ss.sssZ", e.g. 2020-07-22T07:10:02.782Z) or (&lt;date&gt;, e.g. "2020-07-22"). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudSCC.CloudAsset.Resource.name | String | The full name of the asset. | 
| GoogleCloudSCC.CloudAsset.Resource.assetType | String | The type of the asset. | 
| GoogleCloudSCC.CloudAsset.Resource.updateTime | String | The last update timestamp of an asset. The updateTime is updated when create/update/delete operation is performed. | 
| GoogleCloudSCC.CloudAsset.Resource.readTime | String | Time used for executing the list request. | 
| GoogleCloudSCC.CloudAsset.Resource.ancestors | Unknown | The ancestry path of an asset in Google Cloud resource hierarchy, represented as a list of relative resource names. An ancestry path starts with the closest ancestor in the hierarchy and ends at root. If the asset is a project, folder, or organization, the ancestry path starts from the asset itself. | 
| GoogleCloudSCC.CloudAsset.Resource.resource.version | String | The API version. | 
| GoogleCloudSCC.CloudAsset.Resource.resource.discoveryDocumentUri | String | The URL of the discovery document containing the resource's JSON schema. This value is unspecified for resources that do not have an API based on a discovery document, such as Cloud Bigtable. | 
| GoogleCloudSCC.CloudAsset.Resource.resource.discoveryName | String | The JSON schema name listed in the discovery document. This value is unspecified for resources that do not have an API based on a discovery document, such as Cloud Bigtable. | 
| GoogleCloudSCC.CloudAsset.Resource.resource.resourceUrl | String | The REST URL for accessing the resource. An HTTP GET request using this URL returns the resource itself. | 
| GoogleCloudSCC.CloudAsset.Resource.resource.parent | String | The full name of the immediate parent of this resource. For third-party assets, this field may be set differently. | 
| GoogleCloudSCC.CloudAsset.Resource.resource.data | String | The content of the resource, in which some sensitive fields are removed and may not be present. | 
| GoogleCloudSCC.CloudAsset.Resource.resource.location | String | The location of the resource in Google Cloud, such as its zone and region. | 
| GoogleCloudSCC.Token.name | String | Name of the command. | 
| GoogleCloudSCC.Token.nextPageToken | String | Token to retrieve the next page of results, or empty if there are no more results. | 


#### Command Example
```!google-cloud-scc-asset-resource-list pageSize=2```

#### Context Example
```json
{
    "GoogleCloudSCC": {
        "CloudAsset": {
            "Resource": [
                {
                    "ancestors": [
                        "organizations/123456789"
                    ],
                    "assetType": "cloudbilling.googleapis.com/BillingAccount",
                    "name": "//cloudbilling.googleapis.com/billingAccounts/12345-6789",
                    "readTime": "2021-06-17T10:19:59.557941456Z",
                    "resource": {
                        "data": {
                            "displayName": "My Billing Account",
                            "name": "billingAccounts/12345-6789"
                        },
                        "discoveryDocumentUri": "https://cloudbilling.googleapis.com/$discovery/rest",
                        "discoveryName": "BillingAccount",
                        "location": "global",
                        "version": "v1"
                    },
                    "updateTime": "2020-08-21T09:05:39.425Z"
                },
                {
                    "ancestors": [
                        "organizations/123456789"
                    ],
                    "assetType": "cloudbilling.googleapis.com/BillingAccount",
                    "name": "//cloudbilling.googleapis.com/billingAccounts/23456-7890",
                    "readTime": "2021-06-17T10:19:59.557941456Z",
                    "resource": {
                        "data": {
                            "displayName": "Our-Account",
                            "name": "billingAccounts/23456-7890"
                        },
                        "discoveryDocumentUri": "https://cloudbilling.googleapis.com/$discovery/rest",
                        "discoveryName": "BillingAccount",
                        "location": "global",
                        "version": "v1"
                    },
                    "updateTime": "2021-04-01T19:38:12.836197Z"
                }
            ]
        },
        "Token": {
            "name": "google-cloud-scc-asset-resource-list",
            "nextPageToken": "dummy"
        }
    }
}
```

#### Human Readable Output

>|Asset Name|Asset Type|Discovery Name|Ancestors|Update Time (In UTC)|
>|---|---|---|---|---|
>| //cloudbilling.googleapis.com/billingAccounts/12345-6789 | cloudbilling.googleapis.com/BillingAccount | BillingAccount | organizations/123456789 | August 21, 2020 at 09:05:39 AM |
>| //cloudbilling.googleapis.com/billingAccounts/23456-7890 | cloudbilling.googleapis.com/BillingAccount | BillingAccount | organizations/123456789 | April 01, 2021 at 07:38:12 PM |


### google-cloud-scc-asset-owner-get
***
Gets the owner information for the provided projects.


#### Base Command

`google-cloud-scc-asset-owner-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| projectName | Name of the project. Supports comma separated values.<br/><br/>Format: "projects/[project-number]" or for multiple projects "projects/[first-project-number], projects/[second-project-number]". | Required | 
| maxIteration | Number of iterations to search the owner information. Each iteration retrieves 1000 records. The minimum value is 1 and maximum value is 10. Default is 2. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudSCC.CloudAsset.IamPolicy.name | String | The full name of the asset. | 
| GoogleCloudSCC.CloudAsset.IamPolicy.owners | Unknown | List of owners of the asset. | 
| GoogleCloudSCC.CloudAsset.IamPolicy.assetType | String | The type of the asset. | 
| GoogleCloudSCC.CloudAsset.IamPolicy.updateTime | String | The last update timestamp of an asset. The updateTime is updated when create/update/delete operation is performed. | 
| GoogleCloudSCC.CloudAsset.IamPolicy.readTime | String | Time used for executing the list request. | 
| GoogleCloudSCC.CloudAsset.IamPolicy.ancestors | Unknown | The ancestry path of an asset in Google Cloud resource hierarchy, represented as a list of relative resource names. An ancestry path starts with the closest ancestor in the hierarchy and ends at root. If the asset is a project, folder, or organization, the ancestry path starts from the asset itself. | 
| GoogleCloudSCC.CloudAsset.IamPolicy.version | String | Specifies the format of the policy. | 
| GoogleCloudSCC.CloudAsset.IamPolicy.etag | String | The etag is used for optimistic concurrency control as a way to help prevent simultaneous updates of a policy from overwriting each other. It is strongly suggested that systems make use of the etag in the read-modify-write cycle to perform policy updates in order to avoid race conditions: An etag is returned in the response to getIamPolicy, and systems are expected to put that etag in the request to setIamPolicy to ensure that their change will be applied to the same version of the policy. | 
| GoogleCloudSCC.CloudAsset.IamPolicy.bindings.role | String | A role is a named collection of permissions that provide the ability to perform actions on Google Cloud resources. | 
| GoogleCloudSCC.CloudAsset.IamPolicy.bindings.members | Unknown | A member, also known as an identity or principal, which can be a user account, service account, Google group, or domain. | 
| GoogleCloudSCC.CloudAsset.IamPolicy.bindings.condition | String | A condition, which is an optional logic expression that further constrains the role binding based on attributes about the request, such as its origin, the target resource, and so on. Conditions are typically used to control whether access is granted based on the context for a request. | 
| GoogleCloudSCC.CloudAsset.IamPolicy.auditConfigs.service | String | Specifies a service that will be enabled for audit logging. | 
| GoogleCloudSCC.CloudAsset.IamPolicy.auditConfigs.auditLogConfigs.logType | String | The log type that this config enables. | 
| GoogleCloudSCC.CloudAsset.IamPolicy.auditConfigs.auditLogConfigs.exemptedMembers | String | Specifies the identities that do not cause logging for this type of permission. | 


#### Command Example
```!google-cloud-scc-asset-owner-get projectName="projects/123456789"```

#### Context Example
```json
{
    "GoogleCloudSCC": {
        "CloudAsset": {
            "IamPolicy": {
                "ancestors": [
                    "projects/123456789",
                    "organizations/123456789"
                ],
                "assetType": "cloudresourcemanager.googleapis.com/Project",
                "iamPolicy": {
                    "bindings": [
                        {
                            "members": [
                                "serviceAccount:dummmyaccount@dummycom",
                                "user:dummmyuser1@dummycom"
                            ],
                            "role": "roles/owner"
                        }
                    ],
                    "etag": "BwV9ONRnkz4=",
                    "version": 1
                },
                "name": "//cloudresourcemanager.googleapis.com/projects/123456789",
                "owners": [
                    "serviceAccount:dummmyaccount@dummycom",
                    "user:dummmyuser1@dummycom"
                ],
                "readTime": "2021-06-17T10:20:43.762746137Z",
                "updateTime": "2018-12-24T10:00:00Z"
            }
        }
    }
}
```

#### Human Readable Output

>|Project Name|Project Owner|Ancestors|Update Time (In UTC)|
>|---|---|---|---|
>| //cloudresourcemanager.googleapis.com/projects/123456789 | serviceAccount:dummmyaccount@dummycom,<br/>user:dummmyuser1@dummycom | projects/123456789,<br/>organizations/123456789 | December 24, 2018 at 10:00:00 AM |


### google-cloud-scc-finding-state-update
***
Update the state of organization's or source's finding.


#### Base Command

`google-cloud-scc-finding-state-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The relative resource name of the finding.<br/><br/>Format: organizations/{organization_id}/sources/{source_id}/finding/{findingId}<br/><br/>Example: organizations/595779152576/sources/14801394649435054450/findings/bc5a86da657611ebb979005056a5924e. | Required | 
| state | The desired state of the finding. Possible values are: ACTIVE, INACTIVE. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudSCC.Finding.name | String | The relative resource name of this finding. | 
| GoogleCloudSCC.Finding.parent | String | The relative resource name of the source the finding belongs to. | 
| GoogleCloudSCC.Finding.resourceName | String | For findings on Google Cloud resources, the full resource name of the Google Cloud resource this finding is for. | 
| GoogleCloudSCC.Finding.state | String | The state of the finding. | 
| GoogleCloudSCC.Finding.category | String | The additional taxonomy group within findings from a given source. | 
| GoogleCloudSCC.Finding.externalUri | String | The URI that, if available, points to a web page outside of Security Command Center where additional information about the finding can be found. | 
| GoogleCloudSCC.Finding.createTime | String | The time at which the finding was created in Security Command Center. | 
| GoogleCloudSCC.Finding.eventTime | String | The time at which the event took place, or when an update to the finding occurred. | 
| GoogleCloudSCC.Finding.sourceProperties | Unknown | Source specific properties. These properties are managed by the source that writes the finding. Properties are varying from finding to finding. | 
| GoogleCloudSCC.Finding.severity | String | Severity of the finding. | 
| GoogleCloudSCC.Finding.securityMarks.name | String | The relative resource name of the SecurityMarks. | 
| GoogleCloudSCC.Finding.securityMarks.marks | String | Mutable user specified security marks belonging to the parent resource. | 


#### Command Example
```!google-cloud-scc-finding-state-update name="organizations/595779152576/sources/10134421585261057824/findings/00002906967111ea87141217baf6db4d" state=ACTIVE"```

#### Context Example
```json
{
    "GoogleCloudSCC": {
        "Finding": {
            "category": "page",
            "createTime": "2020-05-15T05:57:46.641Z",
            "eventTime": "2021-02-11T13:52:25.986162Z",
            "externalUri": "http://www.fake-url.com",
            "name": "organizations/595779152576/sources/10134421585261057824/findings/00002906967111ea87141217baf6db4d",
            "parent": "organizations/595779152576/sources/10134421585261057824",
            "resourceName": "//cloudresourcemanager.googleapis.com/projects/339295427573",
            "securityMarks": {
                "name": "organizations/595779152576/sources/10134421585261057824/findings/00002906967111ea87141217baf6db4d/securityMarks"
            },
            "sourceProperties": {
                "access_method": "IPSec",
                "appcategory": "Technology",
                "bypass_traffic": "yes",
                "category": "Technology",
                "ccl": "unknown",
                "count": "1",
                "domain": "www.fake-url.com",
                "dst_country": "US",
                "dst_geoip_src": "2",
                "dst_latitude": 35.7319,
                "dst_location": "Morganton",
                "dst_longitude": -81.7091,
                "dst_region": "North Carolina",
                "dst_zipcode": "28655",
                "dstip": "127.0.0.1",
                "id": "fda1f2cb566f247dac4c4c77",
                "insertion_epoch_timestamp": "1584069016",
                "organization_unit": "None",
                "page": "www.fake-url.com",
                "page_id": "0",
                "policy": "Domains",
                "site": "apple",
                "src_country": "US",
                "src_geoip_src": "2",
                "src_latitude": 37.4073,
                "src_location": "San Jose",
                "src_longitude": -121.939,
                "src_region": "California",
                "src_zipcode": "95134",
                "srcip": "127.0.0.1",
                "ssl_decrypt_policy": "no",
                "tenant_name": "partners",
                "timestamp": "1584069012",
                "traffic_type": "Web",
                "transaction_id": "0",
                "type": "page",
                "ur_normalized": "127.0.0.1",
                "url": "www.fake-url.com",
                "user": "127.0.0.1",
                "user_generated": "yes",
                "userip": "127.0.0.1"
            },
            "state": "ACTIVE"
        }
    }
}
```

#### Human Readable Output

>### The finding has been updated successfully.
>|Name|State|Severity|Category|Event Time|Create Time|External Uri|Resource Name|
>|---|---|---|---|---|---|---|---|
>| [organizations/595779152576/sources/10134421585261057824/findings/00002906967111ea87141217baf6db4d](https://console.cloud.google.com/security/command-center/findings?organizationId=595779152576&resourceId=organizations/595779152576/sources/10134421585261057824/findings/00002906967111ea87141217baf6db4d) | ACTIVE | High | page | February 11, 2021 at 01:52:25 PM | May 15, 2020 at 05:57:46 AM | [http://www.fake-url.com](http://www.fake-url.com) | //cloudresourcemanager.googleapis.com/projects/339295427573 |


## Known Limitations
This integration supports only secure connection hence disabling SSL(Trust any certificate) support is not provided.
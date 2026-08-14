Security Command Center is a security and risk management platform for Google Cloud. Security Command Center enables you to understand your security and data attack surface by providing asset inventory and discovery, identifying vulnerabilities and threats, and helping you mitigate and remediate risks across an organization. This integration helps you to perform tasks related to findings and assets.
This integration was integrated and tested with version v1 of GoogleCloudSCC.

## Detailed Description

This integration uses Pub/Sub to fetch the incidents. This integration supports multiple organizations. In order to fetch data from multiple organizations, configure multiple instances for different organizations. To set up the initial parameters of Google SCC in Cortex XSOAR, please follow the below instructions. For more information, refer to this [guide](https://cloud.google.com/security-command-center/docs/how-to-configure-scc-cortex-xsoar) by Google SCC for configuring Cortex XSOAR Integration.

### Scope

We need to provide the below mentioned OAuth scope to execute the commands: https://www.googleapis.com/auth/cloud-platform.

### Create a Service Account

1. Go to the [Google documentation](https://developers.google.com/identity/protocols/OAuth2ServiceAccount#creatinganaccount) and follow the procedure mentioned in the _Creating a Service Account_ section. After you create a service account, a Service Account Private Key file is downloaded. You will need this file when configuring an instance of the integration.
2. Grant the Security Command Center admin permission to the Service Account to enable the Service Account to perform certain Google Cloud API commands.
3. For additional information on the types of permissions that can be granted to Service Account, see the _**Permissions**_ section below.
4. In Cortex XSOAR, configure an instance of the Google Cloud Security Command Center integration. For the Service Account Private Key parameter, add the Service Account Private Key file contents (JSON).

### Permissions

To set up Security Command Center or change the configuration of your organization, you need both of the following roles at the organization level:

* Organization Admin (roles/resourcemanager.organizationAdmin)
* Security Center Admin (roles/securitycenter.admin)

If a user doesn't require edit permissions, consider granting them viewer roles. To view all assets and findings in Security Command Center, users need the _**Security Center Admin Viewer**_ (roles/securitycenter.adminViewer) role at the organization level. Users who need to edit the findings need the _**Security Center Admin**_ (roles/securitycenter.admin) role at the organization level.

To restrict access to individual folders and projects, don't grant all roles at the organization level. Instead, grant the following roles at the folder or project level:

* Security Center Assets Viewer (roles/securitycenter.assetsViewer)
* Security Center Findings Viewer (roles/securitycenter.findingsViewer)

Refer to [Google Documentation](https://cloud.google.com/security-command-center/docs/access-control) for further information on granting roles to persons and applications, as well as specific permissions.

### Steps to configure workload identity federation

1. Follow the [steps](https://cloud.google.com/iam/docs/configuring-workload-identity-federation) to construct a workload identity pool and a workload identity pool provider to leverage workload identity federation.
2. Navigate to the '[Granting external identities permission to impersonate a service account](https://cloud.google.com/iam/docs/using-workload-identity-federation#impersonate)' section.
3. Follow the step-1 mentioned in the [Google documentation](https://cloud.google.com/iam/docs/using-workload-identity-federation#generate-automatic) to create a credential file for external identities. The contents of the downloaded file should be given into the 'Service Account Configuration' parameter.

   ### Prerequisite for accessing Google services from AWS

    1. [Create an IAM AWS Role.](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#create-iam-role)
    2. [Attach the IAM role to EC2 instance.](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#attach-iam-role)

   ### Prerequisite for accessing Google services from Azure

    1. [Create an Azure AD application and service principal.](https://docs.microsoft.com/en-au/azure/active-directory/develop/howto-create-service-principal-portal#register-an-application-with-azure-ad-and-create-a-service-principal)
    2. Set an **Application ID URI** for the application.
    3. [Create a managed identity](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/how-manage-user-assigned-managed-identities?pivots=identity-mi-methods-azp). Note the Object ID of the managed identity. You need it later when you configure impersonation.
    4. [Assign the managed identity](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/qs-configure-portal-windows-vm#user-assigned-managed-identity) to a virtual machine or another resource that runs your application.

### Getting your Organization ID

The Organization ID is a unique identifier for an organization and is automatically created when your organization resource is created.

1. To get the Organization ID for your organization, follow the steps mentioned in Google documentation provided [here](https://cloud.google.com/resource-manager/docs/creating-managing-organization#retrieving_your_organization_id).
2. To get your Organization ID using the Cloud Console, [Go to the Cloud Console](https://console.cloud.google.com/) and at the top of the page, click the project selection drop-down list and **from the Select** window that appears, click the organization drop-down list and select the organization you want.
3. On the right side, click **More**, then click **Settings**. The **Settings** page displays your organization's ID.

### Getting your Project ID

When we create a new project or for an existing project, Project ID generates for that project. To get the Project ID and the Project number, you can follow the same instructions provided above for getting Organization ID. For more details, You can follow the instructions provided in Google documentation [here](https://cloud.google.com/resource-manager/docs/creating-managing-projects).

### Getting Subscription ID from Pub/Sub

To fetch incidents using Google Pub/Sub, we need to configure Pub/Sub first. This [Google documentation](https://cloud.google.com/pubsub/docs/quickstart-console) will help setting up Pub/Sub prerequisites for creating a subscription.

1. To add a subscription, we need to have a topic first. So after you create a topic, go to the menu for the topic and click on **Create subscription** and it will take you to the _Add new subscription_ page.
2. Type a name for the subscription and leave the delivery type as **Pull**.
3. Set the Message retention duration to retain unacknowledged messages for a specified duration. If the checkbox of _Retain acknowledged messages_ is enabled, acknowledged messages are retained for the same duration. It is recommended to keep maximum possible value for Message retention so messages can be retained inside subscription until they are pulled.
4. Set the Acknowledgement deadline for pub/sub to wait for the subscriber to acknowledge receipt before resending the message. Minimum recommended value for Acknowledgement deadline is 300 seconds for this integration.
5. Apply the other settings as required and click on the CREATE button.
6. Once the subscription is created, it will take you to the Subscriptions page, where you can see the Subscription ID for the subscription you just created.

### Setting up finding notifications

* Enable the Security Command Center API notifications feature. Notifications send information to a Pub/Sub topic to provide findings updates and new findings within minutes. Set up the notifications as per [Google Documentation](https://cloud.google.com/security-command-center/docs/how-to-notifications) available and get SCC data in Cortex XSOAR.
* The basic parameters required for setting up pub/sub notifications are ORGANIZATION_ID, PUBSUB_TOPIC, DESCRIPTION and FILTER.
* Before creating a pub/sub notification, make sure to check the filter parameters using **google-cloud-scc-v2-finding-list** command provided in this integration (**google-cloud-scc-finding-list** is deprecated). The total size applicable for the filter provided can be checked using _Total retrieved findings_ available inside the command results section. A maximum of 200 findings per minute is recommended.

## Configure GoogleCloudSCC on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for GoogleCloudSCC.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Service Account Configuration | If the application runs on cloud provider (AWS, Azure) use workload identity federation configuration setup file otherwise use service account credential file. | True |
    | Organization ID | Organization ID defines from which organization incidents need to be fetched. | True |
    | Fetch incidents | Enables fetch incident. | False |
    | Project ID | ID of the project to use for fetching incidents. If ID is not provided it will be taken from the provided service account JSON. <br>Only required if the XSOAR instance is running on AWS or Azure cloud solutions. | False |
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
>
>| Organization ID |Name|Project|Resource Name|Resource Type|Resource Owners|Security Marks|
>|---|---|---|---|---|---|---|
>| 595779152576 | [organizations/595779152576/assets/7180457033309348544](https://console.cloud.google.com/security/command-center/assets?organizationId=595779152576&resourceId=organizations/595779152576/assets/7180457033309348544) | organizations/595779152576 | //cloudresourcemanager.googleapis.com/organizations/595779152576 | google.cloud.resourcemanager.Organization |  | compressed: SSH<br/>LastSeen: Yesterday |
>| 595779152576 | [organizations/595779152576/assets/2994068353411300094](https://console.cloud.google.com/security/command-center/assets?organizationId=595779152576&resourceId=organizations/595779152576/assets/2994068353411300094) | Calender | //cloudresourcemanager.googleapis.com/projects/455757558851 | google.cloud.resourcemanager.Project | user:milankumar.thummar@test.com | compressed: SSH<br/>LastSeen: Yesterday |
>| 595779152576 | [organizations/595779152576/assets/14656821127596596302](https://console.cloud.google.com/security/command-center/assets?organizationId=595779152576&resourceId=organizations/595779152576/assets/14656821127596596302) | Test Proj | //cloudresourcemanager.googleapis.com/projects/265894444436 | google.cloud.resourcemanager.Project | user:heena.vaghela@test.com |  |
>To fetch the next batch of results, execute the command with the page token as next-page-token

### google-cloud-scc-finding-list

***
Use [google-cloud-scc-v2-finding-list](#google-cloud-scc-v2-finding-list) instead. Lists an organization or source's findings.

This command is backed by the Security Command Center v1 API. Its own behavior, arguments and context outputs (`GoogleCloudSCC.Finding.*`) are unchanged, so existing playbooks keep working, but it will not receive new functionality and may be removed in a future release. See [Deprecated commands](#deprecated-commands) for migration notes.

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
>
>| Organization ID |Name|Category|Resource Name|Finding Class|Event Time|Create Time|Security Marks|
>|---|---|---|---|---|---|---|---|
>| 595779152576 | [organizations/595779152576/sources/10134421585261057824/findings/00002906967111ea87141217baf6db4d](https://console.cloud.google.com/security/command-center/findings?organizationId=595779152576&resourceId=organizations/595779152576/sources/10134421585261057824/findings/00002906967111ea87141217baf6db4d) | page | //cloudresourcemanager.googleapis.com/projects/339295427573 | THREAT | February 11, 2021 at 09:33:30 AM | May 15, 2020 at 05:57:46 AM | { "name": "wrench", "count": "3" } |
>| 595779152576 | [organizations/595779152576/sources/10134421585261057824/findings/00002ccaa28911ea9d221217baf6db4d](https://console.cloud.google.com/security/command-center/findings?organizationId=595779152576&resourceId=organizations/595779152576/sources/10134421585261057824/findings/00002ccaa28911ea9d221217baf6db4d) | page | //cloudresourcemanager.googleapis.com/projects/339295427573 | THREAT | February 11, 2021 at 07:21:45 AM | May 30, 2020 at 03:19:49 PM | { "name": "wrench", "count": "3" } |
>| 595779152576 | [organizations/595779152576/sources/10134421585261057824/findings/000031c6a21f11ea9d221217baf6db4d](https://console.cloud.google.com/security/command-center/findings?organizationId=595779152576&resourceId=organizations/595779152576/sources/10134421585261057824/findings/000031c6a21f11ea9d221217baf6db4d) | page | //cloudresourcemanager.googleapis.com/projects/339295427573 | THREAT | March 16, 2020 at 01:38:52 AM | May 30, 2020 at 02:41:01 AM | { "name": "wrench", "count": "3" } |
>To fetch the next batch of results, execute the command with the page token as next-page-token

### google-cloud-scc-finding-update

***
Use [google-cloud-scc-v2-finding-update](#google-cloud-scc-v2-finding-update) instead. Update an organization's or source's finding.

This command is backed by the Security Command Center v1 API. Its own behavior, arguments and context outputs (`GoogleCloudSCC.Finding.*`) are unchanged, so existing playbooks keep working, but it will not receive new functionality and may be removed in a future release. See [Deprecated commands](#deprecated-commands) for migration notes.

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

>### The finding has been updated successfully
>
>| Organization ID |Name|State|Category|Event Time|Create Time|External Uri|Resource Name|
>|---|---|---|---|---|---|---|---|
>| 595779152576 | [organizations/595779152576/sources/10134421585261057824/findings/00002906967111ea87141217baf6db4d](https://console.cloud.google.com/security/command-center/findings?organizationId=595779152576&resourceId=organizations/595779152576/sources/10134421585261057824/findings/00002906967111ea87141217baf6db4d) | ACTIVE | page | February 11, 2021 at 01:52:25 PM | May 15, 2020 at 05:57:46 AM | [http://www.fake-url.com](http://www.fake-url.com) | //cloudresourcemanager.googleapis.com/projects/339295427573 |

### google-cloud-scc-asset-resource-list

***
Lists cloud asset's resources.

#### Base Command

`google-cloud-scc-asset-resource-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| parent | Name of the organization or project the assets belong to. Organization Id provided in the Integration Configuration will be taken by default, if no value is provided to the parent.<br/><br/>Format: "organizations/[organization-number]" (such as "organizations/123"), "projects/[project-id]" (such as "projects/my-project-id"), or "projects/[project-number]" (such as "projects/12345"). | Optional |
| assetTypes | This parameter is used to filter assets by asset types by providing a single value or a comma-separated value of asset types.<br/>For example: "compute.googleapis.com/Disk".<br/><br/>Regular expression is also supported. <br/>For example:<br/>1) "compute.googleapis.com.*" resources whose asset type starts with "compute.googleapis.com".<br/>2) ".*Instance" resources whose asset type ends with "Instance".<br/>3) "._Instance._" resources whose asset type contains "Instance". | Optional |
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
            "nextPageToken": "next-page-token"
        }
    }
}
```

#### Human Readable Output

>| Organization ID |Asset Name|Asset Type|Discovery Name|Ancestors|Update Time (In UTC)|
>|---|---|---|---|---|---|
>| 595779152576 | //cloudbilling.googleapis.com/billingAccounts/12345-6789 | cloudbilling.googleapis.com/BillingAccount | BillingAccount | organizations/123456789 | August 21, 2020 at 09:05:39 AM |
>| 595779152576 | //cloudbilling.googleapis.com/billingAccounts/23456-7890 | cloudbilling.googleapis.com/BillingAccount | BillingAccount | organizations/123456789 | April 01, 2021 at 07:38:12 PM |
>To fetch the next batch of results, execute the command with the page token as next-page-token

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

>| Organization ID |Project Name|Project Owner|Ancestors|Update Time (In UTC)|
>|---|---|---|---|---|
>| 595779152576 | //cloudresourcemanager.googleapis.com/projects/123456789 | serviceAccount:dummmyaccount@dummycom,<br/>user:dummmyuser1@dummycom | projects/123456789,<br/>organizations/123456789 | December 24, 2018 at 10:00:00 AM |

### google-cloud-scc-finding-state-update

***
Use [google-cloud-scc-v2-finding-state-update](#google-cloud-scc-v2-finding-state-update) instead. Update the state of organization's or source's finding.

This command is backed by the Security Command Center v1 API. Its own behavior, arguments and context outputs (`GoogleCloudSCC.Finding.*`) are unchanged, so existing playbooks keep working, but it will not receive new functionality and may be removed in a future release. See [Deprecated commands](#deprecated-commands) for migration notes.

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

>### The finding has been updated successfully
>
>| Organization ID |Name|State|Severity|Category|Event Time|Create Time|External Uri|Resource Name|
>|---|---|---|---|---|---|---|---|---|
>| 595779152576 | [organizations/595779152576/sources/10134421585261057824/findings/00002906967111ea87141217baf6db4d](https://console.cloud.google.com/security/command-center/findings?organizationId=595779152576&resourceId=organizations/595779152576/sources/10134421585261057824/findings/00002906967111ea87141217baf6db4d) | ACTIVE | High | page | February 11, 2021 at 01:52:25 PM | May 15, 2020 at 05:57:46 AM | [http://www.fake-url.com](http://www.fake-url.com) | //cloudresourcemanager.googleapis.com/projects/339295427573 |

### google-cloud-scc-v2-finding-list

***
Lists an organization or source's findings using the Security Command Center v2 API.

#### Base Command

`google-cloud-scc-v2-finding-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| severity | Filter findings by their severity (LOW, MEDIUM, HIGH, CRITICAL). Comma-separated values are supported and if any severity value is not provided, by default all the severities will be considered for listing of findings. Value provided inside severity would be applied in the query as a filter parameter for filtering results. Possible values are: LOW, MEDIUM, HIGH, CRITICAL. | Optional |
| category | Filter findings by providing comma-separated values of categories or a single category.<br/>If any category value is not provided, by default all the categories will be considered for listing findings.<br/>Value provided inside the category would be applied in the query as a filter parameter for filtering results.<br/><br/>For Example: anomaly,application. | Optional |
| sourceTypeId | Filter findings by providing the value of a single source type. If any source type Id value is not provided, by default all source types will be considered for list findings. Default is -. | Optional |
| pageSize | The maximum number of results to return in a single response. The minimum value is 1 and maximum value is 1000. Default is 10. | Optional |
| state | Filter the findings by their state. Can be 'ACTIVE', 'INACTIVE'. Comma-separated values are supported and if any state value is not provided, by default 'ACTIVE' state will be considered for listing of findings. Value provided inside the state would be applied in the query as a filter parameter for filtering results. Possible values are: ACTIVE, INACTIVE. Default is ACTIVE. | Optional |
| location | The location in which the findings reside (for example, 'global', 'us', 'eu', 'me-central2'). If no location is provided, findings are assumed to be in 'global'. Possible values are: global, us, eu, me-central2. Default is global. | Optional |
| filter | The v2 filter expression is a list of one or more restrictions combined via logical operators AND and OR.<br/>Parentheses are supported, and OR has higher precedence than AND. Examples include:<br/>1) name<br/>2) securityMarks.marks.marka<br/><br/>The supported operators are:<br/>1) = for all value types.<br/>2) &gt;, &lt;, &gt;=, &lt;= for integer values.<br/>3) :, meaning substring matching, for strings.<br/><br/>The following field and operator combinations are supported:<br/>1) name: =<br/>2) parent: =, :<br/>3) resourceName: =, :<br/>4) state: =, :<br/>5) category: =, :<br/>6) externalUri: =, :<br/>7) eventTime: =, &gt;, &lt;, &gt;=, &lt;= (using an RFC3339 timestamp or milliseconds since epoch)<br/>8) severity: =, :<br/>9) securityMarks.marks: =, :<br/>10) resource:<br/>11) resource.name: =, :<br/><br/>Examples: "category="XSS_SCRIPTING" AND state="ACTIVE""<br/>Use a negated partial match on the empty string to filter based on a property not existing: "-severity=LOW".<br/>. | Optional |
| orderBy | This parameter defines what fields and order to use for sorting.<br/>The string value should be a comma-separated list of fields. The default sorting order is ascending.<br/>To specify descending order for a field, a suffix " desc" should be appended to the field name.<br/><br/>For example: "name desc,category".<br/><br/>Supported fields in the v2 API: name, parent, state, category, resourceName, eventTime, severity, securityMarks.marks. | Optional |
| pageToken | The value returned by the last response of a google-cloud-scc-v2-finding-list command indicates that this is a continuation of a prior findings.list call, and that the system should return the next page of data. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudSCC.FindingV2.name | String | 'The relative resource name of this finding. Format: organizations/\{organization\}/sources/\{source\}/locations/\{location\}/findings/\{finding\}.' |
| GoogleCloudSCC.FindingV2.canonicalName | String | The canonical name of the finding, always suffixed with the region-agnostic \(global\) resource path. |
| GoogleCloudSCC.FindingV2.parent | String | The relative resource name of the source the finding belongs to. |
| GoogleCloudSCC.FindingV2.resourceName | String | For findings on Google Cloud resources, the full resource name of the Google Cloud resource this finding is for. |
| GoogleCloudSCC.FindingV2.state | String | The state of the finding \(ACTIVE or INACTIVE\). |
| GoogleCloudSCC.FindingV2.category | String | The additional taxonomy group within findings from a given source. |
| GoogleCloudSCC.FindingV2.externalUri | String | The URI that, if available, points to a web page outside of Security Command Center where additional information about the finding can be found. |
| GoogleCloudSCC.FindingV2.sourceProperties | Unknown | Source specific properties. These properties are managed by the source that writes the finding. Properties are varying from finding to finding. |
| GoogleCloudSCC.FindingV2.securityMarks | Unknown | Output only. |
| GoogleCloudSCC.FindingV2.securityMarks.name | String | The relative resource name of the SecurityMarks. |
| GoogleCloudSCC.FindingV2.securityMarks.marks | Unknown | Mutable user specified security marks belonging to the parent resource. |
| GoogleCloudSCC.FindingV2.securityMarks.canonicalName | String | The canonical name of the marks. |
| GoogleCloudSCC.FindingV2.eventTime | String | The time at which the event took place, or when an update to the finding occurred. |
| GoogleCloudSCC.FindingV2.createTime | String | The time at which the finding was created in Security Command Center. |
| GoogleCloudSCC.FindingV2.severity | String | The severity of the finding \(CRITICAL, HIGH, MEDIUM, LOW\). |
| GoogleCloudSCC.FindingV2.mute | String | Indicates the mute state of the finding \(MUTED, UNMUTED, UNDEFINED\). |
| GoogleCloudSCC.FindingV2.muteInfo | Unknown | Additional details about the mute state of the finding, including static and dynamic mute records. |
| GoogleCloudSCC.FindingV2.muteInfo.staticMute | Unknown | If set, the static mute applied to this finding. |
| GoogleCloudSCC.FindingV2.muteInfo.staticMute.state | String | The static mute state. |
| GoogleCloudSCC.FindingV2.muteInfo.staticMute.applyTime | String | When the static mute was applied. |
| GoogleCloudSCC.FindingV2.muteInfo.dynamicMuteRecords | Unknown | The list of dynamic mute rules that currently match the finding. |
| GoogleCloudSCC.FindingV2.muteInfo.dynamicMuteRecords.muteConfig | String | The relative resource name of the mute rule, represented by a mute config, that created this record, for example organizations/123/muteConfigs/mymuteconfig or organizations/123/locations/global/muteConfigs/mymuteconfig. |
| GoogleCloudSCC.FindingV2.muteInfo.dynamicMuteRecords.matchTime | String | When the dynamic mute rule first matched the finding. |
| GoogleCloudSCC.FindingV2.findingClass | String | The class of the finding \(THREAT, VULNERABILITY, MISCONFIGURATION, OBSERVATION, SCC_ERROR, POSTURE_VIOLATION, TOXIC_COMBINATION\). |
| GoogleCloudSCC.FindingV2.indicator | Unknown | Represents what's commonly known as an indicator of compromise \(IoC\) in computer forensics. |
| GoogleCloudSCC.FindingV2.indicator.ipAddresses | Unknown | The list of IP addresses that are associated with the finding. |
| GoogleCloudSCC.FindingV2.indicator.domains | Unknown | List of domains associated to the Finding. |
| GoogleCloudSCC.FindingV2.indicator.signatures | Unknown | The list of matched signatures indicating that the given process is present in the environment. |
| GoogleCloudSCC.FindingV2.indicator.signatures.signatureType | String | Describes the type of resource associated with the signature. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature | Unknown | Signature indicating that a binary family was matched. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature.binaryFamily | String | The binary family. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature.detections | Unknown | The list of memory hash detections contributing to the binary family match. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature.detections.binary | String | The name of the binary associated with the memory hash signature detection. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature.detections.percentPagesMatched | Number | The percentage of memory page hashes in the signature that were matched. |
| GoogleCloudSCC.FindingV2.indicator.signatures.yaraRuleSignature | Unknown | Signature indicating that a YARA rule was matched. |
| GoogleCloudSCC.FindingV2.indicator.signatures.yaraRuleSignature.yaraRule | String | The name of the YARA rule. |
| GoogleCloudSCC.FindingV2.indicator.uris | Unknown | The list of URIs associated to the Findings. |
| GoogleCloudSCC.FindingV2.vulnerability | Unknown | Represents vulnerability-specific fields like CVE and CVSS scores. |
| GoogleCloudSCC.FindingV2.vulnerability.cve | Unknown | CVE stands for Common Vulnerabilities and Exposures \(&lt;<https://cve.mitre.org/about/&gt;\>) |
| GoogleCloudSCC.FindingV2.vulnerability.cve.id | String | The unique identifier for the vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.references | Unknown | Additional information about the CVE. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.references.source | String | Source of the reference e.g. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.references.uri | String | Uri for the mentioned source e.g. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3 | Unknown | Describe Common Vulnerability Scoring System specified at &lt;<https://www.first.org/cvss/v3.1/specification-document>&gt; |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.baseScore | Number | The base score is a function of the base metric scores. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.attackVector | String | Base Metrics Represents the intrinsic characteristics of a vulnerability that are constant over time and across user environments. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.attackComplexity | String | This metric describes the conditions beyond the attacker's control that must exist in order to exploit the vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.privilegesRequired | String | This metric describes the level of privileges an attacker must possess before successfully exploiting the vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.userInteraction | String | This metric captures the requirement for a human user, other than the attacker, to participate in the successful compromise of the vulnerable component. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.scope | String | The Scope metric captures whether a vulnerability in one vulnerable component impacts resources in components beyond its security scope. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.confidentialityImpact | String | This metric measures the impact to the confidentiality of the information resources managed by a software component due to a successfully exploited vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.integrityImpact | String | This metric measures the impact to integrity of a successfully exploited vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.availabilityImpact | String | This metric measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.upstreamFixAvailable | Boolean | Whether upstream fix is available for the CVE. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.impact | String | The potential impact of the vulnerability if it was to be exploited. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.exploitationActivity | String | The exploitation activity of the vulnerability in the wild. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.observedInTheWild | Boolean | Whether or not the vulnerability has been observed in the wild. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.zeroDay | Boolean | Whether or not the vulnerability was zero day when the finding was published. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.exploitReleaseDate | String | Date the first publicly available exploit or PoC was released. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.firstExploitationDate | String | Date of the earliest known exploitation. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage | Unknown | The offending package is relevant to the finding. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage.packageName | String | The name of the package where the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage.cpeUri | String | The CPE URI where the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage.packageType | String | Type of package, for example, os, maven, or go. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage.packageVersion | String | The version of the package. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage | Unknown | The fixed package is relevant to the finding. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage.packageName | String | The name of the package where the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage.cpeUri | String | The CPE URI where the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage.packageType | String | Type of package, for example, os, maven, or go. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage.packageVersion | String | The version of the package. |
| GoogleCloudSCC.FindingV2.vulnerability.securityBulletin | Unknown | The security bulletin is relevant to this finding. |
| GoogleCloudSCC.FindingV2.vulnerability.securityBulletin.bulletinId | String | ID of the bulletin corresponding to the vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.securityBulletin.submissionTime | String | Submission time of this Security Bulletin. |
| GoogleCloudSCC.FindingV2.vulnerability.securityBulletin.suggestedUpgradeVersion | String | This represents a version that the cluster receiving this notification should be upgraded to, based on its current version. |
| GoogleCloudSCC.FindingV2.vulnerability.providerRiskScore | String | Provider provided risk_score based on multiple factors. |
| GoogleCloudSCC.FindingV2.vulnerability.reachable | Boolean | Represents whether the vulnerability is reachable \(detected via static analysis\) |
| GoogleCloudSCC.FindingV2.vulnerability.cwes | Unknown | Represents one or more Common Weakness Enumeration \(CWE\) information on this vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cwes.id | String | The CWE identifier, e.g. |
| GoogleCloudSCC.FindingV2.vulnerability.cwes.references | Unknown | Any reference to the details on the CWE, for example, &lt;<https://dummyuser1@dummy.com/data/definitions/94.html>&gt; |
| GoogleCloudSCC.FindingV2.vulnerability.cwes.references.source | String | Source of the reference e.g. |
| GoogleCloudSCC.FindingV2.vulnerability.cwes.references.uri | String | Uri for the mentioned source e.g. |
| GoogleCloudSCC.FindingV2.muteUpdateTime | String | The time at which the finding was muted or unmuted. |
| GoogleCloudSCC.FindingV2.externalSystems | Unknown | Third party SIEM/SOAR fields within Security Command Center, contains external system information and external system finding fields. |
| GoogleCloudSCC.FindingV2.mitreAttack | Unknown | MITRE ATT&amp;CK tactics and techniques related to this finding. |
| GoogleCloudSCC.FindingV2.mitreAttack.primaryTactic | String | The MITRE ATT\\&amp;CK tactic most closely represented by this finding, if any. |
| GoogleCloudSCC.FindingV2.mitreAttack.primaryTechniques | Unknown | The MITRE ATT\\&amp;CK technique most closely represented by this finding, if any. |
| GoogleCloudSCC.FindingV2.mitreAttack.additionalTactics | Unknown | Additional MITRE ATT\\&amp;CK tactics related to this finding, if any. |
| GoogleCloudSCC.FindingV2.mitreAttack.additionalTechniques | Unknown | Additional MITRE ATT\\&amp;CK techniques related to this finding, if any, along with any of their respective parent techniques. |
| GoogleCloudSCC.FindingV2.mitreAttack.version | String | The MITRE ATT\\&amp;CK version referenced by the above fields. |
| GoogleCloudSCC.FindingV2.access | Unknown | Access details associated with the finding, such as more information on the caller, which method was accessed, and from where. |
| GoogleCloudSCC.FindingV2.access.principalEmail | String | Associated email, such as "<foo@google.com>". |
| GoogleCloudSCC.FindingV2.access.callerIp | String | Caller's IP address, such as "1.1.1.1". |
| GoogleCloudSCC.FindingV2.access.callerIpGeo | Unknown | The caller IP's geolocation, which identifies where the call came from. |
| GoogleCloudSCC.FindingV2.access.callerIpGeo.regionCode | String | A CLDR. |
| GoogleCloudSCC.FindingV2.access.userAgentFamily | String | Type of user agent associated with the finding. |
| GoogleCloudSCC.FindingV2.access.userAgent | String | The caller's user agent string associated with the finding. |
| GoogleCloudSCC.FindingV2.access.serviceName | String | This is the API service that the service account made a call to, e.g. |
| GoogleCloudSCC.FindingV2.access.methodName | String | The method that the service account called, e.g. |
| GoogleCloudSCC.FindingV2.access.principalSubject | String | A string that represents the principalSubject that is associated with the identity. |
| GoogleCloudSCC.FindingV2.access.serviceAccountKeyName | String | The name of the service account key that was used to create or exchange credentials when authenticating the service account that made the request. |
| GoogleCloudSCC.FindingV2.access.serviceAccountDelegationInfo | Unknown | The identity delegation history of an authenticated service account that made the request. |
| GoogleCloudSCC.FindingV2.access.serviceAccountDelegationInfo.principalEmail | String | The email address of a Google account. |
| GoogleCloudSCC.FindingV2.access.serviceAccountDelegationInfo.principalSubject | String | A string representing the principalSubject associated with the identity. |
| GoogleCloudSCC.FindingV2.access.userName | String | A string that represents a username. |
| GoogleCloudSCC.FindingV2.connections | Unknown | Contains information about the IP connection associated with the finding. |
| GoogleCloudSCC.FindingV2.connections.destinationIp | String | Destination IP address. |
| GoogleCloudSCC.FindingV2.connections.destinationPort | Number | Destination port. |
| GoogleCloudSCC.FindingV2.connections.sourceIp | String | Source IP address. |
| GoogleCloudSCC.FindingV2.connections.sourcePort | Number | Source port. |
| GoogleCloudSCC.FindingV2.connections.protocol | String | IANA Internet Protocol Number such as TCP\(6\) and UDP\(17\). |
| GoogleCloudSCC.FindingV2.muteInitiator | String | Records the entity that is responsible for the muting of the finding. |
| GoogleCloudSCC.FindingV2.processes | Unknown | Represents operating system processes associated with the finding. |
| GoogleCloudSCC.FindingV2.processes.name | String | The process name, as displayed in utilities like top and ps. |
| GoogleCloudSCC.FindingV2.processes.binary | Unknown | File information for the process executable. |
| GoogleCloudSCC.FindingV2.processes.binary.path | String | Absolute path of the file as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.binary.size | String | Size of the file in bytes. |
| GoogleCloudSCC.FindingV2.processes.binary.sha256 | String | SHA256 hash of the first hashedSize bytes of the file encoded as a hex string. |
| GoogleCloudSCC.FindingV2.processes.binary.hashedSize | String | The length in bytes of the file prefix that was hashed. |
| GoogleCloudSCC.FindingV2.processes.binary.partiallyHashed | Boolean | True when the hash covers only a prefix of the file. |
| GoogleCloudSCC.FindingV2.processes.binary.contents | String | Prefix of the file contents as a JSON-encoded string. |
| GoogleCloudSCC.FindingV2.processes.binary.diskPath | Unknown | Path of the file in terms of underlying disk/partition identifiers. |
| GoogleCloudSCC.FindingV2.processes.binary.diskPath.partitionUuid | String | UUID of the partition \(format &lt;<https://wiki.archlinux.org/title/persistent_block_device_naming\#by-uuid&gt;\>) |
| GoogleCloudSCC.FindingV2.processes.binary.diskPath.relativePath | String | Relative path of the file in the partition as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.binary.operations | Unknown | Operation\(s\) performed on a file. |
| GoogleCloudSCC.FindingV2.processes.binary.operations.type | String | The type of the operation |
| GoogleCloudSCC.FindingV2.processes.binary.fileLoadState | String | The load state of the file. |
| GoogleCloudSCC.FindingV2.processes.libraries | Unknown | File information for libraries loaded by the process. |
| GoogleCloudSCC.FindingV2.processes.libraries.path | String | Absolute path of the file as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.libraries.size | String | Size of the file in bytes. |
| GoogleCloudSCC.FindingV2.processes.libraries.sha256 | String | SHA256 hash of the first hashedSize bytes of the file encoded as a hex string. |
| GoogleCloudSCC.FindingV2.processes.libraries.hashedSize | String | The length in bytes of the file prefix that was hashed. |
| GoogleCloudSCC.FindingV2.processes.libraries.partiallyHashed | Boolean | True when the hash covers only a prefix of the file. |
| GoogleCloudSCC.FindingV2.processes.libraries.contents | String | Prefix of the file contents as a JSON-encoded string. |
| GoogleCloudSCC.FindingV2.processes.libraries.diskPath | Unknown | Path of the file in terms of underlying disk/partition identifiers. |
| GoogleCloudSCC.FindingV2.processes.libraries.diskPath.partitionUuid | String | UUID of the partition \(format &lt;<https://wiki.archlinux.org/title/persistent_block_device_naming\#by-uuid&gt;\>) |
| GoogleCloudSCC.FindingV2.processes.libraries.diskPath.relativePath | String | Relative path of the file in the partition as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.libraries.operations | Unknown | Operation\(s\) performed on a file. |
| GoogleCloudSCC.FindingV2.processes.libraries.operations.type | String | The type of the operation |
| GoogleCloudSCC.FindingV2.processes.libraries.fileLoadState | String | The load state of the file. |
| GoogleCloudSCC.FindingV2.processes.script | Unknown | When the process represents the invocation of a script, binary provides information about the interpreter, while script provides information about the script file provided to the interpreter. |
| GoogleCloudSCC.FindingV2.processes.script.path | String | Absolute path of the file as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.script.size | String | Size of the file in bytes. |
| GoogleCloudSCC.FindingV2.processes.script.sha256 | String | SHA256 hash of the first hashedSize bytes of the file encoded as a hex string. |
| GoogleCloudSCC.FindingV2.processes.script.hashedSize | String | The length in bytes of the file prefix that was hashed. |
| GoogleCloudSCC.FindingV2.processes.script.partiallyHashed | Boolean | True when the hash covers only a prefix of the file. |
| GoogleCloudSCC.FindingV2.processes.script.contents | String | Prefix of the file contents as a JSON-encoded string. |
| GoogleCloudSCC.FindingV2.processes.script.diskPath | Unknown | Path of the file in terms of underlying disk/partition identifiers. |
| GoogleCloudSCC.FindingV2.processes.script.diskPath.partitionUuid | String | UUID of the partition \(format &lt;<https://wiki.archlinux.org/title/persistent_block_device_naming\#by-uuid&gt;\>) |
| GoogleCloudSCC.FindingV2.processes.script.diskPath.relativePath | String | Relative path of the file in the partition as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.script.operations | Unknown | Operation\(s\) performed on a file. |
| GoogleCloudSCC.FindingV2.processes.script.operations.type | String | The type of the operation |
| GoogleCloudSCC.FindingV2.processes.script.fileLoadState | String | The load state of the file. |
| GoogleCloudSCC.FindingV2.processes.args | Unknown | Process arguments as JSON encoded strings. |
| GoogleCloudSCC.FindingV2.processes.argumentsTruncated | Boolean | True if args is incomplete. |
| GoogleCloudSCC.FindingV2.processes.envVariables | Unknown | Process environment variables. |
| GoogleCloudSCC.FindingV2.processes.envVariables.name | String | Environment variable name as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.envVariables.val | String | Environment variable value as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.envVariablesTruncated | Boolean | True if envVariables is incomplete. |
| GoogleCloudSCC.FindingV2.processes.pid | String | The process ID. |
| GoogleCloudSCC.FindingV2.processes.parentPid | String | The parent process ID. |
| GoogleCloudSCC.FindingV2.processes.userId | String | The ID of the user that executed the process. |
| GoogleCloudSCC.FindingV2.contacts | Unknown | Map containing the points of contact for the given finding. |
| GoogleCloudSCC.FindingV2.compliances | Unknown | Contains compliance information for security standards associated to the finding. |
| GoogleCloudSCC.FindingV2.compliances.standard | String | Industry-wide compliance standards or benchmarks, such as CIS, PCI, and OWASP. |
| GoogleCloudSCC.FindingV2.compliances.version | String | Version of the standard or benchmark, for example, 1.1 |
| GoogleCloudSCC.FindingV2.compliances.ids | Unknown | Policies within the standard or benchmark, for example, A.12.4.1 |
| GoogleCloudSCC.FindingV2.parentDisplayName | String | The human readable display name of the finding source, such as "Event Threat Detection" or "Security Health Analytics". |
| GoogleCloudSCC.FindingV2.description | String | Contains more details about the finding. |
| GoogleCloudSCC.FindingV2.exfiltration | Unknown | Represents exfiltrations associated with the finding. |
| GoogleCloudSCC.FindingV2.exfiltration.sources | Unknown | If there are multiple sources, then the data is considered "joined" between them. |
| GoogleCloudSCC.FindingV2.exfiltration.sources.name | String | The resource's full resource name. |
| GoogleCloudSCC.FindingV2.exfiltration.sources.components | Unknown | Subcomponents of the asset that was exfiltrated, like URIs used during exfiltration, table names, databases, and filenames. |
| GoogleCloudSCC.FindingV2.exfiltration.targets | Unknown | If there are multiple targets, each target would get a complete copy of the "joined" source data. |
| GoogleCloudSCC.FindingV2.exfiltration.targets.name | String | The resource's full resource name. |
| GoogleCloudSCC.FindingV2.exfiltration.targets.components | Unknown | Subcomponents of the asset that was exfiltrated, like URIs used during exfiltration, table names, databases, and filenames. |
| GoogleCloudSCC.FindingV2.exfiltration.totalExfiltratedBytes | String | Total exfiltrated bytes processed for the entire job. |
| GoogleCloudSCC.FindingV2.iamBindings | Unknown | Represents IAM bindings associated with the finding. |
| GoogleCloudSCC.FindingV2.iamBindings.action | String | The action that was performed on a Binding. |
| GoogleCloudSCC.FindingV2.iamBindings.role | String | Role that is assigned to "members". |
| GoogleCloudSCC.FindingV2.iamBindings.member | String | A single identity requesting access for a Cloud Platform resource, for example, "<foo@google.com>". |
| GoogleCloudSCC.FindingV2.nextSteps | String | Steps to address the finding. |
| GoogleCloudSCC.FindingV2.moduleName | String | Unique identifier of the module which generated the finding. |
| GoogleCloudSCC.FindingV2.containers | Unknown | Containers associated with the finding. This field provides information for both Kubernetes and non-Kubernetes containers. |
| GoogleCloudSCC.FindingV2.containers.name | String | Name of the container. |
| GoogleCloudSCC.FindingV2.containers.uri | String | Container image URI provided when configuring a pod or container. |
| GoogleCloudSCC.FindingV2.containers.imageId | String | Optional container image ID, if provided by the container runtime. |
| GoogleCloudSCC.FindingV2.containers.labels | Unknown | Container labels, as provided by the container runtime. |
| GoogleCloudSCC.FindingV2.containers.labels.name | String | Name of the label. |
| GoogleCloudSCC.FindingV2.containers.labels.value | String | Value that corresponds to the label's name. |
| GoogleCloudSCC.FindingV2.containers.createTime | String | The time that the container was created. |
| GoogleCloudSCC.FindingV2.kubernetes | Unknown | Kubernetes resources associated with the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.pods | Unknown | Kubernetes Pods associated with the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.ns | String | Kubernetes Pod namespace. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.name | String | Kubernetes Pod name. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.labels | Unknown | Pod labels. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.labels.name | String | Name of the label. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.labels.value | String | Value that corresponds to the label's name. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers | Unknown | Pod containers associated with this finding, if any. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.name | String | Name of the container. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.uri | String | Container image URI provided when configuring a pod or container. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.imageId | String | Optional container image ID, if provided by the container runtime. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.labels | Unknown | Container labels, as provided by the container runtime. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.labels.name | String | Name of the label. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.labels.value | String | Value that corresponds to the label's name. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.createTime | String | The time that the container was created. |
| GoogleCloudSCC.FindingV2.kubernetes.nodes | Unknown | Provides Kubernetes node information. |
| GoogleCloudSCC.FindingV2.kubernetes.nodes.name | String | Full resource name of the Compute Engine VM running the cluster node. |
| GoogleCloudSCC.FindingV2.kubernetes.nodePools | Unknown | GKE node pools associated with the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.nodePools.name | String | Kubernetes node pool name. |
| GoogleCloudSCC.FindingV2.kubernetes.nodePools.nodes | Unknown | Nodes associated with the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.nodePools.nodes.name | String | Full resource name of the Compute Engine VM running the cluster node. |
| GoogleCloudSCC.FindingV2.kubernetes.roles | Unknown | Provides Kubernetes role information for findings that involve Roles or ClusterRoles. |
| GoogleCloudSCC.FindingV2.kubernetes.roles.kind | String | Role type. |
| GoogleCloudSCC.FindingV2.kubernetes.roles.ns | String | Role namespace. |
| GoogleCloudSCC.FindingV2.kubernetes.roles.name | String | Role name. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings | Unknown | Provides Kubernetes role binding information for findings that involve RoleBindings or ClusterRoleBindings. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.ns | String | Namespace for the binding. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.name | String | Name for the binding. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.role | Unknown | The Role or ClusterRole referenced by the binding. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.role.kind | String | Role type. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.role.ns | String | Role namespace. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.role.name | String | Role name. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.subjects | Unknown | Represents one or more subjects that are bound to the role. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.subjects.kind | String | Authentication type for the subject. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.subjects.ns | String | Namespace for the subject. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.subjects.name | String | Name for the subject. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews | Unknown | Provides information on any Kubernetes access reviews \(privilege checks\) relevant to the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.group | String | The API group of the resource. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.ns | String | Namespace of the action being requested. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.name | String | The name of the resource being requested. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.resource | String | The optional resource type requested. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.subresource | String | The optional subresource type. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.verb | String | A Kubernetes resource API verb, like get, list, watch, create, update, delete, proxy. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.version | String | The API version of the resource. |
| GoogleCloudSCC.FindingV2.kubernetes.objects | Unknown | Kubernetes objects related to the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.group | String | Kubernetes object group, such as "policy.k8s.io/v1". |
| GoogleCloudSCC.FindingV2.kubernetes.objects.kind | String | Kubernetes object kind, such as "Namespace". |
| GoogleCloudSCC.FindingV2.kubernetes.objects.ns | String | Kubernetes object namespace. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.name | String | Kubernetes object name. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers | Unknown | Pod containers associated with this finding, if any. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.name | String | Name of the container. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.uri | String | Container image URI provided when configuring a pod or container. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.imageId | String | Optional container image ID, if provided by the container runtime. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.labels | Unknown | Container labels, as provided by the container runtime. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.labels.name | String | Name of the label. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.labels.value | String | Value that corresponds to the label's name. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.createTime | String | The time that the container was created. |
| GoogleCloudSCC.FindingV2.database | Unknown | Database associated with the finding. |
| GoogleCloudSCC.FindingV2.database.name | String | Some database resources may not have the full resource name populated because these resource types are not yet supported by Cloud Asset Inventory \(e.g. |
| GoogleCloudSCC.FindingV2.database.displayName | String | The human-readable name of the database that the user connected to. |
| GoogleCloudSCC.FindingV2.database.userName | String | The username used to connect to the database. |
| GoogleCloudSCC.FindingV2.database.query | String | The SQL statement that is associated with the database access. |
| GoogleCloudSCC.FindingV2.database.grantees | Unknown | The target usernames, roles, or groups of an SQL privilege grant, which is not an IAM policy change. |
| GoogleCloudSCC.FindingV2.database.version | String | The version of the database, for example, POSTGRES_14. |
| GoogleCloudSCC.FindingV2.attackExposure | Unknown | The results of an attack path simulation relevant to this finding. |
| GoogleCloudSCC.FindingV2.attackExposure.score | Number | A number between 0 \(inclusive\) and infinity that represents how important this finding is to remediate. |
| GoogleCloudSCC.FindingV2.attackExposure.latestCalculationTime | String | The most recent time the attack exposure was updated on this finding. |
| GoogleCloudSCC.FindingV2.attackExposure.attackExposureResult | String | The resource name of the attack path simulation result that contains the details regarding this attack exposure score. |
| GoogleCloudSCC.FindingV2.attackExposure.state | String | Output only. |
| GoogleCloudSCC.FindingV2.attackExposure.exposedHighValueResourcesCount | Number | The number of high value resources that are exposed as a result of this finding. |
| GoogleCloudSCC.FindingV2.attackExposure.exposedMediumValueResourcesCount | Number | The number of medium value resources that are exposed as a result of this finding. |
| GoogleCloudSCC.FindingV2.attackExposure.exposedLowValueResourcesCount | Number | The number of high value resources that are exposed as a result of this finding. |
| GoogleCloudSCC.FindingV2.files | Unknown | File associated with the finding. |
| GoogleCloudSCC.FindingV2.files.path | String | Absolute path of the file as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.files.size | String | Size of the file in bytes. |
| GoogleCloudSCC.FindingV2.files.sha256 | String | SHA256 hash of the first hashedSize bytes of the file encoded as a hex string. |
| GoogleCloudSCC.FindingV2.files.hashedSize | String | The length in bytes of the file prefix that was hashed. |
| GoogleCloudSCC.FindingV2.files.partiallyHashed | Boolean | True when the hash covers only a prefix of the file. |
| GoogleCloudSCC.FindingV2.files.contents | String | Prefix of the file contents as a JSON-encoded string. |
| GoogleCloudSCC.FindingV2.files.diskPath | Unknown | Path of the file in terms of underlying disk/partition identifiers. |
| GoogleCloudSCC.FindingV2.files.diskPath.partitionUuid | String | UUID of the partition \(format &lt;<https://wiki.archlinux.org/title/persistent_block_device_naming\#by-uuid&gt;\>) |
| GoogleCloudSCC.FindingV2.files.diskPath.relativePath | String | Relative path of the file in the partition as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.files.operations | Unknown | Operation\(s\) performed on a file. |
| GoogleCloudSCC.FindingV2.files.operations.type | String | The type of the operation |
| GoogleCloudSCC.FindingV2.files.fileLoadState | String | The load state of the file. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection | Unknown | Cloud Data Loss Prevention \(Cloud DLP\) inspection results that are associated with the finding. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection.inspectJob | String | Name of the inspection job, for example, projects/123/locations/europe/dlpJobs/i-8383929. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection.infoType | String | The type of information \(or \*infoType\* \) found, for example, EMAIL_ADDRESS or STREET_ADDRESS. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection.infoTypeCount | String | The number of times Cloud DLP found this infoType within this job and resource. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection.fullScan | Boolean | Whether Cloud DLP scanned the complete resource or a sampled subset. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile | Unknown | Cloud DLP data profile that is associated with the finding. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.dataProfile | String | Name of the data profile, for example, projects/123/locations/europe/tableProfiles/8383929. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.parentType | String | The resource hierarchy level at which the data profile was generated. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes | Unknown | Type of information detected by SDP. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes.name | String | Name of the information type. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes.version | String | Optional version name for this InfoType. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes.sensitivityScore | Unknown | Optional custom sensitivity for this InfoType. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes.sensitivityScore.score | String | The sensitivity score applied to the resource. |
| GoogleCloudSCC.FindingV2.kernelRootkit | Unknown | Signature of the kernel rootkit. |
| GoogleCloudSCC.FindingV2.kernelRootkit.name | String | Rootkit name, when available. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedCodeModification | Boolean | True if unexpected modifications of kernel code memory are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedReadOnlyDataModification | Boolean | True if unexpected modifications of kernel read-only data memory are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedFtraceHandler | Boolean | True if ftrace points are present with callbacks pointing to regions that are not in the expected kernel or module code range. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedKprobeHandler | Boolean | True if kprobe points are present with callbacks pointing to regions that are not in the expected kernel or module code range. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedKernelCodePages | Boolean | True if kernel code pages that are not in the expected kernel or module code regions are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedSystemCallHandler | Boolean | True if system call handlers that are are not in the expected kernel or module code regions are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedInterruptHandler | Boolean | True if interrupt handlers that are are not in the expected kernel or module code regions are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedProcessesInRunqueue | Boolean | True if unexpected processes in the scheduler run queue are present. |
| GoogleCloudSCC.FindingV2.orgPolicies | Unknown | Contains information about the org policies associated with the finding. |
| GoogleCloudSCC.FindingV2.orgPolicies.name | String | Identifier. |
| GoogleCloudSCC.FindingV2.job | Unknown | Job associated with the finding. |
| GoogleCloudSCC.FindingV2.job.name | String | The fully-qualified name for a job. |
| GoogleCloudSCC.FindingV2.job.state | String | Output only. |
| GoogleCloudSCC.FindingV2.job.errorCode | Number | Optional. |
| GoogleCloudSCC.FindingV2.job.location | String | Optional. |
| GoogleCloudSCC.FindingV2.application | Unknown | Represents an application associated with the finding. |
| GoogleCloudSCC.FindingV2.application.baseUri | String | The base URI that identifies the network location of the application in which the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.application.fullUri | String | The full URI with payload that could be used to reproduce the vulnerability. |
| GoogleCloudSCC.FindingV2.ipRules | Unknown | IP rules associated with the finding. |
| GoogleCloudSCC.FindingV2.ipRules.direction | String | The direction that the rule is applicable to, one of ingress or egress. |
| GoogleCloudSCC.FindingV2.ipRules.sourceIpRanges | Unknown | If source IP ranges are specified, the firewall rule applies only to traffic that has a source IP address in these ranges. |
| GoogleCloudSCC.FindingV2.ipRules.destinationIpRanges | Unknown | If destination IP ranges are specified, the firewall rule applies only to traffic that has a destination IP address in these ranges. |
| GoogleCloudSCC.FindingV2.ipRules.exposedServices | Unknown | Name of the network protocol service, such as FTP, that is exposed by the open port. |
| GoogleCloudSCC.FindingV2.ipRules.allowed | Unknown | Tuple with allowed rules. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules | Unknown | Optional. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules.protocol | String | The IP protocol this rule applies to. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules.portRanges | Unknown | Optional. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules.portRanges.min | String | Minimum port value. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules.portRanges.max | String | Maximum port value. |
| GoogleCloudSCC.FindingV2.ipRules.denied | Unknown | Tuple with denied rules. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules | Unknown | Optional. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules.protocol | String | The IP protocol this rule applies to. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules.portRanges | Unknown | Optional. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules.portRanges.min | String | Minimum port value. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules.portRanges.max | String | Maximum port value. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery | Unknown | Fields related to Backup and Disaster Recovery findings. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.backupTemplate | String | The name of a Backup and DR template which comprises one or more backup policies. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.policies | Unknown | The names of Backup and DR policies that are associated with a template and that define when to run a backup, how frequently to run a backup, and how long to retain the backup image. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.host | String | The name of a Backup and DR host, which is managed by the backup and recovery appliance and known to the management console. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.applications | Unknown | The names of Backup and DR applications. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.storagePool | String | The name of the Backup and DR storage pool that the backup and recovery appliance is storing data in. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.policyOptions | Unknown | The names of Backup and DR advanced policy options of a policy applying to an application. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.profile | String | The name of the Backup and DR resource profile that specifies the storage media for backups of application and VM data. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.appliance | String | The name of the Backup and DR appliance that captures, moves, and manages the lifecycle of backup data. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.backupType | String | The backup type of the Backup and DR image. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.backupCreateTime | String | The timestamp at which the Backup and DR backup was created. |
| GoogleCloudSCC.FindingV2.securityPosture | Unknown | The security posture associated with the finding. |
| GoogleCloudSCC.FindingV2.securityPosture.name | String | Name of the posture, for example, CIS-Posture. |
| GoogleCloudSCC.FindingV2.securityPosture.revisionId | String | The version of the posture, for example, c7cfa2a8. |
| GoogleCloudSCC.FindingV2.securityPosture.postureDeploymentResource | String | The project, folder, or organization on which the posture is deployed, for example, projects/\{project_number\}. |
| GoogleCloudSCC.FindingV2.securityPosture.postureDeployment | String | The name of the posture deployment, for example, organizations/\{org_id\}/posturedeployments/\{posture_deployment_id\}. |
| GoogleCloudSCC.FindingV2.securityPosture.changedPolicy | String | The name of the updated policy, for example, projects/\{projectId\}/policies/\{constraint_name\}. |
| GoogleCloudSCC.FindingV2.securityPosture.policySet | String | The name of the updated policy set, for example, cis-policyset. |
| GoogleCloudSCC.FindingV2.securityPosture.policy | String | The ID of the updated policy, for example, compute-policy-1. |
| GoogleCloudSCC.FindingV2.securityPosture.policyDriftDetails | Unknown | The details about a change in an updated policy that violates the deployed posture. |
| GoogleCloudSCC.FindingV2.securityPosture.policyDriftDetails.field | String | The name of the updated field, for example constraint.implementation.policy_rules\\\[0\\\].enforce |
| GoogleCloudSCC.FindingV2.securityPosture.policyDriftDetails.expectedValue | String | The value of this field that was configured in a posture, for example, true or allowed_values=\{"projects/29831892"\}. |
| GoogleCloudSCC.FindingV2.securityPosture.policyDriftDetails.detectedValue | String | The detected value that violates the deployed posture, for example, false or allowed_values=\{"projects/22831892"\}. |
| GoogleCloudSCC.FindingV2.logEntries | Unknown | Log entries that are relevant to the finding. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry | Unknown | An individual entry in a log stored in Cloud Logging. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry.insertId | String | A unique identifier for the log entry. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry.logId | String | The type of the log \(part of logName. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry.resourceContainer | String | The organization, folder, or project of the monitored resource that produced this log entry. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry.timestamp | String | The time the event described by the log entry occurred. |
| GoogleCloudSCC.FindingV2.loadBalancers | Unknown | The load balancers associated with the finding. |
| GoogleCloudSCC.FindingV2.loadBalancers.name | String | The name of the load balancer associated with the finding. |
| GoogleCloudSCC.FindingV2.cloudArmor | Unknown | Fields related to Google Cloud Armor findings. |
| GoogleCloudSCC.FindingV2.cloudArmor.securityPolicy | Unknown | Information about the Google Cloud Armor security policy relevant to the finding. |
| GoogleCloudSCC.FindingV2.cloudArmor.securityPolicy.name | String | The name of the Google Cloud Armor security policy, for example, "my-security-policy". |
| GoogleCloudSCC.FindingV2.cloudArmor.securityPolicy.type | String | The type of Google Cloud Armor security policy for example, 'backend security policy', 'edge security policy', 'network edge security policy', or 'always-on DDoS protection'. |
| GoogleCloudSCC.FindingV2.cloudArmor.securityPolicy.preview | Boolean | Whether or not the associated rule or policy is in preview mode. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests | Unknown | Information about incoming requests evaluated by Google Cloud Armor security policies. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests.ratio | Number | For 'Increasing deny ratio', the ratio is the denied traffic divided by the allowed traffic. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests.shortTermAllowed | Number | Allowed RPS \(requests per second\) in the short term. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests.longTermAllowed | Number | Allowed RPS \(requests per second\) over the long term. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests.longTermDenied | Number | Denied RPS \(requests per second\) over the long term. |
| GoogleCloudSCC.FindingV2.cloudArmor.adaptiveProtection | Unknown | Information about potential Layer 7 DDoS attacks identified by Google Cloud Armor Adaptive Protection. |
| GoogleCloudSCC.FindingV2.cloudArmor.adaptiveProtection.confidence | Number | A score of 0 means that there is low confidence that the detected event is an actual attack. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack | Unknown | Information about DDoS attack volume and classification. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.volumePpsLong | String | Total PPS \(packets per second\) volume of attack. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.volumeBpsLong | String | Total BPS \(bytes per second\) volume of attack. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.classification | String | Type of attack, for example, 'SYN-flood', 'NTP-udp', or 'CHARGEN-udp'. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.volumePps | Number | Volume Pps. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.volumeBps | Number | Volume Bps. |
| GoogleCloudSCC.FindingV2.cloudArmor.threatVector | String | Distinguish between volumetric \\&amp; protocol DDoS attack and application layer attacks. |
| GoogleCloudSCC.FindingV2.cloudArmor.duration | String | Duration of attack from the start until the current moment \(updated every 5 minutes\). |
| GoogleCloudSCC.FindingV2.notebook | Unknown | Notebook associated with the finding. |
| GoogleCloudSCC.FindingV2.notebook.name | String | The name of the notebook. |
| GoogleCloudSCC.FindingV2.notebook.service | String | The source notebook service, for example, "Colab Enterprise". |
| GoogleCloudSCC.FindingV2.notebook.lastAuthor | String | The user ID of the latest author to modify the notebook. |
| GoogleCloudSCC.FindingV2.notebook.notebookUpdateTime | String | The most recent time the notebook was updated. |
| GoogleCloudSCC.FindingV2.toxicCombination | Unknown | Contains details about a group of security issues that, when combined, represent a greater risk than when the issues occur independently. |
| GoogleCloudSCC.FindingV2.toxicCombination.attackExposureScore | Number | The Attack exposure score of this toxic combination. |
| GoogleCloudSCC.FindingV2.toxicCombination.relatedFindings | Unknown | List of resource names of findings associated with this toxic combination. |
| GoogleCloudSCC.FindingV2.groupMemberships | Unknown | Contains details about groups of which this finding is a member. |
| GoogleCloudSCC.FindingV2.groupMemberships.groupType | String | Type of group. |
| GoogleCloudSCC.FindingV2.groupMemberships.groupId | String | ID of the group. |
| GoogleCloudSCC.FindingV2.disk | Unknown | Disk associated with the finding. |
| GoogleCloudSCC.FindingV2.disk.name | String | The name of the disk, for example, "<https://www.googleapis.com/compute/v1/projects/\{project-id\}/zones/\{zone-id\}/disks/\{disk-id\}>". |
| GoogleCloudSCC.FindingV2.dataAccessEvents | Unknown | Data access events associated with the finding. |
| GoogleCloudSCC.FindingV2.dataAccessEvents.eventId | String | Unique identifier for data access event. |
| GoogleCloudSCC.FindingV2.dataAccessEvents.principalEmail | String | The email address of the principal that accessed the data. |
| GoogleCloudSCC.FindingV2.dataAccessEvents.operation | String | The operation performed by the principal to access the data. |
| GoogleCloudSCC.FindingV2.dataAccessEvents.eventTime | String | Timestamp of data access event. |
| GoogleCloudSCC.FindingV2.dataFlowEvents | Unknown | Data flow events associated with the finding. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.eventId | String | Unique identifier for data flow event. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.principalEmail | String | The email address of the principal that initiated the data flow event. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.operation | String | The operation performed by the principal for the data flow event. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.violatedLocation | String | Non-compliant location of the principal or the data destination. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.eventTime | String | Timestamp of data flow event. |
| GoogleCloudSCC.FindingV2.networks | Unknown | Represents the VPC networks that the resource is attached to. |
| GoogleCloudSCC.FindingV2.networks.name | String | The name of the VPC network resource, for example, //compute.googleapis.com/projects/my-project/global/networks/my-network. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents | Unknown | Data retention deletion events associated with the finding. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.eventDetectionTime | String | Timestamp indicating when the event was detected. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.dataObjectCount | String | Number of objects that violated the policy for this resource. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.maxRetentionAllowed | String | Maximum duration of retention allowed from the DRD control. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.minRetentionAllowed | String | The minimum duration that the resource associated with this finding must be retained, as enforced by the DSPM retention control. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.eventType | String | Type of the DRD event. |
| GoogleCloudSCC.FindingV2.affectedResources | Unknown | The details about a distinct count of resources affected by the finding. |
| GoogleCloudSCC.FindingV2.affectedResources.count | String | The count of resources affected by the finding. |
| GoogleCloudSCC.FindingV2.aiModel | Unknown | The AI model associated with the finding. |
| GoogleCloudSCC.FindingV2.aiModel.name | String | The name of the AI model, for example, "gemini:1.0.0". |
| GoogleCloudSCC.FindingV2.aiModel.domain | String | The domain of the model, for example, "image-classification". |
| GoogleCloudSCC.FindingV2.aiModel.library | String | The name of the model library, for example, "transformers". |
| GoogleCloudSCC.FindingV2.aiModel.location | String | The region in which the model is used, for example, "us-central1". |
| GoogleCloudSCC.FindingV2.aiModel.publisher | String | The publisher of the model, for example, "google" or "nvidia". |
| GoogleCloudSCC.FindingV2.aiModel.deploymentPlatform | String | The platform on which the model is deployed. |
| GoogleCloudSCC.FindingV2.aiModel.displayName | String | The user defined display name of model. |
| GoogleCloudSCC.FindingV2.aiModel.usageCategory | String | The purpose of the model, for example, "Interference" or "Training". |
| GoogleCloudSCC.FindingV2.chokepoint | Unknown | Contains details about a chokepoint, which is a resource or resource group where high-risk attack paths converge. |
| GoogleCloudSCC.FindingV2.chokepoint.relatedFindings | Unknown | List of resource names of findings associated with this chokepoint. |
| GoogleCloudSCC.FindingV2.complianceDetails | Unknown | Details about the compliance implications of the finding. |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks | Unknown | Details of Frameworks associated with the finding |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.name | String | Name of the framework associated with the finding |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.displayName | String | Display name of the framework. |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.category | Unknown | Category of the framework associated with the finding. |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.type | String | Type of the framework associated with the finding, to specify whether the framework is built-in \(pre-defined and immutable\) or a custom framework defined by the customer \(equivalent to security posture\) |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.controls | Unknown | The controls associated with the framework. |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.controls.controlName | String | Name of the Control |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.controls.displayName | String | Display name of the control. |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl | Unknown | CloudControl associated with the finding |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl.cloudControlName | String | Name of the CloudControl associated with the finding. |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl.type | String | Type of cloud control. |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl.policyType | String | Policy type of the CloudControl |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl.version | Number | Version of the Cloud Control |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControlDeploymentNames | Unknown | Cloud Control Deployments associated with the finding. |
| GoogleCloudSCC.FindingV2.vertexAi | Unknown | VertexAi associated with the finding. |
| GoogleCloudSCC.FindingV2.vertexAi.datasets | Unknown | Datasets associated with the finding. |
| GoogleCloudSCC.FindingV2.vertexAi.datasets.name | String | Resource name of the dataset, e.g. |
| GoogleCloudSCC.FindingV2.vertexAi.datasets.displayName | String | The user defined display name of dataset, e.g. |
| GoogleCloudSCC.FindingV2.vertexAi.datasets.source | String | Data source, such as a BigQuery source URI, e.g. |
| GoogleCloudSCC.FindingV2.vertexAi.pipelines | Unknown | Pipelines associated with the finding. |
| GoogleCloudSCC.FindingV2.vertexAi.pipelines.name | String | Resource name of the pipeline, e.g. |
| GoogleCloudSCC.FindingV2.vertexAi.pipelines.displayName | String | The user-defined display name of pipeline, e.g. |
| GoogleCloudSCC.FindingV2.cryptoKeyName | String | The name of the crypto key associated with the finding. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies | Unknown | Artifact Guard policies associated with the finding. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.resourceId | String | The ID of the resource that has policies configured. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.failingPolicies | Unknown | A list of artifact guard policies that the resource violated. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.failingPolicies.type | String | The type of the policy evaluation. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.failingPolicies.policyId | String | The ID of the failing policy, for example, "organizations/3392779/locations/global/policies/prod-policy". |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.failingPolicies.failureReason | String | The reason for the policy failure, for example, "severity=HIGH AND max_vuln_count=2". |
| GoogleCloudSCC.FindingV2.secret | Unknown | Secret associated with the finding. |
| GoogleCloudSCC.FindingV2.secret.type | String | The type of secret, for example, GCP_API_KEY. |
| GoogleCloudSCC.FindingV2.secret.status | Unknown | The status of the secret. |
| GoogleCloudSCC.FindingV2.secret.status.lastUpdatedTime | String | Time that the secret was found. |
| GoogleCloudSCC.FindingV2.secret.status.validity | String | The validity of the secret. |
| GoogleCloudSCC.FindingV2.secret.environmentVariable | Unknown | The environment variable containing the secret. |
| GoogleCloudSCC.FindingV2.secret.environmentVariable.key | String | The environment variable name as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.secret.filePath | Unknown | The file containing the secret. |
| GoogleCloudSCC.FindingV2.secret.filePath.path | String | Path to the file. |
| GoogleCloudSCC.FindingV2.externalExposure | Unknown | Represents the external exposure of the finding. |
| GoogleCloudSCC.FindingV2.externalExposure.privateIpAddress | String | Private IP address of the exposed endpoint. |
| GoogleCloudSCC.FindingV2.externalExposure.privatePort | String | Port number associated with private IP address. |
| GoogleCloudSCC.FindingV2.externalExposure.exposedService | String | The name and version of the service, for example, "Jupyter Notebook 6.14.0". |
| GoogleCloudSCC.FindingV2.externalExposure.publicIpAddress | String | Public IP address of the exposed endpoint. |
| GoogleCloudSCC.FindingV2.externalExposure.publicPort | String | Public port number of the exposed endpoint. |
| GoogleCloudSCC.FindingV2.externalExposure.exposedEndpoint | String | The resource which is running the exposed service, for example, "//compute.googleapis.com/projects/\{project-id\}/zones/\{zone\}/instances/\{instance\}". |
| GoogleCloudSCC.FindingV2.externalExposure.loadBalancerFirewallPolicy | String | The full resource name of the load balancer firewall policy, for example, "//compute.googleapis.com/projects/\{project-id\}/global/firewallPolicies/\{policy-name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.serviceFirewallPolicy | String | The full resource name of the firewall policy of the exposed service, for example, "//compute.googleapis.com/projects/\{project-id\}/global/firewallPolicies/\{policy-name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.forwardingRule | String | The full resource name of the forwarding rule, for example, "//compute.googleapis.com/projects/\{project-id\}/global/forwardingRules/\{forwarding-rule-name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.backendService | String | The full resource name of load balancer backend service, for example, "//compute.googleapis.com/projects/\{project-id\}/global/backendServices/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.instanceGroup | String | The full resource name of the instance group, for example, "//compute.googleapis.com/projects/\{project-id\}/global/instanceGroups/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.networkEndpointGroup | String | The full resource name of the network endpoint group, for example, "//compute.googleapis.com/projects/\{project-id\}/global/networkEndpointGroups/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.hostnameUri | String | Hostname of the exposed application, for example, <https://example.com/> |
| GoogleCloudSCC.FindingV2.externalExposure.pscServiceAttachment | String | The full resource name of the PSC \(Private Service Connect\) service attachment that the load balancer network endpoint group targets, for example, "//compute.googleapis.com/projects/\{project-id\}/regions/\{region\}/serviceAttachments/\{name\}" |
| GoogleCloudSCC.FindingV2.externalExposure.pscNetworkAttachment | String | The full resource name of the PSC \(Private Service Connect\) network attachment that network interface controller is attached to, for example, "//compute.googleapis.com/projects/\{project-id\}/regions/\{region\}/networkAttachments/\{name\}" |
| GoogleCloudSCC.FindingV2.externalExposure.internalBackendService | String | The full resource name of load balancer backend service in the internal project having resource exposed via PSC, for example, "//compute.googleapis.com/projects/\{project-id\}/global/backendServices/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.backendBucket | String | The full resource name of the load balancer backend bucket, for example, "//compute.googleapis.com/projects/\{project-id\}/global/backendBuckets/\{name\}" |
| GoogleCloudSCC.FindingV2.externalExposure.exposedApplication | String | The name and version of the exposed web application, for example, "Jenkins 2.184". |
| GoogleCloudSCC.FindingV2.externalExposure.networkIngressFirewallPolicy | String | The full resource name of the network ingress firewall policy, for example, "//compute.googleapis.com/projects/\{project-id\}/global/firewallPolicies/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.httpResponse | Unknown | The http response returned by the web application. |
| GoogleCloudSCC.FindingV2.externalExposure.httpResponse.statusCode | String | The http response code returned by the web application, for example, 200. |
| GoogleCloudSCC.FindingV2.externalExposure.httpResponse.path | String | The http path for which response code was returned by web application, for example, <https://example.com/example>. |
| GoogleCloudSCC.FindingV2.externalExposure.networkPathInsightsGenerationTime | String | The timestamp when the network reachability trace was generated or verified. |
| GoogleCloudSCC.FindingV2.policyViolationSummary | Unknown | Summary of the policy violations associated with the finding. |
| GoogleCloudSCC.FindingV2.policyViolationSummary.policyViolationsCount | String | Count of child resources in violation of the policy. |
| GoogleCloudSCC.FindingV2.policyViolationSummary.conformantResourcesCount | String | Total number of child resources that conform to the policy. |
| GoogleCloudSCC.FindingV2.policyViolationSummary.evaluationErrorsCount | String | Number of child resources for which errors during evaluation occurred. |
| GoogleCloudSCC.FindingV2.policyViolationSummary.outOfScopeResourcesCount | String | Total count of child resources which were not in scope for evaluation. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents | Unknown | Agent data access events associated with the finding. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents.eventId | String | Unique identifier for data access event. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents.principalSubject | String | The agent principal that accessed the data. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents.operation | String | The operation performed by the principal to access the data. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents.eventTime | String | Timestamp of data access event. |
| GoogleCloudSCC.FindingV2.discoveredWorkload | Unknown | The workload that this finding is associated with. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.workloadType | String | The type of workload. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.confidence | String | The confidence in detection of this workload. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.detectedRelevantPackages | Boolean | A boolean flag set to true if installed packages strongly predict the workload type. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.detectedRelevantKeywords | Boolean | A boolean flag set to true if associated keywords strongly predict the workload type. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.detectedRelevantHardware | Boolean | A boolean flag set to true if associated hardware strongly predicts the workload type. |
| GoogleCloudSCC.FindingV2.resource | Unknown | Resource. |
| GoogleCloudSCC.FindingV2.resource.name | String | The full resource name of the resource the finding is for. |
| GoogleCloudSCC.FindingV2.resource.displayName | String | The human readable name of the resource. |
| GoogleCloudSCC.FindingV2.resource.type | String | The full resource type of the resource. |
| GoogleCloudSCC.FindingV2.resource.cloudProvider | String | Indicates which cloud provider the finding is from \(GOOGLE_CLOUD_PLATFORM, AMAZON_WEB_SERVICES, MICROSOFT_AZURE\). |
| GoogleCloudSCC.FindingV2.resource.service | String | The parent service or product from which the resource is provided. |
| GoogleCloudSCC.FindingV2.resource.location | String | The region or location of the service, resource, or the finding source. |
| GoogleCloudSCC.FindingV2.resource.resourcePath | Unknown | Provides the path to the resource within the resource hierarchy. |
| GoogleCloudSCC.FindingV2.resource.resourcePath.nodes | Unknown | The list of nodes that make the up resource path, ordered from lowest level to highest level. |
| GoogleCloudSCC.FindingV2.resource.resourcePath.nodes.nodeType | String | The type of resource this node represents. |
| GoogleCloudSCC.FindingV2.resource.resourcePath.nodes.id | String | The ID of the resource this node represents. |
| GoogleCloudSCC.FindingV2.resource.resourcePath.nodes.displayName | String | The display name of the resource this node represents. |
| GoogleCloudSCC.FindingV2.resource.resourcePathString | String | A string representation of the resource path, made up of the resources of the ancestry hierarchy of the resource separated by forward slashes. |
| GoogleCloudSCC.FindingV2.resource.application | Unknown | The App Hub application this resource belongs to. |
| GoogleCloudSCC.FindingV2.resource.application.name | String | The resource name of an Application. |
| GoogleCloudSCC.FindingV2.resource.application.attributes | Unknown | Consumer provided attributes for the application |
| GoogleCloudSCC.FindingV2.resource.application.attributes.criticality | Unknown | User-defined criticality information. |
| GoogleCloudSCC.FindingV2.resource.application.attributes.criticality.type | String | Criticality Type. |
| GoogleCloudSCC.FindingV2.resource.application.attributes.environment | Unknown | User-defined environment information. |
| GoogleCloudSCC.FindingV2.resource.application.attributes.environment.type | String | Environment Type. |
| GoogleCloudSCC.FindingV2.resource.application.attributes.developerOwners | Unknown | Developer team that owns development and coding. |
| GoogleCloudSCC.FindingV2.resource.application.attributes.developerOwners.email | String | Email address of the contacts. |
| GoogleCloudSCC.FindingV2.resource.application.attributes.operatorOwners | Unknown | Operator team that ensures runtime and operations. |
| GoogleCloudSCC.FindingV2.resource.application.attributes.operatorOwners.email | String | Email address of the contacts. |
| GoogleCloudSCC.FindingV2.resource.application.attributes.businessOwners | Unknown | Business team that ensures user needs are met and value is delivered |
| GoogleCloudSCC.FindingV2.resource.application.attributes.businessOwners.email | String | Email address of the contacts. |
| GoogleCloudSCC.FindingV2.resource.adcApplication | Unknown | The ADC application associated with the finding. |
| GoogleCloudSCC.FindingV2.resource.adcApplication.name | String | The resource name of an ADC Application. |
| GoogleCloudSCC.FindingV2.resource.adcApplication.attributes | Unknown | Consumer provided attributes for the AppHub application. |
| GoogleCloudSCC.FindingV2.resource.adcApplication.attributes.criticality | Unknown | User-defined criticality information. |
| GoogleCloudSCC.FindingV2.resource.adcApplication.attributes.criticality.type | String | Criticality Type. |
| GoogleCloudSCC.FindingV2.resource.adcApplication.attributes.environment | Unknown | User-defined environment information. |
| GoogleCloudSCC.FindingV2.resource.adcApplication.attributes.environment.type | String | Environment Type. |
| GoogleCloudSCC.FindingV2.resource.adcApplication.attributes.developerOwners | Unknown | Developer team that owns development and coding. |
| GoogleCloudSCC.FindingV2.resource.adcApplication.attributes.developerOwners.email | String | Email address of the contacts. |
| GoogleCloudSCC.FindingV2.resource.adcApplication.attributes.operatorOwners | Unknown | Operator team that ensures runtime and operations. |
| GoogleCloudSCC.FindingV2.resource.adcApplication.attributes.operatorOwners.email | String | Email address of the contacts. |
| GoogleCloudSCC.FindingV2.resource.adcApplication.attributes.businessOwners | Unknown | Business team that ensures user needs are met and value is delivered |
| GoogleCloudSCC.FindingV2.resource.adcApplication.attributes.businessOwners.email | String | Email address of the contacts. |
| GoogleCloudSCC.FindingV2.resource.adcApplicationTemplate | Unknown | The ADC template associated with the finding. |
| GoogleCloudSCC.FindingV2.resource.adcApplicationTemplate.name | String | The resource name of an ADC Application Template Revision. |
| GoogleCloudSCC.FindingV2.resource.adcSharedTemplate | Unknown | The ADC shared template associated with the finding. |
| GoogleCloudSCC.FindingV2.resource.adcSharedTemplate.name | String | The resource name of an ADC Shared Template Revision. |
| GoogleCloudSCC.FindingV2.resource.gcpMetadata | Unknown | The Google Cloud metadata associated with the finding. |
| GoogleCloudSCC.FindingV2.resource.gcpMetadata.project | String | The full resource name of project that the resource belongs to. |
| GoogleCloudSCC.FindingV2.resource.gcpMetadata.projectDisplayName | String | The project ID that the resource belongs to. |
| GoogleCloudSCC.FindingV2.resource.gcpMetadata.parent | String | The full resource name of resource's parent. |
| GoogleCloudSCC.FindingV2.resource.gcpMetadata.parentDisplayName | String | The human readable name of resource's parent. |
| GoogleCloudSCC.FindingV2.resource.gcpMetadata.folders | Unknown | Output only. |
| GoogleCloudSCC.FindingV2.resource.gcpMetadata.folders.resourceFolder | String | Full resource name of this folder. |
| GoogleCloudSCC.FindingV2.resource.gcpMetadata.folders.resourceFolderDisplayName | String | The user defined display name for this folder. |
| GoogleCloudSCC.FindingV2.resource.gcpMetadata.organization | String | The name of the organization that the resource belongs to. |
| GoogleCloudSCC.FindingV2.resource.awsMetadata | Unknown | The AWS metadata associated with the finding. |
| GoogleCloudSCC.FindingV2.resource.awsMetadata.organization | Unknown | The AWS organization associated with the resource. |
| GoogleCloudSCC.FindingV2.resource.awsMetadata.organization.id | String | The unique identifier \(ID\) for the organization. |
| GoogleCloudSCC.FindingV2.resource.awsMetadata.organizationalUnits | Unknown | A list of AWS organizational units associated with the resource, ordered from lowest level \(closest to the account\) to highest level. |
| GoogleCloudSCC.FindingV2.resource.awsMetadata.organizationalUnits.id | String | The unique identifier \(ID\) associated with this OU. |
| GoogleCloudSCC.FindingV2.resource.awsMetadata.organizationalUnits.name | String | The friendly name of the OU. |
| GoogleCloudSCC.FindingV2.resource.awsMetadata.account | Unknown | The AWS account associated with the resource. |
| GoogleCloudSCC.FindingV2.resource.awsMetadata.account.id | String | The unique identifier \(ID\) of the account, containing exactly 12 digits. |
| GoogleCloudSCC.FindingV2.resource.awsMetadata.account.name | String | The friendly name of this account. |
| GoogleCloudSCC.FindingV2.resource.azureMetadata | Unknown | The Azure metadata associated with the finding. |
| GoogleCloudSCC.FindingV2.resource.azureMetadata.managementGroups | Unknown | A list of Azure management groups associated with the resource, ordered from lowest level \(closest to the subscription\) to highest level. |
| GoogleCloudSCC.FindingV2.resource.azureMetadata.managementGroups.id | String | The UUID of the Azure management group, for example, 20000000-0001-0000-0000-000000000000. |
| GoogleCloudSCC.FindingV2.resource.azureMetadata.managementGroups.displayName | String | The display name of the Azure management group. |
| GoogleCloudSCC.FindingV2.resource.azureMetadata.subscription | Unknown | The Azure subscription associated with the resource. |
| GoogleCloudSCC.FindingV2.resource.azureMetadata.subscription.id | String | The UUID of the Azure subscription, for example, 291bba3f-e0a5-47bc-a099-3bdcb2a50a05. |
| GoogleCloudSCC.FindingV2.resource.azureMetadata.subscription.displayName | String | The display name of the Azure subscription. |
| GoogleCloudSCC.FindingV2.resource.azureMetadata.resourceGroup | Unknown | The Azure resource group associated with the resource. |
| GoogleCloudSCC.FindingV2.resource.azureMetadata.resourceGroup.id | String | The ID of the Azure resource group. |
| GoogleCloudSCC.FindingV2.resource.azureMetadata.resourceGroup.name | String | The name of the Azure resource group. |
| GoogleCloudSCC.FindingV2.resource.azureMetadata.tenant | Unknown | The Azure Entra tenant associated with the resource. |
| GoogleCloudSCC.FindingV2.resource.azureMetadata.tenant.id | String | The ID of the Microsoft Entra tenant, for example, "a11aaa11-aa11-1aa1-11aa-1aaa11a". |
| GoogleCloudSCC.FindingV2.resource.azureMetadata.tenant.displayName | String | The display name of the Azure tenant. |
| GoogleCloudSCC.FindingV2.stateChange | String | State change of the finding between the points in time \(UNUSED, CHANGED, UNCHANGED, ADDED, REMOVED\). |
| GoogleCloudSCC.Token.nextPageToken | String | Token to retrieve the next page of results, or empty if there are no more results. |
| GoogleCloudSCC.Token.name | String | Name of the command. |

#### Command Example

```!google-cloud-scc-v2-finding-list location="global" sourceTypeId="-" pageSize="3" state="ACTIVE"```

#### Context Example

```json
{
    "GoogleCloudSCC": {
        "FindingV2": {
            "resource": {
                "name": "//compute.googleapis.com/projects/prod-web-app-284002/zones/us-central1-a/instances/web-server-01",
                "displayName": "web-server-01",
                "type": "google.compute.Instance",
                "cloudProvider": "GOOGLE_CLOUD_PLATFORM",
                "service": "compute.googleapis.com",
                "location": "us-central1-a",
                "resourcePath": {
                    "nodes": [
                        {
                            "nodeType": "GCP_ORGANIZATION",
                            "id": "organizations/284002401341",
                            "displayName": "example.com"
                        }
                    ]
                },
                "resourcePathString": "org/example.com/project/prod-web-app-284002/instance/web-server-01",
                "application": {
                    "name": "//apphub.googleapis.com/projects/prod-web-app-284002/locations/us-central1/applications/web-app",
                    "attributes": {
                        "criticality": {
                            "type": "MISSION_CRITICAL"
                        },
                        "environment": {
                            "type": "PRODUCTION"
                        },
                        "developerOwners": [
                            {
                                "email": "dev-team@example.com"
                            }
                        ],
                        "operatorOwners": [
                            {
                                "email": "ops-team@example.com"
                            }
                        ],
                        "businessOwners": [
                            {
                                "email": "product-owner@example.com"
                            }
                        ]
                    }
                },
                "adcApplication": {
                    "name": "//apphub.googleapis.com/projects/prod-web-app-284002/locations/us-central1/applications/web-app",
                    "attributes": {
                        "criticality": {
                            "type": "MISSION_CRITICAL"
                        },
                        "environment": {
                            "type": "PRODUCTION"
                        },
                        "developerOwners": [
                            {
                                "email": "dev-team@example.com"
                            }
                        ],
                        "operatorOwners": [
                            {
                                "email": "ops-team@example.com"
                            }
                        ],
                        "businessOwners": [
                            {
                                "email": "product-owner@example.com"
                            }
                        ]
                    }
                },
                "adcApplicationTemplate": {
                    "name": "web-app-template"
                },
                "adcSharedTemplate": {
                    "name": "shared-web-template"
                },
                "gcpMetadata": {
                    "project": "//cloudresourcemanager.googleapis.com/projects/593109727002",
                    "projectDisplayName": "prod-web-app-284002",
                    "parent": "//cloudresourcemanager.googleapis.com/folders/456789012345",
                    "parentDisplayName": "production-folder",
                    "folders": [
                        {
                            "resourceFolder": "//cloudresourcemanager.googleapis.com/folders/456789012345",
                            "resourceFolderDisplayName": "production-folder"
                        }
                    ],
                    "organization": "//cloudresourcemanager.googleapis.com/organizations/284002401341"
                },
                "awsMetadata": {
                    "organization": {
                        "id": "o-a1b2c3d4e5"
                    },
                    "organizationalUnits": [
                        {
                            "id": "ou-a1b2-c3d4e5f6",
                            "name": "production"
                        }
                    ],
                    "account": {
                        "id": "123456789012",
                        "name": "prod-account"
                    }
                },
                "azureMetadata": {
                    "managementGroups": [
                        {
                            "id": "mg-production",
                            "displayName": "Production"
                        }
                    ],
                    "subscription": {
                        "id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
                        "displayName": "prod-subscription"
                    },
                    "resourceGroup": {
                        "id": "rg-web-prod",
                        "name": "web-prod-rg"
                    },
                    "tenant": {
                        "id": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                        "displayName": "example-tenant"
                    }
                }
            },
            "name": "organizations/284002401341/sources/5473473300599573546/findings/f8e7d6c5b4a3928170615243aabbccdd",
            "canonicalName": "projects/593109727002/sources/5473473300599573546/findings/f8e7d6c5b4a3928170615243aabbccdd",
            "parent": "organizations/284002401341/sources/5473473300599573546",
            "resourceName": "//compute.googleapis.com/projects/prod-web-app-284002/zones/us-central1-a/instances/web-server-01",
            "state": "ACTIVE",
            "category": "Malware: Bad IP",
            "externalUri": "https://console.cloud.google.com/security/command-center/findings",
            "sourceProperties": {
                "dst_zipcode": "78701",
                "browser": "Chrome",
                "dst_region": "Texas",
                "userkey": "jdoe@example.com",
                "traffic_type": "CloudApp",
                "count": "1",
                "dst_longitude": -97.7431,
                "src_region": "California",
                "app": "Google Drive",
                "dst_latitude": 30.2672,
                "object": "quarterly-report.xlsx",
                "src_latitude": 37.7749,
                "sv": "vpn",
                "os": "Windows 10",
                "src_geoip_src": "MaxMind",
                "dst_location": "Austin",
                "device": "Windows Device",
                "srcip": "10.0.0.1"
            },
            "securityMarks": {
                "name": "organizations/284002401341/sources/5473473300599573546/findings/f8e7d6c5b4a3928170615243aabbccdd/securityMarks",
                "marks": {
                    "team": "secops"
                },
                "canonicalName": "projects/593109727002/sources/5473473300599573546/findings/f8e7d6c5b4a3928170615243aabbccdd/securityMarks"
            },
            "eventTime": "2024-11-15T09:42:18Z",
            "createTime": "2024-11-15T09:42:20.531Z",
            "severity": "CRITICAL",
            "mute": "UNMUTED",
            "muteInfo": {
                "staticMute": {
                    "state": "UNMUTED",
                    "applyTime": "2024-11-15T09:42:20Z"
                },
                "dynamicMuteRecords": [
                    {
                        "muteConfig": "organizations/284002401341/muteConfigs/low-severity-mute",
                        "matchTime": "2024-11-15T09:42:20Z"
                    }
                ]
            },
            "findingClass": "THREAT",
            "indicator": {
                "ipAddresses": [
                    "10.0.0.1"
                ],
                "domains": [
                    "malicious-c2.example.com"
                ],
                "signatures": [
                    {
                        "signatureType": "SIGNATURE_TYPE_PROCESS",
                        "memoryHashSignature": {
                            "binaryFamily": "Linux.Generic",
                            "detections": [
                                {
                                    "binary": "cryptominer",
                                    "percentPagesMatched": 0.87
                                }
                            ]
                        },
                        "yaraRuleSignature": {
                            "yaraRule": "rule_crypto_miner_generic"
                        }
                    }
                ],
                "uris": [
                    "http://malicious-c2.example.com/gate.php"
                ]
            },
            "vulnerability": {
                "cve": {
                    "id": "CVE-2021-44228",
                    "references": [
                        {
                            "source": "NVD",
                            "uri": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
                        }
                    ],
                    "cvssv3": {
                        "baseScore": 10.0,
                        "attackVector": "ATTACK_VECTOR_NETWORK",
                        "attackComplexity": "ATTACK_COMPLEXITY_LOW",
                        "privilegesRequired": "PRIVILEGES_REQUIRED_NONE",
                        "userInteraction": "USER_INTERACTION_NONE",
                        "scope": "SCOPE_CHANGED",
                        "confidentialityImpact": "IMPACT_HIGH",
                        "integrityImpact": "IMPACT_HIGH",
                        "availabilityImpact": "IMPACT_HIGH"
                    },
                    "upstreamFixAvailable": true,
                    "impact": "HIGH",
                    "exploitationActivity": "WIDE",
                    "observedInTheWild": true,
                    "zeroDay": false,
                    "exploitReleaseDate": "2021-12-10T00:00:00Z",
                    "firstExploitationDate": "2021-12-10T00:00:00Z"
                },
                "offendingPackage": {
                    "packageName": "log4j-core",
                    "cpeUri": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                    "packageType": "MAVEN",
                    "packageVersion": "2.14.1"
                },
                "fixedPackage": {
                    "packageName": "log4j-core",
                    "cpeUri": "cpe:2.3:a:apache:log4j:2.17.1:*:*:*:*:*:*:*",
                    "packageType": "MAVEN",
                    "packageVersion": "2.17.1"
                },
                "securityBulletin": {
                    "bulletinId": "GCP-2021-021",
                    "submissionTime": "2021-12-10T00:00:00Z",
                    "suggestedUpgradeVersion": "2.17.1"
                },
                "providerRiskScore": "95",
                "reachable": true,
                "cwes": [
                    {
                        "id": "CWE-502",
                        "references": [
                            {
                                "source": "MITRE",
                                "uri": "https://dummyuser1@dummy.com/data/definitions/502.html"
                            }
                        ]
                    }
                ]
            },
            "muteUpdateTime": "2024-11-15T09:42:20Z",
            "externalSystems": {
                "jira": {
                    "name": "organizations/284002401341/sources/5473473300599573546/findings/f8e7d6c5b4a3928170615243aabbccdd/externalSystems/jira",
                    "assignees": [
                        "jdoe@example.com"
                    ],
                    "externalUid": "SEC-1042",
                    "status": "In Progress",
                    "externalSystemUpdateTime": "2024-11-15T10:15:00Z",
                    "caseUri": "https://example.atlassian.net/browse/SEC-1042",
                    "casePriority": "P1",
                    "caseSla": "2024-11-16T09:42:18Z",
                    "caseCreateTime": "2024-11-15T09:45:00Z",
                    "caseCloseTime": "2024-11-15T18:00:00Z",
                    "ticketInfo": {
                        "id": "SEC-1042",
                        "assignee": "jdoe@example.com",
                        "description": "Investigate malware bad IP on web-server-01",
                        "uri": "https://example.atlassian.net/browse/SEC-1042",
                        "status": "In Progress",
                        "updateTime": "2024-11-15T10:15:00Z"
                    }
                }
            },
            "mitreAttack": {
                "primaryTactic": "COMMAND_AND_CONTROL",
                "primaryTechniques": [
                    "APPLICATION_LAYER_PROTOCOL"
                ],
                "additionalTactics": [
                    "EXFILTRATION"
                ],
                "additionalTechniques": [
                    "EXFILTRATION_OVER_C2_CHANNEL"
                ],
                "version": "14"
            },
            "access": {
                "principalEmail": "compute-sa@prod-web-app-284002.iam.gserviceaccount.com",
                "callerIp": "10.0.0.1",
                "callerIpGeo": {
                    "regionCode": "US"
                },
                "userAgentFamily": "curl",
                "userAgent": "curl/7.68.0",
                "serviceName": "compute.googleapis.com",
                "methodName": "v1.compute.instances.get",
                "principalSubject": "serviceAccount:compute-sa@prod-web-app-284002.iam.gserviceaccount.com",
                "serviceAccountKeyName": "projects/prod-web-app-284002/serviceAccounts/compute-sa@prod-web-app-284002.iam.gserviceaccount.com/keys/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
                "serviceAccountDelegationInfo": [
                    {
                        "principalEmail": "admin@example.com",
                        "principalSubject": "user:admin@example.com"
                    }
                ],
                "userName": "compute-sa"
            },
            "connections": [
                {
                    "destinationIp": "10.0.0.1",
                    "destinationPort": 443,
                    "sourceIp": "10.128.0.4",
                    "sourcePort": 51820,
                    "protocol": "TCP"
                }
            ],
            "muteInitiator": "jdoe@example.com",
            "processes": [
                {
                    "name": "cryptominer",
                    "binary": {
                        "path": "/tmp/.x/cryptominer",
                        "size": "4587520",
                        "sha256": "3a7bd3e2360a3d9f9c5f8b1a2c4d6e8f0a1b2c3d4e5f60718293a4b5c6d7e8f9",
                        "hashedSize": "4587520",
                        "partiallyHashed": false,
                        "contents": "ELF binary (truncated)",
                        "diskPath": {
                            "partitionUuid": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                            "relativePath": "/tmp/.x/cryptominer"
                        },
                        "operations": [
                            {
                                "type": "OPEN"
                            }
                        ],
                        "fileLoadState": "LOADED_BY_PROCESS"
                    },
                    "libraries": [
                        {
                            "path": "/lib/x86_64-linux-gnu/libc.so.6",
                            "size": "2029224",
                            "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                            "hashedSize": "2029224",
                            "partiallyHashed": false,
                            "contents": "shared library",
                            "diskPath": {
                                "partitionUuid": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                                "relativePath": "/lib/x86_64-linux-gnu/libc.so.6"
                            },
                            "operations": [
                                {
                                    "type": "OPEN"
                                }
                            ],
                            "fileLoadState": "LOADED_BY_PROCESS"
                        }
                    ],
                    "script": {
                        "path": "/tmp/.x/run.sh",
                        "size": "512",
                        "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
                        "hashedSize": "512",
                        "partiallyHashed": false,
                        "contents": "#!/bin/sh (truncated)",
                        "diskPath": {
                            "partitionUuid": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                            "relativePath": "/tmp/.x/run.sh"
                        },
                        "operations": [
                            {
                                "type": "OPEN"
                            }
                        ],
                        "fileLoadState": "LOADED_BY_PROCESS"
                    },
                    "args": [
                        "/tmp/.x/cryptominer",
                        "--pool",
                        "malicious-c2.example.com:443"
                    ],
                    "argumentsTruncated": false,
                    "envVariables": [
                        {
                            "name": "PATH",
                            "val": "/usr/local/bin:/usr/bin:/bin"
                        }
                    ],
                    "envVariablesTruncated": false,
                    "pid": "48213",
                    "parentPid": "1",
                    "userId": "0"
                }
            ],
            "contacts": {
                "security": {
                    "contacts": [
                        {
                            "email": "security@example.com"
                        }
                    ]
                }
            },
            "compliances": [
                {
                    "standard": "cis",
                    "version": "1.3",
                    "ids": [
                        "4.1"
                    ]
                }
            ],
            "parentDisplayName": "Event Threat Detection",
            "description": "A connection to a known malicious IP address was detected from a Compute Engine instance.",
            "exfiltration": {
                "sources": [
                    {
                        "name": "//bigquery.googleapis.com/projects/prod-web-app-284002/datasets/customer_data",
                        "components": [
                            "customers"
                        ]
                    }
                ],
                "targets": [
                    {
                        "name": "//bigquery.googleapis.com/projects/attacker-project/datasets/exfil",
                        "components": [
                            "customers_copy"
                        ]
                    }
                ],
                "totalExfiltratedBytes": "1048576"
            },
            "iamBindings": [
                {
                    "action": "ADD",
                    "role": "roles/owner",
                    "member": "user:attacker@example.com"
                }
            ],
            "nextSteps": "Isolate the instance and rotate potentially compromised credentials.",
            "moduleName": "MALWARE_BAD_IP",
            "containers": [
                {
                    "name": "web-app",
                    "uri": "gcr.io/prod-web-app-284002/web-app@sha256:3a7bd3e2360a3d9f9c5f8b1a2c4d6e8f0a1b2c3d4e5f60718293a4b5c6d7e8f9",
                    "imageId": "sha256:3a7bd3e2360a3d9f9c5f8b1a2c4d6e8f0a1b2c3d4e5f60718293a4b5c6d7e8f9",
                    "labels": [
                        {
                            "name": "app",
                            "value": "web"
                        }
                    ],
                    "createTime": "2024-11-10T08:00:00Z"
                }
            ],
            "kubernetes": {
                "pods": [
                    {
                        "ns": "default",
                        "name": "web-app-7d9f8c5b4-x2k9p",
                        "labels": [
                            {
                                "name": "app",
                                "value": "web"
                            }
                        ],
                        "containers": [
                            {
                                "name": "web-app",
                                "uri": "gcr.io/prod-web-app-284002/web-app@sha256:3a7bd3e2360a3d9f9c5f8b1a2c4d6e8f0a1b2c3d4e5f60718293a4b5c6d7e8f9",
                                "imageId": "sha256:3a7bd3e2360a3d9f9c5f8b1a2c4d6e8f0a1b2c3d4e5f60718293a4b5c6d7e8f9",
                                "labels": [
                                    {
                                        "name": "app",
                                        "value": "web"
                                    }
                                ],
                                "createTime": "2024-11-10T08:00:00Z"
                            }
                        ]
                    }
                ],
                "nodes": [
                    {
                        "name": "gke-prod-cluster-default-pool-a1b2c3d4-node1"
                    }
                ],
                "nodePools": [
                    {
                        "name": "default-pool",
                        "nodes": [
                            {
                                "name": "gke-prod-cluster-default-pool-a1b2c3d4-node1"
                            }
                        ]
                    }
                ],
                "roles": [
                    {
                        "kind": "ROLE",
                        "ns": "default",
                        "name": "pod-reader"
                    }
                ],
                "bindings": [
                    {
                        "ns": "default",
                        "name": "read-pods",
                        "role": {
                            "kind": "ROLE",
                            "ns": "default",
                            "name": "pod-reader"
                        },
                        "subjects": [
                            {
                                "kind": "USER",
                                "ns": "default",
                                "name": "jdoe@example.com"
                            }
                        ]
                    }
                ],
                "accessReviews": [
                    {
                        "group": "apps",
                        "ns": "default",
                        "name": "deployments",
                        "resource": "deployments",
                        "subresource": "",
                        "verb": "create",
                        "version": "v1"
                    }
                ],
                "objects": [
                    {
                        "group": "apps",
                        "kind": "Deployment",
                        "ns": "default",
                        "name": "web-app",
                        "containers": [
                            {
                                "name": "web-app",
                                "uri": "gcr.io/prod-web-app-284002/web-app@sha256:3a7bd3e2360a3d9f9c5f8b1a2c4d6e8f0a1b2c3d4e5f60718293a4b5c6d7e8f9",
                                "imageId": "sha256:3a7bd3e2360a3d9f9c5f8b1a2c4d6e8f0a1b2c3d4e5f60718293a4b5c6d7e8f9",
                                "labels": [
                                    {
                                        "name": "app",
                                        "value": "web"
                                    }
                                ],
                                "createTime": "2024-11-10T08:00:00Z"
                            }
                        ]
                    }
                ]
            },
            "database": {
                "name": "//cloudsql.googleapis.com/projects/prod-web-app-284002/instances/app-db",
                "displayName": "app-db",
                "userName": "app_user",
                "query": "SELECT * FROM customers",
                "grantees": [
                    "app_user"
                ],
                "version": "POSTGRES_14"
            },
            "attackExposure": {
                "score": 8.7,
                "latestCalculationTime": "2024-11-15T09:45:00Z",
                "attackExposureResult": "organizations/284002401341/simulations/1234567890/attackExposureResults/f8e7d6c5",
                "state": "CALCULATED",
                "exposedHighValueResourcesCount": 3,
                "exposedMediumValueResourcesCount": 5,
                "exposedLowValueResourcesCount": 12
            },
            "files": [
                {
                    "path": "/tmp/.x/cryptominer",
                    "size": "4587520",
                    "sha256": "3a7bd3e2360a3d9f9c5f8b1a2c4d6e8f0a1b2c3d4e5f60718293a4b5c6d7e8f9",
                    "hashedSize": "4587520",
                    "partiallyHashed": false,
                    "contents": "ELF binary (truncated)",
                    "diskPath": {
                        "partitionUuid": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                        "relativePath": "/tmp/.x/cryptominer"
                    },
                    "operations": [
                        {
                            "type": "OPEN"
                        }
                    ],
                    "fileLoadState": "LOADED_BY_PROCESS"
                }
            ],
            "cloudDlpInspection": {
                "inspectJob": "projects/prod-web-app-284002/locations/us-central1/dlpJobs/i-1234567890",
                "infoType": "CREDIT_CARD_NUMBER",
                "infoTypeCount": "42",
                "fullScan": true
            },
            "cloudDlpDataProfile": {
                "dataProfile": "projects/prod-web-app-284002/locations/us-central1/tableProfiles/customer_data",
                "parentType": "ORGANIZATION",
                "infoTypes": [
                    {
                        "name": "EMAIL_ADDRESS",
                        "version": "stable",
                        "sensitivityScore": {
                            "score": "SENSITIVITY_MODERATE"
                        }
                    }
                ]
            },
            "kernelRootkit": {
                "name": "Suspicious kernel modification",
                "unexpectedCodeModification": true,
                "unexpectedReadOnlyDataModification": false,
                "unexpectedFtraceHandler": false,
                "unexpectedKprobeHandler": false,
                "unexpectedKernelCodePages": true,
                "unexpectedSystemCallHandler": true,
                "unexpectedInterruptHandler": false,
                "unexpectedProcessesInRunqueue": false
            },
            "orgPolicies": [
                {
                    "name": "organizations/284002401341/policies/compute.requireOsLogin"
                }
            ],
            "job": {
                "name": "projects/prod-web-app-284002/locations/us-central1/jobs/scan-job",
                "state": "FAILED",
                "errorCode": 13,
                "location": "us-central1"
            },
            "application": {
                "baseUri": "https://app.example.com",
                "fullUri": "https://app.example.com/login"
            },
            "ipRules": {
                "direction": "INGRESS",
                "sourceIpRanges": [
                    "0.0.0.0/0"
                ],
                "destinationIpRanges": [
                    "10.0.0.1/20"
                ],
                "exposedServices": [
                    "ssh"
                ],
                "allowed": {
                    "ipRules": [
                        {
                            "protocol": "tcp",
                            "portRanges": [
                                {
                                    "min": "22",
                                    "max": "22"
                                }
                            ]
                        }
                    ]
                },
                "denied": {
                    "ipRules": [
                        {
                            "protocol": "tcp",
                            "portRanges": [
                                {
                                    "min": "3389",
                                    "max": "3389"
                                }
                            ]
                        }
                    ]
                }
            },
            "backupDisasterRecovery": {
                "backupTemplate": "gold-template",
                "policies": [
                    "daily-backup"
                ],
                "host": "web-server-01",
                "applications": [
                    "web-app"
                ],
                "storagePool": "primary-pool",
                "policyOptions": [
                    "retention=30d"
                ],
                "profile": "production-profile",
                "appliance": "backup-appliance-01",
                "backupType": "INCREMENTAL",
                "backupCreateTime": "2024-11-14T02:00:00Z"
            },
            "securityPosture": {
                "name": "organizations/284002401341/locations/global/postures/production-posture",
                "revisionId": "a1b2c3d4",
                "postureDeploymentResource": "organizations/284002401341",
                "postureDeployment": "organizations/284002401341/locations/global/postureDeployments/prod-deployment",
                "changedPolicy": "compute.requireOsLogin",
                "policySet": "cis-benchmark",
                "policy": "os-login-required",
                "policyDriftDetails": [
                    {
                        "field": "enforce",
                        "expectedValue": "true",
                        "detectedValue": "false"
                    }
                ]
            },
            "logEntries": [
                {
                    "cloudLoggingEntry": {
                        "insertId": "1a2b3c4d5e",
                        "logId": "cloudaudit.googleapis.com%2Factivity",
                        "resourceContainer": "projects/prod-web-app-284002",
                        "timestamp": "2024-11-15T09:42:18Z"
                    }
                }
            ],
            "loadBalancers": [
                {
                    "name": "web-lb-frontend"
                }
            ],
            "cloudArmor": {
                "securityPolicy": {
                    "name": "web-security-policy",
                    "type": "CLOUD_ARMOR",
                    "preview": false
                },
                "requests": {
                    "ratio": 0.92,
                    "shortTermAllowed": 1500,
                    "longTermAllowed": 42000,
                    "longTermDenied": 3800
                },
                "adaptiveProtection": {
                    "confidence": 0.95
                },
                "attack": {
                    "volumePpsLong": "150000",
                    "volumeBpsLong": "1200000000",
                    "classification": "HTTP_FLOOD",
                    "volumePps": 180000,
                    "volumeBps": 1450000000
                },
                "threatVector": "L7 HTTP flood",
                "duration": "300s"
            },
            "notebook": {
                "name": "projects/prod-web-app-284002/locations/us-central1/instances/analytics-notebook",
                "service": "Vertex AI Workbench",
                "lastAuthor": "analyst@example.com",
                "notebookUpdateTime": "2024-11-14T16:30:00Z"
            },
            "toxicCombination": {
                "attackExposureScore": 9.1,
                "relatedFindings": [
                    "organizations/284002401341/sources/5473473300599573546/findings/aa11bb22cc33dd44ee55ff6677889900"
                ]
            },
            "groupMemberships": [
                {
                    "groupType": "GROUP_TYPE_TOXIC_COMBINATION",
                    "groupId": "toxic-combo-001"
                }
            ],
            "disk": {
                "name": "//compute.googleapis.com/projects/prod-web-app-284002/zones/us-central1-a/disks/web-server-01"
            },
            "dataAccessEvents": [
                {
                    "eventId": "evt-1001",
                    "principalEmail": "compute-sa@prod-web-app-284002.iam.gserviceaccount.com",
                    "operation": "READ",
                    "eventTime": "2024-11-15T09:40:00Z"
                }
            ],
            "dataFlowEvents": [
                {
                    "eventId": "evt-2001",
                    "principalEmail": "compute-sa@prod-web-app-284002.iam.gserviceaccount.com",
                    "operation": "READ",
                    "violatedLocation": "us-central1",
                    "eventTime": "2024-11-15T09:41:00Z"
                }
            ],
            "networks": [
                {
                    "name": "//compute.googleapis.com/projects/prod-web-app-284002/global/networks/prod-vpc"
                }
            ],
            "dataRetentionDeletionEvents": [
                {
                    "eventDetectionTime": "2024-11-15T09:42:18Z",
                    "dataObjectCount": "1500",
                    "maxRetentionAllowed": "7776000s",
                    "minRetentionAllowed": "86400s",
                    "eventType": "EVENT_TYPE_MAX_TTL_EXCEEDED"
                }
            ],
            "affectedResources": {
                "count": "3"
            },
            "aiModel": {
                "name": "text-bison",
                "domain": "NLP",
                "library": "TensorFlow",
                "location": "us-central1",
                "publisher": "Google",
                "deploymentPlatform": "VERTEX_AI",
                "displayName": "Text Bison",
                "usageCategory": "TEXT_GENERATION"
            },
            "chokepoint": {
                "relatedFindings": [
                    "organizations/284002401341/sources/5473473300599573546/findings/aa11bb22cc33dd44ee55ff6677889900"
                ]
            },
            "complianceDetails": {
                "frameworks": [
                    {
                        "name": "cis_gcp_v1.3",
                        "displayName": "CIS Google Cloud Platform Foundation Benchmark v1.3",
                        "category": [
                            "SECURITY_BENCHMARKS"
                        ],
                        "type": "FRAMEWORK_TYPE_BUILT_IN",
                        "controls": [
                            {
                                "controlName": "4.1",
                                "displayName": "Ensure instances are not configured to use the default service account"
                            }
                        ]
                    }
                ],
                "cloudControl": {
                    "cloudControlName": "restrict-default-service-account",
                    "type": "BUILT_IN",
                    "policyType": "ORG_POLICY",
                    "version": 1
                },
                "cloudControlDeploymentNames": [
                    "organizations/284002401341/locations/global/cloudControlDeployments/restrict-default-sa"
                ]
            },
            "vertexAi": {
                "datasets": [
                    {
                        "name": "projects/prod-web-app-284002/locations/us-central1/datasets/1234567890",
                        "displayName": "training-dataset",
                        "source": "bq://prod-web-app-284002.ml_data.training"
                    }
                ],
                "pipelines": [
                    {
                        "name": "projects/prod-web-app-284002/locations/us-central1/pipelineJobs/train-pipeline",
                        "displayName": "train-pipeline"
                    }
                ]
            },
            "cryptoKeyName": "projects/prod-web-app-284002/locations/us-central1/keyRings/app-keyring/cryptoKeys/app-key",
            "artifactGuardPolicies": {
                "resourceId": "gcr.io/prod-web-app-284002/web-app",
                "failingPolicies": [
                    {
                        "type": "VULNERABILITY",
                        "policyId": "block-critical-cves",
                        "failureReason": "Image contains critical CVE-2021-44228"
                    }
                ]
            },
            "secret": {
                "type": "GCP_API_KEY",
                "status": {
                    "lastUpdatedTime": "2024-11-15T09:42:18Z",
                    "validity": "SECRET_VALIDITY_UNSUPPORTED"
                },
                "environmentVariable": {
                    "key": "API_TOKEN"
                },
                "filePath": {
                    "path": "/app/config/.env"
                }
            },
            "externalExposure": {
                "privateIpAddress": "10.128.0.4",
                "privatePort": "8080",
                "exposedService": "http",
                "publicIpAddress": "10.0.0.1",
                "publicPort": "443",
                "exposedEndpoint": "10.0.0.1:443",
                "loadBalancerFirewallPolicy": "allow-https",
                "serviceFirewallPolicy": "allow-http-8080",
                "forwardingRule": "web-forwarding-rule",
                "backendService": "web-backend",
                "instanceGroup": "web-instance-group",
                "networkEndpointGroup": "web-neg",
                "hostnameUri": "app.example.com",
                "pscServiceAttachment": "web-psc-attachment",
                "pscNetworkAttachment": "web-psc-network",
                "internalBackendService": "internal-web-backend",
                "backendBucket": "web-static-bucket",
                "exposedApplication": "web-app",
                "networkIngressFirewallPolicy": "allow-ingress-https",
                "httpResponse": [
                    {
                        "statusCode": "200",
                        "path": "/login"
                    }
                ],
                "networkPathInsightsGenerationTime": "2024-11-15T09:42:18Z"
            },
            "policyViolationSummary": {
                "policyViolationsCount": "5",
                "conformantResourcesCount": "120",
                "evaluationErrorsCount": "0",
                "outOfScopeResourcesCount": "3"
            },
            "agentDataAccessEvents": [
                {
                    "eventId": "evt-3001",
                    "principalSubject": "serviceAccount:compute-sa@prod-web-app-284002.iam.gserviceaccount.com",
                    "operation": "READ",
                    "eventTime": "2024-11-15T09:42:00Z"
                }
            ],
            "discoveredWorkload": {
                "workloadType": "MCP_SERVER",
                "confidence": "CONFIDENCE_HIGH",
                "detectedRelevantPackages": true,
                "detectedRelevantKeywords": true,
                "detectedRelevantHardware": false
            }
        },
        "Token": {
            "name": "google-cloud-scc-v2-finding-list",
            "nextPageToken": "CiAKHnByb2plY3RzLzU5MzEwOTcyNzAwMg"
        }
    }
}
```

#### Human Readable Output

>### Total retrieved finding(s): 1
>
>|Organization ID|Name|Category|Resource Name|Finding Class|Event Time (In UTC)|Create Time (In UTC)|Security Marks|
>|---|---|---|---|---|---|---|---|
>| 123 | [organizations/284002401341/sources/5473473300599573546/findings/f8e7d6c5b4a3928170615243aabbccdd](https://console.cloud.google.com/security/command-center/findings?organizationId=123&resourceId=organizations/284002401341/sources/5473473300599573546/findings/f8e7d6c5b4a3928170615243aabbccdd) | Malware: Bad IP | //compute.googleapis.com/projects/prod-web-app-284002/zones/us-central1-a/instances/web-server-01 | THREAT | November 15, 2024 at 09:42:18 AM | November 15, 2024 at 09:42:20 AM | team: secops |
>
>
>To fetch the next batch of results, execute the command with the page token as CiAKHnByb2plY3RzLzU5MzEwOTcyNzAwMg

### google-cloud-scc-v2-finding-update

***
Update an organization's or source's finding using the Security Command Center v2 API.

#### Base Command

`google-cloud-scc-v2-finding-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The relative resource name of the finding.<br/>In the v2 API the name may include an optional "locations/{location}" segment.<br/><br/>Format: organizations/{organization_id}/sources/{source_id}/findings/{findingId} or organizations/{organization_id}/sources/{source_id}/locations/{location_id}/findings/{findingId}<br/><br/>Example: organizations/595779152576/sources/14801394649435054450/locations/global/findings/bc5a86da657611ebb979005056a5924e.<br/><br/>Note: Users can retrieve the list of the finding names by executing the "google-cloud-scc-v2-finding-list" command. | Required |
| eventTime | Time at which the event took place. By default UTC current time will be taken if no value is provided in eventTime.<br/><br/>Format: YYYY-MM-ddTHH:mm:ss.sssZ<br/><br/>Example: 2026-07-22T07:10:02.782Z, 2026-06-02T15:01:23.045123456Z. | Optional |
| severity | Related severity of the finding. Possible values are: LOW, MEDIUM, HIGH, CRITICAL. | Optional |
| externalUri | URI that points to a web page outside of Cloud SCC (Security Command Center) where additional information about the finding can be found. | Optional |
| sourceProperties | Source specific properties. These properties are managed by the source that writes the finding. For example "key1=val1,key2=val2". | Optional |
| updateMask | A updateMask argument supports single or comma-separated fields that need to be updated/deleted. A updateMask is automatically generated in the backend for the specific arguments provided in the command and only those values will be updated. To delete attributes/properties, add those keys in updateMask without specifying those fields individually in the command arguments. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudSCC.FindingV2.name | String | 'The relative resource name of this finding. Format: organizations/\{organization\}/sources/\{source\}/locations/\{location\}/findings/\{finding\}.' |
| GoogleCloudSCC.FindingV2.canonicalName | String | The canonical name of the finding, always suffixed with the region-agnostic \(global\) resource path. |
| GoogleCloudSCC.FindingV2.parent | String | The relative resource name of the source the finding belongs to. |
| GoogleCloudSCC.FindingV2.resourceName | String | For findings on Google Cloud resources, the full resource name of the Google Cloud resource this finding is for. |
| GoogleCloudSCC.FindingV2.state | String | The state of the finding \(ACTIVE or INACTIVE\). |
| GoogleCloudSCC.FindingV2.category | String | The additional taxonomy group within findings from a given source. |
| GoogleCloudSCC.FindingV2.externalUri | String | The URI that, if available, points to a web page outside of Security Command Center where additional information about the finding can be found. |
| GoogleCloudSCC.FindingV2.sourceProperties | Unknown | Source specific properties. These properties are managed by the source that writes the finding. Properties are varying from finding to finding. |
| GoogleCloudSCC.FindingV2.securityMarks | Unknown | Output only. |
| GoogleCloudSCC.FindingV2.securityMarks.name | String | The relative resource name of the SecurityMarks. |
| GoogleCloudSCC.FindingV2.securityMarks.marks | Unknown | Mutable user specified security marks belonging to the parent resource. |
| GoogleCloudSCC.FindingV2.securityMarks.canonicalName | String | The canonical name of the marks. |
| GoogleCloudSCC.FindingV2.eventTime | String | The time at which the event took place, or when an update to the finding occurred. |
| GoogleCloudSCC.FindingV2.createTime | String | The time at which the finding was created in Security Command Center. |
| GoogleCloudSCC.FindingV2.severity | String | The severity of the finding \(CRITICAL, HIGH, MEDIUM, LOW\). |
| GoogleCloudSCC.FindingV2.mute | String | Indicates the mute state of the finding \(MUTED, UNMUTED, UNDEFINED\). |
| GoogleCloudSCC.FindingV2.muteInfo | Unknown | Additional details about the mute state of the finding, including static and dynamic mute records. |
| GoogleCloudSCC.FindingV2.muteInfo.staticMute | Unknown | If set, the static mute applied to this finding. |
| GoogleCloudSCC.FindingV2.muteInfo.staticMute.state | String | The static mute state. |
| GoogleCloudSCC.FindingV2.muteInfo.staticMute.applyTime | String | When the static mute was applied. |
| GoogleCloudSCC.FindingV2.muteInfo.dynamicMuteRecords | Unknown | The list of dynamic mute rules that currently match the finding. |
| GoogleCloudSCC.FindingV2.muteInfo.dynamicMuteRecords.muteConfig | String | The relative resource name of the mute rule, represented by a mute config, that created this record, for example organizations/123/muteConfigs/mymuteconfig or organizations/123/locations/global/muteConfigs/mymuteconfig. |
| GoogleCloudSCC.FindingV2.muteInfo.dynamicMuteRecords.matchTime | String | When the dynamic mute rule first matched the finding. |
| GoogleCloudSCC.FindingV2.findingClass | String | The class of the finding \(THREAT, VULNERABILITY, MISCONFIGURATION, OBSERVATION, SCC_ERROR, POSTURE_VIOLATION, TOXIC_COMBINATION\). |
| GoogleCloudSCC.FindingV2.indicator | Unknown | Represents what's commonly known as an indicator of compromise \(IoC\) in computer forensics. |
| GoogleCloudSCC.FindingV2.indicator.ipAddresses | Unknown | The list of IP addresses that are associated with the finding. |
| GoogleCloudSCC.FindingV2.indicator.domains | Unknown | List of domains associated to the Finding. |
| GoogleCloudSCC.FindingV2.indicator.signatures | Unknown | The list of matched signatures indicating that the given process is present in the environment. |
| GoogleCloudSCC.FindingV2.indicator.signatures.signatureType | String | Describes the type of resource associated with the signature. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature | Unknown | Signature indicating that a binary family was matched. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature.binaryFamily | String | The binary family. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature.detections | Unknown | The list of memory hash detections contributing to the binary family match. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature.detections.binary | String | The name of the binary associated with the memory hash signature detection. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature.detections.percentPagesMatched | Number | The percentage of memory page hashes in the signature that were matched. |
| GoogleCloudSCC.FindingV2.indicator.signatures.yaraRuleSignature | Unknown | Signature indicating that a YARA rule was matched. |
| GoogleCloudSCC.FindingV2.indicator.signatures.yaraRuleSignature.yaraRule | String | The name of the YARA rule. |
| GoogleCloudSCC.FindingV2.indicator.uris | Unknown | The list of URIs associated to the Findings. |
| GoogleCloudSCC.FindingV2.vulnerability | Unknown | Represents vulnerability-specific fields like CVE and CVSS scores. |
| GoogleCloudSCC.FindingV2.vulnerability.cve | Unknown | CVE stands for Common Vulnerabilities and Exposures \(&lt;<https://cve.mitre.org/about/&gt;\>) |
| GoogleCloudSCC.FindingV2.vulnerability.cve.id | String | The unique identifier for the vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.references | Unknown | Additional information about the CVE. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.references.source | String | Source of the reference e.g. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.references.uri | String | Uri for the mentioned source e.g. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3 | Unknown | Describe Common Vulnerability Scoring System specified at &lt;<https://www.first.org/cvss/v3.1/specification-document>&gt; |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.baseScore | Number | The base score is a function of the base metric scores. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.attackVector | String | Base Metrics Represents the intrinsic characteristics of a vulnerability that are constant over time and across user environments. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.attackComplexity | String | This metric describes the conditions beyond the attacker's control that must exist in order to exploit the vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.privilegesRequired | String | This metric describes the level of privileges an attacker must possess before successfully exploiting the vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.userInteraction | String | This metric captures the requirement for a human user, other than the attacker, to participate in the successful compromise of the vulnerable component. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.scope | String | The Scope metric captures whether a vulnerability in one vulnerable component impacts resources in components beyond its security scope. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.confidentialityImpact | String | This metric measures the impact to the confidentiality of the information resources managed by a software component due to a successfully exploited vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.integrityImpact | String | This metric measures the impact to integrity of a successfully exploited vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.availabilityImpact | String | This metric measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.upstreamFixAvailable | Boolean | Whether upstream fix is available for the CVE. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.impact | String | The potential impact of the vulnerability if it was to be exploited. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.exploitationActivity | String | The exploitation activity of the vulnerability in the wild. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.observedInTheWild | Boolean | Whether or not the vulnerability has been observed in the wild. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.zeroDay | Boolean | Whether or not the vulnerability was zero day when the finding was published. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.exploitReleaseDate | String | Date the first publicly available exploit or PoC was released. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.firstExploitationDate | String | Date of the earliest known exploitation. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage | Unknown | The offending package is relevant to the finding. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage.packageName | String | The name of the package where the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage.cpeUri | String | The CPE URI where the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage.packageType | String | Type of package, for example, os, maven, or go. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage.packageVersion | String | The version of the package. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage | Unknown | The fixed package is relevant to the finding. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage.packageName | String | The name of the package where the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage.cpeUri | String | The CPE URI where the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage.packageType | String | Type of package, for example, os, maven, or go. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage.packageVersion | String | The version of the package. |
| GoogleCloudSCC.FindingV2.vulnerability.securityBulletin | Unknown | The security bulletin is relevant to this finding. |
| GoogleCloudSCC.FindingV2.vulnerability.securityBulletin.bulletinId | String | ID of the bulletin corresponding to the vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.securityBulletin.submissionTime | String | Submission time of this Security Bulletin. |
| GoogleCloudSCC.FindingV2.vulnerability.securityBulletin.suggestedUpgradeVersion | String | This represents a version that the cluster receiving this notification should be upgraded to, based on its current version. |
| GoogleCloudSCC.FindingV2.vulnerability.providerRiskScore | String | Provider provided risk_score based on multiple factors. |
| GoogleCloudSCC.FindingV2.vulnerability.reachable | Boolean | Represents whether the vulnerability is reachable \(detected via static analysis\) |
| GoogleCloudSCC.FindingV2.vulnerability.cwes | Unknown | Represents one or more Common Weakness Enumeration \(CWE\) information on this vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cwes.id | String | The CWE identifier, e.g. |
| GoogleCloudSCC.FindingV2.vulnerability.cwes.references | Unknown | Any reference to the details on the CWE, for example, &lt;<https://dummyuser1@dummy.com/data/definitions/94.html>&gt; |
| GoogleCloudSCC.FindingV2.vulnerability.cwes.references.source | String | Source of the reference e.g. |
| GoogleCloudSCC.FindingV2.vulnerability.cwes.references.uri | String | Uri for the mentioned source e.g. |
| GoogleCloudSCC.FindingV2.muteUpdateTime | String | The time at which the finding was muted or unmuted. |
| GoogleCloudSCC.FindingV2.externalSystems | Unknown | Third party SIEM/SOAR fields within Security Command Center, contains external system information and external system finding fields. |
| GoogleCloudSCC.FindingV2.mitreAttack | Unknown | MITRE ATT&amp;CK tactics and techniques related to this finding. |
| GoogleCloudSCC.FindingV2.mitreAttack.primaryTactic | String | The MITRE ATT\\&amp;CK tactic most closely represented by this finding, if any. |
| GoogleCloudSCC.FindingV2.mitreAttack.primaryTechniques | Unknown | The MITRE ATT\\&amp;CK technique most closely represented by this finding, if any. |
| GoogleCloudSCC.FindingV2.mitreAttack.additionalTactics | Unknown | Additional MITRE ATT\\&amp;CK tactics related to this finding, if any. |
| GoogleCloudSCC.FindingV2.mitreAttack.additionalTechniques | Unknown | Additional MITRE ATT\\&amp;CK techniques related to this finding, if any, along with any of their respective parent techniques. |
| GoogleCloudSCC.FindingV2.mitreAttack.version | String | The MITRE ATT\\&amp;CK version referenced by the above fields. |
| GoogleCloudSCC.FindingV2.access | Unknown | Access details associated with the finding, such as more information on the caller, which method was accessed, and from where. |
| GoogleCloudSCC.FindingV2.access.principalEmail | String | Associated email, such as "<foo@google.com>". |
| GoogleCloudSCC.FindingV2.access.callerIp | String | Caller's IP address, such as "1.1.1.1". |
| GoogleCloudSCC.FindingV2.access.callerIpGeo | Unknown | The caller IP's geolocation, which identifies where the call came from. |
| GoogleCloudSCC.FindingV2.access.callerIpGeo.regionCode | String | A CLDR. |
| GoogleCloudSCC.FindingV2.access.userAgentFamily | String | Type of user agent associated with the finding. |
| GoogleCloudSCC.FindingV2.access.userAgent | String | The caller's user agent string associated with the finding. |
| GoogleCloudSCC.FindingV2.access.serviceName | String | This is the API service that the service account made a call to, e.g. |
| GoogleCloudSCC.FindingV2.access.methodName | String | The method that the service account called, e.g. |
| GoogleCloudSCC.FindingV2.access.principalSubject | String | A string that represents the principalSubject that is associated with the identity. |
| GoogleCloudSCC.FindingV2.access.serviceAccountKeyName | String | The name of the service account key that was used to create or exchange credentials when authenticating the service account that made the request. |
| GoogleCloudSCC.FindingV2.access.serviceAccountDelegationInfo | Unknown | The identity delegation history of an authenticated service account that made the request. |
| GoogleCloudSCC.FindingV2.access.serviceAccountDelegationInfo.principalEmail | String | The email address of a Google account. |
| GoogleCloudSCC.FindingV2.access.serviceAccountDelegationInfo.principalSubject | String | A string representing the principalSubject associated with the identity. |
| GoogleCloudSCC.FindingV2.access.userName | String | A string that represents a username. |
| GoogleCloudSCC.FindingV2.connections | Unknown | Contains information about the IP connection associated with the finding. |
| GoogleCloudSCC.FindingV2.connections.destinationIp | String | Destination IP address. |
| GoogleCloudSCC.FindingV2.connections.destinationPort | Number | Destination port. |
| GoogleCloudSCC.FindingV2.connections.sourceIp | String | Source IP address. |
| GoogleCloudSCC.FindingV2.connections.sourcePort | Number | Source port. |
| GoogleCloudSCC.FindingV2.connections.protocol | String | IANA Internet Protocol Number such as TCP\(6\) and UDP\(17\). |
| GoogleCloudSCC.FindingV2.muteInitiator | String | Records the entity that is responsible for the muting of the finding. |
| GoogleCloudSCC.FindingV2.processes | Unknown | Represents operating system processes associated with the finding. |
| GoogleCloudSCC.FindingV2.processes.name | String | The process name, as displayed in utilities like top and ps. |
| GoogleCloudSCC.FindingV2.processes.binary | Unknown | File information for the process executable. |
| GoogleCloudSCC.FindingV2.processes.binary.path | String | Absolute path of the file as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.binary.size | String | Size of the file in bytes. |
| GoogleCloudSCC.FindingV2.processes.binary.sha256 | String | SHA256 hash of the first hashedSize bytes of the file encoded as a hex string. |
| GoogleCloudSCC.FindingV2.processes.binary.hashedSize | String | The length in bytes of the file prefix that was hashed. |
| GoogleCloudSCC.FindingV2.processes.binary.partiallyHashed | Boolean | True when the hash covers only a prefix of the file. |
| GoogleCloudSCC.FindingV2.processes.binary.contents | String | Prefix of the file contents as a JSON-encoded string. |
| GoogleCloudSCC.FindingV2.processes.binary.diskPath | Unknown | Path of the file in terms of underlying disk/partition identifiers. |
| GoogleCloudSCC.FindingV2.processes.binary.diskPath.partitionUuid | String | UUID of the partition \(format &lt;<https://wiki.archlinux.org/title/persistent_block_device_naming\#by-uuid&gt;\>) |
| GoogleCloudSCC.FindingV2.processes.binary.diskPath.relativePath | String | Relative path of the file in the partition as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.binary.operations | Unknown | Operation\(s\) performed on a file. |
| GoogleCloudSCC.FindingV2.processes.binary.operations.type | String | The type of the operation |
| GoogleCloudSCC.FindingV2.processes.binary.fileLoadState | String | The load state of the file. |
| GoogleCloudSCC.FindingV2.processes.libraries | Unknown | File information for libraries loaded by the process. |
| GoogleCloudSCC.FindingV2.processes.libraries.path | String | Absolute path of the file as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.libraries.size | String | Size of the file in bytes. |
| GoogleCloudSCC.FindingV2.processes.libraries.sha256 | String | SHA256 hash of the first hashedSize bytes of the file encoded as a hex string. |
| GoogleCloudSCC.FindingV2.processes.libraries.hashedSize | String | The length in bytes of the file prefix that was hashed. |
| GoogleCloudSCC.FindingV2.processes.libraries.partiallyHashed | Boolean | True when the hash covers only a prefix of the file. |
| GoogleCloudSCC.FindingV2.processes.libraries.contents | String | Prefix of the file contents as a JSON-encoded string. |
| GoogleCloudSCC.FindingV2.processes.libraries.diskPath | Unknown | Path of the file in terms of underlying disk/partition identifiers. |
| GoogleCloudSCC.FindingV2.processes.libraries.diskPath.partitionUuid | String | UUID of the partition \(format &lt;<https://wiki.archlinux.org/title/persistent_block_device_naming\#by-uuid&gt;\>) |
| GoogleCloudSCC.FindingV2.processes.libraries.diskPath.relativePath | String | Relative path of the file in the partition as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.libraries.operations | Unknown | Operation\(s\) performed on a file. |
| GoogleCloudSCC.FindingV2.processes.libraries.operations.type | String | The type of the operation |
| GoogleCloudSCC.FindingV2.processes.libraries.fileLoadState | String | The load state of the file. |
| GoogleCloudSCC.FindingV2.processes.script | Unknown | When the process represents the invocation of a script, binary provides information about the interpreter, while script provides information about the script file provided to the interpreter. |
| GoogleCloudSCC.FindingV2.processes.script.path | String | Absolute path of the file as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.script.size | String | Size of the file in bytes. |
| GoogleCloudSCC.FindingV2.processes.script.sha256 | String | SHA256 hash of the first hashedSize bytes of the file encoded as a hex string. |
| GoogleCloudSCC.FindingV2.processes.script.hashedSize | String | The length in bytes of the file prefix that was hashed. |
| GoogleCloudSCC.FindingV2.processes.script.partiallyHashed | Boolean | True when the hash covers only a prefix of the file. |
| GoogleCloudSCC.FindingV2.processes.script.contents | String | Prefix of the file contents as a JSON-encoded string. |
| GoogleCloudSCC.FindingV2.processes.script.diskPath | Unknown | Path of the file in terms of underlying disk/partition identifiers. |
| GoogleCloudSCC.FindingV2.processes.script.diskPath.partitionUuid | String | UUID of the partition \(format &lt;<https://wiki.archlinux.org/title/persistent_block_device_naming\#by-uuid&gt;\>) |
| GoogleCloudSCC.FindingV2.processes.script.diskPath.relativePath | String | Relative path of the file in the partition as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.script.operations | Unknown | Operation\(s\) performed on a file. |
| GoogleCloudSCC.FindingV2.processes.script.operations.type | String | The type of the operation |
| GoogleCloudSCC.FindingV2.processes.script.fileLoadState | String | The load state of the file. |
| GoogleCloudSCC.FindingV2.processes.args | Unknown | Process arguments as JSON encoded strings. |
| GoogleCloudSCC.FindingV2.processes.argumentsTruncated | Boolean | True if args is incomplete. |
| GoogleCloudSCC.FindingV2.processes.envVariables | Unknown | Process environment variables. |
| GoogleCloudSCC.FindingV2.processes.envVariables.name | String | Environment variable name as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.envVariables.val | String | Environment variable value as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.envVariablesTruncated | Boolean | True if envVariables is incomplete. |
| GoogleCloudSCC.FindingV2.processes.pid | String | The process ID. |
| GoogleCloudSCC.FindingV2.processes.parentPid | String | The parent process ID. |
| GoogleCloudSCC.FindingV2.processes.userId | String | The ID of the user that executed the process. |
| GoogleCloudSCC.FindingV2.contacts | Unknown | Map containing the points of contact for the given finding. |
| GoogleCloudSCC.FindingV2.compliances | Unknown | Contains compliance information for security standards associated to the finding. |
| GoogleCloudSCC.FindingV2.compliances.standard | String | Industry-wide compliance standards or benchmarks, such as CIS, PCI, and OWASP. |
| GoogleCloudSCC.FindingV2.compliances.version | String | Version of the standard or benchmark, for example, 1.1 |
| GoogleCloudSCC.FindingV2.compliances.ids | Unknown | Policies within the standard or benchmark, for example, A.12.4.1 |
| GoogleCloudSCC.FindingV2.parentDisplayName | String | The human readable display name of the finding source, such as "Event Threat Detection" or "Security Health Analytics". |
| GoogleCloudSCC.FindingV2.description | String | Contains more details about the finding. |
| GoogleCloudSCC.FindingV2.exfiltration | Unknown | Represents exfiltrations associated with the finding. |
| GoogleCloudSCC.FindingV2.exfiltration.sources | Unknown | If there are multiple sources, then the data is considered "joined" between them. |
| GoogleCloudSCC.FindingV2.exfiltration.sources.name | String | The resource's full resource name. |
| GoogleCloudSCC.FindingV2.exfiltration.sources.components | Unknown | Subcomponents of the asset that was exfiltrated, like URIs used during exfiltration, table names, databases, and filenames. |
| GoogleCloudSCC.FindingV2.exfiltration.targets | Unknown | If there are multiple targets, each target would get a complete copy of the "joined" source data. |
| GoogleCloudSCC.FindingV2.exfiltration.targets.name | String | The resource's full resource name. |
| GoogleCloudSCC.FindingV2.exfiltration.targets.components | Unknown | Subcomponents of the asset that was exfiltrated, like URIs used during exfiltration, table names, databases, and filenames. |
| GoogleCloudSCC.FindingV2.exfiltration.totalExfiltratedBytes | String | Total exfiltrated bytes processed for the entire job. |
| GoogleCloudSCC.FindingV2.iamBindings | Unknown | Represents IAM bindings associated with the finding. |
| GoogleCloudSCC.FindingV2.iamBindings.action | String | The action that was performed on a Binding. |
| GoogleCloudSCC.FindingV2.iamBindings.role | String | Role that is assigned to "members". |
| GoogleCloudSCC.FindingV2.iamBindings.member | String | A single identity requesting access for a Cloud Platform resource, for example, "<foo@google.com>". |
| GoogleCloudSCC.FindingV2.nextSteps | String | Steps to address the finding. |
| GoogleCloudSCC.FindingV2.moduleName | String | Unique identifier of the module which generated the finding. |
| GoogleCloudSCC.FindingV2.containers | Unknown | Containers associated with the finding. This field provides information for both Kubernetes and non-Kubernetes containers. |
| GoogleCloudSCC.FindingV2.containers.name | String | Name of the container. |
| GoogleCloudSCC.FindingV2.containers.uri | String | Container image URI provided when configuring a pod or container. |
| GoogleCloudSCC.FindingV2.containers.imageId | String | Optional container image ID, if provided by the container runtime. |
| GoogleCloudSCC.FindingV2.containers.labels | Unknown | Container labels, as provided by the container runtime. |
| GoogleCloudSCC.FindingV2.containers.labels.name | String | Name of the label. |
| GoogleCloudSCC.FindingV2.containers.labels.value | String | Value that corresponds to the label's name. |
| GoogleCloudSCC.FindingV2.containers.createTime | String | The time that the container was created. |
| GoogleCloudSCC.FindingV2.kubernetes | Unknown | Kubernetes resources associated with the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.pods | Unknown | Kubernetes Pods associated with the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.ns | String | Kubernetes Pod namespace. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.name | String | Kubernetes Pod name. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.labels | Unknown | Pod labels. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.labels.name | String | Name of the label. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.labels.value | String | Value that corresponds to the label's name. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers | Unknown | Pod containers associated with this finding, if any. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.name | String | Name of the container. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.uri | String | Container image URI provided when configuring a pod or container. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.imageId | String | Optional container image ID, if provided by the container runtime. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.labels | Unknown | Container labels, as provided by the container runtime. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.labels.name | String | Name of the label. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.labels.value | String | Value that corresponds to the label's name. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.createTime | String | The time that the container was created. |
| GoogleCloudSCC.FindingV2.kubernetes.nodes | Unknown | Provides Kubernetes node information. |
| GoogleCloudSCC.FindingV2.kubernetes.nodes.name | String | Full resource name of the Compute Engine VM running the cluster node. |
| GoogleCloudSCC.FindingV2.kubernetes.nodePools | Unknown | GKE node pools associated with the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.nodePools.name | String | Kubernetes node pool name. |
| GoogleCloudSCC.FindingV2.kubernetes.nodePools.nodes | Unknown | Nodes associated with the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.nodePools.nodes.name | String | Full resource name of the Compute Engine VM running the cluster node. |
| GoogleCloudSCC.FindingV2.kubernetes.roles | Unknown | Provides Kubernetes role information for findings that involve Roles or ClusterRoles. |
| GoogleCloudSCC.FindingV2.kubernetes.roles.kind | String | Role type. |
| GoogleCloudSCC.FindingV2.kubernetes.roles.ns | String | Role namespace. |
| GoogleCloudSCC.FindingV2.kubernetes.roles.name | String | Role name. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings | Unknown | Provides Kubernetes role binding information for findings that involve RoleBindings or ClusterRoleBindings. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.ns | String | Namespace for the binding. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.name | String | Name for the binding. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.role | Unknown | The Role or ClusterRole referenced by the binding. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.role.kind | String | Role type. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.role.ns | String | Role namespace. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.role.name | String | Role name. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.subjects | Unknown | Represents one or more subjects that are bound to the role. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.subjects.kind | String | Authentication type for the subject. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.subjects.ns | String | Namespace for the subject. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.subjects.name | String | Name for the subject. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews | Unknown | Provides information on any Kubernetes access reviews \(privilege checks\) relevant to the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.group | String | The API group of the resource. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.ns | String | Namespace of the action being requested. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.name | String | The name of the resource being requested. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.resource | String | The optional resource type requested. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.subresource | String | The optional subresource type. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.verb | String | A Kubernetes resource API verb, like get, list, watch, create, update, delete, proxy. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.version | String | The API version of the resource. |
| GoogleCloudSCC.FindingV2.kubernetes.objects | Unknown | Kubernetes objects related to the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.group | String | Kubernetes object group, such as "policy.k8s.io/v1". |
| GoogleCloudSCC.FindingV2.kubernetes.objects.kind | String | Kubernetes object kind, such as "Namespace". |
| GoogleCloudSCC.FindingV2.kubernetes.objects.ns | String | Kubernetes object namespace. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.name | String | Kubernetes object name. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers | Unknown | Pod containers associated with this finding, if any. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.name | String | Name of the container. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.uri | String | Container image URI provided when configuring a pod or container. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.imageId | String | Optional container image ID, if provided by the container runtime. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.labels | Unknown | Container labels, as provided by the container runtime. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.labels.name | String | Name of the label. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.labels.value | String | Value that corresponds to the label's name. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.createTime | String | The time that the container was created. |
| GoogleCloudSCC.FindingV2.database | Unknown | Database associated with the finding. |
| GoogleCloudSCC.FindingV2.database.name | String | Some database resources may not have the full resource name populated because these resource types are not yet supported by Cloud Asset Inventory \(e.g. |
| GoogleCloudSCC.FindingV2.database.displayName | String | The human-readable name of the database that the user connected to. |
| GoogleCloudSCC.FindingV2.database.userName | String | The username used to connect to the database. |
| GoogleCloudSCC.FindingV2.database.query | String | The SQL statement that is associated with the database access. |
| GoogleCloudSCC.FindingV2.database.grantees | Unknown | The target usernames, roles, or groups of an SQL privilege grant, which is not an IAM policy change. |
| GoogleCloudSCC.FindingV2.database.version | String | The version of the database, for example, POSTGRES_14. |
| GoogleCloudSCC.FindingV2.attackExposure | Unknown | The results of an attack path simulation relevant to this finding. |
| GoogleCloudSCC.FindingV2.attackExposure.score | Number | A number between 0 \(inclusive\) and infinity that represents how important this finding is to remediate. |
| GoogleCloudSCC.FindingV2.attackExposure.latestCalculationTime | String | The most recent time the attack exposure was updated on this finding. |
| GoogleCloudSCC.FindingV2.attackExposure.attackExposureResult | String | The resource name of the attack path simulation result that contains the details regarding this attack exposure score. |
| GoogleCloudSCC.FindingV2.attackExposure.state | String | Output only. |
| GoogleCloudSCC.FindingV2.attackExposure.exposedHighValueResourcesCount | Number | The number of high value resources that are exposed as a result of this finding. |
| GoogleCloudSCC.FindingV2.attackExposure.exposedMediumValueResourcesCount | Number | The number of medium value resources that are exposed as a result of this finding. |
| GoogleCloudSCC.FindingV2.attackExposure.exposedLowValueResourcesCount | Number | The number of high value resources that are exposed as a result of this finding. |
| GoogleCloudSCC.FindingV2.files | Unknown | File associated with the finding. |
| GoogleCloudSCC.FindingV2.files.path | String | Absolute path of the file as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.files.size | String | Size of the file in bytes. |
| GoogleCloudSCC.FindingV2.files.sha256 | String | SHA256 hash of the first hashedSize bytes of the file encoded as a hex string. |
| GoogleCloudSCC.FindingV2.files.hashedSize | String | The length in bytes of the file prefix that was hashed. |
| GoogleCloudSCC.FindingV2.files.partiallyHashed | Boolean | True when the hash covers only a prefix of the file. |
| GoogleCloudSCC.FindingV2.files.contents | String | Prefix of the file contents as a JSON-encoded string. |
| GoogleCloudSCC.FindingV2.files.diskPath | Unknown | Path of the file in terms of underlying disk/partition identifiers. |
| GoogleCloudSCC.FindingV2.files.diskPath.partitionUuid | String | UUID of the partition \(format &lt;<https://wiki.archlinux.org/title/persistent_block_device_naming\#by-uuid&gt;\>) |
| GoogleCloudSCC.FindingV2.files.diskPath.relativePath | String | Relative path of the file in the partition as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.files.operations | Unknown | Operation\(s\) performed on a file. |
| GoogleCloudSCC.FindingV2.files.operations.type | String | The type of the operation |
| GoogleCloudSCC.FindingV2.files.fileLoadState | String | The load state of the file. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection | Unknown | Cloud Data Loss Prevention \(Cloud DLP\) inspection results that are associated with the finding. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection.inspectJob | String | Name of the inspection job, for example, projects/123/locations/europe/dlpJobs/i-8383929. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection.infoType | String | The type of information \(or \*infoType\* \) found, for example, EMAIL_ADDRESS or STREET_ADDRESS. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection.infoTypeCount | String | The number of times Cloud DLP found this infoType within this job and resource. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection.fullScan | Boolean | Whether Cloud DLP scanned the complete resource or a sampled subset. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile | Unknown | Cloud DLP data profile that is associated with the finding. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.dataProfile | String | Name of the data profile, for example, projects/123/locations/europe/tableProfiles/8383929. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.parentType | String | The resource hierarchy level at which the data profile was generated. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes | Unknown | Type of information detected by SDP. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes.name | String | Name of the information type. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes.version | String | Optional version name for this InfoType. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes.sensitivityScore | Unknown | Optional custom sensitivity for this InfoType. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes.sensitivityScore.score | String | The sensitivity score applied to the resource. |
| GoogleCloudSCC.FindingV2.kernelRootkit | Unknown | Signature of the kernel rootkit. |
| GoogleCloudSCC.FindingV2.kernelRootkit.name | String | Rootkit name, when available. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedCodeModification | Boolean | True if unexpected modifications of kernel code memory are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedReadOnlyDataModification | Boolean | True if unexpected modifications of kernel read-only data memory are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedFtraceHandler | Boolean | True if ftrace points are present with callbacks pointing to regions that are not in the expected kernel or module code range. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedKprobeHandler | Boolean | True if kprobe points are present with callbacks pointing to regions that are not in the expected kernel or module code range. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedKernelCodePages | Boolean | True if kernel code pages that are not in the expected kernel or module code regions are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedSystemCallHandler | Boolean | True if system call handlers that are are not in the expected kernel or module code regions are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedInterruptHandler | Boolean | True if interrupt handlers that are are not in the expected kernel or module code regions are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedProcessesInRunqueue | Boolean | True if unexpected processes in the scheduler run queue are present. |
| GoogleCloudSCC.FindingV2.orgPolicies | Unknown | Contains information about the org policies associated with the finding. |
| GoogleCloudSCC.FindingV2.orgPolicies.name | String | Identifier. |
| GoogleCloudSCC.FindingV2.job | Unknown | Job associated with the finding. |
| GoogleCloudSCC.FindingV2.job.name | String | The fully-qualified name for a job. |
| GoogleCloudSCC.FindingV2.job.state | String | Output only. |
| GoogleCloudSCC.FindingV2.job.errorCode | Number | Optional. |
| GoogleCloudSCC.FindingV2.job.location | String | Optional. |
| GoogleCloudSCC.FindingV2.application | Unknown | Represents an application associated with the finding. |
| GoogleCloudSCC.FindingV2.application.baseUri | String | The base URI that identifies the network location of the application in which the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.application.fullUri | String | The full URI with payload that could be used to reproduce the vulnerability. |
| GoogleCloudSCC.FindingV2.ipRules | Unknown | IP rules associated with the finding. |
| GoogleCloudSCC.FindingV2.ipRules.direction | String | The direction that the rule is applicable to, one of ingress or egress. |
| GoogleCloudSCC.FindingV2.ipRules.sourceIpRanges | Unknown | If source IP ranges are specified, the firewall rule applies only to traffic that has a source IP address in these ranges. |
| GoogleCloudSCC.FindingV2.ipRules.destinationIpRanges | Unknown | If destination IP ranges are specified, the firewall rule applies only to traffic that has a destination IP address in these ranges. |
| GoogleCloudSCC.FindingV2.ipRules.exposedServices | Unknown | Name of the network protocol service, such as FTP, that is exposed by the open port. |
| GoogleCloudSCC.FindingV2.ipRules.allowed | Unknown | Tuple with allowed rules. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules | Unknown | Optional. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules.protocol | String | The IP protocol this rule applies to. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules.portRanges | Unknown | Optional. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules.portRanges.min | String | Minimum port value. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules.portRanges.max | String | Maximum port value. |
| GoogleCloudSCC.FindingV2.ipRules.denied | Unknown | Tuple with denied rules. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules | Unknown | Optional. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules.protocol | String | The IP protocol this rule applies to. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules.portRanges | Unknown | Optional. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules.portRanges.min | String | Minimum port value. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules.portRanges.max | String | Maximum port value. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery | Unknown | Fields related to Backup and Disaster Recovery findings. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.backupTemplate | String | The name of a Backup and DR template which comprises one or more backup policies. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.policies | Unknown | The names of Backup and DR policies that are associated with a template and that define when to run a backup, how frequently to run a backup, and how long to retain the backup image. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.host | String | The name of a Backup and DR host, which is managed by the backup and recovery appliance and known to the management console. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.applications | Unknown | The names of Backup and DR applications. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.storagePool | String | The name of the Backup and DR storage pool that the backup and recovery appliance is storing data in. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.policyOptions | Unknown | The names of Backup and DR advanced policy options of a policy applying to an application. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.profile | String | The name of the Backup and DR resource profile that specifies the storage media for backups of application and VM data. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.appliance | String | The name of the Backup and DR appliance that captures, moves, and manages the lifecycle of backup data. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.backupType | String | The backup type of the Backup and DR image. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.backupCreateTime | String | The timestamp at which the Backup and DR backup was created. |
| GoogleCloudSCC.FindingV2.securityPosture | Unknown | The security posture associated with the finding. |
| GoogleCloudSCC.FindingV2.securityPosture.name | String | Name of the posture, for example, CIS-Posture. |
| GoogleCloudSCC.FindingV2.securityPosture.revisionId | String | The version of the posture, for example, c7cfa2a8. |
| GoogleCloudSCC.FindingV2.securityPosture.postureDeploymentResource | String | The project, folder, or organization on which the posture is deployed, for example, projects/\{project_number\}. |
| GoogleCloudSCC.FindingV2.securityPosture.postureDeployment | String | The name of the posture deployment, for example, organizations/\{org_id\}/posturedeployments/\{posture_deployment_id\}. |
| GoogleCloudSCC.FindingV2.securityPosture.changedPolicy | String | The name of the updated policy, for example, projects/\{projectId\}/policies/\{constraint_name\}. |
| GoogleCloudSCC.FindingV2.securityPosture.policySet | String | The name of the updated policy set, for example, cis-policyset. |
| GoogleCloudSCC.FindingV2.securityPosture.policy | String | The ID of the updated policy, for example, compute-policy-1. |
| GoogleCloudSCC.FindingV2.securityPosture.policyDriftDetails | Unknown | The details about a change in an updated policy that violates the deployed posture. |
| GoogleCloudSCC.FindingV2.securityPosture.policyDriftDetails.field | String | The name of the updated field, for example constraint.implementation.policy_rules\\\[0\\\].enforce |
| GoogleCloudSCC.FindingV2.securityPosture.policyDriftDetails.expectedValue | String | The value of this field that was configured in a posture, for example, true or allowed_values=\{"projects/29831892"\}. |
| GoogleCloudSCC.FindingV2.securityPosture.policyDriftDetails.detectedValue | String | The detected value that violates the deployed posture, for example, false or allowed_values=\{"projects/22831892"\}. |
| GoogleCloudSCC.FindingV2.logEntries | Unknown | Log entries that are relevant to the finding. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry | Unknown | An individual entry in a log stored in Cloud Logging. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry.insertId | String | A unique identifier for the log entry. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry.logId | String | The type of the log \(part of logName. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry.resourceContainer | String | The organization, folder, or project of the monitored resource that produced this log entry. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry.timestamp | String | The time the event described by the log entry occurred. |
| GoogleCloudSCC.FindingV2.loadBalancers | Unknown | The load balancers associated with the finding. |
| GoogleCloudSCC.FindingV2.loadBalancers.name | String | The name of the load balancer associated with the finding. |
| GoogleCloudSCC.FindingV2.cloudArmor | Unknown | Fields related to Google Cloud Armor findings. |
| GoogleCloudSCC.FindingV2.cloudArmor.securityPolicy | Unknown | Information about the Google Cloud Armor security policy relevant to the finding. |
| GoogleCloudSCC.FindingV2.cloudArmor.securityPolicy.name | String | The name of the Google Cloud Armor security policy, for example, "my-security-policy". |
| GoogleCloudSCC.FindingV2.cloudArmor.securityPolicy.type | String | The type of Google Cloud Armor security policy for example, 'backend security policy', 'edge security policy', 'network edge security policy', or 'always-on DDoS protection'. |
| GoogleCloudSCC.FindingV2.cloudArmor.securityPolicy.preview | Boolean | Whether or not the associated rule or policy is in preview mode. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests | Unknown | Information about incoming requests evaluated by Google Cloud Armor security policies. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests.ratio | Number | For 'Increasing deny ratio', the ratio is the denied traffic divided by the allowed traffic. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests.shortTermAllowed | Number | Allowed RPS \(requests per second\) in the short term. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests.longTermAllowed | Number | Allowed RPS \(requests per second\) over the long term. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests.longTermDenied | Number | Denied RPS \(requests per second\) over the long term. |
| GoogleCloudSCC.FindingV2.cloudArmor.adaptiveProtection | Unknown | Information about potential Layer 7 DDoS attacks identified by Google Cloud Armor Adaptive Protection. |
| GoogleCloudSCC.FindingV2.cloudArmor.adaptiveProtection.confidence | Number | A score of 0 means that there is low confidence that the detected event is an actual attack. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack | Unknown | Information about DDoS attack volume and classification. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.volumePpsLong | String | Total PPS \(packets per second\) volume of attack. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.volumeBpsLong | String | Total BPS \(bytes per second\) volume of attack. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.classification | String | Type of attack, for example, 'SYN-flood', 'NTP-udp', or 'CHARGEN-udp'. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.volumePps | Number | Volume Pps. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.volumeBps | Number | Volume Bps. |
| GoogleCloudSCC.FindingV2.cloudArmor.threatVector | String | Distinguish between volumetric \\&amp; protocol DDoS attack and application layer attacks. |
| GoogleCloudSCC.FindingV2.cloudArmor.duration | String | Duration of attack from the start until the current moment \(updated every 5 minutes\). |
| GoogleCloudSCC.FindingV2.notebook | Unknown | Notebook associated with the finding. |
| GoogleCloudSCC.FindingV2.notebook.name | String | The name of the notebook. |
| GoogleCloudSCC.FindingV2.notebook.service | String | The source notebook service, for example, "Colab Enterprise". |
| GoogleCloudSCC.FindingV2.notebook.lastAuthor | String | The user ID of the latest author to modify the notebook. |
| GoogleCloudSCC.FindingV2.notebook.notebookUpdateTime | String | The most recent time the notebook was updated. |
| GoogleCloudSCC.FindingV2.toxicCombination | Unknown | Contains details about a group of security issues that, when combined, represent a greater risk than when the issues occur independently. |
| GoogleCloudSCC.FindingV2.toxicCombination.attackExposureScore | Number | The Attack exposure score of this toxic combination. |
| GoogleCloudSCC.FindingV2.toxicCombination.relatedFindings | Unknown | List of resource names of findings associated with this toxic combination. |
| GoogleCloudSCC.FindingV2.groupMemberships | Unknown | Contains details about groups of which this finding is a member. |
| GoogleCloudSCC.FindingV2.groupMemberships.groupType | String | Type of group. |
| GoogleCloudSCC.FindingV2.groupMemberships.groupId | String | ID of the group. |
| GoogleCloudSCC.FindingV2.disk | Unknown | Disk associated with the finding. |
| GoogleCloudSCC.FindingV2.disk.name | String | The name of the disk, for example, "<https://www.googleapis.com/compute/v1/projects/\{project-id\}/zones/\{zone-id\}/disks/\{disk-id\}>". |
| GoogleCloudSCC.FindingV2.dataAccessEvents | Unknown | Data access events associated with the finding. |
| GoogleCloudSCC.FindingV2.dataAccessEvents.eventId | String | Unique identifier for data access event. |
| GoogleCloudSCC.FindingV2.dataAccessEvents.principalEmail | String | The email address of the principal that accessed the data. |
| GoogleCloudSCC.FindingV2.dataAccessEvents.operation | String | The operation performed by the principal to access the data. |
| GoogleCloudSCC.FindingV2.dataAccessEvents.eventTime | String | Timestamp of data access event. |
| GoogleCloudSCC.FindingV2.dataFlowEvents | Unknown | Data flow events associated with the finding. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.eventId | String | Unique identifier for data flow event. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.principalEmail | String | The email address of the principal that initiated the data flow event. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.operation | String | The operation performed by the principal for the data flow event. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.violatedLocation | String | Non-compliant location of the principal or the data destination. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.eventTime | String | Timestamp of data flow event. |
| GoogleCloudSCC.FindingV2.networks | Unknown | Represents the VPC networks that the resource is attached to. |
| GoogleCloudSCC.FindingV2.networks.name | String | The name of the VPC network resource, for example, //compute.googleapis.com/projects/my-project/global/networks/my-network. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents | Unknown | Data retention deletion events associated with the finding. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.eventDetectionTime | String | Timestamp indicating when the event was detected. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.dataObjectCount | String | Number of objects that violated the policy for this resource. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.maxRetentionAllowed | String | Maximum duration of retention allowed from the DRD control. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.minRetentionAllowed | String | The minimum duration that the resource associated with this finding must be retained, as enforced by the DSPM retention control. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.eventType | String | Type of the DRD event. |
| GoogleCloudSCC.FindingV2.affectedResources | Unknown | The details about a distinct count of resources affected by the finding. |
| GoogleCloudSCC.FindingV2.affectedResources.count | String | The count of resources affected by the finding. |
| GoogleCloudSCC.FindingV2.aiModel | Unknown | The AI model associated with the finding. |
| GoogleCloudSCC.FindingV2.aiModel.name | String | The name of the AI model, for example, "gemini:1.0.0". |
| GoogleCloudSCC.FindingV2.aiModel.domain | String | The domain of the model, for example, "image-classification". |
| GoogleCloudSCC.FindingV2.aiModel.library | String | The name of the model library, for example, "transformers". |
| GoogleCloudSCC.FindingV2.aiModel.location | String | The region in which the model is used, for example, "us-central1". |
| GoogleCloudSCC.FindingV2.aiModel.publisher | String | The publisher of the model, for example, "google" or "nvidia". |
| GoogleCloudSCC.FindingV2.aiModel.deploymentPlatform | String | The platform on which the model is deployed. |
| GoogleCloudSCC.FindingV2.aiModel.displayName | String | The user defined display name of model. |
| GoogleCloudSCC.FindingV2.aiModel.usageCategory | String | The purpose of the model, for example, "Interference" or "Training". |
| GoogleCloudSCC.FindingV2.chokepoint | Unknown | Contains details about a chokepoint, which is a resource or resource group where high-risk attack paths converge. |
| GoogleCloudSCC.FindingV2.chokepoint.relatedFindings | Unknown | List of resource names of findings associated with this chokepoint. |
| GoogleCloudSCC.FindingV2.complianceDetails | Unknown | Details about the compliance implications of the finding. |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks | Unknown | Details of Frameworks associated with the finding |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.name | String | Name of the framework associated with the finding |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.displayName | String | Display name of the framework. |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.category | Unknown | Category of the framework associated with the finding. |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.type | String | Type of the framework associated with the finding, to specify whether the framework is built-in \(pre-defined and immutable\) or a custom framework defined by the customer \(equivalent to security posture\) |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.controls | Unknown | The controls associated with the framework. |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.controls.controlName | String | Name of the Control |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.controls.displayName | String | Display name of the control. |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl | Unknown | CloudControl associated with the finding |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl.cloudControlName | String | Name of the CloudControl associated with the finding. |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl.type | String | Type of cloud control. |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl.policyType | String | Policy type of the CloudControl |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl.version | Number | Version of the Cloud Control |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControlDeploymentNames | Unknown | Cloud Control Deployments associated with the finding. |
| GoogleCloudSCC.FindingV2.vertexAi | Unknown | VertexAi associated with the finding. |
| GoogleCloudSCC.FindingV2.vertexAi.datasets | Unknown | Datasets associated with the finding. |
| GoogleCloudSCC.FindingV2.vertexAi.datasets.name | String | Resource name of the dataset, e.g. |
| GoogleCloudSCC.FindingV2.vertexAi.datasets.displayName | String | The user defined display name of dataset, e.g. |
| GoogleCloudSCC.FindingV2.vertexAi.datasets.source | String | Data source, such as a BigQuery source URI, e.g. |
| GoogleCloudSCC.FindingV2.vertexAi.pipelines | Unknown | Pipelines associated with the finding. |
| GoogleCloudSCC.FindingV2.vertexAi.pipelines.name | String | Resource name of the pipeline, e.g. |
| GoogleCloudSCC.FindingV2.vertexAi.pipelines.displayName | String | The user-defined display name of pipeline, e.g. |
| GoogleCloudSCC.FindingV2.cryptoKeyName | String | The name of the crypto key associated with the finding. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies | Unknown | Artifact Guard policies associated with the finding. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.resourceId | String | The ID of the resource that has policies configured. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.failingPolicies | Unknown | A list of artifact guard policies that the resource violated. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.failingPolicies.type | String | The type of the policy evaluation. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.failingPolicies.policyId | String | The ID of the failing policy, for example, "organizations/3392779/locations/global/policies/prod-policy". |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.failingPolicies.failureReason | String | The reason for the policy failure, for example, "severity=HIGH AND max_vuln_count=2". |
| GoogleCloudSCC.FindingV2.secret | Unknown | Secret associated with the finding. |
| GoogleCloudSCC.FindingV2.secret.type | String | The type of secret, for example, GCP_API_KEY. |
| GoogleCloudSCC.FindingV2.secret.status | Unknown | The status of the secret. |
| GoogleCloudSCC.FindingV2.secret.status.lastUpdatedTime | String | Time that the secret was found. |
| GoogleCloudSCC.FindingV2.secret.status.validity | String | The validity of the secret. |
| GoogleCloudSCC.FindingV2.secret.environmentVariable | Unknown | The environment variable containing the secret. |
| GoogleCloudSCC.FindingV2.secret.environmentVariable.key | String | The environment variable name as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.secret.filePath | Unknown | The file containing the secret. |
| GoogleCloudSCC.FindingV2.secret.filePath.path | String | Path to the file. |
| GoogleCloudSCC.FindingV2.externalExposure | Unknown | Represents the external exposure of the finding. |
| GoogleCloudSCC.FindingV2.externalExposure.privateIpAddress | String | Private IP address of the exposed endpoint. |
| GoogleCloudSCC.FindingV2.externalExposure.privatePort | String | Port number associated with private IP address. |
| GoogleCloudSCC.FindingV2.externalExposure.exposedService | String | The name and version of the service, for example, "Jupyter Notebook 6.14.0". |
| GoogleCloudSCC.FindingV2.externalExposure.publicIpAddress | String | Public IP address of the exposed endpoint. |
| GoogleCloudSCC.FindingV2.externalExposure.publicPort | String | Public port number of the exposed endpoint. |
| GoogleCloudSCC.FindingV2.externalExposure.exposedEndpoint | String | The resource which is running the exposed service, for example, "//compute.googleapis.com/projects/\{project-id\}/zones/\{zone\}/instances/\{instance\}". |
| GoogleCloudSCC.FindingV2.externalExposure.loadBalancerFirewallPolicy | String | The full resource name of the load balancer firewall policy, for example, "//compute.googleapis.com/projects/\{project-id\}/global/firewallPolicies/\{policy-name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.serviceFirewallPolicy | String | The full resource name of the firewall policy of the exposed service, for example, "//compute.googleapis.com/projects/\{project-id\}/global/firewallPolicies/\{policy-name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.forwardingRule | String | The full resource name of the forwarding rule, for example, "//compute.googleapis.com/projects/\{project-id\}/global/forwardingRules/\{forwarding-rule-name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.backendService | String | The full resource name of load balancer backend service, for example, "//compute.googleapis.com/projects/\{project-id\}/global/backendServices/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.instanceGroup | String | The full resource name of the instance group, for example, "//compute.googleapis.com/projects/\{project-id\}/global/instanceGroups/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.networkEndpointGroup | String | The full resource name of the network endpoint group, for example, "//compute.googleapis.com/projects/\{project-id\}/global/networkEndpointGroups/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.hostnameUri | String | Hostname of the exposed application, for example, <https://example.com/> |
| GoogleCloudSCC.FindingV2.externalExposure.pscServiceAttachment | String | The full resource name of the PSC \(Private Service Connect\) service attachment that the load balancer network endpoint group targets, for example, "//compute.googleapis.com/projects/\{project-id\}/regions/\{region\}/serviceAttachments/\{name\}" |
| GoogleCloudSCC.FindingV2.externalExposure.pscNetworkAttachment | String | The full resource name of the PSC \(Private Service Connect\) network attachment that network interface controller is attached to, for example, "//compute.googleapis.com/projects/\{project-id\}/regions/\{region\}/networkAttachments/\{name\}" |
| GoogleCloudSCC.FindingV2.externalExposure.internalBackendService | String | The full resource name of load balancer backend service in the internal project having resource exposed via PSC, for example, "//compute.googleapis.com/projects/\{project-id\}/global/backendServices/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.backendBucket | String | The full resource name of the load balancer backend bucket, for example, "//compute.googleapis.com/projects/\{project-id\}/global/backendBuckets/\{name\}" |
| GoogleCloudSCC.FindingV2.externalExposure.exposedApplication | String | The name and version of the exposed web application, for example, "Jenkins 2.184". |
| GoogleCloudSCC.FindingV2.externalExposure.networkIngressFirewallPolicy | String | The full resource name of the network ingress firewall policy, for example, "//compute.googleapis.com/projects/\{project-id\}/global/firewallPolicies/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.httpResponse | Unknown | The http response returned by the web application. |
| GoogleCloudSCC.FindingV2.externalExposure.httpResponse.statusCode | String | The http response code returned by the web application, for example, 200. |
| GoogleCloudSCC.FindingV2.externalExposure.httpResponse.path | String | The http path for which response code was returned by web application, for example, <https://example.com/example>. |
| GoogleCloudSCC.FindingV2.externalExposure.networkPathInsightsGenerationTime | String | The timestamp when the network reachability trace was generated or verified. |
| GoogleCloudSCC.FindingV2.policyViolationSummary | Unknown | Summary of the policy violations associated with the finding. |
| GoogleCloudSCC.FindingV2.policyViolationSummary.policyViolationsCount | String | Count of child resources in violation of the policy. |
| GoogleCloudSCC.FindingV2.policyViolationSummary.conformantResourcesCount | String | Total number of child resources that conform to the policy. |
| GoogleCloudSCC.FindingV2.policyViolationSummary.evaluationErrorsCount | String | Number of child resources for which errors during evaluation occurred. |
| GoogleCloudSCC.FindingV2.policyViolationSummary.outOfScopeResourcesCount | String | Total count of child resources which were not in scope for evaluation. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents | Unknown | Agent data access events associated with the finding. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents.eventId | String | Unique identifier for data access event. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents.principalSubject | String | The agent principal that accessed the data. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents.operation | String | The operation performed by the principal to access the data. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents.eventTime | String | Timestamp of data access event. |
| GoogleCloudSCC.FindingV2.discoveredWorkload | Unknown | The workload that this finding is associated with. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.workloadType | String | The type of workload. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.confidence | String | The confidence in detection of this workload. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.detectedRelevantPackages | Boolean | A boolean flag set to true if installed packages strongly predict the workload type. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.detectedRelevantKeywords | Boolean | A boolean flag set to true if associated keywords strongly predict the workload type. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.detectedRelevantHardware | Boolean | A boolean flag set to true if associated hardware strongly predicts the workload type. |

#### Command Example

```!google-cloud-scc-v2-finding-update name="organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a" severity="CRITICAL"```

#### Context Example

```json
{
    "GoogleCloudSCC": {
        "FindingV2": {
            "name": "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a",
            "canonicalName": "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a",
            "parent": "organizations/1094826489209/sources/5629340921983475201",
            "resourceName": "//compute.googleapis.com/projects/prod-webapp-284917/zones/us-central1-a/instances/web-server-01",
            "state": "ACTIVE",
            "category": "Malware: Cryptomining Bad IP",
            "externalUri": "https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/web-server-01?project=prod-webapp-284917",
            "sourceProperties": {
                "dst_zipcode": "94043",
                "browser": "Chrome",
                "dst_region": "California",
                "userkey": "jdoe@example.com",
                "traffic_type": "CloudApp",
                "count": "3",
                "dst_longitude": -122.0841,
                "src_region": "Maharashtra",
                "app": "Google Cloud Platform",
                "dst_latitude": 37.422,
                "object": "instances/web-server-01",
                "src_latitude": 19.076,
                "sv": "malsite",
                "os": "Linux",
                "src_geoip_src": "MaxMind",
                "dst_location": "Mountain View",
                "device": "Server",
                "srcip": "10.0.0.1"
            },
            "securityMarks": {
                "name": "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a/securityMarks",
                "marks": {
                    "priority": "P1",
                    "reviewed": "true"
                },
                "canonicalName": "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a/securityMarks"
            },
            "eventTime": "2020-02-18T07:26:42Z",
            "createTime": "2020-02-19T13:37:43.858Z",
            "severity": "CRITICAL",
            "mute": "MUTED",
            "muteInfo": {
                "staticMute": {
                    "state": "MUTED",
                    "applyTime": "2020-02-18T07:26:42Z"
                },
                "dynamicMuteRecords": [
                    {
                        "muteConfig": "organizations/1094826489209/muteConfigs/known-cryptomining-testrange",
                        "matchTime": "2020-02-18T07:26:42Z"
                    }
                ]
            },
            "findingClass": "THREAT",
            "indicator": {
                "ipAddresses": [
                    "10.0.0.1"
                ],
                "domains": [
                    "xmr-pool.badactor.example"
                ],
                "signatures": [
                    {
                        "signatureType": "SIGNATURE_TYPE_PROCESS",
                        "memoryHashSignature": {
                            "binaryFamily": "XMRig",
                            "detections": [
                                {
                                    "binary": "xmrig",
                                    "percentPagesMatched": 0.87
                                }
                            ]
                        },
                        "yaraRuleSignature": {
                            "yaraRule": "Cryptominer_XMRig_Generic"
                        }
                    }
                ],
                "uris": [
                    "http://xmr-pool.badactor.example:3333"
                ]
            },
            "vulnerability": {
                "cve": {
                    "id": "CVE-2021-44228",
                    "references": [
                        {
                            "source": "NVD",
                            "uri": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
                        }
                    ],
                    "cvssv3": {
                        "baseScore": 10.0,
                        "attackVector": "ATTACK_VECTOR_NETWORK",
                        "attackComplexity": "ATTACK_COMPLEXITY_LOW",
                        "privilegesRequired": "PRIVILEGES_REQUIRED_NONE",
                        "userInteraction": "USER_INTERACTION_NONE",
                        "scope": "SCOPE_CHANGED",
                        "confidentialityImpact": "IMPACT_HIGH",
                        "integrityImpact": "IMPACT_HIGH",
                        "availabilityImpact": "IMPACT_HIGH"
                    },
                    "upstreamFixAvailable": true,
                    "impact": "LOW",
                    "exploitationActivity": "WIDE",
                    "observedInTheWild": true,
                    "zeroDay": false,
                    "exploitReleaseDate": "2021-12-10T00:00:00Z",
                    "firstExploitationDate": "2021-12-10T00:00:00Z"
                },
                "offendingPackage": {
                    "packageName": "log4j-core",
                    "cpeUri": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                    "packageType": "MAVEN",
                    "packageVersion": "2.14.1"
                },
                "fixedPackage": {
                    "packageName": "log4j-core",
                    "cpeUri": "cpe:2.3:a:apache:log4j:2.17.1:*:*:*:*:*:*:*",
                    "packageType": "MAVEN",
                    "packageVersion": "2.17.1"
                },
                "securityBulletin": {
                    "bulletinId": "GCP-2021-021",
                    "submissionTime": "2021-12-11T00:00:00Z",
                    "suggestedUpgradeVersion": "2.17.1"
                },
                "providerRiskScore": "95",
                "reachable": true,
                "cwes": [
                    {
                        "id": "CWE-502",
                        "references": [
                            {
                                "source": "MITRE",
                                "uri": "https://dummyuser1@dummy.com/data/definitions/502.html"
                            }
                        ]
                    }
                ]
            },
            "muteUpdateTime": "2020-02-18T07:26:42Z",
            "externalSystems": {
                "jira": {
                    "name": "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a/externalSystems/jira",
                    "assignees": [
                        "secops@example.com"
                    ],
                    "externalUid": "SEC-4821",
                    "status": "In Progress",
                    "externalSystemUpdateTime": "2020-02-18T07:26:42Z",
                    "caseUri": "https://example.atlassian.net/browse/SEC-4821",
                    "casePriority": "High",
                    "caseSla": "2020-02-20T07:26:42Z",
                    "caseCreateTime": "2020-02-18T07:26:42Z",
                    "caseCloseTime": "2020-02-19T07:26:42Z",
                    "ticketInfo": {
                        "id": "SEC-4821",
                        "assignee": "secops@example.com",
                        "description": "Cryptomining activity detected on web-server-01",
                        "uri": "https://example.atlassian.net/browse/SEC-4821",
                        "status": "In Progress",
                        "updateTime": "2020-02-18T07:26:42Z"
                    }
                }
            },
            "mitreAttack": {
                "primaryTactic": "IMPACT",
                "primaryTechniques": [
                    "RESOURCE_HIJACKING"
                ],
                "additionalTactics": [
                    "COMMAND_AND_CONTROL"
                ],
                "additionalTechniques": [
                    "INGRESS_TOOL_TRANSFER"
                ],
                "version": "12"
            },
            "access": {
                "principalEmail": "jdoe@example.com",
                "callerIp": "10.0.0.1",
                "callerIpGeo": {
                    "regionCode": "IN"
                },
                "userAgentFamily": "curl",
                "userAgent": "curl/7.68.0",
                "serviceName": "compute.googleapis.com",
                "methodName": "v1.compute.instances.get",
                "principalSubject": "user:jdoe@example.com",
                "serviceAccountKeyName": "//iam.googleapis.com/projects/prod-webapp-284917/serviceAccounts/compute@prod-webapp-284917.iam.gserviceaccount.com/keys/a1b2c3d4",
                "serviceAccountDelegationInfo": [
                    {
                        "principalEmail": "compute@prod-webapp-284917.iam.gserviceaccount.com",
                        "principalSubject": "serviceAccount:compute@prod-webapp-284917.iam.gserviceaccount.com"
                    }
                ],
                "userName": "jdoe"
            },
            "connections": [
                {
                    "destinationIp": "10.0.0.1",
                    "destinationPort": 3333,
                    "sourceIp": "10.128.0.12",
                    "sourcePort": 51244,
                    "protocol": "TCP"
                }
            ],
            "muteInitiator": "secops@example.com",
            "processes": [
                {
                    "name": "xmrig",
                    "binary": {
                        "path": "/tmp/.cache/xmrig",
                        "size": "4194304",
                        "sha256": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                        "hashedSize": "4194304",
                        "partiallyHashed": false,
                        "contents": "ELF binary",
                        "diskPath": {
                            "partitionUuid": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                            "relativePath": "/tmp/.cache/xmrig"
                        },
                        "operations": [
                            {
                                "type": "EXECUTE"
                            }
                        ],
                        "fileLoadState": "LOADED_BY_PROCESS"
                    },
                    "libraries": [
                        {
                            "path": "/lib/x86_64-linux-gnu/libc.so.6",
                            "size": "2029224",
                            "sha256": "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe",
                            "hashedSize": "2029224",
                            "partiallyHashed": false,
                            "contents": "shared object",
                            "diskPath": {
                                "partitionUuid": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                                "relativePath": "/lib/x86_64-linux-gnu/libc.so.6"
                            },
                            "operations": [
                                {
                                    "type": "OPEN"
                                }
                            ],
                            "fileLoadState": "LOADED_BY_PROCESS"
                        }
                    ],
                    "script": {
                        "path": "/tmp/.cache/install.sh",
                        "size": "2048",
                        "sha256": "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface",
                        "hashedSize": "2048",
                        "partiallyHashed": false,
                        "contents": "#!/bin/bash",
                        "diskPath": {
                            "partitionUuid": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                            "relativePath": "/tmp/.cache/install.sh"
                        },
                        "operations": [
                            {
                                "type": "EXECUTE"
                            }
                        ],
                        "fileLoadState": "LOADED_BY_PROCESS"
                    },
                    "args": [
                        "./xmrig",
                        "-o",
                        "xmr-pool.badactor.example:3333"
                    ],
                    "argumentsTruncated": false,
                    "envVariables": [
                        {
                            "name": "HOME",
                            "val": "/root"
                        }
                    ],
                    "envVariablesTruncated": false,
                    "pid": "34521",
                    "parentPid": "1042",
                    "userId": "0"
                }
            ],
            "contacts": {
                "security": {
                    "contacts": [
                        {
                            "email": "security-admin@example.com"
                        }
                    ]
                }
            },
            "compliances": [
                {
                    "standard": "cis",
                    "version": "1.2.0",
                    "ids": [
                        "4.1"
                    ]
                }
            ],
            "parentDisplayName": "Event Threat Detection",
            "description": "The VM web-server-01 connected to a known cryptomining command-and-control IP address.",
            "exfiltration": {
                "sources": [
                    {
                        "name": "//compute.googleapis.com/projects/prod-webapp-284917/zones/us-central1-a/instances/web-server-01",
                        "components": [
                            "disk"
                        ]
                    }
                ],
                "targets": [
                    {
                        "name": "//storage.googleapis.com/exfil-bucket-badactor",
                        "components": [
                            "bucket"
                        ]
                    }
                ],
                "totalExfiltratedBytes": "1048576"
            },
            "iamBindings": [
                {
                    "action": "ADD",
                    "role": "roles/owner",
                    "member": "user:jdoe@example.com"
                }
            ],
            "nextSteps": "Isolate the affected VM, terminate the xmrig process, and rotate the associated service account keys.",
            "moduleName": "known_cryptomining_bad_ip",
            "containers": [
                {
                    "name": "web-app",
                    "uri": "gcr.io/prod-webapp-284917/web-app@sha256:baddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecaf",
                    "imageId": "sha256:baddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecaf",
                    "labels": [
                        {
                            "name": "app",
                            "value": "web"
                        }
                    ],
                    "createTime": "2020-02-18T07:26:42Z"
                }
            ],
            "kubernetes": {
                "pods": [
                    {
                        "ns": "default",
                        "name": "web-app-7d9f8c6b5-x2k4p",
                        "labels": [
                            {
                                "name": "app",
                                "value": "web"
                            }
                        ],
                        "containers": [
                            {
                                "name": "web-app",
                                "uri": "gcr.io/prod-webapp-284917/web-app@sha256:baddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecaf",
                                "imageId": "sha256:baddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecaf",
                                "labels": [
                                    {
                                        "name": "app",
                                        "value": "web"
                                    }
                                ],
                                "createTime": "2020-02-18T07:26:42Z"
                            }
                        ]
                    }
                ],
                "nodes": [
                    {
                        "name": "gke-prod-cluster-default-pool-a1b2c3d4-x9k2"
                    }
                ],
                "nodePools": [
                    {
                        "name": "default-pool",
                        "nodes": [
                            {
                                "name": "gke-prod-cluster-default-pool-a1b2c3d4-x9k2"
                            }
                        ]
                    }
                ],
                "roles": [
                    {
                        "kind": "ROLE",
                        "ns": "default",
                        "name": "pod-reader"
                    }
                ],
                "bindings": [
                    {
                        "ns": "default",
                        "name": "read-pods",
                        "role": {
                            "kind": "ROLE",
                            "ns": "default",
                            "name": "pod-reader"
                        },
                        "subjects": [
                            {
                                "kind": "USER",
                                "ns": "default",
                                "name": "jdoe@example.com"
                            }
                        ]
                    }
                ],
                "accessReviews": [
                    {
                        "group": "apps",
                        "ns": "default",
                        "name": "deployments",
                        "resource": "deployments",
                        "subresource": "",
                        "verb": "create",
                        "version": "v1"
                    }
                ],
                "objects": [
                    {
                        "group": "apps",
                        "kind": "Deployment",
                        "ns": "default",
                        "name": "web-app",
                        "containers": [
                            {
                                "name": "web-app",
                                "uri": "gcr.io/prod-webapp-284917/web-app@sha256:baddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecaf",
                                "imageId": "sha256:baddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecaf",
                                "labels": [
                                    {
                                        "name": "app",
                                        "value": "web"
                                    }
                                ],
                                "createTime": "2020-02-18T07:26:42Z"
                            }
                        ]
                    }
                ]
            },
            "database": {
                "name": "//cloudsql.googleapis.com/projects/prod-webapp-284917/instances/main-db",
                "displayName": "main-db",
                "userName": "app_user",
                "query": "SELECT * FROM users WHERE role = 'admin'",
                "grantees": [
                    "app_user"
                ],
                "version": "POSTGRES_14"
            },
            "attackExposure": {
                "score": 8.5,
                "latestCalculationTime": "2020-02-18T07:26:42Z",
                "attackExposureResult": "organizations/1094826489209/simulations/latest/attackExposureResults/6d7e8f9a",
                "state": "CALCULATED",
                "exposedHighValueResourcesCount": 3,
                "exposedMediumValueResourcesCount": 5,
                "exposedLowValueResourcesCount": 12
            },
            "files": [
                {
                    "path": "/tmp/.cache/xmrig",
                    "size": "4194304",
                    "sha256": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "hashedSize": "4194304",
                    "partiallyHashed": false,
                    "contents": "ELF binary",
                    "diskPath": {
                        "partitionUuid": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                        "relativePath": "/tmp/.cache/xmrig"
                    },
                    "operations": [
                        {
                            "type": "EXECUTE"
                        }
                    ],
                    "fileLoadState": "LOADED_BY_PROCESS"
                }
            ],
            "cloudDlpInspection": {
                "inspectJob": "projects/prod-webapp-284917/locations/global/dlpJobs/i-1234567890123456789",
                "infoType": "CREDIT_CARD_NUMBER",
                "infoTypeCount": "42",
                "fullScan": true
            },
            "cloudDlpDataProfile": {
                "dataProfile": "projects/prod-webapp-284917/locations/us/tableProfiles/9876543210",
                "parentType": "ORGANIZATION",
                "infoTypes": [
                    {
                        "name": "EMAIL_ADDRESS",
                        "version": "1",
                        "sensitivityScore": {
                            "score": "SENSITIVITY_LOW"
                        }
                    }
                ]
            },
            "kernelRootkit": {
                "name": "Diamorphine",
                "unexpectedCodeModification": true,
                "unexpectedReadOnlyDataModification": false,
                "unexpectedFtraceHandler": true,
                "unexpectedKprobeHandler": false,
                "unexpectedKernelCodePages": true,
                "unexpectedSystemCallHandler": true,
                "unexpectedInterruptHandler": false,
                "unexpectedProcessesInRunqueue": false
            },
            "orgPolicies": [
                {
                    "name": "organizations/1094826489209/policies/compute.requireShieldedVm"
                }
            ],
            "job": {
                "name": "projects/prod-webapp-284917/jobs/etl-nightly-run",
                "state": "PENDING",
                "errorCode": 0,
                "location": "us-central1"
            },
            "application": {
                "baseUri": "https://web-server-01.example.com",
                "fullUri": "https://web-server-01.example.com/api/v1/login"
            },
            "ipRules": {
                "direction": "INGRESS",
                "sourceIpRanges": [
                    "0.0.0.0/0"
                ],
                "destinationIpRanges": [
                    "10.0.0.1/20"
                ],
                "exposedServices": [
                    "ssh"
                ],
                "allowed": {
                    "ipRules": [
                        {
                            "protocol": "tcp",
                            "portRanges": [
                                {
                                    "min": "22",
                                    "max": "22"
                                }
                            ]
                        }
                    ]
                },
                "denied": {
                    "ipRules": [
                        {
                            "protocol": "tcp",
                            "portRanges": [
                                {
                                    "min": "3333",
                                    "max": "3333"
                                }
                            ]
                        }
                    ]
                }
            },
            "backupDisasterRecovery": {
                "backupTemplate": "gold-daily",
                "policies": [
                    "daily-30d-retention"
                ],
                "host": "web-server-01",
                "applications": [
                    "web-app"
                ],
                "storagePool": "primary-pool",
                "policyOptions": [
                    "compression"
                ],
                "profile": "production",
                "appliance": "bdr-appliance-01",
                "backupType": "Incremental",
                "backupCreateTime": "2020-02-18T07:26:42Z"
            },
            "securityPosture": {
                "name": "organizations/1094826489209/locations/global/postures/production-posture",
                "revisionId": "a1b2c3d4",
                "postureDeploymentResource": "organizations/1094826489209",
                "postureDeployment": "organizations/1094826489209/locations/global/postureDeployments/prod-deployment",
                "changedPolicy": "compute.requireShieldedVm",
                "policySet": "cis-gcp-1.2",
                "policy": "compute.requireShieldedVm",
                "policyDriftDetails": [
                    {
                        "field": "enableSecureBoot",
                        "expectedValue": "true",
                        "detectedValue": "false"
                    }
                ]
            },
            "logEntries": [
                {
                    "cloudLoggingEntry": {
                        "insertId": "1a2b3c4d5e6f",
                        "logId": "cloudaudit.googleapis.com%2Fdata_access",
                        "resourceContainer": "projects/prod-webapp-284917",
                        "timestamp": "2020-02-18T07:26:42Z"
                    }
                }
            ],
            "loadBalancers": [
                {
                    "name": "web-lb-frontend"
                }
            ],
            "cloudArmor": {
                "securityPolicy": {
                    "name": "prod-waf-policy",
                    "type": "CLOUD_ARMOR",
                    "preview": false
                },
                "requests": {
                    "ratio": 0.35,
                    "shortTermAllowed": 1200,
                    "longTermAllowed": 45000,
                    "longTermDenied": 3200
                },
                "adaptiveProtection": {
                    "confidence": 0.92
                },
                "attack": {
                    "volumePpsLong": "150000",
                    "volumeBpsLong": "120000000",
                    "classification": "HTTP_FLOOD",
                    "volumePps": 180000,
                    "volumeBps": 145000000
                },
                "threatVector": "HTTP_FLOOD",
                "duration": "300s"
            },
            "notebook": {
                "name": "projects/prod-webapp-284917/locations/us-central1/instances/analysis-notebook",
                "service": "Vertex AI Workbench",
                "lastAuthor": "data-scientist@example.com",
                "notebookUpdateTime": "2020-02-18T07:26:42Z"
            },
            "toxicCombination": {
                "attackExposureScore": 9.1,
                "relatedFindings": [
                    "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/aabbccddeeff00112233445566778899"
                ]
            },
            "groupMemberships": [
                {
                    "groupType": "GROUP_TYPE_TOXIC_COMBINATION",
                    "groupId": "toxic-combo-9a8b7c6d"
                }
            ],
            "disk": {
                "name": "//compute.googleapis.com/projects/prod-webapp-284917/zones/us-central1-a/disks/web-server-01"
            },
            "dataAccessEvents": [
                {
                    "eventId": "evt-a1b2c3d4",
                    "principalEmail": "jdoe@example.com",
                    "operation": "READ",
                    "eventTime": "2020-02-18T07:26:42Z"
                }
            ],
            "dataFlowEvents": [
                {
                    "eventId": "evt-e5f6a7b8",
                    "principalEmail": "jdoe@example.com",
                    "operation": "READ",
                    "violatedLocation": "asia-south1",
                    "eventTime": "2020-02-18T07:26:42Z"
                }
            ],
            "networks": [
                {
                    "name": "//compute.googleapis.com/projects/prod-webapp-284917/global/networks/default"
                }
            ],
            "dataRetentionDeletionEvents": [
                {
                    "eventDetectionTime": "2020-02-18T07:26:42Z",
                    "dataObjectCount": "15000",
                    "maxRetentionAllowed": "7776000s",
                    "minRetentionAllowed": "2592000s",
                    "eventType": "EVENT_TYPE_MAX_TTL_EXCEEDED"
                }
            ],
            "affectedResources": {
                "count": "3"
            },
            "aiModel": {
                "name": "projects/prod-webapp-284917/locations/us-central1/models/fraud-detector",
                "domain": "Fraud Detection",
                "library": "TensorFlow",
                "location": "us-central1",
                "publisher": "internal",
                "deploymentPlatform": "VERTEX_AI",
                "displayName": "Fraud Detector v3",
                "usageCategory": "Production"
            },
            "chokepoint": {
                "relatedFindings": [
                    "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/aabbccddeeff00112233445566778899"
                ]
            },
            "complianceDetails": {
                "frameworks": [
                    {
                        "name": "cis-gcp-foundation-1.2",
                        "displayName": "CIS Google Cloud Platform Foundation Benchmark v1.2.0",
                        "category": [
                            "SECURITY_BENCHMARKS"
                        ],
                        "type": "FRAMEWORK_TYPE_BUILT_IN",
                        "controls": [
                            {
                                "controlName": "4.1",
                                "displayName": "Ensure That Instances Are Not Configured To Use the Default Service Account"
                            }
                        ]
                    }
                ],
                "cloudControl": {
                    "cloudControlName": "shielded-vm-enabled",
                    "type": "BUILT_IN",
                    "policyType": "ORG_POLICY",
                    "version": 1
                },
                "cloudControlDeploymentNames": [
                    "organizations/1094826489209/locations/global/cloudControlDeployments/shielded-vm-enabled"
                ]
            },
            "vertexAi": {
                "datasets": [
                    {
                        "name": "projects/prod-webapp-284917/locations/us-central1/datasets/transactions",
                        "displayName": "transactions",
                        "source": "bq://prod-webapp-284917.analytics.transactions"
                    }
                ],
                "pipelines": [
                    {
                        "name": "projects/prod-webapp-284917/locations/us-central1/pipelineJobs/training-run-2020",
                        "displayName": "training-run-2020"
                    }
                ]
            },
            "cryptoKeyName": "projects/prod-webapp-284917/locations/us-central1/keyRings/prod-ring/cryptoKeys/data-key",
            "artifactGuardPolicies": {
                "resourceId": "gcr.io/prod-webapp-284917/web-app",
                "failingPolicies": [
                    {
                        "type": "VULNERABILITY",
                        "policyId": "block-critical-cves",
                        "failureReason": "Image contains CVE-2021-44228 with CVSS score 10.0"
                    }
                ]
            },
            "secret": {
                "type": "GCP_SERVICE_ACCOUNT_KEY",
                "status": {
                    "lastUpdatedTime": "2020-02-18T07:26:42Z",
                    "validity": "SECRET_VALIDITY_UNSUPPORTED"
                },
                "environmentVariable": {
                    "key": "GOOGLE_APPLICATION_CREDENTIALS"
                },
                "filePath": {
                    "path": "/etc/secrets/sa-key.json"
                }
            },
            "externalExposure": {
                "privateIpAddress": "10.128.0.12",
                "privatePort": "8080",
                "exposedService": "http",
                "publicIpAddress": "10.0.0.1",
                "publicPort": "80",
                "exposedEndpoint": "10.0.0.1:80",
                "loadBalancerFirewallPolicy": "prod-lb-fw-policy",
                "serviceFirewallPolicy": "prod-svc-fw-policy",
                "forwardingRule": "web-lb-forwarding-rule",
                "backendService": "web-backend-service",
                "instanceGroup": "web-server-ig",
                "networkEndpointGroup": "web-neg",
                "hostnameUri": "https://web-server-01.example.com",
                "pscServiceAttachment": "projects/prod-webapp-284917/regions/us-central1/serviceAttachments/web-psc",
                "pscNetworkAttachment": "projects/prod-webapp-284917/regions/us-central1/networkAttachments/web-na",
                "internalBackendService": "internal-web-backend",
                "backendBucket": "web-static-bucket",
                "exposedApplication": "web-app",
                "networkIngressFirewallPolicy": "prod-ingress-fw-policy",
                "httpResponse": [
                    {
                        "statusCode": "200",
                        "path": "/api/v1/login"
                    }
                ],
                "networkPathInsightsGenerationTime": "2020-02-18T07:26:42Z"
            },
            "policyViolationSummary": {
                "policyViolationsCount": "7",
                "conformantResourcesCount": "42",
                "evaluationErrorsCount": "1",
                "outOfScopeResourcesCount": "3"
            },
            "agentDataAccessEvents": [
                {
                    "eventId": "evt-c9d0e1f2",
                    "principalSubject": "serviceAccount:agent@prod-webapp-284917.iam.gserviceaccount.com",
                    "operation": "READ",
                    "eventTime": "2020-02-18T07:26:42Z"
                }
            ],
            "discoveredWorkload": {
                "workloadType": "MCP_SERVER",
                "confidence": "CONFIDENCE_HIGH",
                "detectedRelevantPackages": true,
                "detectedRelevantKeywords": true,
                "detectedRelevantHardware": false
            }
        }
    }
}
```

#### Human Readable Output

>### The finding has been updated successfully
>
>|Organization ID|Name|State|Severity|Category|Event Time (In UTC)|Create Time (In UTC)|External Uri|Resource Name|
>|---|---|---|---|---|---|---|---|---|
>| 123 | [organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a](https://console.cloud.google.com/security/command-center/findings?organizationId=123&resourceId=organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a) | ACTIVE | CRITICAL | Malware: Cryptomining Bad IP | February 18, 2020 at 07:26:42 AM | February 19, 2020 at 01:37:43 PM | [https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/web-server-01?project=prod-webapp-284917](https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/web-server-01?project=prod-webapp-284917) | //compute.googleapis.com/projects/prod-webapp-284917/zones/us-central1-a/instances/web-server-01 |

### google-cloud-scc-v2-finding-state-update

***
Update the state of an organization's or source's finding using the Security Command Center v2 API.

#### Base Command

`google-cloud-scc-v2-finding-state-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The relative resource name of the finding.<br/>In the v2 API the name may include an optional "locations/{location}" segment. If no location is specified, the finding is assumed to be in "global".<br/><br/>Format: organizations/{organization_id}/sources/{source_id}/findings/{findingId} or organizations/{organization_id}/sources/{source_id}/locations/{location_id}/findings/{findingId}<br/><br/>Example: organizations/595779152576/sources/14801394649435054450/locations/global/findings/bc5a86da657611ebb979005056a5924e.<br/><br/>Note: Users can retrieve the list of the finding names by executing the "google-cloud-scc-v2-finding-list" command. | Required |
| state | The desired state of the finding. Possible values are: ACTIVE, INACTIVE. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudSCC.FindingV2.name | String | 'The relative resource name of this finding. Format: organizations/\{organization\}/sources/\{source\}/locations/\{location\}/findings/\{finding\}.' |
| GoogleCloudSCC.FindingV2.canonicalName | String | The canonical name of the finding, always suffixed with the region-agnostic \(global\) resource path. |
| GoogleCloudSCC.FindingV2.parent | String | The relative resource name of the source the finding belongs to. |
| GoogleCloudSCC.FindingV2.resourceName | String | For findings on Google Cloud resources, the full resource name of the Google Cloud resource this finding is for. |
| GoogleCloudSCC.FindingV2.state | String | The state of the finding \(ACTIVE or INACTIVE\). |
| GoogleCloudSCC.FindingV2.category | String | The additional taxonomy group within findings from a given source. |
| GoogleCloudSCC.FindingV2.externalUri | String | The URI that, if available, points to a web page outside of Security Command Center where additional information about the finding can be found. |
| GoogleCloudSCC.FindingV2.sourceProperties | Unknown | Source specific properties. These properties are managed by the source that writes the finding. Properties are varying from finding to finding. |
| GoogleCloudSCC.FindingV2.securityMarks | Unknown | Output only. |
| GoogleCloudSCC.FindingV2.securityMarks.name | String | The relative resource name of the SecurityMarks. |
| GoogleCloudSCC.FindingV2.securityMarks.marks | Unknown | Mutable user specified security marks belonging to the parent resource. |
| GoogleCloudSCC.FindingV2.securityMarks.canonicalName | String | The canonical name of the marks. |
| GoogleCloudSCC.FindingV2.eventTime | String | The time at which the event took place, or when an update to the finding occurred. |
| GoogleCloudSCC.FindingV2.createTime | String | The time at which the finding was created in Security Command Center. |
| GoogleCloudSCC.FindingV2.severity | String | The severity of the finding \(CRITICAL, HIGH, MEDIUM, LOW\). |
| GoogleCloudSCC.FindingV2.mute | String | Indicates the mute state of the finding \(MUTED, UNMUTED, UNDEFINED\). |
| GoogleCloudSCC.FindingV2.muteInfo | Unknown | Additional details about the mute state of the finding, including static and dynamic mute records. |
| GoogleCloudSCC.FindingV2.muteInfo.staticMute | Unknown | If set, the static mute applied to this finding. |
| GoogleCloudSCC.FindingV2.muteInfo.staticMute.state | String | The static mute state. |
| GoogleCloudSCC.FindingV2.muteInfo.staticMute.applyTime | String | When the static mute was applied. |
| GoogleCloudSCC.FindingV2.muteInfo.dynamicMuteRecords | Unknown | The list of dynamic mute rules that currently match the finding. |
| GoogleCloudSCC.FindingV2.muteInfo.dynamicMuteRecords.muteConfig | String | The relative resource name of the mute rule, represented by a mute config, that created this record, for example organizations/123/muteConfigs/mymuteconfig or organizations/123/locations/global/muteConfigs/mymuteconfig. |
| GoogleCloudSCC.FindingV2.muteInfo.dynamicMuteRecords.matchTime | String | When the dynamic mute rule first matched the finding. |
| GoogleCloudSCC.FindingV2.findingClass | String | The class of the finding \(THREAT, VULNERABILITY, MISCONFIGURATION, OBSERVATION, SCC_ERROR, POSTURE_VIOLATION, TOXIC_COMBINATION\). |
| GoogleCloudSCC.FindingV2.indicator | Unknown | Represents what's commonly known as an indicator of compromise \(IoC\) in computer forensics. |
| GoogleCloudSCC.FindingV2.indicator.ipAddresses | Unknown | The list of IP addresses that are associated with the finding. |
| GoogleCloudSCC.FindingV2.indicator.domains | Unknown | List of domains associated to the Finding. |
| GoogleCloudSCC.FindingV2.indicator.signatures | Unknown | The list of matched signatures indicating that the given process is present in the environment. |
| GoogleCloudSCC.FindingV2.indicator.signatures.signatureType | String | Describes the type of resource associated with the signature. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature | Unknown | Signature indicating that a binary family was matched. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature.binaryFamily | String | The binary family. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature.detections | Unknown | The list of memory hash detections contributing to the binary family match. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature.detections.binary | String | The name of the binary associated with the memory hash signature detection. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature.detections.percentPagesMatched | Number | The percentage of memory page hashes in the signature that were matched. |
| GoogleCloudSCC.FindingV2.indicator.signatures.yaraRuleSignature | Unknown | Signature indicating that a YARA rule was matched. |
| GoogleCloudSCC.FindingV2.indicator.signatures.yaraRuleSignature.yaraRule | String | The name of the YARA rule. |
| GoogleCloudSCC.FindingV2.indicator.uris | Unknown | The list of URIs associated to the Findings. |
| GoogleCloudSCC.FindingV2.vulnerability | Unknown | Represents vulnerability-specific fields like CVE and CVSS scores. |
| GoogleCloudSCC.FindingV2.vulnerability.cve | Unknown | CVE stands for Common Vulnerabilities and Exposures \(&lt;<https://cve.mitre.org/about/&gt;\>) |
| GoogleCloudSCC.FindingV2.vulnerability.cve.id | String | The unique identifier for the vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.references | Unknown | Additional information about the CVE. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.references.source | String | Source of the reference e.g. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.references.uri | String | Uri for the mentioned source e.g. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3 | Unknown | Describe Common Vulnerability Scoring System specified at &lt;<https://www.first.org/cvss/v3.1/specification-document>&gt; |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.baseScore | Number | The base score is a function of the base metric scores. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.attackVector | String | Base Metrics Represents the intrinsic characteristics of a vulnerability that are constant over time and across user environments. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.attackComplexity | String | This metric describes the conditions beyond the attacker's control that must exist in order to exploit the vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.privilegesRequired | String | This metric describes the level of privileges an attacker must possess before successfully exploiting the vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.userInteraction | String | This metric captures the requirement for a human user, other than the attacker, to participate in the successful compromise of the vulnerable component. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.scope | String | The Scope metric captures whether a vulnerability in one vulnerable component impacts resources in components beyond its security scope. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.confidentialityImpact | String | This metric measures the impact to the confidentiality of the information resources managed by a software component due to a successfully exploited vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.integrityImpact | String | This metric measures the impact to integrity of a successfully exploited vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.availabilityImpact | String | This metric measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.upstreamFixAvailable | Boolean | Whether upstream fix is available for the CVE. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.impact | String | The potential impact of the vulnerability if it was to be exploited. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.exploitationActivity | String | The exploitation activity of the vulnerability in the wild. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.observedInTheWild | Boolean | Whether or not the vulnerability has been observed in the wild. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.zeroDay | Boolean | Whether or not the vulnerability was zero day when the finding was published. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.exploitReleaseDate | String | Date the first publicly available exploit or PoC was released. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.firstExploitationDate | String | Date of the earliest known exploitation. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage | Unknown | The offending package is relevant to the finding. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage.packageName | String | The name of the package where the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage.cpeUri | String | The CPE URI where the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage.packageType | String | Type of package, for example, os, maven, or go. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage.packageVersion | String | The version of the package. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage | Unknown | The fixed package is relevant to the finding. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage.packageName | String | The name of the package where the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage.cpeUri | String | The CPE URI where the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage.packageType | String | Type of package, for example, os, maven, or go. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage.packageVersion | String | The version of the package. |
| GoogleCloudSCC.FindingV2.vulnerability.securityBulletin | Unknown | The security bulletin is relevant to this finding. |
| GoogleCloudSCC.FindingV2.vulnerability.securityBulletin.bulletinId | String | ID of the bulletin corresponding to the vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.securityBulletin.submissionTime | String | Submission time of this Security Bulletin. |
| GoogleCloudSCC.FindingV2.vulnerability.securityBulletin.suggestedUpgradeVersion | String | This represents a version that the cluster receiving this notification should be upgraded to, based on its current version. |
| GoogleCloudSCC.FindingV2.vulnerability.providerRiskScore | String | Provider provided risk_score based on multiple factors. |
| GoogleCloudSCC.FindingV2.vulnerability.reachable | Boolean | Represents whether the vulnerability is reachable \(detected via static analysis\) |
| GoogleCloudSCC.FindingV2.vulnerability.cwes | Unknown | Represents one or more Common Weakness Enumeration \(CWE\) information on this vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cwes.id | String | The CWE identifier, e.g. |
| GoogleCloudSCC.FindingV2.vulnerability.cwes.references | Unknown | Any reference to the details on the CWE, for example, &lt;<https://dummyuser1@dummy.com/data/definitions/94.html>&gt; |
| GoogleCloudSCC.FindingV2.vulnerability.cwes.references.source | String | Source of the reference e.g. |
| GoogleCloudSCC.FindingV2.vulnerability.cwes.references.uri | String | Uri for the mentioned source e.g. |
| GoogleCloudSCC.FindingV2.muteUpdateTime | String | The time at which the finding was muted or unmuted. |
| GoogleCloudSCC.FindingV2.externalSystems | Unknown | Third party SIEM/SOAR fields within Security Command Center, contains external system information and external system finding fields. |
| GoogleCloudSCC.FindingV2.mitreAttack | Unknown | MITRE ATT&amp;CK tactics and techniques related to this finding. |
| GoogleCloudSCC.FindingV2.mitreAttack.primaryTactic | String | The MITRE ATT\\&amp;CK tactic most closely represented by this finding, if any. |
| GoogleCloudSCC.FindingV2.mitreAttack.primaryTechniques | Unknown | The MITRE ATT\\&amp;CK technique most closely represented by this finding, if any. |
| GoogleCloudSCC.FindingV2.mitreAttack.additionalTactics | Unknown | Additional MITRE ATT\\&amp;CK tactics related to this finding, if any. |
| GoogleCloudSCC.FindingV2.mitreAttack.additionalTechniques | Unknown | Additional MITRE ATT\\&amp;CK techniques related to this finding, if any, along with any of their respective parent techniques. |
| GoogleCloudSCC.FindingV2.mitreAttack.version | String | The MITRE ATT\\&amp;CK version referenced by the above fields. |
| GoogleCloudSCC.FindingV2.access | Unknown | Access details associated with the finding, such as more information on the caller, which method was accessed, and from where. |
| GoogleCloudSCC.FindingV2.access.principalEmail | String | Associated email, such as "<foo@google.com>". |
| GoogleCloudSCC.FindingV2.access.callerIp | String | Caller's IP address, such as "1.1.1.1". |
| GoogleCloudSCC.FindingV2.access.callerIpGeo | Unknown | The caller IP's geolocation, which identifies where the call came from. |
| GoogleCloudSCC.FindingV2.access.callerIpGeo.regionCode | String | A CLDR. |
| GoogleCloudSCC.FindingV2.access.userAgentFamily | String | Type of user agent associated with the finding. |
| GoogleCloudSCC.FindingV2.access.userAgent | String | The caller's user agent string associated with the finding. |
| GoogleCloudSCC.FindingV2.access.serviceName | String | This is the API service that the service account made a call to, e.g. |
| GoogleCloudSCC.FindingV2.access.methodName | String | The method that the service account called, e.g. |
| GoogleCloudSCC.FindingV2.access.principalSubject | String | A string that represents the principalSubject that is associated with the identity. |
| GoogleCloudSCC.FindingV2.access.serviceAccountKeyName | String | The name of the service account key that was used to create or exchange credentials when authenticating the service account that made the request. |
| GoogleCloudSCC.FindingV2.access.serviceAccountDelegationInfo | Unknown | The identity delegation history of an authenticated service account that made the request. |
| GoogleCloudSCC.FindingV2.access.serviceAccountDelegationInfo.principalEmail | String | The email address of a Google account. |
| GoogleCloudSCC.FindingV2.access.serviceAccountDelegationInfo.principalSubject | String | A string representing the principalSubject associated with the identity. |
| GoogleCloudSCC.FindingV2.access.userName | String | A string that represents a username. |
| GoogleCloudSCC.FindingV2.connections | Unknown | Contains information about the IP connection associated with the finding. |
| GoogleCloudSCC.FindingV2.connections.destinationIp | String | Destination IP address. |
| GoogleCloudSCC.FindingV2.connections.destinationPort | Number | Destination port. |
| GoogleCloudSCC.FindingV2.connections.sourceIp | String | Source IP address. |
| GoogleCloudSCC.FindingV2.connections.sourcePort | Number | Source port. |
| GoogleCloudSCC.FindingV2.connections.protocol | String | IANA Internet Protocol Number such as TCP\(6\) and UDP\(17\). |
| GoogleCloudSCC.FindingV2.muteInitiator | String | Records the entity that is responsible for the muting of the finding. |
| GoogleCloudSCC.FindingV2.processes | Unknown | Represents operating system processes associated with the finding. |
| GoogleCloudSCC.FindingV2.processes.name | String | The process name, as displayed in utilities like top and ps. |
| GoogleCloudSCC.FindingV2.processes.binary | Unknown | File information for the process executable. |
| GoogleCloudSCC.FindingV2.processes.binary.path | String | Absolute path of the file as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.binary.size | String | Size of the file in bytes. |
| GoogleCloudSCC.FindingV2.processes.binary.sha256 | String | SHA256 hash of the first hashedSize bytes of the file encoded as a hex string. |
| GoogleCloudSCC.FindingV2.processes.binary.hashedSize | String | The length in bytes of the file prefix that was hashed. |
| GoogleCloudSCC.FindingV2.processes.binary.partiallyHashed | Boolean | True when the hash covers only a prefix of the file. |
| GoogleCloudSCC.FindingV2.processes.binary.contents | String | Prefix of the file contents as a JSON-encoded string. |
| GoogleCloudSCC.FindingV2.processes.binary.diskPath | Unknown | Path of the file in terms of underlying disk/partition identifiers. |
| GoogleCloudSCC.FindingV2.processes.binary.diskPath.partitionUuid | String | UUID of the partition \(format &lt;<https://wiki.archlinux.org/title/persistent_block_device_naming\#by-uuid&gt;\>) |
| GoogleCloudSCC.FindingV2.processes.binary.diskPath.relativePath | String | Relative path of the file in the partition as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.binary.operations | Unknown | Operation\(s\) performed on a file. |
| GoogleCloudSCC.FindingV2.processes.binary.operations.type | String | The type of the operation |
| GoogleCloudSCC.FindingV2.processes.binary.fileLoadState | String | The load state of the file. |
| GoogleCloudSCC.FindingV2.processes.libraries | Unknown | File information for libraries loaded by the process. |
| GoogleCloudSCC.FindingV2.processes.libraries.path | String | Absolute path of the file as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.libraries.size | String | Size of the file in bytes. |
| GoogleCloudSCC.FindingV2.processes.libraries.sha256 | String | SHA256 hash of the first hashedSize bytes of the file encoded as a hex string. |
| GoogleCloudSCC.FindingV2.processes.libraries.hashedSize | String | The length in bytes of the file prefix that was hashed. |
| GoogleCloudSCC.FindingV2.processes.libraries.partiallyHashed | Boolean | True when the hash covers only a prefix of the file. |
| GoogleCloudSCC.FindingV2.processes.libraries.contents | String | Prefix of the file contents as a JSON-encoded string. |
| GoogleCloudSCC.FindingV2.processes.libraries.diskPath | Unknown | Path of the file in terms of underlying disk/partition identifiers. |
| GoogleCloudSCC.FindingV2.processes.libraries.diskPath.partitionUuid | String | UUID of the partition \(format &lt;<https://wiki.archlinux.org/title/persistent_block_device_naming\#by-uuid&gt;\>) |
| GoogleCloudSCC.FindingV2.processes.libraries.diskPath.relativePath | String | Relative path of the file in the partition as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.libraries.operations | Unknown | Operation\(s\) performed on a file. |
| GoogleCloudSCC.FindingV2.processes.libraries.operations.type | String | The type of the operation |
| GoogleCloudSCC.FindingV2.processes.libraries.fileLoadState | String | The load state of the file. |
| GoogleCloudSCC.FindingV2.processes.script | Unknown | When the process represents the invocation of a script, binary provides information about the interpreter, while script provides information about the script file provided to the interpreter. |
| GoogleCloudSCC.FindingV2.processes.script.path | String | Absolute path of the file as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.script.size | String | Size of the file in bytes. |
| GoogleCloudSCC.FindingV2.processes.script.sha256 | String | SHA256 hash of the first hashedSize bytes of the file encoded as a hex string. |
| GoogleCloudSCC.FindingV2.processes.script.hashedSize | String | The length in bytes of the file prefix that was hashed. |
| GoogleCloudSCC.FindingV2.processes.script.partiallyHashed | Boolean | True when the hash covers only a prefix of the file. |
| GoogleCloudSCC.FindingV2.processes.script.contents | String | Prefix of the file contents as a JSON-encoded string. |
| GoogleCloudSCC.FindingV2.processes.script.diskPath | Unknown | Path of the file in terms of underlying disk/partition identifiers. |
| GoogleCloudSCC.FindingV2.processes.script.diskPath.partitionUuid | String | UUID of the partition \(format &lt;<https://wiki.archlinux.org/title/persistent_block_device_naming\#by-uuid&gt;\>) |
| GoogleCloudSCC.FindingV2.processes.script.diskPath.relativePath | String | Relative path of the file in the partition as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.script.operations | Unknown | Operation\(s\) performed on a file. |
| GoogleCloudSCC.FindingV2.processes.script.operations.type | String | The type of the operation |
| GoogleCloudSCC.FindingV2.processes.script.fileLoadState | String | The load state of the file. |
| GoogleCloudSCC.FindingV2.processes.args | Unknown | Process arguments as JSON encoded strings. |
| GoogleCloudSCC.FindingV2.processes.argumentsTruncated | Boolean | True if args is incomplete. |
| GoogleCloudSCC.FindingV2.processes.envVariables | Unknown | Process environment variables. |
| GoogleCloudSCC.FindingV2.processes.envVariables.name | String | Environment variable name as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.envVariables.val | String | Environment variable value as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.envVariablesTruncated | Boolean | True if envVariables is incomplete. |
| GoogleCloudSCC.FindingV2.processes.pid | String | The process ID. |
| GoogleCloudSCC.FindingV2.processes.parentPid | String | The parent process ID. |
| GoogleCloudSCC.FindingV2.processes.userId | String | The ID of the user that executed the process. |
| GoogleCloudSCC.FindingV2.contacts | Unknown | Map containing the points of contact for the given finding. |
| GoogleCloudSCC.FindingV2.compliances | Unknown | Contains compliance information for security standards associated to the finding. |
| GoogleCloudSCC.FindingV2.compliances.standard | String | Industry-wide compliance standards or benchmarks, such as CIS, PCI, and OWASP. |
| GoogleCloudSCC.FindingV2.compliances.version | String | Version of the standard or benchmark, for example, 1.1 |
| GoogleCloudSCC.FindingV2.compliances.ids | Unknown | Policies within the standard or benchmark, for example, A.12.4.1 |
| GoogleCloudSCC.FindingV2.parentDisplayName | String | The human readable display name of the finding source, such as "Event Threat Detection" or "Security Health Analytics". |
| GoogleCloudSCC.FindingV2.description | String | Contains more details about the finding. |
| GoogleCloudSCC.FindingV2.exfiltration | Unknown | Represents exfiltrations associated with the finding. |
| GoogleCloudSCC.FindingV2.exfiltration.sources | Unknown | If there are multiple sources, then the data is considered "joined" between them. |
| GoogleCloudSCC.FindingV2.exfiltration.sources.name | String | The resource's full resource name. |
| GoogleCloudSCC.FindingV2.exfiltration.sources.components | Unknown | Subcomponents of the asset that was exfiltrated, like URIs used during exfiltration, table names, databases, and filenames. |
| GoogleCloudSCC.FindingV2.exfiltration.targets | Unknown | If there are multiple targets, each target would get a complete copy of the "joined" source data. |
| GoogleCloudSCC.FindingV2.exfiltration.targets.name | String | The resource's full resource name. |
| GoogleCloudSCC.FindingV2.exfiltration.targets.components | Unknown | Subcomponents of the asset that was exfiltrated, like URIs used during exfiltration, table names, databases, and filenames. |
| GoogleCloudSCC.FindingV2.exfiltration.totalExfiltratedBytes | String | Total exfiltrated bytes processed for the entire job. |
| GoogleCloudSCC.FindingV2.iamBindings | Unknown | Represents IAM bindings associated with the finding. |
| GoogleCloudSCC.FindingV2.iamBindings.action | String | The action that was performed on a Binding. |
| GoogleCloudSCC.FindingV2.iamBindings.role | String | Role that is assigned to "members". |
| GoogleCloudSCC.FindingV2.iamBindings.member | String | A single identity requesting access for a Cloud Platform resource, for example, "<foo@google.com>". |
| GoogleCloudSCC.FindingV2.nextSteps | String | Steps to address the finding. |
| GoogleCloudSCC.FindingV2.moduleName | String | Unique identifier of the module which generated the finding. |
| GoogleCloudSCC.FindingV2.containers | Unknown | Containers associated with the finding. This field provides information for both Kubernetes and non-Kubernetes containers. |
| GoogleCloudSCC.FindingV2.containers.name | String | Name of the container. |
| GoogleCloudSCC.FindingV2.containers.uri | String | Container image URI provided when configuring a pod or container. |
| GoogleCloudSCC.FindingV2.containers.imageId | String | Optional container image ID, if provided by the container runtime. |
| GoogleCloudSCC.FindingV2.containers.labels | Unknown | Container labels, as provided by the container runtime. |
| GoogleCloudSCC.FindingV2.containers.labels.name | String | Name of the label. |
| GoogleCloudSCC.FindingV2.containers.labels.value | String | Value that corresponds to the label's name. |
| GoogleCloudSCC.FindingV2.containers.createTime | String | The time that the container was created. |
| GoogleCloudSCC.FindingV2.kubernetes | Unknown | Kubernetes resources associated with the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.pods | Unknown | Kubernetes Pods associated with the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.ns | String | Kubernetes Pod namespace. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.name | String | Kubernetes Pod name. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.labels | Unknown | Pod labels. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.labels.name | String | Name of the label. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.labels.value | String | Value that corresponds to the label's name. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers | Unknown | Pod containers associated with this finding, if any. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.name | String | Name of the container. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.uri | String | Container image URI provided when configuring a pod or container. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.imageId | String | Optional container image ID, if provided by the container runtime. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.labels | Unknown | Container labels, as provided by the container runtime. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.labels.name | String | Name of the label. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.labels.value | String | Value that corresponds to the label's name. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.createTime | String | The time that the container was created. |
| GoogleCloudSCC.FindingV2.kubernetes.nodes | Unknown | Provides Kubernetes node information. |
| GoogleCloudSCC.FindingV2.kubernetes.nodes.name | String | Full resource name of the Compute Engine VM running the cluster node. |
| GoogleCloudSCC.FindingV2.kubernetes.nodePools | Unknown | GKE node pools associated with the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.nodePools.name | String | Kubernetes node pool name. |
| GoogleCloudSCC.FindingV2.kubernetes.nodePools.nodes | Unknown | Nodes associated with the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.nodePools.nodes.name | String | Full resource name of the Compute Engine VM running the cluster node. |
| GoogleCloudSCC.FindingV2.kubernetes.roles | Unknown | Provides Kubernetes role information for findings that involve Roles or ClusterRoles. |
| GoogleCloudSCC.FindingV2.kubernetes.roles.kind | String | Role type. |
| GoogleCloudSCC.FindingV2.kubernetes.roles.ns | String | Role namespace. |
| GoogleCloudSCC.FindingV2.kubernetes.roles.name | String | Role name. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings | Unknown | Provides Kubernetes role binding information for findings that involve RoleBindings or ClusterRoleBindings. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.ns | String | Namespace for the binding. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.name | String | Name for the binding. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.role | Unknown | The Role or ClusterRole referenced by the binding. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.role.kind | String | Role type. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.role.ns | String | Role namespace. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.role.name | String | Role name. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.subjects | Unknown | Represents one or more subjects that are bound to the role. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.subjects.kind | String | Authentication type for the subject. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.subjects.ns | String | Namespace for the subject. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.subjects.name | String | Name for the subject. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews | Unknown | Provides information on any Kubernetes access reviews \(privilege checks\) relevant to the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.group | String | The API group of the resource. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.ns | String | Namespace of the action being requested. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.name | String | The name of the resource being requested. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.resource | String | The optional resource type requested. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.subresource | String | The optional subresource type. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.verb | String | A Kubernetes resource API verb, like get, list, watch, create, update, delete, proxy. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.version | String | The API version of the resource. |
| GoogleCloudSCC.FindingV2.kubernetes.objects | Unknown | Kubernetes objects related to the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.group | String | Kubernetes object group, such as "policy.k8s.io/v1". |
| GoogleCloudSCC.FindingV2.kubernetes.objects.kind | String | Kubernetes object kind, such as "Namespace". |
| GoogleCloudSCC.FindingV2.kubernetes.objects.ns | String | Kubernetes object namespace. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.name | String | Kubernetes object name. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers | Unknown | Pod containers associated with this finding, if any. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.name | String | Name of the container. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.uri | String | Container image URI provided when configuring a pod or container. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.imageId | String | Optional container image ID, if provided by the container runtime. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.labels | Unknown | Container labels, as provided by the container runtime. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.labels.name | String | Name of the label. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.labels.value | String | Value that corresponds to the label's name. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.createTime | String | The time that the container was created. |
| GoogleCloudSCC.FindingV2.database | Unknown | Database associated with the finding. |
| GoogleCloudSCC.FindingV2.database.name | String | Some database resources may not have the full resource name populated because these resource types are not yet supported by Cloud Asset Inventory \(e.g. |
| GoogleCloudSCC.FindingV2.database.displayName | String | The human-readable name of the database that the user connected to. |
| GoogleCloudSCC.FindingV2.database.userName | String | The username used to connect to the database. |
| GoogleCloudSCC.FindingV2.database.query | String | The SQL statement that is associated with the database access. |
| GoogleCloudSCC.FindingV2.database.grantees | Unknown | The target usernames, roles, or groups of an SQL privilege grant, which is not an IAM policy change. |
| GoogleCloudSCC.FindingV2.database.version | String | The version of the database, for example, POSTGRES_14. |
| GoogleCloudSCC.FindingV2.attackExposure | Unknown | The results of an attack path simulation relevant to this finding. |
| GoogleCloudSCC.FindingV2.attackExposure.score | Number | A number between 0 \(inclusive\) and infinity that represents how important this finding is to remediate. |
| GoogleCloudSCC.FindingV2.attackExposure.latestCalculationTime | String | The most recent time the attack exposure was updated on this finding. |
| GoogleCloudSCC.FindingV2.attackExposure.attackExposureResult | String | The resource name of the attack path simulation result that contains the details regarding this attack exposure score. |
| GoogleCloudSCC.FindingV2.attackExposure.state | String | Output only. |
| GoogleCloudSCC.FindingV2.attackExposure.exposedHighValueResourcesCount | Number | The number of high value resources that are exposed as a result of this finding. |
| GoogleCloudSCC.FindingV2.attackExposure.exposedMediumValueResourcesCount | Number | The number of medium value resources that are exposed as a result of this finding. |
| GoogleCloudSCC.FindingV2.attackExposure.exposedLowValueResourcesCount | Number | The number of high value resources that are exposed as a result of this finding. |
| GoogleCloudSCC.FindingV2.files | Unknown | File associated with the finding. |
| GoogleCloudSCC.FindingV2.files.path | String | Absolute path of the file as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.files.size | String | Size of the file in bytes. |
| GoogleCloudSCC.FindingV2.files.sha256 | String | SHA256 hash of the first hashedSize bytes of the file encoded as a hex string. |
| GoogleCloudSCC.FindingV2.files.hashedSize | String | The length in bytes of the file prefix that was hashed. |
| GoogleCloudSCC.FindingV2.files.partiallyHashed | Boolean | True when the hash covers only a prefix of the file. |
| GoogleCloudSCC.FindingV2.files.contents | String | Prefix of the file contents as a JSON-encoded string. |
| GoogleCloudSCC.FindingV2.files.diskPath | Unknown | Path of the file in terms of underlying disk/partition identifiers. |
| GoogleCloudSCC.FindingV2.files.diskPath.partitionUuid | String | UUID of the partition \(format &lt;<https://wiki.archlinux.org/title/persistent_block_device_naming\#by-uuid&gt;\>) |
| GoogleCloudSCC.FindingV2.files.diskPath.relativePath | String | Relative path of the file in the partition as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.files.operations | Unknown | Operation\(s\) performed on a file. |
| GoogleCloudSCC.FindingV2.files.operations.type | String | The type of the operation |
| GoogleCloudSCC.FindingV2.files.fileLoadState | String | The load state of the file. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection | Unknown | Cloud Data Loss Prevention \(Cloud DLP\) inspection results that are associated with the finding. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection.inspectJob | String | Name of the inspection job, for example, projects/123/locations/europe/dlpJobs/i-8383929. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection.infoType | String | The type of information \(or \*infoType\* \) found, for example, EMAIL_ADDRESS or STREET_ADDRESS. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection.infoTypeCount | String | The number of times Cloud DLP found this infoType within this job and resource. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection.fullScan | Boolean | Whether Cloud DLP scanned the complete resource or a sampled subset. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile | Unknown | Cloud DLP data profile that is associated with the finding. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.dataProfile | String | Name of the data profile, for example, projects/123/locations/europe/tableProfiles/8383929. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.parentType | String | The resource hierarchy level at which the data profile was generated. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes | Unknown | Type of information detected by SDP. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes.name | String | Name of the information type. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes.version | String | Optional version name for this InfoType. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes.sensitivityScore | Unknown | Optional custom sensitivity for this InfoType. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes.sensitivityScore.score | String | The sensitivity score applied to the resource. |
| GoogleCloudSCC.FindingV2.kernelRootkit | Unknown | Signature of the kernel rootkit. |
| GoogleCloudSCC.FindingV2.kernelRootkit.name | String | Rootkit name, when available. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedCodeModification | Boolean | True if unexpected modifications of kernel code memory are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedReadOnlyDataModification | Boolean | True if unexpected modifications of kernel read-only data memory are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedFtraceHandler | Boolean | True if ftrace points are present with callbacks pointing to regions that are not in the expected kernel or module code range. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedKprobeHandler | Boolean | True if kprobe points are present with callbacks pointing to regions that are not in the expected kernel or module code range. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedKernelCodePages | Boolean | True if kernel code pages that are not in the expected kernel or module code regions are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedSystemCallHandler | Boolean | True if system call handlers that are are not in the expected kernel or module code regions are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedInterruptHandler | Boolean | True if interrupt handlers that are are not in the expected kernel or module code regions are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedProcessesInRunqueue | Boolean | True if unexpected processes in the scheduler run queue are present. |
| GoogleCloudSCC.FindingV2.orgPolicies | Unknown | Contains information about the org policies associated with the finding. |
| GoogleCloudSCC.FindingV2.orgPolicies.name | String | Identifier. |
| GoogleCloudSCC.FindingV2.job | Unknown | Job associated with the finding. |
| GoogleCloudSCC.FindingV2.job.name | String | The fully-qualified name for a job. |
| GoogleCloudSCC.FindingV2.job.state | String | Output only. |
| GoogleCloudSCC.FindingV2.job.errorCode | Number | Optional. |
| GoogleCloudSCC.FindingV2.job.location | String | Optional. |
| GoogleCloudSCC.FindingV2.application | Unknown | Represents an application associated with the finding. |
| GoogleCloudSCC.FindingV2.application.baseUri | String | The base URI that identifies the network location of the application in which the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.application.fullUri | String | The full URI with payload that could be used to reproduce the vulnerability. |
| GoogleCloudSCC.FindingV2.ipRules | Unknown | IP rules associated with the finding. |
| GoogleCloudSCC.FindingV2.ipRules.direction | String | The direction that the rule is applicable to, one of ingress or egress. |
| GoogleCloudSCC.FindingV2.ipRules.sourceIpRanges | Unknown | If source IP ranges are specified, the firewall rule applies only to traffic that has a source IP address in these ranges. |
| GoogleCloudSCC.FindingV2.ipRules.destinationIpRanges | Unknown | If destination IP ranges are specified, the firewall rule applies only to traffic that has a destination IP address in these ranges. |
| GoogleCloudSCC.FindingV2.ipRules.exposedServices | Unknown | Name of the network protocol service, such as FTP, that is exposed by the open port. |
| GoogleCloudSCC.FindingV2.ipRules.allowed | Unknown | Tuple with allowed rules. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules | Unknown | Optional. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules.protocol | String | The IP protocol this rule applies to. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules.portRanges | Unknown | Optional. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules.portRanges.min | String | Minimum port value. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules.portRanges.max | String | Maximum port value. |
| GoogleCloudSCC.FindingV2.ipRules.denied | Unknown | Tuple with denied rules. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules | Unknown | Optional. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules.protocol | String | The IP protocol this rule applies to. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules.portRanges | Unknown | Optional. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules.portRanges.min | String | Minimum port value. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules.portRanges.max | String | Maximum port value. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery | Unknown | Fields related to Backup and Disaster Recovery findings. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.backupTemplate | String | The name of a Backup and DR template which comprises one or more backup policies. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.policies | Unknown | The names of Backup and DR policies that are associated with a template and that define when to run a backup, how frequently to run a backup, and how long to retain the backup image. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.host | String | The name of a Backup and DR host, which is managed by the backup and recovery appliance and known to the management console. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.applications | Unknown | The names of Backup and DR applications. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.storagePool | String | The name of the Backup and DR storage pool that the backup and recovery appliance is storing data in. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.policyOptions | Unknown | The names of Backup and DR advanced policy options of a policy applying to an application. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.profile | String | The name of the Backup and DR resource profile that specifies the storage media for backups of application and VM data. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.appliance | String | The name of the Backup and DR appliance that captures, moves, and manages the lifecycle of backup data. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.backupType | String | The backup type of the Backup and DR image. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.backupCreateTime | String | The timestamp at which the Backup and DR backup was created. |
| GoogleCloudSCC.FindingV2.securityPosture | Unknown | The security posture associated with the finding. |
| GoogleCloudSCC.FindingV2.securityPosture.name | String | Name of the posture, for example, CIS-Posture. |
| GoogleCloudSCC.FindingV2.securityPosture.revisionId | String | The version of the posture, for example, c7cfa2a8. |
| GoogleCloudSCC.FindingV2.securityPosture.postureDeploymentResource | String | The project, folder, or organization on which the posture is deployed, for example, projects/\{project_number\}. |
| GoogleCloudSCC.FindingV2.securityPosture.postureDeployment | String | The name of the posture deployment, for example, organizations/\{org_id\}/posturedeployments/\{posture_deployment_id\}. |
| GoogleCloudSCC.FindingV2.securityPosture.changedPolicy | String | The name of the updated policy, for example, projects/\{projectId\}/policies/\{constraint_name\}. |
| GoogleCloudSCC.FindingV2.securityPosture.policySet | String | The name of the updated policy set, for example, cis-policyset. |
| GoogleCloudSCC.FindingV2.securityPosture.policy | String | The ID of the updated policy, for example, compute-policy-1. |
| GoogleCloudSCC.FindingV2.securityPosture.policyDriftDetails | Unknown | The details about a change in an updated policy that violates the deployed posture. |
| GoogleCloudSCC.FindingV2.securityPosture.policyDriftDetails.field | String | The name of the updated field, for example constraint.implementation.policy_rules\\\[0\\\].enforce |
| GoogleCloudSCC.FindingV2.securityPosture.policyDriftDetails.expectedValue | String | The value of this field that was configured in a posture, for example, true or allowed_values=\{"projects/29831892"\}. |
| GoogleCloudSCC.FindingV2.securityPosture.policyDriftDetails.detectedValue | String | The detected value that violates the deployed posture, for example, false or allowed_values=\{"projects/22831892"\}. |
| GoogleCloudSCC.FindingV2.logEntries | Unknown | Log entries that are relevant to the finding. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry | Unknown | An individual entry in a log stored in Cloud Logging. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry.insertId | String | A unique identifier for the log entry. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry.logId | String | The type of the log \(part of logName. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry.resourceContainer | String | The organization, folder, or project of the monitored resource that produced this log entry. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry.timestamp | String | The time the event described by the log entry occurred. |
| GoogleCloudSCC.FindingV2.loadBalancers | Unknown | The load balancers associated with the finding. |
| GoogleCloudSCC.FindingV2.loadBalancers.name | String | The name of the load balancer associated with the finding. |
| GoogleCloudSCC.FindingV2.cloudArmor | Unknown | Fields related to Google Cloud Armor findings. |
| GoogleCloudSCC.FindingV2.cloudArmor.securityPolicy | Unknown | Information about the Google Cloud Armor security policy relevant to the finding. |
| GoogleCloudSCC.FindingV2.cloudArmor.securityPolicy.name | String | The name of the Google Cloud Armor security policy, for example, "my-security-policy". |
| GoogleCloudSCC.FindingV2.cloudArmor.securityPolicy.type | String | The type of Google Cloud Armor security policy for example, 'backend security policy', 'edge security policy', 'network edge security policy', or 'always-on DDoS protection'. |
| GoogleCloudSCC.FindingV2.cloudArmor.securityPolicy.preview | Boolean | Whether or not the associated rule or policy is in preview mode. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests | Unknown | Information about incoming requests evaluated by Google Cloud Armor security policies. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests.ratio | Number | For 'Increasing deny ratio', the ratio is the denied traffic divided by the allowed traffic. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests.shortTermAllowed | Number | Allowed RPS \(requests per second\) in the short term. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests.longTermAllowed | Number | Allowed RPS \(requests per second\) over the long term. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests.longTermDenied | Number | Denied RPS \(requests per second\) over the long term. |
| GoogleCloudSCC.FindingV2.cloudArmor.adaptiveProtection | Unknown | Information about potential Layer 7 DDoS attacks identified by Google Cloud Armor Adaptive Protection. |
| GoogleCloudSCC.FindingV2.cloudArmor.adaptiveProtection.confidence | Number | A score of 0 means that there is low confidence that the detected event is an actual attack. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack | Unknown | Information about DDoS attack volume and classification. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.volumePpsLong | String | Total PPS \(packets per second\) volume of attack. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.volumeBpsLong | String | Total BPS \(bytes per second\) volume of attack. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.classification | String | Type of attack, for example, 'SYN-flood', 'NTP-udp', or 'CHARGEN-udp'. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.volumePps | Number | Volume Pps. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.volumeBps | Number | Volume Bps. |
| GoogleCloudSCC.FindingV2.cloudArmor.threatVector | String | Distinguish between volumetric \\&amp; protocol DDoS attack and application layer attacks. |
| GoogleCloudSCC.FindingV2.cloudArmor.duration | String | Duration of attack from the start until the current moment \(updated every 5 minutes\). |
| GoogleCloudSCC.FindingV2.notebook | Unknown | Notebook associated with the finding. |
| GoogleCloudSCC.FindingV2.notebook.name | String | The name of the notebook. |
| GoogleCloudSCC.FindingV2.notebook.service | String | The source notebook service, for example, "Colab Enterprise". |
| GoogleCloudSCC.FindingV2.notebook.lastAuthor | String | The user ID of the latest author to modify the notebook. |
| GoogleCloudSCC.FindingV2.notebook.notebookUpdateTime | String | The most recent time the notebook was updated. |
| GoogleCloudSCC.FindingV2.toxicCombination | Unknown | Contains details about a group of security issues that, when combined, represent a greater risk than when the issues occur independently. |
| GoogleCloudSCC.FindingV2.toxicCombination.attackExposureScore | Number | The Attack exposure score of this toxic combination. |
| GoogleCloudSCC.FindingV2.toxicCombination.relatedFindings | Unknown | List of resource names of findings associated with this toxic combination. |
| GoogleCloudSCC.FindingV2.groupMemberships | Unknown | Contains details about groups of which this finding is a member. |
| GoogleCloudSCC.FindingV2.groupMemberships.groupType | String | Type of group. |
| GoogleCloudSCC.FindingV2.groupMemberships.groupId | String | ID of the group. |
| GoogleCloudSCC.FindingV2.disk | Unknown | Disk associated with the finding. |
| GoogleCloudSCC.FindingV2.disk.name | String | The name of the disk, for example, "<https://www.googleapis.com/compute/v1/projects/\{project-id\}/zones/\{zone-id\}/disks/\{disk-id\}>". |
| GoogleCloudSCC.FindingV2.dataAccessEvents | Unknown | Data access events associated with the finding. |
| GoogleCloudSCC.FindingV2.dataAccessEvents.eventId | String | Unique identifier for data access event. |
| GoogleCloudSCC.FindingV2.dataAccessEvents.principalEmail | String | The email address of the principal that accessed the data. |
| GoogleCloudSCC.FindingV2.dataAccessEvents.operation | String | The operation performed by the principal to access the data. |
| GoogleCloudSCC.FindingV2.dataAccessEvents.eventTime | String | Timestamp of data access event. |
| GoogleCloudSCC.FindingV2.dataFlowEvents | Unknown | Data flow events associated with the finding. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.eventId | String | Unique identifier for data flow event. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.principalEmail | String | The email address of the principal that initiated the data flow event. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.operation | String | The operation performed by the principal for the data flow event. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.violatedLocation | String | Non-compliant location of the principal or the data destination. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.eventTime | String | Timestamp of data flow event. |
| GoogleCloudSCC.FindingV2.networks | Unknown | Represents the VPC networks that the resource is attached to. |
| GoogleCloudSCC.FindingV2.networks.name | String | The name of the VPC network resource, for example, //compute.googleapis.com/projects/my-project/global/networks/my-network. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents | Unknown | Data retention deletion events associated with the finding. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.eventDetectionTime | String | Timestamp indicating when the event was detected. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.dataObjectCount | String | Number of objects that violated the policy for this resource. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.maxRetentionAllowed | String | Maximum duration of retention allowed from the DRD control. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.minRetentionAllowed | String | The minimum duration that the resource associated with this finding must be retained, as enforced by the DSPM retention control. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.eventType | String | Type of the DRD event. |
| GoogleCloudSCC.FindingV2.affectedResources | Unknown | The details about a distinct count of resources affected by the finding. |
| GoogleCloudSCC.FindingV2.affectedResources.count | String | The count of resources affected by the finding. |
| GoogleCloudSCC.FindingV2.aiModel | Unknown | The AI model associated with the finding. |
| GoogleCloudSCC.FindingV2.aiModel.name | String | The name of the AI model, for example, "gemini:1.0.0". |
| GoogleCloudSCC.FindingV2.aiModel.domain | String | The domain of the model, for example, "image-classification". |
| GoogleCloudSCC.FindingV2.aiModel.library | String | The name of the model library, for example, "transformers". |
| GoogleCloudSCC.FindingV2.aiModel.location | String | The region in which the model is used, for example, "us-central1". |
| GoogleCloudSCC.FindingV2.aiModel.publisher | String | The publisher of the model, for example, "google" or "nvidia". |
| GoogleCloudSCC.FindingV2.aiModel.deploymentPlatform | String | The platform on which the model is deployed. |
| GoogleCloudSCC.FindingV2.aiModel.displayName | String | The user defined display name of model. |
| GoogleCloudSCC.FindingV2.aiModel.usageCategory | String | The purpose of the model, for example, "Interference" or "Training". |
| GoogleCloudSCC.FindingV2.chokepoint | Unknown | Contains details about a chokepoint, which is a resource or resource group where high-risk attack paths converge. |
| GoogleCloudSCC.FindingV2.chokepoint.relatedFindings | Unknown | List of resource names of findings associated with this chokepoint. |
| GoogleCloudSCC.FindingV2.complianceDetails | Unknown | Details about the compliance implications of the finding. |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks | Unknown | Details of Frameworks associated with the finding |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.name | String | Name of the framework associated with the finding |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.displayName | String | Display name of the framework. |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.category | Unknown | Category of the framework associated with the finding. |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.type | String | Type of the framework associated with the finding, to specify whether the framework is built-in \(pre-defined and immutable\) or a custom framework defined by the customer \(equivalent to security posture\) |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.controls | Unknown | The controls associated with the framework. |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.controls.controlName | String | Name of the Control |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.controls.displayName | String | Display name of the control. |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl | Unknown | CloudControl associated with the finding |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl.cloudControlName | String | Name of the CloudControl associated with the finding. |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl.type | String | Type of cloud control. |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl.policyType | String | Policy type of the CloudControl |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl.version | Number | Version of the Cloud Control |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControlDeploymentNames | Unknown | Cloud Control Deployments associated with the finding. |
| GoogleCloudSCC.FindingV2.vertexAi | Unknown | VertexAi associated with the finding. |
| GoogleCloudSCC.FindingV2.vertexAi.datasets | Unknown | Datasets associated with the finding. |
| GoogleCloudSCC.FindingV2.vertexAi.datasets.name | String | Resource name of the dataset, e.g. |
| GoogleCloudSCC.FindingV2.vertexAi.datasets.displayName | String | The user defined display name of dataset, e.g. |
| GoogleCloudSCC.FindingV2.vertexAi.datasets.source | String | Data source, such as a BigQuery source URI, e.g. |
| GoogleCloudSCC.FindingV2.vertexAi.pipelines | Unknown | Pipelines associated with the finding. |
| GoogleCloudSCC.FindingV2.vertexAi.pipelines.name | String | Resource name of the pipeline, e.g. |
| GoogleCloudSCC.FindingV2.vertexAi.pipelines.displayName | String | The user-defined display name of pipeline, e.g. |
| GoogleCloudSCC.FindingV2.cryptoKeyName | String | The name of the crypto key associated with the finding. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies | Unknown | Artifact Guard policies associated with the finding. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.resourceId | String | The ID of the resource that has policies configured. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.failingPolicies | Unknown | A list of artifact guard policies that the resource violated. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.failingPolicies.type | String | The type of the policy evaluation. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.failingPolicies.policyId | String | The ID of the failing policy, for example, "organizations/3392779/locations/global/policies/prod-policy". |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.failingPolicies.failureReason | String | The reason for the policy failure, for example, "severity=HIGH AND max_vuln_count=2". |
| GoogleCloudSCC.FindingV2.secret | Unknown | Secret associated with the finding. |
| GoogleCloudSCC.FindingV2.secret.type | String | The type of secret, for example, GCP_API_KEY. |
| GoogleCloudSCC.FindingV2.secret.status | Unknown | The status of the secret. |
| GoogleCloudSCC.FindingV2.secret.status.lastUpdatedTime | String | Time that the secret was found. |
| GoogleCloudSCC.FindingV2.secret.status.validity | String | The validity of the secret. |
| GoogleCloudSCC.FindingV2.secret.environmentVariable | Unknown | The environment variable containing the secret. |
| GoogleCloudSCC.FindingV2.secret.environmentVariable.key | String | The environment variable name as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.secret.filePath | Unknown | The file containing the secret. |
| GoogleCloudSCC.FindingV2.secret.filePath.path | String | Path to the file. |
| GoogleCloudSCC.FindingV2.externalExposure | Unknown | Represents the external exposure of the finding. |
| GoogleCloudSCC.FindingV2.externalExposure.privateIpAddress | String | Private IP address of the exposed endpoint. |
| GoogleCloudSCC.FindingV2.externalExposure.privatePort | String | Port number associated with private IP address. |
| GoogleCloudSCC.FindingV2.externalExposure.exposedService | String | The name and version of the service, for example, "Jupyter Notebook 6.14.0". |
| GoogleCloudSCC.FindingV2.externalExposure.publicIpAddress | String | Public IP address of the exposed endpoint. |
| GoogleCloudSCC.FindingV2.externalExposure.publicPort | String | Public port number of the exposed endpoint. |
| GoogleCloudSCC.FindingV2.externalExposure.exposedEndpoint | String | The resource which is running the exposed service, for example, "//compute.googleapis.com/projects/\{project-id\}/zones/\{zone\}/instances/\{instance\}". |
| GoogleCloudSCC.FindingV2.externalExposure.loadBalancerFirewallPolicy | String | The full resource name of the load balancer firewall policy, for example, "//compute.googleapis.com/projects/\{project-id\}/global/firewallPolicies/\{policy-name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.serviceFirewallPolicy | String | The full resource name of the firewall policy of the exposed service, for example, "//compute.googleapis.com/projects/\{project-id\}/global/firewallPolicies/\{policy-name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.forwardingRule | String | The full resource name of the forwarding rule, for example, "//compute.googleapis.com/projects/\{project-id\}/global/forwardingRules/\{forwarding-rule-name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.backendService | String | The full resource name of load balancer backend service, for example, "//compute.googleapis.com/projects/\{project-id\}/global/backendServices/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.instanceGroup | String | The full resource name of the instance group, for example, "//compute.googleapis.com/projects/\{project-id\}/global/instanceGroups/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.networkEndpointGroup | String | The full resource name of the network endpoint group, for example, "//compute.googleapis.com/projects/\{project-id\}/global/networkEndpointGroups/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.hostnameUri | String | Hostname of the exposed application, for example, <https://example.com/> |
| GoogleCloudSCC.FindingV2.externalExposure.pscServiceAttachment | String | The full resource name of the PSC \(Private Service Connect\) service attachment that the load balancer network endpoint group targets, for example, "//compute.googleapis.com/projects/\{project-id\}/regions/\{region\}/serviceAttachments/\{name\}" |
| GoogleCloudSCC.FindingV2.externalExposure.pscNetworkAttachment | String | The full resource name of the PSC \(Private Service Connect\) network attachment that network interface controller is attached to, for example, "//compute.googleapis.com/projects/\{project-id\}/regions/\{region\}/networkAttachments/\{name\}" |
| GoogleCloudSCC.FindingV2.externalExposure.internalBackendService | String | The full resource name of load balancer backend service in the internal project having resource exposed via PSC, for example, "//compute.googleapis.com/projects/\{project-id\}/global/backendServices/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.backendBucket | String | The full resource name of the load balancer backend bucket, for example, "//compute.googleapis.com/projects/\{project-id\}/global/backendBuckets/\{name\}" |
| GoogleCloudSCC.FindingV2.externalExposure.exposedApplication | String | The name and version of the exposed web application, for example, "Jenkins 2.184". |
| GoogleCloudSCC.FindingV2.externalExposure.networkIngressFirewallPolicy | String | The full resource name of the network ingress firewall policy, for example, "//compute.googleapis.com/projects/\{project-id\}/global/firewallPolicies/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.httpResponse | Unknown | The http response returned by the web application. |
| GoogleCloudSCC.FindingV2.externalExposure.httpResponse.statusCode | String | The http response code returned by the web application, for example, 200. |
| GoogleCloudSCC.FindingV2.externalExposure.httpResponse.path | String | The http path for which response code was returned by web application, for example, <https://example.com/example>. |
| GoogleCloudSCC.FindingV2.externalExposure.networkPathInsightsGenerationTime | String | The timestamp when the network reachability trace was generated or verified. |
| GoogleCloudSCC.FindingV2.policyViolationSummary | Unknown | Summary of the policy violations associated with the finding. |
| GoogleCloudSCC.FindingV2.policyViolationSummary.policyViolationsCount | String | Count of child resources in violation of the policy. |
| GoogleCloudSCC.FindingV2.policyViolationSummary.conformantResourcesCount | String | Total number of child resources that conform to the policy. |
| GoogleCloudSCC.FindingV2.policyViolationSummary.evaluationErrorsCount | String | Number of child resources for which errors during evaluation occurred. |
| GoogleCloudSCC.FindingV2.policyViolationSummary.outOfScopeResourcesCount | String | Total count of child resources which were not in scope for evaluation. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents | Unknown | Agent data access events associated with the finding. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents.eventId | String | Unique identifier for data access event. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents.principalSubject | String | The agent principal that accessed the data. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents.operation | String | The operation performed by the principal to access the data. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents.eventTime | String | Timestamp of data access event. |
| GoogleCloudSCC.FindingV2.discoveredWorkload | Unknown | The workload that this finding is associated with. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.workloadType | String | The type of workload. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.confidence | String | The confidence in detection of this workload. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.detectedRelevantPackages | Boolean | A boolean flag set to true if installed packages strongly predict the workload type. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.detectedRelevantKeywords | Boolean | A boolean flag set to true if associated keywords strongly predict the workload type. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.detectedRelevantHardware | Boolean | A boolean flag set to true if associated hardware strongly predicts the workload type. |

#### Command Example

```!google-cloud-scc-v2-finding-state-update name="organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a" state="INACTIVE"```

#### Context Example

```json
{
    "GoogleCloudSCC": {
        "FindingV2": {
            "name": "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a",
            "canonicalName": "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a",
            "parent": "organizations/1094826489209/sources/5629340921983475201",
            "resourceName": "//compute.googleapis.com/projects/prod-webapp-284917/zones/us-central1-a/instances/web-server-01",
            "state": "INACTIVE",
            "category": "Malware: Cryptomining Bad IP",
            "externalUri": "https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/web-server-01?project=prod-webapp-284917",
            "sourceProperties": {
                "dst_zipcode": "94043",
                "browser": "Chrome",
                "dst_region": "California",
                "userkey": "jdoe@example.com",
                "traffic_type": "CloudApp",
                "count": "3",
                "dst_longitude": -122.0841,
                "src_region": "Maharashtra",
                "app": "Google Cloud Platform",
                "dst_latitude": 37.422,
                "object": "instances/web-server-01",
                "src_latitude": 19.076,
                "sv": "malsite",
                "os": "Linux",
                "src_geoip_src": "MaxMind",
                "dst_location": "Mountain View",
                "device": "Server",
                "srcip": "10.0.0.1"
            },
            "securityMarks": {
                "name": "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a/securityMarks",
                "marks": {
                    "priority": "P1",
                    "reviewed": "true"
                },
                "canonicalName": "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a/securityMarks"
            },
            "eventTime": "2020-02-18T07:26:42Z",
            "createTime": "2020-02-19T13:37:43.858Z",
            "severity": "CRITICAL",
            "mute": "MUTED",
            "muteInfo": {
                "staticMute": {
                    "state": "MUTED",
                    "applyTime": "2020-02-18T07:26:42Z"
                },
                "dynamicMuteRecords": [
                    {
                        "muteConfig": "organizations/1094826489209/muteConfigs/known-cryptomining-testrange",
                        "matchTime": "2020-02-18T07:26:42Z"
                    }
                ]
            },
            "findingClass": "THREAT",
            "indicator": {
                "ipAddresses": [
                    "10.0.0.1"
                ],
                "domains": [
                    "xmr-pool.badactor.example"
                ],
                "signatures": [
                    {
                        "signatureType": "SIGNATURE_TYPE_PROCESS",
                        "memoryHashSignature": {
                            "binaryFamily": "XMRig",
                            "detections": [
                                {
                                    "binary": "xmrig",
                                    "percentPagesMatched": 0.87
                                }
                            ]
                        },
                        "yaraRuleSignature": {
                            "yaraRule": "Cryptominer_XMRig_Generic"
                        }
                    }
                ],
                "uris": [
                    "http://xmr-pool.badactor.example:3333"
                ]
            },
            "vulnerability": {
                "cve": {
                    "id": "CVE-2021-44228",
                    "references": [
                        {
                            "source": "NVD",
                            "uri": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
                        }
                    ],
                    "cvssv3": {
                        "baseScore": 10.0,
                        "attackVector": "ATTACK_VECTOR_NETWORK",
                        "attackComplexity": "ATTACK_COMPLEXITY_LOW",
                        "privilegesRequired": "PRIVILEGES_REQUIRED_NONE",
                        "userInteraction": "USER_INTERACTION_NONE",
                        "scope": "SCOPE_CHANGED",
                        "confidentialityImpact": "IMPACT_HIGH",
                        "integrityImpact": "IMPACT_HIGH",
                        "availabilityImpact": "IMPACT_HIGH"
                    },
                    "upstreamFixAvailable": true,
                    "impact": "LOW",
                    "exploitationActivity": "WIDE",
                    "observedInTheWild": true,
                    "zeroDay": false,
                    "exploitReleaseDate": "2021-12-10T00:00:00Z",
                    "firstExploitationDate": "2021-12-10T00:00:00Z"
                },
                "offendingPackage": {
                    "packageName": "log4j-core",
                    "cpeUri": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                    "packageType": "MAVEN",
                    "packageVersion": "2.14.1"
                },
                "fixedPackage": {
                    "packageName": "log4j-core",
                    "cpeUri": "cpe:2.3:a:apache:log4j:2.17.1:*:*:*:*:*:*:*",
                    "packageType": "MAVEN",
                    "packageVersion": "2.17.1"
                },
                "securityBulletin": {
                    "bulletinId": "GCP-2021-021",
                    "submissionTime": "2021-12-11T00:00:00Z",
                    "suggestedUpgradeVersion": "2.17.1"
                },
                "providerRiskScore": "95",
                "reachable": true,
                "cwes": [
                    {
                        "id": "CWE-502",
                        "references": [
                            {
                                "source": "MITRE",
                                "uri": "https://dummyuser1@dummy.com/data/definitions/502.html"
                            }
                        ]
                    }
                ]
            },
            "muteUpdateTime": "2020-02-18T07:26:42Z",
            "externalSystems": {
                "jira": {
                    "name": "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a/externalSystems/jira",
                    "assignees": [
                        "secops@example.com"
                    ],
                    "externalUid": "SEC-4821",
                    "status": "In Progress",
                    "externalSystemUpdateTime": "2020-02-18T07:26:42Z",
                    "caseUri": "https://example.atlassian.net/browse/SEC-4821",
                    "casePriority": "High",
                    "caseSla": "2020-02-20T07:26:42Z",
                    "caseCreateTime": "2020-02-18T07:26:42Z",
                    "caseCloseTime": "2020-02-19T07:26:42Z",
                    "ticketInfo": {
                        "id": "SEC-4821",
                        "assignee": "secops@example.com",
                        "description": "Cryptomining activity detected on web-server-01",
                        "uri": "https://example.atlassian.net/browse/SEC-4821",
                        "status": "In Progress",
                        "updateTime": "2020-02-18T07:26:42Z"
                    }
                }
            },
            "mitreAttack": {
                "primaryTactic": "IMPACT",
                "primaryTechniques": [
                    "RESOURCE_HIJACKING"
                ],
                "additionalTactics": [
                    "COMMAND_AND_CONTROL"
                ],
                "additionalTechniques": [
                    "INGRESS_TOOL_TRANSFER"
                ],
                "version": "12"
            },
            "access": {
                "principalEmail": "jdoe@example.com",
                "callerIp": "10.0.0.1",
                "callerIpGeo": {
                    "regionCode": "IN"
                },
                "userAgentFamily": "curl",
                "userAgent": "curl/7.68.0",
                "serviceName": "compute.googleapis.com",
                "methodName": "v1.compute.instances.get",
                "principalSubject": "user:jdoe@example.com",
                "serviceAccountKeyName": "//iam.googleapis.com/projects/prod-webapp-284917/serviceAccounts/compute@prod-webapp-284917.iam.gserviceaccount.com/keys/a1b2c3d4",
                "serviceAccountDelegationInfo": [
                    {
                        "principalEmail": "compute@prod-webapp-284917.iam.gserviceaccount.com",
                        "principalSubject": "serviceAccount:compute@prod-webapp-284917.iam.gserviceaccount.com"
                    }
                ],
                "userName": "jdoe"
            },
            "connections": [
                {
                    "destinationIp": "10.0.0.1",
                    "destinationPort": 3333,
                    "sourceIp": "10.128.0.12",
                    "sourcePort": 51244,
                    "protocol": "TCP"
                }
            ],
            "muteInitiator": "secops@example.com",
            "processes": [
                {
                    "name": "xmrig",
                    "binary": {
                        "path": "/tmp/.cache/xmrig",
                        "size": "4194304",
                        "sha256": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                        "hashedSize": "4194304",
                        "partiallyHashed": false,
                        "contents": "ELF binary",
                        "diskPath": {
                            "partitionUuid": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                            "relativePath": "/tmp/.cache/xmrig"
                        },
                        "operations": [
                            {
                                "type": "EXECUTE"
                            }
                        ],
                        "fileLoadState": "LOADED_BY_PROCESS"
                    },
                    "libraries": [
                        {
                            "path": "/lib/x86_64-linux-gnu/libc.so.6",
                            "size": "2029224",
                            "sha256": "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe",
                            "hashedSize": "2029224",
                            "partiallyHashed": false,
                            "contents": "shared object",
                            "diskPath": {
                                "partitionUuid": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                                "relativePath": "/lib/x86_64-linux-gnu/libc.so.6"
                            },
                            "operations": [
                                {
                                    "type": "OPEN"
                                }
                            ],
                            "fileLoadState": "LOADED_BY_PROCESS"
                        }
                    ],
                    "script": {
                        "path": "/tmp/.cache/install.sh",
                        "size": "2048",
                        "sha256": "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface",
                        "hashedSize": "2048",
                        "partiallyHashed": false,
                        "contents": "#!/bin/bash",
                        "diskPath": {
                            "partitionUuid": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                            "relativePath": "/tmp/.cache/install.sh"
                        },
                        "operations": [
                            {
                                "type": "EXECUTE"
                            }
                        ],
                        "fileLoadState": "LOADED_BY_PROCESS"
                    },
                    "args": [
                        "./xmrig",
                        "-o",
                        "xmr-pool.badactor.example:3333"
                    ],
                    "argumentsTruncated": false,
                    "envVariables": [
                        {
                            "name": "HOME",
                            "val": "/root"
                        }
                    ],
                    "envVariablesTruncated": false,
                    "pid": "34521",
                    "parentPid": "1042",
                    "userId": "0"
                }
            ],
            "contacts": {
                "security": {
                    "contacts": [
                        {
                            "email": "security-admin@example.com"
                        }
                    ]
                }
            },
            "compliances": [
                {
                    "standard": "cis",
                    "version": "1.2.0",
                    "ids": [
                        "4.1"
                    ]
                }
            ],
            "parentDisplayName": "Event Threat Detection",
            "description": "The VM web-server-01 connected to a known cryptomining command-and-control IP address.",
            "exfiltration": {
                "sources": [
                    {
                        "name": "//compute.googleapis.com/projects/prod-webapp-284917/zones/us-central1-a/instances/web-server-01",
                        "components": [
                            "disk"
                        ]
                    }
                ],
                "targets": [
                    {
                        "name": "//storage.googleapis.com/exfil-bucket-badactor",
                        "components": [
                            "bucket"
                        ]
                    }
                ],
                "totalExfiltratedBytes": "1048576"
            },
            "iamBindings": [
                {
                    "action": "ADD",
                    "role": "roles/owner",
                    "member": "user:jdoe@example.com"
                }
            ],
            "nextSteps": "Isolate the affected VM, terminate the xmrig process, and rotate the associated service account keys.",
            "moduleName": "known_cryptomining_bad_ip",
            "containers": [
                {
                    "name": "web-app",
                    "uri": "gcr.io/prod-webapp-284917/web-app@sha256:baddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecaf",
                    "imageId": "sha256:baddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecaf",
                    "labels": [
                        {
                            "name": "app",
                            "value": "web"
                        }
                    ],
                    "createTime": "2020-02-18T07:26:42Z"
                }
            ],
            "kubernetes": {
                "pods": [
                    {
                        "ns": "default",
                        "name": "web-app-7d9f8c6b5-x2k4p",
                        "labels": [
                            {
                                "name": "app",
                                "value": "web"
                            }
                        ],
                        "containers": [
                            {
                                "name": "web-app",
                                "uri": "gcr.io/prod-webapp-284917/web-app@sha256:baddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecaf",
                                "imageId": "sha256:baddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecaf",
                                "labels": [
                                    {
                                        "name": "app",
                                        "value": "web"
                                    }
                                ],
                                "createTime": "2020-02-18T07:26:42Z"
                            }
                        ]
                    }
                ],
                "nodes": [
                    {
                        "name": "gke-prod-cluster-default-pool-a1b2c3d4-x9k2"
                    }
                ],
                "nodePools": [
                    {
                        "name": "default-pool",
                        "nodes": [
                            {
                                "name": "gke-prod-cluster-default-pool-a1b2c3d4-x9k2"
                            }
                        ]
                    }
                ],
                "roles": [
                    {
                        "kind": "ROLE",
                        "ns": "default",
                        "name": "pod-reader"
                    }
                ],
                "bindings": [
                    {
                        "ns": "default",
                        "name": "read-pods",
                        "role": {
                            "kind": "ROLE",
                            "ns": "default",
                            "name": "pod-reader"
                        },
                        "subjects": [
                            {
                                "kind": "USER",
                                "ns": "default",
                                "name": "jdoe@example.com"
                            }
                        ]
                    }
                ],
                "accessReviews": [
                    {
                        "group": "apps",
                        "ns": "default",
                        "name": "deployments",
                        "resource": "deployments",
                        "subresource": "",
                        "verb": "create",
                        "version": "v1"
                    }
                ],
                "objects": [
                    {
                        "group": "apps",
                        "kind": "Deployment",
                        "ns": "default",
                        "name": "web-app",
                        "containers": [
                            {
                                "name": "web-app",
                                "uri": "gcr.io/prod-webapp-284917/web-app@sha256:baddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecaf",
                                "imageId": "sha256:baddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecaf",
                                "labels": [
                                    {
                                        "name": "app",
                                        "value": "web"
                                    }
                                ],
                                "createTime": "2020-02-18T07:26:42Z"
                            }
                        ]
                    }
                ]
            },
            "database": {
                "name": "//cloudsql.googleapis.com/projects/prod-webapp-284917/instances/main-db",
                "displayName": "main-db",
                "userName": "app_user",
                "query": "SELECT * FROM users WHERE role = 'admin'",
                "grantees": [
                    "app_user"
                ],
                "version": "POSTGRES_14"
            },
            "attackExposure": {
                "score": 8.5,
                "latestCalculationTime": "2020-02-18T07:26:42Z",
                "attackExposureResult": "organizations/1094826489209/simulations/latest/attackExposureResults/6d7e8f9a",
                "state": "CALCULATED",
                "exposedHighValueResourcesCount": 3,
                "exposedMediumValueResourcesCount": 5,
                "exposedLowValueResourcesCount": 12
            },
            "files": [
                {
                    "path": "/tmp/.cache/xmrig",
                    "size": "4194304",
                    "sha256": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "hashedSize": "4194304",
                    "partiallyHashed": false,
                    "contents": "ELF binary",
                    "diskPath": {
                        "partitionUuid": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                        "relativePath": "/tmp/.cache/xmrig"
                    },
                    "operations": [
                        {
                            "type": "EXECUTE"
                        }
                    ],
                    "fileLoadState": "LOADED_BY_PROCESS"
                }
            ],
            "cloudDlpInspection": {
                "inspectJob": "projects/prod-webapp-284917/locations/global/dlpJobs/i-1234567890123456789",
                "infoType": "CREDIT_CARD_NUMBER",
                "infoTypeCount": "42",
                "fullScan": true
            },
            "cloudDlpDataProfile": {
                "dataProfile": "projects/prod-webapp-284917/locations/us/tableProfiles/9876543210",
                "parentType": "ORGANIZATION",
                "infoTypes": [
                    {
                        "name": "EMAIL_ADDRESS",
                        "version": "1",
                        "sensitivityScore": {
                            "score": "SENSITIVITY_LOW"
                        }
                    }
                ]
            },
            "kernelRootkit": {
                "name": "Diamorphine",
                "unexpectedCodeModification": true,
                "unexpectedReadOnlyDataModification": false,
                "unexpectedFtraceHandler": true,
                "unexpectedKprobeHandler": false,
                "unexpectedKernelCodePages": true,
                "unexpectedSystemCallHandler": true,
                "unexpectedInterruptHandler": false,
                "unexpectedProcessesInRunqueue": false
            },
            "orgPolicies": [
                {
                    "name": "organizations/1094826489209/policies/compute.requireShieldedVm"
                }
            ],
            "job": {
                "name": "projects/prod-webapp-284917/jobs/etl-nightly-run",
                "state": "PENDING",
                "errorCode": 0,
                "location": "us-central1"
            },
            "application": {
                "baseUri": "https://web-server-01.example.com",
                "fullUri": "https://web-server-01.example.com/api/v1/login"
            },
            "ipRules": {
                "direction": "INGRESS",
                "sourceIpRanges": [
                    "0.0.0.0/0"
                ],
                "destinationIpRanges": [
                    "10.0.0.1/20"
                ],
                "exposedServices": [
                    "ssh"
                ],
                "allowed": {
                    "ipRules": [
                        {
                            "protocol": "tcp",
                            "portRanges": [
                                {
                                    "min": "22",
                                    "max": "22"
                                }
                            ]
                        }
                    ]
                },
                "denied": {
                    "ipRules": [
                        {
                            "protocol": "tcp",
                            "portRanges": [
                                {
                                    "min": "3333",
                                    "max": "3333"
                                }
                            ]
                        }
                    ]
                }
            },
            "backupDisasterRecovery": {
                "backupTemplate": "gold-daily",
                "policies": [
                    "daily-30d-retention"
                ],
                "host": "web-server-01",
                "applications": [
                    "web-app"
                ],
                "storagePool": "primary-pool",
                "policyOptions": [
                    "compression"
                ],
                "profile": "production",
                "appliance": "bdr-appliance-01",
                "backupType": "Incremental",
                "backupCreateTime": "2020-02-18T07:26:42Z"
            },
            "securityPosture": {
                "name": "organizations/1094826489209/locations/global/postures/production-posture",
                "revisionId": "a1b2c3d4",
                "postureDeploymentResource": "organizations/1094826489209",
                "postureDeployment": "organizations/1094826489209/locations/global/postureDeployments/prod-deployment",
                "changedPolicy": "compute.requireShieldedVm",
                "policySet": "cis-gcp-1.2",
                "policy": "compute.requireShieldedVm",
                "policyDriftDetails": [
                    {
                        "field": "enableSecureBoot",
                        "expectedValue": "true",
                        "detectedValue": "false"
                    }
                ]
            },
            "logEntries": [
                {
                    "cloudLoggingEntry": {
                        "insertId": "1a2b3c4d5e6f",
                        "logId": "cloudaudit.googleapis.com%2Fdata_access",
                        "resourceContainer": "projects/prod-webapp-284917",
                        "timestamp": "2020-02-18T07:26:42Z"
                    }
                }
            ],
            "loadBalancers": [
                {
                    "name": "web-lb-frontend"
                }
            ],
            "cloudArmor": {
                "securityPolicy": {
                    "name": "prod-waf-policy",
                    "type": "CLOUD_ARMOR",
                    "preview": false
                },
                "requests": {
                    "ratio": 0.35,
                    "shortTermAllowed": 1200,
                    "longTermAllowed": 45000,
                    "longTermDenied": 3200
                },
                "adaptiveProtection": {
                    "confidence": 0.92
                },
                "attack": {
                    "volumePpsLong": "150000",
                    "volumeBpsLong": "120000000",
                    "classification": "HTTP_FLOOD",
                    "volumePps": 180000,
                    "volumeBps": 145000000
                },
                "threatVector": "HTTP_FLOOD",
                "duration": "300s"
            },
            "notebook": {
                "name": "projects/prod-webapp-284917/locations/us-central1/instances/analysis-notebook",
                "service": "Vertex AI Workbench",
                "lastAuthor": "data-scientist@example.com",
                "notebookUpdateTime": "2020-02-18T07:26:42Z"
            },
            "toxicCombination": {
                "attackExposureScore": 9.1,
                "relatedFindings": [
                    "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/aabbccddeeff00112233445566778899"
                ]
            },
            "groupMemberships": [
                {
                    "groupType": "GROUP_TYPE_TOXIC_COMBINATION",
                    "groupId": "toxic-combo-9a8b7c6d"
                }
            ],
            "disk": {
                "name": "//compute.googleapis.com/projects/prod-webapp-284917/zones/us-central1-a/disks/web-server-01"
            },
            "dataAccessEvents": [
                {
                    "eventId": "evt-a1b2c3d4",
                    "principalEmail": "jdoe@example.com",
                    "operation": "READ",
                    "eventTime": "2020-02-18T07:26:42Z"
                }
            ],
            "dataFlowEvents": [
                {
                    "eventId": "evt-e5f6a7b8",
                    "principalEmail": "jdoe@example.com",
                    "operation": "READ",
                    "violatedLocation": "asia-south1",
                    "eventTime": "2020-02-18T07:26:42Z"
                }
            ],
            "networks": [
                {
                    "name": "//compute.googleapis.com/projects/prod-webapp-284917/global/networks/default"
                }
            ],
            "dataRetentionDeletionEvents": [
                {
                    "eventDetectionTime": "2020-02-18T07:26:42Z",
                    "dataObjectCount": "15000",
                    "maxRetentionAllowed": "7776000s",
                    "minRetentionAllowed": "2592000s",
                    "eventType": "EVENT_TYPE_MAX_TTL_EXCEEDED"
                }
            ],
            "affectedResources": {
                "count": "3"
            },
            "aiModel": {
                "name": "projects/prod-webapp-284917/locations/us-central1/models/fraud-detector",
                "domain": "Fraud Detection",
                "library": "TensorFlow",
                "location": "us-central1",
                "publisher": "internal",
                "deploymentPlatform": "VERTEX_AI",
                "displayName": "Fraud Detector v3",
                "usageCategory": "Production"
            },
            "chokepoint": {
                "relatedFindings": [
                    "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/aabbccddeeff00112233445566778899"
                ]
            },
            "complianceDetails": {
                "frameworks": [
                    {
                        "name": "cis-gcp-foundation-1.2",
                        "displayName": "CIS Google Cloud Platform Foundation Benchmark v1.2.0",
                        "category": [
                            "SECURITY_BENCHMARKS"
                        ],
                        "type": "FRAMEWORK_TYPE_BUILT_IN",
                        "controls": [
                            {
                                "controlName": "4.1",
                                "displayName": "Ensure That Instances Are Not Configured To Use the Default Service Account"
                            }
                        ]
                    }
                ],
                "cloudControl": {
                    "cloudControlName": "shielded-vm-enabled",
                    "type": "BUILT_IN",
                    "policyType": "ORG_POLICY",
                    "version": 1
                },
                "cloudControlDeploymentNames": [
                    "organizations/1094826489209/locations/global/cloudControlDeployments/shielded-vm-enabled"
                ]
            },
            "vertexAi": {
                "datasets": [
                    {
                        "name": "projects/prod-webapp-284917/locations/us-central1/datasets/transactions",
                        "displayName": "transactions",
                        "source": "bq://prod-webapp-284917.analytics.transactions"
                    }
                ],
                "pipelines": [
                    {
                        "name": "projects/prod-webapp-284917/locations/us-central1/pipelineJobs/training-run-2020",
                        "displayName": "training-run-2020"
                    }
                ]
            },
            "cryptoKeyName": "projects/prod-webapp-284917/locations/us-central1/keyRings/prod-ring/cryptoKeys/data-key",
            "artifactGuardPolicies": {
                "resourceId": "gcr.io/prod-webapp-284917/web-app",
                "failingPolicies": [
                    {
                        "type": "VULNERABILITY",
                        "policyId": "block-critical-cves",
                        "failureReason": "Image contains CVE-2021-44228 with CVSS score 10.0"
                    }
                ]
            },
            "secret": {
                "type": "GCP_SERVICE_ACCOUNT_KEY",
                "status": {
                    "lastUpdatedTime": "2020-02-18T07:26:42Z",
                    "validity": "SECRET_VALIDITY_UNSUPPORTED"
                },
                "environmentVariable": {
                    "key": "GOOGLE_APPLICATION_CREDENTIALS"
                },
                "filePath": {
                    "path": "/etc/secrets/sa-key.json"
                }
            },
            "externalExposure": {
                "privateIpAddress": "10.128.0.12",
                "privatePort": "8080",
                "exposedService": "http",
                "publicIpAddress": "10.0.0.1",
                "publicPort": "80",
                "exposedEndpoint": "10.0.0.1:80",
                "loadBalancerFirewallPolicy": "prod-lb-fw-policy",
                "serviceFirewallPolicy": "prod-svc-fw-policy",
                "forwardingRule": "web-lb-forwarding-rule",
                "backendService": "web-backend-service",
                "instanceGroup": "web-server-ig",
                "networkEndpointGroup": "web-neg",
                "hostnameUri": "https://web-server-01.example.com",
                "pscServiceAttachment": "projects/prod-webapp-284917/regions/us-central1/serviceAttachments/web-psc",
                "pscNetworkAttachment": "projects/prod-webapp-284917/regions/us-central1/networkAttachments/web-na",
                "internalBackendService": "internal-web-backend",
                "backendBucket": "web-static-bucket",
                "exposedApplication": "web-app",
                "networkIngressFirewallPolicy": "prod-ingress-fw-policy",
                "httpResponse": [
                    {
                        "statusCode": "200",
                        "path": "/api/v1/login"
                    }
                ],
                "networkPathInsightsGenerationTime": "2020-02-18T07:26:42Z"
            },
            "policyViolationSummary": {
                "policyViolationsCount": "7",
                "conformantResourcesCount": "42",
                "evaluationErrorsCount": "1",
                "outOfScopeResourcesCount": "3"
            },
            "agentDataAccessEvents": [
                {
                    "eventId": "evt-c9d0e1f2",
                    "principalSubject": "serviceAccount:agent@prod-webapp-284917.iam.gserviceaccount.com",
                    "operation": "READ",
                    "eventTime": "2020-02-18T07:26:42Z"
                }
            ],
            "discoveredWorkload": {
                "workloadType": "MCP_SERVER",
                "confidence": "CONFIDENCE_HIGH",
                "detectedRelevantPackages": true,
                "detectedRelevantKeywords": true,
                "detectedRelevantHardware": false
            }
        }
    }
}
```

#### Human Readable Output

>### The finding has been updated successfully
>
>|Organization ID|Name|State|Severity|Category|Event Time (In UTC)|Create Time (In UTC)|External Uri|Resource Name|
>|---|---|---|---|---|---|---|---|---|
>| 123 | [organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a](https://console.cloud.google.com/security/command-center/findings?organizationId=123&resourceId=organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a) | INACTIVE | CRITICAL | Malware: Cryptomining Bad IP | February 18, 2020 at 07:26:42 AM | February 19, 2020 at 01:37:43 PM | [https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/web-server-01?project=prod-webapp-284917](https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/web-server-01?project=prod-webapp-284917) | //compute.googleapis.com/projects/prod-webapp-284917/zones/us-central1-a/instances/web-server-01 |

### google-cloud-scc-finding-mute

***
Mute an organization's or source's finding using the Security Command Center v2 API.

#### Base Command

`google-cloud-scc-finding-mute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The relative resource name of the finding.<br/>In the v2 API the name may include an optional "locations/{location}" segment. If no location is specified, the finding is assumed to be in "global".<br/><br/>Format: organizations/{organization_id}/sources/{source_id}/findings/{findingId} or organizations/{organization_id}/sources/{source_id}/locations/{location_id}/findings/{findingId}<br/><br/>Example: organizations/595779152576/sources/14801394649435054450/locations/global/findings/bc5a86da657611ebb979005056a5924e.<br/><br/>Note: Users can retrieve the list of the finding names by executing the "google-cloud-scc-v2-finding-list" command. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudSCC.FindingV2.name | String | 'The relative resource name of this finding. Format: organizations/\{organization\}/sources/\{source\}/locations/\{location\}/findings/\{finding\}.' |
| GoogleCloudSCC.FindingV2.canonicalName | String | The canonical name of the finding, always suffixed with the region-agnostic \(global\) resource path. |
| GoogleCloudSCC.FindingV2.parent | String | The relative resource name of the source the finding belongs to. |
| GoogleCloudSCC.FindingV2.resourceName | String | For findings on Google Cloud resources, the full resource name of the Google Cloud resource this finding is for. |
| GoogleCloudSCC.FindingV2.state | String | The state of the finding \(ACTIVE or INACTIVE\). |
| GoogleCloudSCC.FindingV2.category | String | The additional taxonomy group within findings from a given source. |
| GoogleCloudSCC.FindingV2.externalUri | String | The URI that, if available, points to a web page outside of Security Command Center where additional information about the finding can be found. |
| GoogleCloudSCC.FindingV2.sourceProperties | Unknown | Source specific properties. These properties are managed by the source that writes the finding. Properties are varying from finding to finding. |
| GoogleCloudSCC.FindingV2.securityMarks | Unknown | Output only. |
| GoogleCloudSCC.FindingV2.securityMarks.name | String | The relative resource name of the SecurityMarks. |
| GoogleCloudSCC.FindingV2.securityMarks.marks | Unknown | Mutable user specified security marks belonging to the parent resource. |
| GoogleCloudSCC.FindingV2.securityMarks.canonicalName | String | The canonical name of the marks. |
| GoogleCloudSCC.FindingV2.eventTime | String | The time at which the event took place, or when an update to the finding occurred. |
| GoogleCloudSCC.FindingV2.createTime | String | The time at which the finding was created in Security Command Center. |
| GoogleCloudSCC.FindingV2.severity | String | The severity of the finding \(CRITICAL, HIGH, MEDIUM, LOW\). |
| GoogleCloudSCC.FindingV2.mute | String | Indicates the mute state of the finding \(MUTED, UNMUTED, UNDEFINED\). |
| GoogleCloudSCC.FindingV2.muteInfo | Unknown | Additional details about the mute state of the finding, including static and dynamic mute records. |
| GoogleCloudSCC.FindingV2.muteInfo.staticMute | Unknown | If set, the static mute applied to this finding. |
| GoogleCloudSCC.FindingV2.muteInfo.staticMute.state | String | The static mute state. |
| GoogleCloudSCC.FindingV2.muteInfo.staticMute.applyTime | String | When the static mute was applied. |
| GoogleCloudSCC.FindingV2.muteInfo.dynamicMuteRecords | Unknown | The list of dynamic mute rules that currently match the finding. |
| GoogleCloudSCC.FindingV2.muteInfo.dynamicMuteRecords.muteConfig | String | The relative resource name of the mute rule, represented by a mute config, that created this record, for example organizations/123/muteConfigs/mymuteconfig or organizations/123/locations/global/muteConfigs/mymuteconfig. |
| GoogleCloudSCC.FindingV2.muteInfo.dynamicMuteRecords.matchTime | String | When the dynamic mute rule first matched the finding. |
| GoogleCloudSCC.FindingV2.findingClass | String | The class of the finding \(THREAT, VULNERABILITY, MISCONFIGURATION, OBSERVATION, SCC_ERROR, POSTURE_VIOLATION, TOXIC_COMBINATION\). |
| GoogleCloudSCC.FindingV2.indicator | Unknown | Represents what's commonly known as an indicator of compromise \(IoC\) in computer forensics. |
| GoogleCloudSCC.FindingV2.indicator.ipAddresses | Unknown | The list of IP addresses that are associated with the finding. |
| GoogleCloudSCC.FindingV2.indicator.domains | Unknown | List of domains associated to the Finding. |
| GoogleCloudSCC.FindingV2.indicator.signatures | Unknown | The list of matched signatures indicating that the given process is present in the environment. |
| GoogleCloudSCC.FindingV2.indicator.signatures.signatureType | String | Describes the type of resource associated with the signature. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature | Unknown | Signature indicating that a binary family was matched. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature.binaryFamily | String | The binary family. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature.detections | Unknown | The list of memory hash detections contributing to the binary family match. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature.detections.binary | String | The name of the binary associated with the memory hash signature detection. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature.detections.percentPagesMatched | Number | The percentage of memory page hashes in the signature that were matched. |
| GoogleCloudSCC.FindingV2.indicator.signatures.yaraRuleSignature | Unknown | Signature indicating that a YARA rule was matched. |
| GoogleCloudSCC.FindingV2.indicator.signatures.yaraRuleSignature.yaraRule | String | The name of the YARA rule. |
| GoogleCloudSCC.FindingV2.indicator.uris | Unknown | The list of URIs associated to the Findings. |
| GoogleCloudSCC.FindingV2.vulnerability | Unknown | Represents vulnerability-specific fields like CVE and CVSS scores. |
| GoogleCloudSCC.FindingV2.vulnerability.cve | Unknown | CVE stands for Common Vulnerabilities and Exposures \(&lt;<https://cve.mitre.org/about/&gt;\>) |
| GoogleCloudSCC.FindingV2.vulnerability.cve.id | String | The unique identifier for the vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.references | Unknown | Additional information about the CVE. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.references.source | String | Source of the reference e.g. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.references.uri | String | Uri for the mentioned source e.g. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3 | Unknown | Describe Common Vulnerability Scoring System specified at &lt;<https://www.first.org/cvss/v3.1/specification-document>&gt; |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.baseScore | Number | The base score is a function of the base metric scores. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.attackVector | String | Base Metrics Represents the intrinsic characteristics of a vulnerability that are constant over time and across user environments. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.attackComplexity | String | This metric describes the conditions beyond the attacker's control that must exist in order to exploit the vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.privilegesRequired | String | This metric describes the level of privileges an attacker must possess before successfully exploiting the vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.userInteraction | String | This metric captures the requirement for a human user, other than the attacker, to participate in the successful compromise of the vulnerable component. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.scope | String | The Scope metric captures whether a vulnerability in one vulnerable component impacts resources in components beyond its security scope. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.confidentialityImpact | String | This metric measures the impact to the confidentiality of the information resources managed by a software component due to a successfully exploited vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.integrityImpact | String | This metric measures the impact to integrity of a successfully exploited vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.availabilityImpact | String | This metric measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.upstreamFixAvailable | Boolean | Whether upstream fix is available for the CVE. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.impact | String | The potential impact of the vulnerability if it was to be exploited. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.exploitationActivity | String | The exploitation activity of the vulnerability in the wild. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.observedInTheWild | Boolean | Whether or not the vulnerability has been observed in the wild. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.zeroDay | Boolean | Whether or not the vulnerability was zero day when the finding was published. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.exploitReleaseDate | String | Date the first publicly available exploit or PoC was released. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.firstExploitationDate | String | Date of the earliest known exploitation. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage | Unknown | The offending package is relevant to the finding. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage.packageName | String | The name of the package where the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage.cpeUri | String | The CPE URI where the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage.packageType | String | Type of package, for example, os, maven, or go. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage.packageVersion | String | The version of the package. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage | Unknown | The fixed package is relevant to the finding. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage.packageName | String | The name of the package where the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage.cpeUri | String | The CPE URI where the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage.packageType | String | Type of package, for example, os, maven, or go. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage.packageVersion | String | The version of the package. |
| GoogleCloudSCC.FindingV2.vulnerability.securityBulletin | Unknown | The security bulletin is relevant to this finding. |
| GoogleCloudSCC.FindingV2.vulnerability.securityBulletin.bulletinId | String | ID of the bulletin corresponding to the vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.securityBulletin.submissionTime | String | Submission time of this Security Bulletin. |
| GoogleCloudSCC.FindingV2.vulnerability.securityBulletin.suggestedUpgradeVersion | String | This represents a version that the cluster receiving this notification should be upgraded to, based on its current version. |
| GoogleCloudSCC.FindingV2.vulnerability.providerRiskScore | String | Provider provided risk_score based on multiple factors. |
| GoogleCloudSCC.FindingV2.vulnerability.reachable | Boolean | Represents whether the vulnerability is reachable \(detected via static analysis\) |
| GoogleCloudSCC.FindingV2.vulnerability.cwes | Unknown | Represents one or more Common Weakness Enumeration \(CWE\) information on this vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cwes.id | String | The CWE identifier, e.g. |
| GoogleCloudSCC.FindingV2.vulnerability.cwes.references | Unknown | Any reference to the details on the CWE, for example, &lt;<https://dummyuser1@dummy.com/data/definitions/94.html>&gt; |
| GoogleCloudSCC.FindingV2.vulnerability.cwes.references.source | String | Source of the reference e.g. |
| GoogleCloudSCC.FindingV2.vulnerability.cwes.references.uri | String | Uri for the mentioned source e.g. |
| GoogleCloudSCC.FindingV2.muteUpdateTime | String | The time at which the finding was muted or unmuted. |
| GoogleCloudSCC.FindingV2.externalSystems | Unknown | Third party SIEM/SOAR fields within Security Command Center, contains external system information and external system finding fields. |
| GoogleCloudSCC.FindingV2.mitreAttack | Unknown | MITRE ATT&amp;CK tactics and techniques related to this finding. |
| GoogleCloudSCC.FindingV2.mitreAttack.primaryTactic | String | The MITRE ATT\\&amp;CK tactic most closely represented by this finding, if any. |
| GoogleCloudSCC.FindingV2.mitreAttack.primaryTechniques | Unknown | The MITRE ATT\\&amp;CK technique most closely represented by this finding, if any. |
| GoogleCloudSCC.FindingV2.mitreAttack.additionalTactics | Unknown | Additional MITRE ATT\\&amp;CK tactics related to this finding, if any. |
| GoogleCloudSCC.FindingV2.mitreAttack.additionalTechniques | Unknown | Additional MITRE ATT\\&amp;CK techniques related to this finding, if any, along with any of their respective parent techniques. |
| GoogleCloudSCC.FindingV2.mitreAttack.version | String | The MITRE ATT\\&amp;CK version referenced by the above fields. |
| GoogleCloudSCC.FindingV2.access | Unknown | Access details associated with the finding, such as more information on the caller, which method was accessed, and from where. |
| GoogleCloudSCC.FindingV2.access.principalEmail | String | Associated email, such as "<foo@google.com>". |
| GoogleCloudSCC.FindingV2.access.callerIp | String | Caller's IP address, such as "1.1.1.1". |
| GoogleCloudSCC.FindingV2.access.callerIpGeo | Unknown | The caller IP's geolocation, which identifies where the call came from. |
| GoogleCloudSCC.FindingV2.access.callerIpGeo.regionCode | String | A CLDR. |
| GoogleCloudSCC.FindingV2.access.userAgentFamily | String | Type of user agent associated with the finding. |
| GoogleCloudSCC.FindingV2.access.userAgent | String | The caller's user agent string associated with the finding. |
| GoogleCloudSCC.FindingV2.access.serviceName | String | This is the API service that the service account made a call to, e.g. |
| GoogleCloudSCC.FindingV2.access.methodName | String | The method that the service account called, e.g. |
| GoogleCloudSCC.FindingV2.access.principalSubject | String | A string that represents the principalSubject that is associated with the identity. |
| GoogleCloudSCC.FindingV2.access.serviceAccountKeyName | String | The name of the service account key that was used to create or exchange credentials when authenticating the service account that made the request. |
| GoogleCloudSCC.FindingV2.access.serviceAccountDelegationInfo | Unknown | The identity delegation history of an authenticated service account that made the request. |
| GoogleCloudSCC.FindingV2.access.serviceAccountDelegationInfo.principalEmail | String | The email address of a Google account. |
| GoogleCloudSCC.FindingV2.access.serviceAccountDelegationInfo.principalSubject | String | A string representing the principalSubject associated with the identity. |
| GoogleCloudSCC.FindingV2.access.userName | String | A string that represents a username. |
| GoogleCloudSCC.FindingV2.connections | Unknown | Contains information about the IP connection associated with the finding. |
| GoogleCloudSCC.FindingV2.connections.destinationIp | String | Destination IP address. |
| GoogleCloudSCC.FindingV2.connections.destinationPort | Number | Destination port. |
| GoogleCloudSCC.FindingV2.connections.sourceIp | String | Source IP address. |
| GoogleCloudSCC.FindingV2.connections.sourcePort | Number | Source port. |
| GoogleCloudSCC.FindingV2.connections.protocol | String | IANA Internet Protocol Number such as TCP\(6\) and UDP\(17\). |
| GoogleCloudSCC.FindingV2.muteInitiator | String | Records the entity that is responsible for the muting of the finding. |
| GoogleCloudSCC.FindingV2.processes | Unknown | Represents operating system processes associated with the finding. |
| GoogleCloudSCC.FindingV2.processes.name | String | The process name, as displayed in utilities like top and ps. |
| GoogleCloudSCC.FindingV2.processes.binary | Unknown | File information for the process executable. |
| GoogleCloudSCC.FindingV2.processes.binary.path | String | Absolute path of the file as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.binary.size | String | Size of the file in bytes. |
| GoogleCloudSCC.FindingV2.processes.binary.sha256 | String | SHA256 hash of the first hashedSize bytes of the file encoded as a hex string. |
| GoogleCloudSCC.FindingV2.processes.binary.hashedSize | String | The length in bytes of the file prefix that was hashed. |
| GoogleCloudSCC.FindingV2.processes.binary.partiallyHashed | Boolean | True when the hash covers only a prefix of the file. |
| GoogleCloudSCC.FindingV2.processes.binary.contents | String | Prefix of the file contents as a JSON-encoded string. |
| GoogleCloudSCC.FindingV2.processes.binary.diskPath | Unknown | Path of the file in terms of underlying disk/partition identifiers. |
| GoogleCloudSCC.FindingV2.processes.binary.diskPath.partitionUuid | String | UUID of the partition \(format &lt;<https://wiki.archlinux.org/title/persistent_block_device_naming\#by-uuid&gt;\>) |
| GoogleCloudSCC.FindingV2.processes.binary.diskPath.relativePath | String | Relative path of the file in the partition as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.binary.operations | Unknown | Operation\(s\) performed on a file. |
| GoogleCloudSCC.FindingV2.processes.binary.operations.type | String | The type of the operation |
| GoogleCloudSCC.FindingV2.processes.binary.fileLoadState | String | The load state of the file. |
| GoogleCloudSCC.FindingV2.processes.libraries | Unknown | File information for libraries loaded by the process. |
| GoogleCloudSCC.FindingV2.processes.libraries.path | String | Absolute path of the file as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.libraries.size | String | Size of the file in bytes. |
| GoogleCloudSCC.FindingV2.processes.libraries.sha256 | String | SHA256 hash of the first hashedSize bytes of the file encoded as a hex string. |
| GoogleCloudSCC.FindingV2.processes.libraries.hashedSize | String | The length in bytes of the file prefix that was hashed. |
| GoogleCloudSCC.FindingV2.processes.libraries.partiallyHashed | Boolean | True when the hash covers only a prefix of the file. |
| GoogleCloudSCC.FindingV2.processes.libraries.contents | String | Prefix of the file contents as a JSON-encoded string. |
| GoogleCloudSCC.FindingV2.processes.libraries.diskPath | Unknown | Path of the file in terms of underlying disk/partition identifiers. |
| GoogleCloudSCC.FindingV2.processes.libraries.diskPath.partitionUuid | String | UUID of the partition \(format &lt;<https://wiki.archlinux.org/title/persistent_block_device_naming\#by-uuid&gt;\>) |
| GoogleCloudSCC.FindingV2.processes.libraries.diskPath.relativePath | String | Relative path of the file in the partition as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.libraries.operations | Unknown | Operation\(s\) performed on a file. |
| GoogleCloudSCC.FindingV2.processes.libraries.operations.type | String | The type of the operation |
| GoogleCloudSCC.FindingV2.processes.libraries.fileLoadState | String | The load state of the file. |
| GoogleCloudSCC.FindingV2.processes.script | Unknown | When the process represents the invocation of a script, binary provides information about the interpreter, while script provides information about the script file provided to the interpreter. |
| GoogleCloudSCC.FindingV2.processes.script.path | String | Absolute path of the file as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.script.size | String | Size of the file in bytes. |
| GoogleCloudSCC.FindingV2.processes.script.sha256 | String | SHA256 hash of the first hashedSize bytes of the file encoded as a hex string. |
| GoogleCloudSCC.FindingV2.processes.script.hashedSize | String | The length in bytes of the file prefix that was hashed. |
| GoogleCloudSCC.FindingV2.processes.script.partiallyHashed | Boolean | True when the hash covers only a prefix of the file. |
| GoogleCloudSCC.FindingV2.processes.script.contents | String | Prefix of the file contents as a JSON-encoded string. |
| GoogleCloudSCC.FindingV2.processes.script.diskPath | Unknown | Path of the file in terms of underlying disk/partition identifiers. |
| GoogleCloudSCC.FindingV2.processes.script.diskPath.partitionUuid | String | UUID of the partition \(format &lt;<https://wiki.archlinux.org/title/persistent_block_device_naming\#by-uuid&gt;\>) |
| GoogleCloudSCC.FindingV2.processes.script.diskPath.relativePath | String | Relative path of the file in the partition as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.script.operations | Unknown | Operation\(s\) performed on a file. |
| GoogleCloudSCC.FindingV2.processes.script.operations.type | String | The type of the operation |
| GoogleCloudSCC.FindingV2.processes.script.fileLoadState | String | The load state of the file. |
| GoogleCloudSCC.FindingV2.processes.args | Unknown | Process arguments as JSON encoded strings. |
| GoogleCloudSCC.FindingV2.processes.argumentsTruncated | Boolean | True if args is incomplete. |
| GoogleCloudSCC.FindingV2.processes.envVariables | Unknown | Process environment variables. |
| GoogleCloudSCC.FindingV2.processes.envVariables.name | String | Environment variable name as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.envVariables.val | String | Environment variable value as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.envVariablesTruncated | Boolean | True if envVariables is incomplete. |
| GoogleCloudSCC.FindingV2.processes.pid | String | The process ID. |
| GoogleCloudSCC.FindingV2.processes.parentPid | String | The parent process ID. |
| GoogleCloudSCC.FindingV2.processes.userId | String | The ID of the user that executed the process. |
| GoogleCloudSCC.FindingV2.contacts | Unknown | Map containing the points of contact for the given finding. |
| GoogleCloudSCC.FindingV2.compliances | Unknown | Contains compliance information for security standards associated to the finding. |
| GoogleCloudSCC.FindingV2.compliances.standard | String | Industry-wide compliance standards or benchmarks, such as CIS, PCI, and OWASP. |
| GoogleCloudSCC.FindingV2.compliances.version | String | Version of the standard or benchmark, for example, 1.1 |
| GoogleCloudSCC.FindingV2.compliances.ids | Unknown | Policies within the standard or benchmark, for example, A.12.4.1 |
| GoogleCloudSCC.FindingV2.parentDisplayName | String | The human readable display name of the finding source, such as "Event Threat Detection" or "Security Health Analytics". |
| GoogleCloudSCC.FindingV2.description | String | Contains more details about the finding. |
| GoogleCloudSCC.FindingV2.exfiltration | Unknown | Represents exfiltrations associated with the finding. |
| GoogleCloudSCC.FindingV2.exfiltration.sources | Unknown | If there are multiple sources, then the data is considered "joined" between them. |
| GoogleCloudSCC.FindingV2.exfiltration.sources.name | String | The resource's full resource name. |
| GoogleCloudSCC.FindingV2.exfiltration.sources.components | Unknown | Subcomponents of the asset that was exfiltrated, like URIs used during exfiltration, table names, databases, and filenames. |
| GoogleCloudSCC.FindingV2.exfiltration.targets | Unknown | If there are multiple targets, each target would get a complete copy of the "joined" source data. |
| GoogleCloudSCC.FindingV2.exfiltration.targets.name | String | The resource's full resource name. |
| GoogleCloudSCC.FindingV2.exfiltration.targets.components | Unknown | Subcomponents of the asset that was exfiltrated, like URIs used during exfiltration, table names, databases, and filenames. |
| GoogleCloudSCC.FindingV2.exfiltration.totalExfiltratedBytes | String | Total exfiltrated bytes processed for the entire job. |
| GoogleCloudSCC.FindingV2.iamBindings | Unknown | Represents IAM bindings associated with the finding. |
| GoogleCloudSCC.FindingV2.iamBindings.action | String | The action that was performed on a Binding. |
| GoogleCloudSCC.FindingV2.iamBindings.role | String | Role that is assigned to "members". |
| GoogleCloudSCC.FindingV2.iamBindings.member | String | A single identity requesting access for a Cloud Platform resource, for example, "<foo@google.com>". |
| GoogleCloudSCC.FindingV2.nextSteps | String | Steps to address the finding. |
| GoogleCloudSCC.FindingV2.moduleName | String | Unique identifier of the module which generated the finding. |
| GoogleCloudSCC.FindingV2.containers | Unknown | Containers associated with the finding. This field provides information for both Kubernetes and non-Kubernetes containers. |
| GoogleCloudSCC.FindingV2.containers.name | String | Name of the container. |
| GoogleCloudSCC.FindingV2.containers.uri | String | Container image URI provided when configuring a pod or container. |
| GoogleCloudSCC.FindingV2.containers.imageId | String | Optional container image ID, if provided by the container runtime. |
| GoogleCloudSCC.FindingV2.containers.labels | Unknown | Container labels, as provided by the container runtime. |
| GoogleCloudSCC.FindingV2.containers.labels.name | String | Name of the label. |
| GoogleCloudSCC.FindingV2.containers.labels.value | String | Value that corresponds to the label's name. |
| GoogleCloudSCC.FindingV2.containers.createTime | String | The time that the container was created. |
| GoogleCloudSCC.FindingV2.kubernetes | Unknown | Kubernetes resources associated with the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.pods | Unknown | Kubernetes Pods associated with the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.ns | String | Kubernetes Pod namespace. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.name | String | Kubernetes Pod name. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.labels | Unknown | Pod labels. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.labels.name | String | Name of the label. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.labels.value | String | Value that corresponds to the label's name. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers | Unknown | Pod containers associated with this finding, if any. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.name | String | Name of the container. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.uri | String | Container image URI provided when configuring a pod or container. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.imageId | String | Optional container image ID, if provided by the container runtime. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.labels | Unknown | Container labels, as provided by the container runtime. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.labels.name | String | Name of the label. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.labels.value | String | Value that corresponds to the label's name. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.createTime | String | The time that the container was created. |
| GoogleCloudSCC.FindingV2.kubernetes.nodes | Unknown | Provides Kubernetes node information. |
| GoogleCloudSCC.FindingV2.kubernetes.nodes.name | String | Full resource name of the Compute Engine VM running the cluster node. |
| GoogleCloudSCC.FindingV2.kubernetes.nodePools | Unknown | GKE node pools associated with the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.nodePools.name | String | Kubernetes node pool name. |
| GoogleCloudSCC.FindingV2.kubernetes.nodePools.nodes | Unknown | Nodes associated with the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.nodePools.nodes.name | String | Full resource name of the Compute Engine VM running the cluster node. |
| GoogleCloudSCC.FindingV2.kubernetes.roles | Unknown | Provides Kubernetes role information for findings that involve Roles or ClusterRoles. |
| GoogleCloudSCC.FindingV2.kubernetes.roles.kind | String | Role type. |
| GoogleCloudSCC.FindingV2.kubernetes.roles.ns | String | Role namespace. |
| GoogleCloudSCC.FindingV2.kubernetes.roles.name | String | Role name. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings | Unknown | Provides Kubernetes role binding information for findings that involve RoleBindings or ClusterRoleBindings. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.ns | String | Namespace for the binding. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.name | String | Name for the binding. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.role | Unknown | The Role or ClusterRole referenced by the binding. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.role.kind | String | Role type. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.role.ns | String | Role namespace. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.role.name | String | Role name. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.subjects | Unknown | Represents one or more subjects that are bound to the role. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.subjects.kind | String | Authentication type for the subject. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.subjects.ns | String | Namespace for the subject. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.subjects.name | String | Name for the subject. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews | Unknown | Provides information on any Kubernetes access reviews \(privilege checks\) relevant to the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.group | String | The API group of the resource. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.ns | String | Namespace of the action being requested. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.name | String | The name of the resource being requested. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.resource | String | The optional resource type requested. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.subresource | String | The optional subresource type. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.verb | String | A Kubernetes resource API verb, like get, list, watch, create, update, delete, proxy. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.version | String | The API version of the resource. |
| GoogleCloudSCC.FindingV2.kubernetes.objects | Unknown | Kubernetes objects related to the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.group | String | Kubernetes object group, such as "policy.k8s.io/v1". |
| GoogleCloudSCC.FindingV2.kubernetes.objects.kind | String | Kubernetes object kind, such as "Namespace". |
| GoogleCloudSCC.FindingV2.kubernetes.objects.ns | String | Kubernetes object namespace. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.name | String | Kubernetes object name. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers | Unknown | Pod containers associated with this finding, if any. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.name | String | Name of the container. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.uri | String | Container image URI provided when configuring a pod or container. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.imageId | String | Optional container image ID, if provided by the container runtime. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.labels | Unknown | Container labels, as provided by the container runtime. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.labels.name | String | Name of the label. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.labels.value | String | Value that corresponds to the label's name. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.createTime | String | The time that the container was created. |
| GoogleCloudSCC.FindingV2.database | Unknown | Database associated with the finding. |
| GoogleCloudSCC.FindingV2.database.name | String | Some database resources may not have the full resource name populated because these resource types are not yet supported by Cloud Asset Inventory \(e.g. |
| GoogleCloudSCC.FindingV2.database.displayName | String | The human-readable name of the database that the user connected to. |
| GoogleCloudSCC.FindingV2.database.userName | String | The username used to connect to the database. |
| GoogleCloudSCC.FindingV2.database.query | String | The SQL statement that is associated with the database access. |
| GoogleCloudSCC.FindingV2.database.grantees | Unknown | The target usernames, roles, or groups of an SQL privilege grant, which is not an IAM policy change. |
| GoogleCloudSCC.FindingV2.database.version | String | The version of the database, for example, POSTGRES_14. |
| GoogleCloudSCC.FindingV2.attackExposure | Unknown | The results of an attack path simulation relevant to this finding. |
| GoogleCloudSCC.FindingV2.attackExposure.score | Number | A number between 0 \(inclusive\) and infinity that represents how important this finding is to remediate. |
| GoogleCloudSCC.FindingV2.attackExposure.latestCalculationTime | String | The most recent time the attack exposure was updated on this finding. |
| GoogleCloudSCC.FindingV2.attackExposure.attackExposureResult | String | The resource name of the attack path simulation result that contains the details regarding this attack exposure score. |
| GoogleCloudSCC.FindingV2.attackExposure.state | String | Output only. |
| GoogleCloudSCC.FindingV2.attackExposure.exposedHighValueResourcesCount | Number | The number of high value resources that are exposed as a result of this finding. |
| GoogleCloudSCC.FindingV2.attackExposure.exposedMediumValueResourcesCount | Number | The number of medium value resources that are exposed as a result of this finding. |
| GoogleCloudSCC.FindingV2.attackExposure.exposedLowValueResourcesCount | Number | The number of high value resources that are exposed as a result of this finding. |
| GoogleCloudSCC.FindingV2.files | Unknown | File associated with the finding. |
| GoogleCloudSCC.FindingV2.files.path | String | Absolute path of the file as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.files.size | String | Size of the file in bytes. |
| GoogleCloudSCC.FindingV2.files.sha256 | String | SHA256 hash of the first hashedSize bytes of the file encoded as a hex string. |
| GoogleCloudSCC.FindingV2.files.hashedSize | String | The length in bytes of the file prefix that was hashed. |
| GoogleCloudSCC.FindingV2.files.partiallyHashed | Boolean | True when the hash covers only a prefix of the file. |
| GoogleCloudSCC.FindingV2.files.contents | String | Prefix of the file contents as a JSON-encoded string. |
| GoogleCloudSCC.FindingV2.files.diskPath | Unknown | Path of the file in terms of underlying disk/partition identifiers. |
| GoogleCloudSCC.FindingV2.files.diskPath.partitionUuid | String | UUID of the partition \(format &lt;<https://wiki.archlinux.org/title/persistent_block_device_naming\#by-uuid&gt;\>) |
| GoogleCloudSCC.FindingV2.files.diskPath.relativePath | String | Relative path of the file in the partition as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.files.operations | Unknown | Operation\(s\) performed on a file. |
| GoogleCloudSCC.FindingV2.files.operations.type | String | The type of the operation |
| GoogleCloudSCC.FindingV2.files.fileLoadState | String | The load state of the file. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection | Unknown | Cloud Data Loss Prevention \(Cloud DLP\) inspection results that are associated with the finding. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection.inspectJob | String | Name of the inspection job, for example, projects/123/locations/europe/dlpJobs/i-8383929. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection.infoType | String | The type of information \(or \*infoType\* \) found, for example, EMAIL_ADDRESS or STREET_ADDRESS. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection.infoTypeCount | String | The number of times Cloud DLP found this infoType within this job and resource. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection.fullScan | Boolean | Whether Cloud DLP scanned the complete resource or a sampled subset. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile | Unknown | Cloud DLP data profile that is associated with the finding. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.dataProfile | String | Name of the data profile, for example, projects/123/locations/europe/tableProfiles/8383929. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.parentType | String | The resource hierarchy level at which the data profile was generated. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes | Unknown | Type of information detected by SDP. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes.name | String | Name of the information type. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes.version | String | Optional version name for this InfoType. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes.sensitivityScore | Unknown | Optional custom sensitivity for this InfoType. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes.sensitivityScore.score | String | The sensitivity score applied to the resource. |
| GoogleCloudSCC.FindingV2.kernelRootkit | Unknown | Signature of the kernel rootkit. |
| GoogleCloudSCC.FindingV2.kernelRootkit.name | String | Rootkit name, when available. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedCodeModification | Boolean | True if unexpected modifications of kernel code memory are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedReadOnlyDataModification | Boolean | True if unexpected modifications of kernel read-only data memory are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedFtraceHandler | Boolean | True if ftrace points are present with callbacks pointing to regions that are not in the expected kernel or module code range. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedKprobeHandler | Boolean | True if kprobe points are present with callbacks pointing to regions that are not in the expected kernel or module code range. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedKernelCodePages | Boolean | True if kernel code pages that are not in the expected kernel or module code regions are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedSystemCallHandler | Boolean | True if system call handlers that are are not in the expected kernel or module code regions are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedInterruptHandler | Boolean | True if interrupt handlers that are are not in the expected kernel or module code regions are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedProcessesInRunqueue | Boolean | True if unexpected processes in the scheduler run queue are present. |
| GoogleCloudSCC.FindingV2.orgPolicies | Unknown | Contains information about the org policies associated with the finding. |
| GoogleCloudSCC.FindingV2.orgPolicies.name | String | Identifier. |
| GoogleCloudSCC.FindingV2.job | Unknown | Job associated with the finding. |
| GoogleCloudSCC.FindingV2.job.name | String | The fully-qualified name for a job. |
| GoogleCloudSCC.FindingV2.job.state | String | Output only. |
| GoogleCloudSCC.FindingV2.job.errorCode | Number | Optional. |
| GoogleCloudSCC.FindingV2.job.location | String | Optional. |
| GoogleCloudSCC.FindingV2.application | Unknown | Represents an application associated with the finding. |
| GoogleCloudSCC.FindingV2.application.baseUri | String | The base URI that identifies the network location of the application in which the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.application.fullUri | String | The full URI with payload that could be used to reproduce the vulnerability. |
| GoogleCloudSCC.FindingV2.ipRules | Unknown | IP rules associated with the finding. |
| GoogleCloudSCC.FindingV2.ipRules.direction | String | The direction that the rule is applicable to, one of ingress or egress. |
| GoogleCloudSCC.FindingV2.ipRules.sourceIpRanges | Unknown | If source IP ranges are specified, the firewall rule applies only to traffic that has a source IP address in these ranges. |
| GoogleCloudSCC.FindingV2.ipRules.destinationIpRanges | Unknown | If destination IP ranges are specified, the firewall rule applies only to traffic that has a destination IP address in these ranges. |
| GoogleCloudSCC.FindingV2.ipRules.exposedServices | Unknown | Name of the network protocol service, such as FTP, that is exposed by the open port. |
| GoogleCloudSCC.FindingV2.ipRules.allowed | Unknown | Tuple with allowed rules. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules | Unknown | Optional. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules.protocol | String | The IP protocol this rule applies to. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules.portRanges | Unknown | Optional. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules.portRanges.min | String | Minimum port value. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules.portRanges.max | String | Maximum port value. |
| GoogleCloudSCC.FindingV2.ipRules.denied | Unknown | Tuple with denied rules. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules | Unknown | Optional. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules.protocol | String | The IP protocol this rule applies to. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules.portRanges | Unknown | Optional. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules.portRanges.min | String | Minimum port value. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules.portRanges.max | String | Maximum port value. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery | Unknown | Fields related to Backup and Disaster Recovery findings. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.backupTemplate | String | The name of a Backup and DR template which comprises one or more backup policies. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.policies | Unknown | The names of Backup and DR policies that are associated with a template and that define when to run a backup, how frequently to run a backup, and how long to retain the backup image. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.host | String | The name of a Backup and DR host, which is managed by the backup and recovery appliance and known to the management console. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.applications | Unknown | The names of Backup and DR applications. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.storagePool | String | The name of the Backup and DR storage pool that the backup and recovery appliance is storing data in. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.policyOptions | Unknown | The names of Backup and DR advanced policy options of a policy applying to an application. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.profile | String | The name of the Backup and DR resource profile that specifies the storage media for backups of application and VM data. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.appliance | String | The name of the Backup and DR appliance that captures, moves, and manages the lifecycle of backup data. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.backupType | String | The backup type of the Backup and DR image. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.backupCreateTime | String | The timestamp at which the Backup and DR backup was created. |
| GoogleCloudSCC.FindingV2.securityPosture | Unknown | The security posture associated with the finding. |
| GoogleCloudSCC.FindingV2.securityPosture.name | String | Name of the posture, for example, CIS-Posture. |
| GoogleCloudSCC.FindingV2.securityPosture.revisionId | String | The version of the posture, for example, c7cfa2a8. |
| GoogleCloudSCC.FindingV2.securityPosture.postureDeploymentResource | String | The project, folder, or organization on which the posture is deployed, for example, projects/\{project_number\}. |
| GoogleCloudSCC.FindingV2.securityPosture.postureDeployment | String | The name of the posture deployment, for example, organizations/\{org_id\}/posturedeployments/\{posture_deployment_id\}. |
| GoogleCloudSCC.FindingV2.securityPosture.changedPolicy | String | The name of the updated policy, for example, projects/\{projectId\}/policies/\{constraint_name\}. |
| GoogleCloudSCC.FindingV2.securityPosture.policySet | String | The name of the updated policy set, for example, cis-policyset. |
| GoogleCloudSCC.FindingV2.securityPosture.policy | String | The ID of the updated policy, for example, compute-policy-1. |
| GoogleCloudSCC.FindingV2.securityPosture.policyDriftDetails | Unknown | The details about a change in an updated policy that violates the deployed posture. |
| GoogleCloudSCC.FindingV2.securityPosture.policyDriftDetails.field | String | The name of the updated field, for example constraint.implementation.policy_rules\\\[0\\\].enforce |
| GoogleCloudSCC.FindingV2.securityPosture.policyDriftDetails.expectedValue | String | The value of this field that was configured in a posture, for example, true or allowed_values=\{"projects/29831892"\}. |
| GoogleCloudSCC.FindingV2.securityPosture.policyDriftDetails.detectedValue | String | The detected value that violates the deployed posture, for example, false or allowed_values=\{"projects/22831892"\}. |
| GoogleCloudSCC.FindingV2.logEntries | Unknown | Log entries that are relevant to the finding. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry | Unknown | An individual entry in a log stored in Cloud Logging. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry.insertId | String | A unique identifier for the log entry. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry.logId | String | The type of the log \(part of logName. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry.resourceContainer | String | The organization, folder, or project of the monitored resource that produced this log entry. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry.timestamp | String | The time the event described by the log entry occurred. |
| GoogleCloudSCC.FindingV2.loadBalancers | Unknown | The load balancers associated with the finding. |
| GoogleCloudSCC.FindingV2.loadBalancers.name | String | The name of the load balancer associated with the finding. |
| GoogleCloudSCC.FindingV2.cloudArmor | Unknown | Fields related to Google Cloud Armor findings. |
| GoogleCloudSCC.FindingV2.cloudArmor.securityPolicy | Unknown | Information about the Google Cloud Armor security policy relevant to the finding. |
| GoogleCloudSCC.FindingV2.cloudArmor.securityPolicy.name | String | The name of the Google Cloud Armor security policy, for example, "my-security-policy". |
| GoogleCloudSCC.FindingV2.cloudArmor.securityPolicy.type | String | The type of Google Cloud Armor security policy for example, 'backend security policy', 'edge security policy', 'network edge security policy', or 'always-on DDoS protection'. |
| GoogleCloudSCC.FindingV2.cloudArmor.securityPolicy.preview | Boolean | Whether or not the associated rule or policy is in preview mode. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests | Unknown | Information about incoming requests evaluated by Google Cloud Armor security policies. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests.ratio | Number | For 'Increasing deny ratio', the ratio is the denied traffic divided by the allowed traffic. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests.shortTermAllowed | Number | Allowed RPS \(requests per second\) in the short term. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests.longTermAllowed | Number | Allowed RPS \(requests per second\) over the long term. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests.longTermDenied | Number | Denied RPS \(requests per second\) over the long term. |
| GoogleCloudSCC.FindingV2.cloudArmor.adaptiveProtection | Unknown | Information about potential Layer 7 DDoS attacks identified by Google Cloud Armor Adaptive Protection. |
| GoogleCloudSCC.FindingV2.cloudArmor.adaptiveProtection.confidence | Number | A score of 0 means that there is low confidence that the detected event is an actual attack. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack | Unknown | Information about DDoS attack volume and classification. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.volumePpsLong | String | Total PPS \(packets per second\) volume of attack. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.volumeBpsLong | String | Total BPS \(bytes per second\) volume of attack. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.classification | String | Type of attack, for example, 'SYN-flood', 'NTP-udp', or 'CHARGEN-udp'. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.volumePps | Number | Volume Pps. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.volumeBps | Number | Volume Bps. |
| GoogleCloudSCC.FindingV2.cloudArmor.threatVector | String | Distinguish between volumetric \\&amp; protocol DDoS attack and application layer attacks. |
| GoogleCloudSCC.FindingV2.cloudArmor.duration | String | Duration of attack from the start until the current moment \(updated every 5 minutes\). |
| GoogleCloudSCC.FindingV2.notebook | Unknown | Notebook associated with the finding. |
| GoogleCloudSCC.FindingV2.notebook.name | String | The name of the notebook. |
| GoogleCloudSCC.FindingV2.notebook.service | String | The source notebook service, for example, "Colab Enterprise". |
| GoogleCloudSCC.FindingV2.notebook.lastAuthor | String | The user ID of the latest author to modify the notebook. |
| GoogleCloudSCC.FindingV2.notebook.notebookUpdateTime | String | The most recent time the notebook was updated. |
| GoogleCloudSCC.FindingV2.toxicCombination | Unknown | Contains details about a group of security issues that, when combined, represent a greater risk than when the issues occur independently. |
| GoogleCloudSCC.FindingV2.toxicCombination.attackExposureScore | Number | The Attack exposure score of this toxic combination. |
| GoogleCloudSCC.FindingV2.toxicCombination.relatedFindings | Unknown | List of resource names of findings associated with this toxic combination. |
| GoogleCloudSCC.FindingV2.groupMemberships | Unknown | Contains details about groups of which this finding is a member. |
| GoogleCloudSCC.FindingV2.groupMemberships.groupType | String | Type of group. |
| GoogleCloudSCC.FindingV2.groupMemberships.groupId | String | ID of the group. |
| GoogleCloudSCC.FindingV2.disk | Unknown | Disk associated with the finding. |
| GoogleCloudSCC.FindingV2.disk.name | String | The name of the disk, for example, "<https://www.googleapis.com/compute/v1/projects/\{project-id\}/zones/\{zone-id\}/disks/\{disk-id\}>". |
| GoogleCloudSCC.FindingV2.dataAccessEvents | Unknown | Data access events associated with the finding. |
| GoogleCloudSCC.FindingV2.dataAccessEvents.eventId | String | Unique identifier for data access event. |
| GoogleCloudSCC.FindingV2.dataAccessEvents.principalEmail | String | The email address of the principal that accessed the data. |
| GoogleCloudSCC.FindingV2.dataAccessEvents.operation | String | The operation performed by the principal to access the data. |
| GoogleCloudSCC.FindingV2.dataAccessEvents.eventTime | String | Timestamp of data access event. |
| GoogleCloudSCC.FindingV2.dataFlowEvents | Unknown | Data flow events associated with the finding. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.eventId | String | Unique identifier for data flow event. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.principalEmail | String | The email address of the principal that initiated the data flow event. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.operation | String | The operation performed by the principal for the data flow event. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.violatedLocation | String | Non-compliant location of the principal or the data destination. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.eventTime | String | Timestamp of data flow event. |
| GoogleCloudSCC.FindingV2.networks | Unknown | Represents the VPC networks that the resource is attached to. |
| GoogleCloudSCC.FindingV2.networks.name | String | The name of the VPC network resource, for example, //compute.googleapis.com/projects/my-project/global/networks/my-network. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents | Unknown | Data retention deletion events associated with the finding. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.eventDetectionTime | String | Timestamp indicating when the event was detected. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.dataObjectCount | String | Number of objects that violated the policy for this resource. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.maxRetentionAllowed | String | Maximum duration of retention allowed from the DRD control. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.minRetentionAllowed | String | The minimum duration that the resource associated with this finding must be retained, as enforced by the DSPM retention control. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.eventType | String | Type of the DRD event. |
| GoogleCloudSCC.FindingV2.affectedResources | Unknown | The details about a distinct count of resources affected by the finding. |
| GoogleCloudSCC.FindingV2.affectedResources.count | String | The count of resources affected by the finding. |
| GoogleCloudSCC.FindingV2.aiModel | Unknown | The AI model associated with the finding. |
| GoogleCloudSCC.FindingV2.aiModel.name | String | The name of the AI model, for example, "gemini:1.0.0". |
| GoogleCloudSCC.FindingV2.aiModel.domain | String | The domain of the model, for example, "image-classification". |
| GoogleCloudSCC.FindingV2.aiModel.library | String | The name of the model library, for example, "transformers". |
| GoogleCloudSCC.FindingV2.aiModel.location | String | The region in which the model is used, for example, "us-central1". |
| GoogleCloudSCC.FindingV2.aiModel.publisher | String | The publisher of the model, for example, "google" or "nvidia". |
| GoogleCloudSCC.FindingV2.aiModel.deploymentPlatform | String | The platform on which the model is deployed. |
| GoogleCloudSCC.FindingV2.aiModel.displayName | String | The user defined display name of model. |
| GoogleCloudSCC.FindingV2.aiModel.usageCategory | String | The purpose of the model, for example, "Interference" or "Training". |
| GoogleCloudSCC.FindingV2.chokepoint | Unknown | Contains details about a chokepoint, which is a resource or resource group where high-risk attack paths converge. |
| GoogleCloudSCC.FindingV2.chokepoint.relatedFindings | Unknown | List of resource names of findings associated with this chokepoint. |
| GoogleCloudSCC.FindingV2.complianceDetails | Unknown | Details about the compliance implications of the finding. |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks | Unknown | Details of Frameworks associated with the finding |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.name | String | Name of the framework associated with the finding |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.displayName | String | Display name of the framework. |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.category | Unknown | Category of the framework associated with the finding. |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.type | String | Type of the framework associated with the finding, to specify whether the framework is built-in \(pre-defined and immutable\) or a custom framework defined by the customer \(equivalent to security posture\) |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.controls | Unknown | The controls associated with the framework. |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.controls.controlName | String | Name of the Control |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.controls.displayName | String | Display name of the control. |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl | Unknown | CloudControl associated with the finding |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl.cloudControlName | String | Name of the CloudControl associated with the finding. |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl.type | String | Type of cloud control. |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl.policyType | String | Policy type of the CloudControl |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl.version | Number | Version of the Cloud Control |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControlDeploymentNames | Unknown | Cloud Control Deployments associated with the finding. |
| GoogleCloudSCC.FindingV2.vertexAi | Unknown | VertexAi associated with the finding. |
| GoogleCloudSCC.FindingV2.vertexAi.datasets | Unknown | Datasets associated with the finding. |
| GoogleCloudSCC.FindingV2.vertexAi.datasets.name | String | Resource name of the dataset, e.g. |
| GoogleCloudSCC.FindingV2.vertexAi.datasets.displayName | String | The user defined display name of dataset, e.g. |
| GoogleCloudSCC.FindingV2.vertexAi.datasets.source | String | Data source, such as a BigQuery source URI, e.g. |
| GoogleCloudSCC.FindingV2.vertexAi.pipelines | Unknown | Pipelines associated with the finding. |
| GoogleCloudSCC.FindingV2.vertexAi.pipelines.name | String | Resource name of the pipeline, e.g. |
| GoogleCloudSCC.FindingV2.vertexAi.pipelines.displayName | String | The user-defined display name of pipeline, e.g. |
| GoogleCloudSCC.FindingV2.cryptoKeyName | String | The name of the crypto key associated with the finding. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies | Unknown | Artifact Guard policies associated with the finding. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.resourceId | String | The ID of the resource that has policies configured. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.failingPolicies | Unknown | A list of artifact guard policies that the resource violated. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.failingPolicies.type | String | The type of the policy evaluation. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.failingPolicies.policyId | String | The ID of the failing policy, for example, "organizations/3392779/locations/global/policies/prod-policy". |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.failingPolicies.failureReason | String | The reason for the policy failure, for example, "severity=HIGH AND max_vuln_count=2". |
| GoogleCloudSCC.FindingV2.secret | Unknown | Secret associated with the finding. |
| GoogleCloudSCC.FindingV2.secret.type | String | The type of secret, for example, GCP_API_KEY. |
| GoogleCloudSCC.FindingV2.secret.status | Unknown | The status of the secret. |
| GoogleCloudSCC.FindingV2.secret.status.lastUpdatedTime | String | Time that the secret was found. |
| GoogleCloudSCC.FindingV2.secret.status.validity | String | The validity of the secret. |
| GoogleCloudSCC.FindingV2.secret.environmentVariable | Unknown | The environment variable containing the secret. |
| GoogleCloudSCC.FindingV2.secret.environmentVariable.key | String | The environment variable name as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.secret.filePath | Unknown | The file containing the secret. |
| GoogleCloudSCC.FindingV2.secret.filePath.path | String | Path to the file. |
| GoogleCloudSCC.FindingV2.externalExposure | Unknown | Represents the external exposure of the finding. |
| GoogleCloudSCC.FindingV2.externalExposure.privateIpAddress | String | Private IP address of the exposed endpoint. |
| GoogleCloudSCC.FindingV2.externalExposure.privatePort | String | Port number associated with private IP address. |
| GoogleCloudSCC.FindingV2.externalExposure.exposedService | String | The name and version of the service, for example, "Jupyter Notebook 6.14.0". |
| GoogleCloudSCC.FindingV2.externalExposure.publicIpAddress | String | Public IP address of the exposed endpoint. |
| GoogleCloudSCC.FindingV2.externalExposure.publicPort | String | Public port number of the exposed endpoint. |
| GoogleCloudSCC.FindingV2.externalExposure.exposedEndpoint | String | The resource which is running the exposed service, for example, "//compute.googleapis.com/projects/\{project-id\}/zones/\{zone\}/instances/\{instance\}". |
| GoogleCloudSCC.FindingV2.externalExposure.loadBalancerFirewallPolicy | String | The full resource name of the load balancer firewall policy, for example, "//compute.googleapis.com/projects/\{project-id\}/global/firewallPolicies/\{policy-name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.serviceFirewallPolicy | String | The full resource name of the firewall policy of the exposed service, for example, "//compute.googleapis.com/projects/\{project-id\}/global/firewallPolicies/\{policy-name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.forwardingRule | String | The full resource name of the forwarding rule, for example, "//compute.googleapis.com/projects/\{project-id\}/global/forwardingRules/\{forwarding-rule-name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.backendService | String | The full resource name of load balancer backend service, for example, "//compute.googleapis.com/projects/\{project-id\}/global/backendServices/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.instanceGroup | String | The full resource name of the instance group, for example, "//compute.googleapis.com/projects/\{project-id\}/global/instanceGroups/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.networkEndpointGroup | String | The full resource name of the network endpoint group, for example, "//compute.googleapis.com/projects/\{project-id\}/global/networkEndpointGroups/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.hostnameUri | String | Hostname of the exposed application, for example, <https://example.com/> |
| GoogleCloudSCC.FindingV2.externalExposure.pscServiceAttachment | String | The full resource name of the PSC \(Private Service Connect\) service attachment that the load balancer network endpoint group targets, for example, "//compute.googleapis.com/projects/\{project-id\}/regions/\{region\}/serviceAttachments/\{name\}" |
| GoogleCloudSCC.FindingV2.externalExposure.pscNetworkAttachment | String | The full resource name of the PSC \(Private Service Connect\) network attachment that network interface controller is attached to, for example, "//compute.googleapis.com/projects/\{project-id\}/regions/\{region\}/networkAttachments/\{name\}" |
| GoogleCloudSCC.FindingV2.externalExposure.internalBackendService | String | The full resource name of load balancer backend service in the internal project having resource exposed via PSC, for example, "//compute.googleapis.com/projects/\{project-id\}/global/backendServices/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.backendBucket | String | The full resource name of the load balancer backend bucket, for example, "//compute.googleapis.com/projects/\{project-id\}/global/backendBuckets/\{name\}" |
| GoogleCloudSCC.FindingV2.externalExposure.exposedApplication | String | The name and version of the exposed web application, for example, "Jenkins 2.184". |
| GoogleCloudSCC.FindingV2.externalExposure.networkIngressFirewallPolicy | String | The full resource name of the network ingress firewall policy, for example, "//compute.googleapis.com/projects/\{project-id\}/global/firewallPolicies/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.httpResponse | Unknown | The http response returned by the web application. |
| GoogleCloudSCC.FindingV2.externalExposure.httpResponse.statusCode | String | The http response code returned by the web application, for example, 200. |
| GoogleCloudSCC.FindingV2.externalExposure.httpResponse.path | String | The http path for which response code was returned by web application, for example, <https://example.com/example>. |
| GoogleCloudSCC.FindingV2.externalExposure.networkPathInsightsGenerationTime | String | The timestamp when the network reachability trace was generated or verified. |
| GoogleCloudSCC.FindingV2.policyViolationSummary | Unknown | Summary of the policy violations associated with the finding. |
| GoogleCloudSCC.FindingV2.policyViolationSummary.policyViolationsCount | String | Count of child resources in violation of the policy. |
| GoogleCloudSCC.FindingV2.policyViolationSummary.conformantResourcesCount | String | Total number of child resources that conform to the policy. |
| GoogleCloudSCC.FindingV2.policyViolationSummary.evaluationErrorsCount | String | Number of child resources for which errors during evaluation occurred. |
| GoogleCloudSCC.FindingV2.policyViolationSummary.outOfScopeResourcesCount | String | Total count of child resources which were not in scope for evaluation. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents | Unknown | Agent data access events associated with the finding. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents.eventId | String | Unique identifier for data access event. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents.principalSubject | String | The agent principal that accessed the data. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents.operation | String | The operation performed by the principal to access the data. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents.eventTime | String | Timestamp of data access event. |
| GoogleCloudSCC.FindingV2.discoveredWorkload | Unknown | The workload that this finding is associated with. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.workloadType | String | The type of workload. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.confidence | String | The confidence in detection of this workload. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.detectedRelevantPackages | Boolean | A boolean flag set to true if installed packages strongly predict the workload type. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.detectedRelevantKeywords | Boolean | A boolean flag set to true if associated keywords strongly predict the workload type. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.detectedRelevantHardware | Boolean | A boolean flag set to true if associated hardware strongly predicts the workload type. |

#### Command Example

```!google-cloud-scc-finding-mute name="organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a"```

#### Context Example

```json
{
    "GoogleCloudSCC": {
        "FindingV2": {
            "name": "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a",
            "canonicalName": "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a",
            "parent": "organizations/1094826489209/sources/5629340921983475201",
            "resourceName": "//compute.googleapis.com/projects/prod-webapp-284917/zones/us-central1-a/instances/web-server-01",
            "state": "ACTIVE",
            "category": "Malware: Cryptomining Bad IP",
            "externalUri": "https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/web-server-01?project=prod-webapp-284917",
            "sourceProperties": {
                "dst_zipcode": "94043",
                "browser": "Chrome",
                "dst_region": "California",
                "userkey": "jdoe@example.com",
                "traffic_type": "CloudApp",
                "count": "3",
                "dst_longitude": -122.0841,
                "src_region": "Maharashtra",
                "app": "Google Cloud Platform",
                "dst_latitude": 37.422,
                "object": "instances/web-server-01",
                "src_latitude": 19.076,
                "sv": "malsite",
                "os": "Linux",
                "src_geoip_src": "MaxMind",
                "dst_location": "Mountain View",
                "device": "Server",
                "srcip": "10.0.0.1"
            },
            "securityMarks": {
                "name": "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a/securityMarks",
                "marks": {
                    "priority": "P1",
                    "reviewed": "true"
                },
                "canonicalName": "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a/securityMarks"
            },
            "eventTime": "2020-02-18T07:26:42Z",
            "createTime": "2020-02-19T13:37:43.858Z",
            "severity": "CRITICAL",
            "mute": "MUTED",
            "muteInfo": {
                "staticMute": {
                    "state": "MUTED",
                    "applyTime": "2020-02-18T07:26:42Z"
                },
                "dynamicMuteRecords": [
                    {
                        "muteConfig": "organizations/1094826489209/muteConfigs/known-cryptomining-testrange",
                        "matchTime": "2020-02-18T07:26:42Z"
                    }
                ]
            },
            "findingClass": "THREAT",
            "indicator": {
                "ipAddresses": [
                    "10.0.0.1"
                ],
                "domains": [
                    "xmr-pool.badactor.example"
                ],
                "signatures": [
                    {
                        "signatureType": "SIGNATURE_TYPE_PROCESS",
                        "memoryHashSignature": {
                            "binaryFamily": "XMRig",
                            "detections": [
                                {
                                    "binary": "xmrig",
                                    "percentPagesMatched": 0.87
                                }
                            ]
                        },
                        "yaraRuleSignature": {
                            "yaraRule": "Cryptominer_XMRig_Generic"
                        }
                    }
                ],
                "uris": [
                    "http://xmr-pool.badactor.example:3333"
                ]
            },
            "vulnerability": {
                "cve": {
                    "id": "CVE-2021-44228",
                    "references": [
                        {
                            "source": "NVD",
                            "uri": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
                        }
                    ],
                    "cvssv3": {
                        "baseScore": 10.0,
                        "attackVector": "ATTACK_VECTOR_NETWORK",
                        "attackComplexity": "ATTACK_COMPLEXITY_LOW",
                        "privilegesRequired": "PRIVILEGES_REQUIRED_NONE",
                        "userInteraction": "USER_INTERACTION_NONE",
                        "scope": "SCOPE_CHANGED",
                        "confidentialityImpact": "IMPACT_HIGH",
                        "integrityImpact": "IMPACT_HIGH",
                        "availabilityImpact": "IMPACT_HIGH"
                    },
                    "upstreamFixAvailable": true,
                    "impact": "LOW",
                    "exploitationActivity": "WIDE",
                    "observedInTheWild": true,
                    "zeroDay": false,
                    "exploitReleaseDate": "2021-12-10T00:00:00Z",
                    "firstExploitationDate": "2021-12-10T00:00:00Z"
                },
                "offendingPackage": {
                    "packageName": "log4j-core",
                    "cpeUri": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                    "packageType": "MAVEN",
                    "packageVersion": "2.14.1"
                },
                "fixedPackage": {
                    "packageName": "log4j-core",
                    "cpeUri": "cpe:2.3:a:apache:log4j:2.17.1:*:*:*:*:*:*:*",
                    "packageType": "MAVEN",
                    "packageVersion": "2.17.1"
                },
                "securityBulletin": {
                    "bulletinId": "GCP-2021-021",
                    "submissionTime": "2021-12-11T00:00:00Z",
                    "suggestedUpgradeVersion": "2.17.1"
                },
                "providerRiskScore": "95",
                "reachable": true,
                "cwes": [
                    {
                        "id": "CWE-502",
                        "references": [
                            {
                                "source": "MITRE",
                                "uri": "https://dummyuser1@dummy.com/data/definitions/502.html"
                            }
                        ]
                    }
                ]
            },
            "muteUpdateTime": "2020-02-18T07:26:42Z",
            "externalSystems": {
                "jira": {
                    "name": "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a/externalSystems/jira",
                    "assignees": [
                        "secops@example.com"
                    ],
                    "externalUid": "SEC-4821",
                    "status": "In Progress",
                    "externalSystemUpdateTime": "2020-02-18T07:26:42Z",
                    "caseUri": "https://example.atlassian.net/browse/SEC-4821",
                    "casePriority": "High",
                    "caseSla": "2020-02-20T07:26:42Z",
                    "caseCreateTime": "2020-02-18T07:26:42Z",
                    "caseCloseTime": "2020-02-19T07:26:42Z",
                    "ticketInfo": {
                        "id": "SEC-4821",
                        "assignee": "secops@example.com",
                        "description": "Cryptomining activity detected on web-server-01",
                        "uri": "https://example.atlassian.net/browse/SEC-4821",
                        "status": "In Progress",
                        "updateTime": "2020-02-18T07:26:42Z"
                    }
                }
            },
            "mitreAttack": {
                "primaryTactic": "IMPACT",
                "primaryTechniques": [
                    "RESOURCE_HIJACKING"
                ],
                "additionalTactics": [
                    "COMMAND_AND_CONTROL"
                ],
                "additionalTechniques": [
                    "INGRESS_TOOL_TRANSFER"
                ],
                "version": "12"
            },
            "access": {
                "principalEmail": "jdoe@example.com",
                "callerIp": "10.0.0.1",
                "callerIpGeo": {
                    "regionCode": "IN"
                },
                "userAgentFamily": "curl",
                "userAgent": "curl/7.68.0",
                "serviceName": "compute.googleapis.com",
                "methodName": "v1.compute.instances.get",
                "principalSubject": "user:jdoe@example.com",
                "serviceAccountKeyName": "//iam.googleapis.com/projects/prod-webapp-284917/serviceAccounts/compute@prod-webapp-284917.iam.gserviceaccount.com/keys/a1b2c3d4",
                "serviceAccountDelegationInfo": [
                    {
                        "principalEmail": "compute@prod-webapp-284917.iam.gserviceaccount.com",
                        "principalSubject": "serviceAccount:compute@prod-webapp-284917.iam.gserviceaccount.com"
                    }
                ],
                "userName": "jdoe"
            },
            "connections": [
                {
                    "destinationIp": "10.0.0.1",
                    "destinationPort": 3333,
                    "sourceIp": "10.128.0.12",
                    "sourcePort": 51244,
                    "protocol": "TCP"
                }
            ],
            "muteInitiator": "secops@example.com",
            "processes": [
                {
                    "name": "xmrig",
                    "binary": {
                        "path": "/tmp/.cache/xmrig",
                        "size": "4194304",
                        "sha256": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                        "hashedSize": "4194304",
                        "partiallyHashed": false,
                        "contents": "ELF binary",
                        "diskPath": {
                            "partitionUuid": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                            "relativePath": "/tmp/.cache/xmrig"
                        },
                        "operations": [
                            {
                                "type": "EXECUTE"
                            }
                        ],
                        "fileLoadState": "LOADED_BY_PROCESS"
                    },
                    "libraries": [
                        {
                            "path": "/lib/x86_64-linux-gnu/libc.so.6",
                            "size": "2029224",
                            "sha256": "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe",
                            "hashedSize": "2029224",
                            "partiallyHashed": false,
                            "contents": "shared object",
                            "diskPath": {
                                "partitionUuid": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                                "relativePath": "/lib/x86_64-linux-gnu/libc.so.6"
                            },
                            "operations": [
                                {
                                    "type": "OPEN"
                                }
                            ],
                            "fileLoadState": "LOADED_BY_PROCESS"
                        }
                    ],
                    "script": {
                        "path": "/tmp/.cache/install.sh",
                        "size": "2048",
                        "sha256": "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface",
                        "hashedSize": "2048",
                        "partiallyHashed": false,
                        "contents": "#!/bin/bash",
                        "diskPath": {
                            "partitionUuid": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                            "relativePath": "/tmp/.cache/install.sh"
                        },
                        "operations": [
                            {
                                "type": "EXECUTE"
                            }
                        ],
                        "fileLoadState": "LOADED_BY_PROCESS"
                    },
                    "args": [
                        "./xmrig",
                        "-o",
                        "xmr-pool.badactor.example:3333"
                    ],
                    "argumentsTruncated": false,
                    "envVariables": [
                        {
                            "name": "HOME",
                            "val": "/root"
                        }
                    ],
                    "envVariablesTruncated": false,
                    "pid": "34521",
                    "parentPid": "1042",
                    "userId": "0"
                }
            ],
            "contacts": {
                "security": {
                    "contacts": [
                        {
                            "email": "security-admin@example.com"
                        }
                    ]
                }
            },
            "compliances": [
                {
                    "standard": "cis",
                    "version": "1.2.0",
                    "ids": [
                        "4.1"
                    ]
                }
            ],
            "parentDisplayName": "Event Threat Detection",
            "description": "The VM web-server-01 connected to a known cryptomining command-and-control IP address.",
            "exfiltration": {
                "sources": [
                    {
                        "name": "//compute.googleapis.com/projects/prod-webapp-284917/zones/us-central1-a/instances/web-server-01",
                        "components": [
                            "disk"
                        ]
                    }
                ],
                "targets": [
                    {
                        "name": "//storage.googleapis.com/exfil-bucket-badactor",
                        "components": [
                            "bucket"
                        ]
                    }
                ],
                "totalExfiltratedBytes": "1048576"
            },
            "iamBindings": [
                {
                    "action": "ADD",
                    "role": "roles/owner",
                    "member": "user:jdoe@example.com"
                }
            ],
            "nextSteps": "Isolate the affected VM, terminate the xmrig process, and rotate the associated service account keys.",
            "moduleName": "known_cryptomining_bad_ip",
            "containers": [
                {
                    "name": "web-app",
                    "uri": "gcr.io/prod-webapp-284917/web-app@sha256:baddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecaf",
                    "imageId": "sha256:baddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecaf",
                    "labels": [
                        {
                            "name": "app",
                            "value": "web"
                        }
                    ],
                    "createTime": "2020-02-18T07:26:42Z"
                }
            ],
            "kubernetes": {
                "pods": [
                    {
                        "ns": "default",
                        "name": "web-app-7d9f8c6b5-x2k4p",
                        "labels": [
                            {
                                "name": "app",
                                "value": "web"
                            }
                        ],
                        "containers": [
                            {
                                "name": "web-app",
                                "uri": "gcr.io/prod-webapp-284917/web-app@sha256:baddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecaf",
                                "imageId": "sha256:baddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecaf",
                                "labels": [
                                    {
                                        "name": "app",
                                        "value": "web"
                                    }
                                ],
                                "createTime": "2020-02-18T07:26:42Z"
                            }
                        ]
                    }
                ],
                "nodes": [
                    {
                        "name": "gke-prod-cluster-default-pool-a1b2c3d4-x9k2"
                    }
                ],
                "nodePools": [
                    {
                        "name": "default-pool",
                        "nodes": [
                            {
                                "name": "gke-prod-cluster-default-pool-a1b2c3d4-x9k2"
                            }
                        ]
                    }
                ],
                "roles": [
                    {
                        "kind": "ROLE",
                        "ns": "default",
                        "name": "pod-reader"
                    }
                ],
                "bindings": [
                    {
                        "ns": "default",
                        "name": "read-pods",
                        "role": {
                            "kind": "ROLE",
                            "ns": "default",
                            "name": "pod-reader"
                        },
                        "subjects": [
                            {
                                "kind": "USER",
                                "ns": "default",
                                "name": "jdoe@example.com"
                            }
                        ]
                    }
                ],
                "accessReviews": [
                    {
                        "group": "apps",
                        "ns": "default",
                        "name": "deployments",
                        "resource": "deployments",
                        "subresource": "",
                        "verb": "create",
                        "version": "v1"
                    }
                ],
                "objects": [
                    {
                        "group": "apps",
                        "kind": "Deployment",
                        "ns": "default",
                        "name": "web-app",
                        "containers": [
                            {
                                "name": "web-app",
                                "uri": "gcr.io/prod-webapp-284917/web-app@sha256:baddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecaf",
                                "imageId": "sha256:baddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecaf",
                                "labels": [
                                    {
                                        "name": "app",
                                        "value": "web"
                                    }
                                ],
                                "createTime": "2020-02-18T07:26:42Z"
                            }
                        ]
                    }
                ]
            },
            "database": {
                "name": "//cloudsql.googleapis.com/projects/prod-webapp-284917/instances/main-db",
                "displayName": "main-db",
                "userName": "app_user",
                "query": "SELECT * FROM users WHERE role = 'admin'",
                "grantees": [
                    "app_user"
                ],
                "version": "POSTGRES_14"
            },
            "attackExposure": {
                "score": 8.5,
                "latestCalculationTime": "2020-02-18T07:26:42Z",
                "attackExposureResult": "organizations/1094826489209/simulations/latest/attackExposureResults/6d7e8f9a",
                "state": "CALCULATED",
                "exposedHighValueResourcesCount": 3,
                "exposedMediumValueResourcesCount": 5,
                "exposedLowValueResourcesCount": 12
            },
            "files": [
                {
                    "path": "/tmp/.cache/xmrig",
                    "size": "4194304",
                    "sha256": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "hashedSize": "4194304",
                    "partiallyHashed": false,
                    "contents": "ELF binary",
                    "diskPath": {
                        "partitionUuid": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                        "relativePath": "/tmp/.cache/xmrig"
                    },
                    "operations": [
                        {
                            "type": "EXECUTE"
                        }
                    ],
                    "fileLoadState": "LOADED_BY_PROCESS"
                }
            ],
            "cloudDlpInspection": {
                "inspectJob": "projects/prod-webapp-284917/locations/global/dlpJobs/i-1234567890123456789",
                "infoType": "CREDIT_CARD_NUMBER",
                "infoTypeCount": "42",
                "fullScan": true
            },
            "cloudDlpDataProfile": {
                "dataProfile": "projects/prod-webapp-284917/locations/us/tableProfiles/9876543210",
                "parentType": "ORGANIZATION",
                "infoTypes": [
                    {
                        "name": "EMAIL_ADDRESS",
                        "version": "1",
                        "sensitivityScore": {
                            "score": "SENSITIVITY_LOW"
                        }
                    }
                ]
            },
            "kernelRootkit": {
                "name": "Diamorphine",
                "unexpectedCodeModification": true,
                "unexpectedReadOnlyDataModification": false,
                "unexpectedFtraceHandler": true,
                "unexpectedKprobeHandler": false,
                "unexpectedKernelCodePages": true,
                "unexpectedSystemCallHandler": true,
                "unexpectedInterruptHandler": false,
                "unexpectedProcessesInRunqueue": false
            },
            "orgPolicies": [
                {
                    "name": "organizations/1094826489209/policies/compute.requireShieldedVm"
                }
            ],
            "job": {
                "name": "projects/prod-webapp-284917/jobs/etl-nightly-run",
                "state": "PENDING",
                "errorCode": 0,
                "location": "us-central1"
            },
            "application": {
                "baseUri": "https://web-server-01.example.com",
                "fullUri": "https://web-server-01.example.com/api/v1/login"
            },
            "ipRules": {
                "direction": "INGRESS",
                "sourceIpRanges": [
                    "0.0.0.0/0"
                ],
                "destinationIpRanges": [
                    "10.0.0.1/20"
                ],
                "exposedServices": [
                    "ssh"
                ],
                "allowed": {
                    "ipRules": [
                        {
                            "protocol": "tcp",
                            "portRanges": [
                                {
                                    "min": "22",
                                    "max": "22"
                                }
                            ]
                        }
                    ]
                },
                "denied": {
                    "ipRules": [
                        {
                            "protocol": "tcp",
                            "portRanges": [
                                {
                                    "min": "3333",
                                    "max": "3333"
                                }
                            ]
                        }
                    ]
                }
            },
            "backupDisasterRecovery": {
                "backupTemplate": "gold-daily",
                "policies": [
                    "daily-30d-retention"
                ],
                "host": "web-server-01",
                "applications": [
                    "web-app"
                ],
                "storagePool": "primary-pool",
                "policyOptions": [
                    "compression"
                ],
                "profile": "production",
                "appliance": "bdr-appliance-01",
                "backupType": "Incremental",
                "backupCreateTime": "2020-02-18T07:26:42Z"
            },
            "securityPosture": {
                "name": "organizations/1094826489209/locations/global/postures/production-posture",
                "revisionId": "a1b2c3d4",
                "postureDeploymentResource": "organizations/1094826489209",
                "postureDeployment": "organizations/1094826489209/locations/global/postureDeployments/prod-deployment",
                "changedPolicy": "compute.requireShieldedVm",
                "policySet": "cis-gcp-1.2",
                "policy": "compute.requireShieldedVm",
                "policyDriftDetails": [
                    {
                        "field": "enableSecureBoot",
                        "expectedValue": "true",
                        "detectedValue": "false"
                    }
                ]
            },
            "logEntries": [
                {
                    "cloudLoggingEntry": {
                        "insertId": "1a2b3c4d5e6f",
                        "logId": "cloudaudit.googleapis.com%2Fdata_access",
                        "resourceContainer": "projects/prod-webapp-284917",
                        "timestamp": "2020-02-18T07:26:42Z"
                    }
                }
            ],
            "loadBalancers": [
                {
                    "name": "web-lb-frontend"
                }
            ],
            "cloudArmor": {
                "securityPolicy": {
                    "name": "prod-waf-policy",
                    "type": "CLOUD_ARMOR",
                    "preview": false
                },
                "requests": {
                    "ratio": 0.35,
                    "shortTermAllowed": 1200,
                    "longTermAllowed": 45000,
                    "longTermDenied": 3200
                },
                "adaptiveProtection": {
                    "confidence": 0.92
                },
                "attack": {
                    "volumePpsLong": "150000",
                    "volumeBpsLong": "120000000",
                    "classification": "HTTP_FLOOD",
                    "volumePps": 180000,
                    "volumeBps": 145000000
                },
                "threatVector": "HTTP_FLOOD",
                "duration": "300s"
            },
            "notebook": {
                "name": "projects/prod-webapp-284917/locations/us-central1/instances/analysis-notebook",
                "service": "Vertex AI Workbench",
                "lastAuthor": "data-scientist@example.com",
                "notebookUpdateTime": "2020-02-18T07:26:42Z"
            },
            "toxicCombination": {
                "attackExposureScore": 9.1,
                "relatedFindings": [
                    "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/aabbccddeeff00112233445566778899"
                ]
            },
            "groupMemberships": [
                {
                    "groupType": "GROUP_TYPE_TOXIC_COMBINATION",
                    "groupId": "toxic-combo-9a8b7c6d"
                }
            ],
            "disk": {
                "name": "//compute.googleapis.com/projects/prod-webapp-284917/zones/us-central1-a/disks/web-server-01"
            },
            "dataAccessEvents": [
                {
                    "eventId": "evt-a1b2c3d4",
                    "principalEmail": "jdoe@example.com",
                    "operation": "READ",
                    "eventTime": "2020-02-18T07:26:42Z"
                }
            ],
            "dataFlowEvents": [
                {
                    "eventId": "evt-e5f6a7b8",
                    "principalEmail": "jdoe@example.com",
                    "operation": "READ",
                    "violatedLocation": "asia-south1",
                    "eventTime": "2020-02-18T07:26:42Z"
                }
            ],
            "networks": [
                {
                    "name": "//compute.googleapis.com/projects/prod-webapp-284917/global/networks/default"
                }
            ],
            "dataRetentionDeletionEvents": [
                {
                    "eventDetectionTime": "2020-02-18T07:26:42Z",
                    "dataObjectCount": "15000",
                    "maxRetentionAllowed": "7776000s",
                    "minRetentionAllowed": "2592000s",
                    "eventType": "EVENT_TYPE_MAX_TTL_EXCEEDED"
                }
            ],
            "affectedResources": {
                "count": "3"
            },
            "aiModel": {
                "name": "projects/prod-webapp-284917/locations/us-central1/models/fraud-detector",
                "domain": "Fraud Detection",
                "library": "TensorFlow",
                "location": "us-central1",
                "publisher": "internal",
                "deploymentPlatform": "VERTEX_AI",
                "displayName": "Fraud Detector v3",
                "usageCategory": "Production"
            },
            "chokepoint": {
                "relatedFindings": [
                    "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/aabbccddeeff00112233445566778899"
                ]
            },
            "complianceDetails": {
                "frameworks": [
                    {
                        "name": "cis-gcp-foundation-1.2",
                        "displayName": "CIS Google Cloud Platform Foundation Benchmark v1.2.0",
                        "category": [
                            "SECURITY_BENCHMARKS"
                        ],
                        "type": "FRAMEWORK_TYPE_BUILT_IN",
                        "controls": [
                            {
                                "controlName": "4.1",
                                "displayName": "Ensure That Instances Are Not Configured To Use the Default Service Account"
                            }
                        ]
                    }
                ],
                "cloudControl": {
                    "cloudControlName": "shielded-vm-enabled",
                    "type": "BUILT_IN",
                    "policyType": "ORG_POLICY",
                    "version": 1
                },
                "cloudControlDeploymentNames": [
                    "organizations/1094826489209/locations/global/cloudControlDeployments/shielded-vm-enabled"
                ]
            },
            "vertexAi": {
                "datasets": [
                    {
                        "name": "projects/prod-webapp-284917/locations/us-central1/datasets/transactions",
                        "displayName": "transactions",
                        "source": "bq://prod-webapp-284917.analytics.transactions"
                    }
                ],
                "pipelines": [
                    {
                        "name": "projects/prod-webapp-284917/locations/us-central1/pipelineJobs/training-run-2020",
                        "displayName": "training-run-2020"
                    }
                ]
            },
            "cryptoKeyName": "projects/prod-webapp-284917/locations/us-central1/keyRings/prod-ring/cryptoKeys/data-key",
            "artifactGuardPolicies": {
                "resourceId": "gcr.io/prod-webapp-284917/web-app",
                "failingPolicies": [
                    {
                        "type": "VULNERABILITY",
                        "policyId": "block-critical-cves",
                        "failureReason": "Image contains CVE-2021-44228 with CVSS score 10.0"
                    }
                ]
            },
            "secret": {
                "type": "GCP_SERVICE_ACCOUNT_KEY",
                "status": {
                    "lastUpdatedTime": "2020-02-18T07:26:42Z",
                    "validity": "SECRET_VALIDITY_UNSUPPORTED"
                },
                "environmentVariable": {
                    "key": "GOOGLE_APPLICATION_CREDENTIALS"
                },
                "filePath": {
                    "path": "/etc/secrets/sa-key.json"
                }
            },
            "externalExposure": {
                "privateIpAddress": "10.128.0.12",
                "privatePort": "8080",
                "exposedService": "http",
                "publicIpAddress": "10.0.0.1",
                "publicPort": "80",
                "exposedEndpoint": "10.0.0.1:80",
                "loadBalancerFirewallPolicy": "prod-lb-fw-policy",
                "serviceFirewallPolicy": "prod-svc-fw-policy",
                "forwardingRule": "web-lb-forwarding-rule",
                "backendService": "web-backend-service",
                "instanceGroup": "web-server-ig",
                "networkEndpointGroup": "web-neg",
                "hostnameUri": "https://web-server-01.example.com",
                "pscServiceAttachment": "projects/prod-webapp-284917/regions/us-central1/serviceAttachments/web-psc",
                "pscNetworkAttachment": "projects/prod-webapp-284917/regions/us-central1/networkAttachments/web-na",
                "internalBackendService": "internal-web-backend",
                "backendBucket": "web-static-bucket",
                "exposedApplication": "web-app",
                "networkIngressFirewallPolicy": "prod-ingress-fw-policy",
                "httpResponse": [
                    {
                        "statusCode": "200",
                        "path": "/api/v1/login"
                    }
                ],
                "networkPathInsightsGenerationTime": "2020-02-18T07:26:42Z"
            },
            "policyViolationSummary": {
                "policyViolationsCount": "7",
                "conformantResourcesCount": "42",
                "evaluationErrorsCount": "1",
                "outOfScopeResourcesCount": "3"
            },
            "agentDataAccessEvents": [
                {
                    "eventId": "evt-c9d0e1f2",
                    "principalSubject": "serviceAccount:agent@prod-webapp-284917.iam.gserviceaccount.com",
                    "operation": "READ",
                    "eventTime": "2020-02-18T07:26:42Z"
                }
            ],
            "discoveredWorkload": {
                "workloadType": "MCP_SERVER",
                "confidence": "CONFIDENCE_HIGH",
                "detectedRelevantPackages": true,
                "detectedRelevantKeywords": true,
                "detectedRelevantHardware": false
            }
        }
    }
}
```

#### Human Readable Output

>### The finding has been muted successfully
>
>|Organization ID|Name|Mute|State|Severity|Category|Event Time (In UTC)|Create Time (In UTC)|External Uri|Resource Name|
>|---|---|---|---|---|---|---|---|---|---|
>| 123 | [organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a](https://console.cloud.google.com/security/command-center/findings?organizationId=123&resourceId=organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a) | MUTED | ACTIVE | CRITICAL | Malware: Cryptomining Bad IP | February 18, 2020 at 07:26:42 AM | February 19, 2020 at 01:37:43 PM | [https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/web-server-01?project=prod-webapp-284917](https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/web-server-01?project=prod-webapp-284917) | //compute.googleapis.com/projects/prod-webapp-284917/zones/us-central1-a/instances/web-server-01 |

### google-cloud-scc-finding-unmute

***
Unmute an organization's or source's finding using the Security Command Center v2 API.

#### Base Command

`google-cloud-scc-finding-unmute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The relative resource name of the finding.<br/>In the v2 API the name may include an optional "locations/{location}" segment. If no location is specified, the finding is assumed to be in "global".<br/><br/>Format: organizations/{organization_id}/sources/{source_id}/findings/{findingId} or organizations/{organization_id}/sources/{source_id}/locations/{location_id}/findings/{findingId}<br/><br/>Example: organizations/595779152576/sources/14801394649435054450/locations/global/findings/bc5a86da657611ebb979005056a5924e.<br/><br/>Note: Users can retrieve the list of the finding names by executing the "google-cloud-scc-v2-finding-list" command. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudSCC.FindingV2.name | String | 'The relative resource name of this finding. Format: organizations/\{organization\}/sources/\{source\}/locations/\{location\}/findings/\{finding\}.' |
| GoogleCloudSCC.FindingV2.canonicalName | String | The canonical name of the finding, always suffixed with the region-agnostic \(global\) resource path. |
| GoogleCloudSCC.FindingV2.parent | String | The relative resource name of the source the finding belongs to. |
| GoogleCloudSCC.FindingV2.resourceName | String | For findings on Google Cloud resources, the full resource name of the Google Cloud resource this finding is for. |
| GoogleCloudSCC.FindingV2.state | String | The state of the finding \(ACTIVE or INACTIVE\). |
| GoogleCloudSCC.FindingV2.category | String | The additional taxonomy group within findings from a given source. |
| GoogleCloudSCC.FindingV2.externalUri | String | The URI that, if available, points to a web page outside of Security Command Center where additional information about the finding can be found. |
| GoogleCloudSCC.FindingV2.sourceProperties | Unknown | Source specific properties. These properties are managed by the source that writes the finding. Properties are varying from finding to finding. |
| GoogleCloudSCC.FindingV2.securityMarks | Unknown | Output only. |
| GoogleCloudSCC.FindingV2.securityMarks.name | String | The relative resource name of the SecurityMarks. |
| GoogleCloudSCC.FindingV2.securityMarks.marks | Unknown | Mutable user specified security marks belonging to the parent resource. |
| GoogleCloudSCC.FindingV2.securityMarks.canonicalName | String | The canonical name of the marks. |
| GoogleCloudSCC.FindingV2.eventTime | String | The time at which the event took place, or when an update to the finding occurred. |
| GoogleCloudSCC.FindingV2.createTime | String | The time at which the finding was created in Security Command Center. |
| GoogleCloudSCC.FindingV2.severity | String | The severity of the finding \(CRITICAL, HIGH, MEDIUM, LOW\). |
| GoogleCloudSCC.FindingV2.mute | String | Indicates the mute state of the finding \(MUTED, UNMUTED, UNDEFINED\). |
| GoogleCloudSCC.FindingV2.muteInfo | Unknown | Additional details about the mute state of the finding, including static and dynamic mute records. |
| GoogleCloudSCC.FindingV2.muteInfo.staticMute | Unknown | If set, the static mute applied to this finding. |
| GoogleCloudSCC.FindingV2.muteInfo.staticMute.state | String | The static mute state. |
| GoogleCloudSCC.FindingV2.muteInfo.staticMute.applyTime | String | When the static mute was applied. |
| GoogleCloudSCC.FindingV2.muteInfo.dynamicMuteRecords | Unknown | The list of dynamic mute rules that currently match the finding. |
| GoogleCloudSCC.FindingV2.muteInfo.dynamicMuteRecords.muteConfig | String | The relative resource name of the mute rule, represented by a mute config, that created this record, for example organizations/123/muteConfigs/mymuteconfig or organizations/123/locations/global/muteConfigs/mymuteconfig. |
| GoogleCloudSCC.FindingV2.muteInfo.dynamicMuteRecords.matchTime | String | When the dynamic mute rule first matched the finding. |
| GoogleCloudSCC.FindingV2.findingClass | String | The class of the finding \(THREAT, VULNERABILITY, MISCONFIGURATION, OBSERVATION, SCC_ERROR, POSTURE_VIOLATION, TOXIC_COMBINATION\). |
| GoogleCloudSCC.FindingV2.indicator | Unknown | Represents what's commonly known as an indicator of compromise \(IoC\) in computer forensics. |
| GoogleCloudSCC.FindingV2.indicator.ipAddresses | Unknown | The list of IP addresses that are associated with the finding. |
| GoogleCloudSCC.FindingV2.indicator.domains | Unknown | List of domains associated to the Finding. |
| GoogleCloudSCC.FindingV2.indicator.signatures | Unknown | The list of matched signatures indicating that the given process is present in the environment. |
| GoogleCloudSCC.FindingV2.indicator.signatures.signatureType | String | Describes the type of resource associated with the signature. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature | Unknown | Signature indicating that a binary family was matched. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature.binaryFamily | String | The binary family. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature.detections | Unknown | The list of memory hash detections contributing to the binary family match. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature.detections.binary | String | The name of the binary associated with the memory hash signature detection. |
| GoogleCloudSCC.FindingV2.indicator.signatures.memoryHashSignature.detections.percentPagesMatched | Number | The percentage of memory page hashes in the signature that were matched. |
| GoogleCloudSCC.FindingV2.indicator.signatures.yaraRuleSignature | Unknown | Signature indicating that a YARA rule was matched. |
| GoogleCloudSCC.FindingV2.indicator.signatures.yaraRuleSignature.yaraRule | String | The name of the YARA rule. |
| GoogleCloudSCC.FindingV2.indicator.uris | Unknown | The list of URIs associated to the Findings. |
| GoogleCloudSCC.FindingV2.vulnerability | Unknown | Represents vulnerability-specific fields like CVE and CVSS scores. |
| GoogleCloudSCC.FindingV2.vulnerability.cve | Unknown | CVE stands for Common Vulnerabilities and Exposures \(&lt;<https://cve.mitre.org/about/&gt;\>) |
| GoogleCloudSCC.FindingV2.vulnerability.cve.id | String | The unique identifier for the vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.references | Unknown | Additional information about the CVE. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.references.source | String | Source of the reference e.g. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.references.uri | String | Uri for the mentioned source e.g. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3 | Unknown | Describe Common Vulnerability Scoring System specified at &lt;<https://www.first.org/cvss/v3.1/specification-document>&gt; |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.baseScore | Number | The base score is a function of the base metric scores. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.attackVector | String | Base Metrics Represents the intrinsic characteristics of a vulnerability that are constant over time and across user environments. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.attackComplexity | String | This metric describes the conditions beyond the attacker's control that must exist in order to exploit the vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.privilegesRequired | String | This metric describes the level of privileges an attacker must possess before successfully exploiting the vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.userInteraction | String | This metric captures the requirement for a human user, other than the attacker, to participate in the successful compromise of the vulnerable component. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.scope | String | The Scope metric captures whether a vulnerability in one vulnerable component impacts resources in components beyond its security scope. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.confidentialityImpact | String | This metric measures the impact to the confidentiality of the information resources managed by a software component due to a successfully exploited vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.integrityImpact | String | This metric measures the impact to integrity of a successfully exploited vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.cvssv3.availabilityImpact | String | This metric measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.upstreamFixAvailable | Boolean | Whether upstream fix is available for the CVE. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.impact | String | The potential impact of the vulnerability if it was to be exploited. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.exploitationActivity | String | The exploitation activity of the vulnerability in the wild. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.observedInTheWild | Boolean | Whether or not the vulnerability has been observed in the wild. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.zeroDay | Boolean | Whether or not the vulnerability was zero day when the finding was published. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.exploitReleaseDate | String | Date the first publicly available exploit or PoC was released. |
| GoogleCloudSCC.FindingV2.vulnerability.cve.firstExploitationDate | String | Date of the earliest known exploitation. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage | Unknown | The offending package is relevant to the finding. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage.packageName | String | The name of the package where the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage.cpeUri | String | The CPE URI where the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage.packageType | String | Type of package, for example, os, maven, or go. |
| GoogleCloudSCC.FindingV2.vulnerability.offendingPackage.packageVersion | String | The version of the package. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage | Unknown | The fixed package is relevant to the finding. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage.packageName | String | The name of the package where the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage.cpeUri | String | The CPE URI where the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage.packageType | String | Type of package, for example, os, maven, or go. |
| GoogleCloudSCC.FindingV2.vulnerability.fixedPackage.packageVersion | String | The version of the package. |
| GoogleCloudSCC.FindingV2.vulnerability.securityBulletin | Unknown | The security bulletin is relevant to this finding. |
| GoogleCloudSCC.FindingV2.vulnerability.securityBulletin.bulletinId | String | ID of the bulletin corresponding to the vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.securityBulletin.submissionTime | String | Submission time of this Security Bulletin. |
| GoogleCloudSCC.FindingV2.vulnerability.securityBulletin.suggestedUpgradeVersion | String | This represents a version that the cluster receiving this notification should be upgraded to, based on its current version. |
| GoogleCloudSCC.FindingV2.vulnerability.providerRiskScore | String | Provider provided risk_score based on multiple factors. |
| GoogleCloudSCC.FindingV2.vulnerability.reachable | Boolean | Represents whether the vulnerability is reachable \(detected via static analysis\) |
| GoogleCloudSCC.FindingV2.vulnerability.cwes | Unknown | Represents one or more Common Weakness Enumeration \(CWE\) information on this vulnerability. |
| GoogleCloudSCC.FindingV2.vulnerability.cwes.id | String | The CWE identifier, e.g. |
| GoogleCloudSCC.FindingV2.vulnerability.cwes.references | Unknown | Any reference to the details on the CWE, for example, &lt;<https://dummyuser1@dummy.com/data/definitions/94.html>&gt; |
| GoogleCloudSCC.FindingV2.vulnerability.cwes.references.source | String | Source of the reference e.g. |
| GoogleCloudSCC.FindingV2.vulnerability.cwes.references.uri | String | Uri for the mentioned source e.g. |
| GoogleCloudSCC.FindingV2.muteUpdateTime | String | The time at which the finding was muted or unmuted. |
| GoogleCloudSCC.FindingV2.externalSystems | Unknown | Third party SIEM/SOAR fields within Security Command Center, contains external system information and external system finding fields. |
| GoogleCloudSCC.FindingV2.mitreAttack | Unknown | MITRE ATT&amp;CK tactics and techniques related to this finding. |
| GoogleCloudSCC.FindingV2.mitreAttack.primaryTactic | String | The MITRE ATT\\&amp;CK tactic most closely represented by this finding, if any. |
| GoogleCloudSCC.FindingV2.mitreAttack.primaryTechniques | Unknown | The MITRE ATT\\&amp;CK technique most closely represented by this finding, if any. |
| GoogleCloudSCC.FindingV2.mitreAttack.additionalTactics | Unknown | Additional MITRE ATT\\&amp;CK tactics related to this finding, if any. |
| GoogleCloudSCC.FindingV2.mitreAttack.additionalTechniques | Unknown | Additional MITRE ATT\\&amp;CK techniques related to this finding, if any, along with any of their respective parent techniques. |
| GoogleCloudSCC.FindingV2.mitreAttack.version | String | The MITRE ATT\\&amp;CK version referenced by the above fields. |
| GoogleCloudSCC.FindingV2.access | Unknown | Access details associated with the finding, such as more information on the caller, which method was accessed, and from where. |
| GoogleCloudSCC.FindingV2.access.principalEmail | String | Associated email, such as "<foo@google.com>". |
| GoogleCloudSCC.FindingV2.access.callerIp | String | Caller's IP address, such as "1.1.1.1". |
| GoogleCloudSCC.FindingV2.access.callerIpGeo | Unknown | The caller IP's geolocation, which identifies where the call came from. |
| GoogleCloudSCC.FindingV2.access.callerIpGeo.regionCode | String | A CLDR. |
| GoogleCloudSCC.FindingV2.access.userAgentFamily | String | Type of user agent associated with the finding. |
| GoogleCloudSCC.FindingV2.access.userAgent | String | The caller's user agent string associated with the finding. |
| GoogleCloudSCC.FindingV2.access.serviceName | String | This is the API service that the service account made a call to, e.g. |
| GoogleCloudSCC.FindingV2.access.methodName | String | The method that the service account called, e.g. |
| GoogleCloudSCC.FindingV2.access.principalSubject | String | A string that represents the principalSubject that is associated with the identity. |
| GoogleCloudSCC.FindingV2.access.serviceAccountKeyName | String | The name of the service account key that was used to create or exchange credentials when authenticating the service account that made the request. |
| GoogleCloudSCC.FindingV2.access.serviceAccountDelegationInfo | Unknown | The identity delegation history of an authenticated service account that made the request. |
| GoogleCloudSCC.FindingV2.access.serviceAccountDelegationInfo.principalEmail | String | The email address of a Google account. |
| GoogleCloudSCC.FindingV2.access.serviceAccountDelegationInfo.principalSubject | String | A string representing the principalSubject associated with the identity. |
| GoogleCloudSCC.FindingV2.access.userName | String | A string that represents a username. |
| GoogleCloudSCC.FindingV2.connections | Unknown | Contains information about the IP connection associated with the finding. |
| GoogleCloudSCC.FindingV2.connections.destinationIp | String | Destination IP address. |
| GoogleCloudSCC.FindingV2.connections.destinationPort | Number | Destination port. |
| GoogleCloudSCC.FindingV2.connections.sourceIp | String | Source IP address. |
| GoogleCloudSCC.FindingV2.connections.sourcePort | Number | Source port. |
| GoogleCloudSCC.FindingV2.connections.protocol | String | IANA Internet Protocol Number such as TCP\(6\) and UDP\(17\). |
| GoogleCloudSCC.FindingV2.muteInitiator | String | Records the entity that is responsible for the muting of the finding. |
| GoogleCloudSCC.FindingV2.processes | Unknown | Represents operating system processes associated with the finding. |
| GoogleCloudSCC.FindingV2.processes.name | String | The process name, as displayed in utilities like top and ps. |
| GoogleCloudSCC.FindingV2.processes.binary | Unknown | File information for the process executable. |
| GoogleCloudSCC.FindingV2.processes.binary.path | String | Absolute path of the file as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.binary.size | String | Size of the file in bytes. |
| GoogleCloudSCC.FindingV2.processes.binary.sha256 | String | SHA256 hash of the first hashedSize bytes of the file encoded as a hex string. |
| GoogleCloudSCC.FindingV2.processes.binary.hashedSize | String | The length in bytes of the file prefix that was hashed. |
| GoogleCloudSCC.FindingV2.processes.binary.partiallyHashed | Boolean | True when the hash covers only a prefix of the file. |
| GoogleCloudSCC.FindingV2.processes.binary.contents | String | Prefix of the file contents as a JSON-encoded string. |
| GoogleCloudSCC.FindingV2.processes.binary.diskPath | Unknown | Path of the file in terms of underlying disk/partition identifiers. |
| GoogleCloudSCC.FindingV2.processes.binary.diskPath.partitionUuid | String | UUID of the partition \(format &lt;<https://wiki.archlinux.org/title/persistent_block_device_naming\#by-uuid&gt;\>) |
| GoogleCloudSCC.FindingV2.processes.binary.diskPath.relativePath | String | Relative path of the file in the partition as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.binary.operations | Unknown | Operation\(s\) performed on a file. |
| GoogleCloudSCC.FindingV2.processes.binary.operations.type | String | The type of the operation |
| GoogleCloudSCC.FindingV2.processes.binary.fileLoadState | String | The load state of the file. |
| GoogleCloudSCC.FindingV2.processes.libraries | Unknown | File information for libraries loaded by the process. |
| GoogleCloudSCC.FindingV2.processes.libraries.path | String | Absolute path of the file as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.libraries.size | String | Size of the file in bytes. |
| GoogleCloudSCC.FindingV2.processes.libraries.sha256 | String | SHA256 hash of the first hashedSize bytes of the file encoded as a hex string. |
| GoogleCloudSCC.FindingV2.processes.libraries.hashedSize | String | The length in bytes of the file prefix that was hashed. |
| GoogleCloudSCC.FindingV2.processes.libraries.partiallyHashed | Boolean | True when the hash covers only a prefix of the file. |
| GoogleCloudSCC.FindingV2.processes.libraries.contents | String | Prefix of the file contents as a JSON-encoded string. |
| GoogleCloudSCC.FindingV2.processes.libraries.diskPath | Unknown | Path of the file in terms of underlying disk/partition identifiers. |
| GoogleCloudSCC.FindingV2.processes.libraries.diskPath.partitionUuid | String | UUID of the partition \(format &lt;<https://wiki.archlinux.org/title/persistent_block_device_naming\#by-uuid&gt;\>) |
| GoogleCloudSCC.FindingV2.processes.libraries.diskPath.relativePath | String | Relative path of the file in the partition as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.libraries.operations | Unknown | Operation\(s\) performed on a file. |
| GoogleCloudSCC.FindingV2.processes.libraries.operations.type | String | The type of the operation |
| GoogleCloudSCC.FindingV2.processes.libraries.fileLoadState | String | The load state of the file. |
| GoogleCloudSCC.FindingV2.processes.script | Unknown | When the process represents the invocation of a script, binary provides information about the interpreter, while script provides information about the script file provided to the interpreter. |
| GoogleCloudSCC.FindingV2.processes.script.path | String | Absolute path of the file as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.script.size | String | Size of the file in bytes. |
| GoogleCloudSCC.FindingV2.processes.script.sha256 | String | SHA256 hash of the first hashedSize bytes of the file encoded as a hex string. |
| GoogleCloudSCC.FindingV2.processes.script.hashedSize | String | The length in bytes of the file prefix that was hashed. |
| GoogleCloudSCC.FindingV2.processes.script.partiallyHashed | Boolean | True when the hash covers only a prefix of the file. |
| GoogleCloudSCC.FindingV2.processes.script.contents | String | Prefix of the file contents as a JSON-encoded string. |
| GoogleCloudSCC.FindingV2.processes.script.diskPath | Unknown | Path of the file in terms of underlying disk/partition identifiers. |
| GoogleCloudSCC.FindingV2.processes.script.diskPath.partitionUuid | String | UUID of the partition \(format &lt;<https://wiki.archlinux.org/title/persistent_block_device_naming\#by-uuid&gt;\>) |
| GoogleCloudSCC.FindingV2.processes.script.diskPath.relativePath | String | Relative path of the file in the partition as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.script.operations | Unknown | Operation\(s\) performed on a file. |
| GoogleCloudSCC.FindingV2.processes.script.operations.type | String | The type of the operation |
| GoogleCloudSCC.FindingV2.processes.script.fileLoadState | String | The load state of the file. |
| GoogleCloudSCC.FindingV2.processes.args | Unknown | Process arguments as JSON encoded strings. |
| GoogleCloudSCC.FindingV2.processes.argumentsTruncated | Boolean | True if args is incomplete. |
| GoogleCloudSCC.FindingV2.processes.envVariables | Unknown | Process environment variables. |
| GoogleCloudSCC.FindingV2.processes.envVariables.name | String | Environment variable name as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.envVariables.val | String | Environment variable value as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.processes.envVariablesTruncated | Boolean | True if envVariables is incomplete. |
| GoogleCloudSCC.FindingV2.processes.pid | String | The process ID. |
| GoogleCloudSCC.FindingV2.processes.parentPid | String | The parent process ID. |
| GoogleCloudSCC.FindingV2.processes.userId | String | The ID of the user that executed the process. |
| GoogleCloudSCC.FindingV2.contacts | Unknown | Map containing the points of contact for the given finding. |
| GoogleCloudSCC.FindingV2.compliances | Unknown | Contains compliance information for security standards associated to the finding. |
| GoogleCloudSCC.FindingV2.compliances.standard | String | Industry-wide compliance standards or benchmarks, such as CIS, PCI, and OWASP. |
| GoogleCloudSCC.FindingV2.compliances.version | String | Version of the standard or benchmark, for example, 1.1 |
| GoogleCloudSCC.FindingV2.compliances.ids | Unknown | Policies within the standard or benchmark, for example, A.12.4.1 |
| GoogleCloudSCC.FindingV2.parentDisplayName | String | The human readable display name of the finding source, such as "Event Threat Detection" or "Security Health Analytics". |
| GoogleCloudSCC.FindingV2.description | String | Contains more details about the finding. |
| GoogleCloudSCC.FindingV2.exfiltration | Unknown | Represents exfiltrations associated with the finding. |
| GoogleCloudSCC.FindingV2.exfiltration.sources | Unknown | If there are multiple sources, then the data is considered "joined" between them. |
| GoogleCloudSCC.FindingV2.exfiltration.sources.name | String | The resource's full resource name. |
| GoogleCloudSCC.FindingV2.exfiltration.sources.components | Unknown | Subcomponents of the asset that was exfiltrated, like URIs used during exfiltration, table names, databases, and filenames. |
| GoogleCloudSCC.FindingV2.exfiltration.targets | Unknown | If there are multiple targets, each target would get a complete copy of the "joined" source data. |
| GoogleCloudSCC.FindingV2.exfiltration.targets.name | String | The resource's full resource name. |
| GoogleCloudSCC.FindingV2.exfiltration.targets.components | Unknown | Subcomponents of the asset that was exfiltrated, like URIs used during exfiltration, table names, databases, and filenames. |
| GoogleCloudSCC.FindingV2.exfiltration.totalExfiltratedBytes | String | Total exfiltrated bytes processed for the entire job. |
| GoogleCloudSCC.FindingV2.iamBindings | Unknown | Represents IAM bindings associated with the finding. |
| GoogleCloudSCC.FindingV2.iamBindings.action | String | The action that was performed on a Binding. |
| GoogleCloudSCC.FindingV2.iamBindings.role | String | Role that is assigned to "members". |
| GoogleCloudSCC.FindingV2.iamBindings.member | String | A single identity requesting access for a Cloud Platform resource, for example, "<foo@google.com>". |
| GoogleCloudSCC.FindingV2.nextSteps | String | Steps to address the finding. |
| GoogleCloudSCC.FindingV2.moduleName | String | Unique identifier of the module which generated the finding. |
| GoogleCloudSCC.FindingV2.containers | Unknown | Containers associated with the finding. This field provides information for both Kubernetes and non-Kubernetes containers. |
| GoogleCloudSCC.FindingV2.containers.name | String | Name of the container. |
| GoogleCloudSCC.FindingV2.containers.uri | String | Container image URI provided when configuring a pod or container. |
| GoogleCloudSCC.FindingV2.containers.imageId | String | Optional container image ID, if provided by the container runtime. |
| GoogleCloudSCC.FindingV2.containers.labels | Unknown | Container labels, as provided by the container runtime. |
| GoogleCloudSCC.FindingV2.containers.labels.name | String | Name of the label. |
| GoogleCloudSCC.FindingV2.containers.labels.value | String | Value that corresponds to the label's name. |
| GoogleCloudSCC.FindingV2.containers.createTime | String | The time that the container was created. |
| GoogleCloudSCC.FindingV2.kubernetes | Unknown | Kubernetes resources associated with the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.pods | Unknown | Kubernetes Pods associated with the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.ns | String | Kubernetes Pod namespace. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.name | String | Kubernetes Pod name. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.labels | Unknown | Pod labels. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.labels.name | String | Name of the label. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.labels.value | String | Value that corresponds to the label's name. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers | Unknown | Pod containers associated with this finding, if any. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.name | String | Name of the container. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.uri | String | Container image URI provided when configuring a pod or container. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.imageId | String | Optional container image ID, if provided by the container runtime. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.labels | Unknown | Container labels, as provided by the container runtime. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.labels.name | String | Name of the label. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.labels.value | String | Value that corresponds to the label's name. |
| GoogleCloudSCC.FindingV2.kubernetes.pods.containers.createTime | String | The time that the container was created. |
| GoogleCloudSCC.FindingV2.kubernetes.nodes | Unknown | Provides Kubernetes node information. |
| GoogleCloudSCC.FindingV2.kubernetes.nodes.name | String | Full resource name of the Compute Engine VM running the cluster node. |
| GoogleCloudSCC.FindingV2.kubernetes.nodePools | Unknown | GKE node pools associated with the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.nodePools.name | String | Kubernetes node pool name. |
| GoogleCloudSCC.FindingV2.kubernetes.nodePools.nodes | Unknown | Nodes associated with the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.nodePools.nodes.name | String | Full resource name of the Compute Engine VM running the cluster node. |
| GoogleCloudSCC.FindingV2.kubernetes.roles | Unknown | Provides Kubernetes role information for findings that involve Roles or ClusterRoles. |
| GoogleCloudSCC.FindingV2.kubernetes.roles.kind | String | Role type. |
| GoogleCloudSCC.FindingV2.kubernetes.roles.ns | String | Role namespace. |
| GoogleCloudSCC.FindingV2.kubernetes.roles.name | String | Role name. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings | Unknown | Provides Kubernetes role binding information for findings that involve RoleBindings or ClusterRoleBindings. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.ns | String | Namespace for the binding. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.name | String | Name for the binding. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.role | Unknown | The Role or ClusterRole referenced by the binding. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.role.kind | String | Role type. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.role.ns | String | Role namespace. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.role.name | String | Role name. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.subjects | Unknown | Represents one or more subjects that are bound to the role. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.subjects.kind | String | Authentication type for the subject. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.subjects.ns | String | Namespace for the subject. |
| GoogleCloudSCC.FindingV2.kubernetes.bindings.subjects.name | String | Name for the subject. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews | Unknown | Provides information on any Kubernetes access reviews \(privilege checks\) relevant to the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.group | String | The API group of the resource. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.ns | String | Namespace of the action being requested. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.name | String | The name of the resource being requested. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.resource | String | The optional resource type requested. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.subresource | String | The optional subresource type. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.verb | String | A Kubernetes resource API verb, like get, list, watch, create, update, delete, proxy. |
| GoogleCloudSCC.FindingV2.kubernetes.accessReviews.version | String | The API version of the resource. |
| GoogleCloudSCC.FindingV2.kubernetes.objects | Unknown | Kubernetes objects related to the finding. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.group | String | Kubernetes object group, such as "policy.k8s.io/v1". |
| GoogleCloudSCC.FindingV2.kubernetes.objects.kind | String | Kubernetes object kind, such as "Namespace". |
| GoogleCloudSCC.FindingV2.kubernetes.objects.ns | String | Kubernetes object namespace. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.name | String | Kubernetes object name. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers | Unknown | Pod containers associated with this finding, if any. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.name | String | Name of the container. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.uri | String | Container image URI provided when configuring a pod or container. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.imageId | String | Optional container image ID, if provided by the container runtime. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.labels | Unknown | Container labels, as provided by the container runtime. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.labels.name | String | Name of the label. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.labels.value | String | Value that corresponds to the label's name. |
| GoogleCloudSCC.FindingV2.kubernetes.objects.containers.createTime | String | The time that the container was created. |
| GoogleCloudSCC.FindingV2.database | Unknown | Database associated with the finding. |
| GoogleCloudSCC.FindingV2.database.name | String | Some database resources may not have the full resource name populated because these resource types are not yet supported by Cloud Asset Inventory \(e.g. |
| GoogleCloudSCC.FindingV2.database.displayName | String | The human-readable name of the database that the user connected to. |
| GoogleCloudSCC.FindingV2.database.userName | String | The username used to connect to the database. |
| GoogleCloudSCC.FindingV2.database.query | String | The SQL statement that is associated with the database access. |
| GoogleCloudSCC.FindingV2.database.grantees | Unknown | The target usernames, roles, or groups of an SQL privilege grant, which is not an IAM policy change. |
| GoogleCloudSCC.FindingV2.database.version | String | The version of the database, for example, POSTGRES_14. |
| GoogleCloudSCC.FindingV2.attackExposure | Unknown | The results of an attack path simulation relevant to this finding. |
| GoogleCloudSCC.FindingV2.attackExposure.score | Number | A number between 0 \(inclusive\) and infinity that represents how important this finding is to remediate. |
| GoogleCloudSCC.FindingV2.attackExposure.latestCalculationTime | String | The most recent time the attack exposure was updated on this finding. |
| GoogleCloudSCC.FindingV2.attackExposure.attackExposureResult | String | The resource name of the attack path simulation result that contains the details regarding this attack exposure score. |
| GoogleCloudSCC.FindingV2.attackExposure.state | String | Output only. |
| GoogleCloudSCC.FindingV2.attackExposure.exposedHighValueResourcesCount | Number | The number of high value resources that are exposed as a result of this finding. |
| GoogleCloudSCC.FindingV2.attackExposure.exposedMediumValueResourcesCount | Number | The number of medium value resources that are exposed as a result of this finding. |
| GoogleCloudSCC.FindingV2.attackExposure.exposedLowValueResourcesCount | Number | The number of high value resources that are exposed as a result of this finding. |
| GoogleCloudSCC.FindingV2.files | Unknown | File associated with the finding. |
| GoogleCloudSCC.FindingV2.files.path | String | Absolute path of the file as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.files.size | String | Size of the file in bytes. |
| GoogleCloudSCC.FindingV2.files.sha256 | String | SHA256 hash of the first hashedSize bytes of the file encoded as a hex string. |
| GoogleCloudSCC.FindingV2.files.hashedSize | String | The length in bytes of the file prefix that was hashed. |
| GoogleCloudSCC.FindingV2.files.partiallyHashed | Boolean | True when the hash covers only a prefix of the file. |
| GoogleCloudSCC.FindingV2.files.contents | String | Prefix of the file contents as a JSON-encoded string. |
| GoogleCloudSCC.FindingV2.files.diskPath | Unknown | Path of the file in terms of underlying disk/partition identifiers. |
| GoogleCloudSCC.FindingV2.files.diskPath.partitionUuid | String | UUID of the partition \(format &lt;<https://wiki.archlinux.org/title/persistent_block_device_naming\#by-uuid&gt;\>) |
| GoogleCloudSCC.FindingV2.files.diskPath.relativePath | String | Relative path of the file in the partition as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.files.operations | Unknown | Operation\(s\) performed on a file. |
| GoogleCloudSCC.FindingV2.files.operations.type | String | The type of the operation |
| GoogleCloudSCC.FindingV2.files.fileLoadState | String | The load state of the file. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection | Unknown | Cloud Data Loss Prevention \(Cloud DLP\) inspection results that are associated with the finding. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection.inspectJob | String | Name of the inspection job, for example, projects/123/locations/europe/dlpJobs/i-8383929. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection.infoType | String | The type of information \(or \*infoType\* \) found, for example, EMAIL_ADDRESS or STREET_ADDRESS. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection.infoTypeCount | String | The number of times Cloud DLP found this infoType within this job and resource. |
| GoogleCloudSCC.FindingV2.cloudDlpInspection.fullScan | Boolean | Whether Cloud DLP scanned the complete resource or a sampled subset. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile | Unknown | Cloud DLP data profile that is associated with the finding. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.dataProfile | String | Name of the data profile, for example, projects/123/locations/europe/tableProfiles/8383929. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.parentType | String | The resource hierarchy level at which the data profile was generated. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes | Unknown | Type of information detected by SDP. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes.name | String | Name of the information type. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes.version | String | Optional version name for this InfoType. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes.sensitivityScore | Unknown | Optional custom sensitivity for this InfoType. |
| GoogleCloudSCC.FindingV2.cloudDlpDataProfile.infoTypes.sensitivityScore.score | String | The sensitivity score applied to the resource. |
| GoogleCloudSCC.FindingV2.kernelRootkit | Unknown | Signature of the kernel rootkit. |
| GoogleCloudSCC.FindingV2.kernelRootkit.name | String | Rootkit name, when available. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedCodeModification | Boolean | True if unexpected modifications of kernel code memory are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedReadOnlyDataModification | Boolean | True if unexpected modifications of kernel read-only data memory are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedFtraceHandler | Boolean | True if ftrace points are present with callbacks pointing to regions that are not in the expected kernel or module code range. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedKprobeHandler | Boolean | True if kprobe points are present with callbacks pointing to regions that are not in the expected kernel or module code range. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedKernelCodePages | Boolean | True if kernel code pages that are not in the expected kernel or module code regions are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedSystemCallHandler | Boolean | True if system call handlers that are are not in the expected kernel or module code regions are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedInterruptHandler | Boolean | True if interrupt handlers that are are not in the expected kernel or module code regions are present. |
| GoogleCloudSCC.FindingV2.kernelRootkit.unexpectedProcessesInRunqueue | Boolean | True if unexpected processes in the scheduler run queue are present. |
| GoogleCloudSCC.FindingV2.orgPolicies | Unknown | Contains information about the org policies associated with the finding. |
| GoogleCloudSCC.FindingV2.orgPolicies.name | String | Identifier. |
| GoogleCloudSCC.FindingV2.job | Unknown | Job associated with the finding. |
| GoogleCloudSCC.FindingV2.job.name | String | The fully-qualified name for a job. |
| GoogleCloudSCC.FindingV2.job.state | String | Output only. |
| GoogleCloudSCC.FindingV2.job.errorCode | Number | Optional. |
| GoogleCloudSCC.FindingV2.job.location | String | Optional. |
| GoogleCloudSCC.FindingV2.application | Unknown | Represents an application associated with the finding. |
| GoogleCloudSCC.FindingV2.application.baseUri | String | The base URI that identifies the network location of the application in which the vulnerability was detected. |
| GoogleCloudSCC.FindingV2.application.fullUri | String | The full URI with payload that could be used to reproduce the vulnerability. |
| GoogleCloudSCC.FindingV2.ipRules | Unknown | IP rules associated with the finding. |
| GoogleCloudSCC.FindingV2.ipRules.direction | String | The direction that the rule is applicable to, one of ingress or egress. |
| GoogleCloudSCC.FindingV2.ipRules.sourceIpRanges | Unknown | If source IP ranges are specified, the firewall rule applies only to traffic that has a source IP address in these ranges. |
| GoogleCloudSCC.FindingV2.ipRules.destinationIpRanges | Unknown | If destination IP ranges are specified, the firewall rule applies only to traffic that has a destination IP address in these ranges. |
| GoogleCloudSCC.FindingV2.ipRules.exposedServices | Unknown | Name of the network protocol service, such as FTP, that is exposed by the open port. |
| GoogleCloudSCC.FindingV2.ipRules.allowed | Unknown | Tuple with allowed rules. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules | Unknown | Optional. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules.protocol | String | The IP protocol this rule applies to. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules.portRanges | Unknown | Optional. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules.portRanges.min | String | Minimum port value. |
| GoogleCloudSCC.FindingV2.ipRules.allowed.ipRules.portRanges.max | String | Maximum port value. |
| GoogleCloudSCC.FindingV2.ipRules.denied | Unknown | Tuple with denied rules. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules | Unknown | Optional. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules.protocol | String | The IP protocol this rule applies to. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules.portRanges | Unknown | Optional. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules.portRanges.min | String | Minimum port value. |
| GoogleCloudSCC.FindingV2.ipRules.denied.ipRules.portRanges.max | String | Maximum port value. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery | Unknown | Fields related to Backup and Disaster Recovery findings. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.backupTemplate | String | The name of a Backup and DR template which comprises one or more backup policies. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.policies | Unknown | The names of Backup and DR policies that are associated with a template and that define when to run a backup, how frequently to run a backup, and how long to retain the backup image. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.host | String | The name of a Backup and DR host, which is managed by the backup and recovery appliance and known to the management console. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.applications | Unknown | The names of Backup and DR applications. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.storagePool | String | The name of the Backup and DR storage pool that the backup and recovery appliance is storing data in. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.policyOptions | Unknown | The names of Backup and DR advanced policy options of a policy applying to an application. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.profile | String | The name of the Backup and DR resource profile that specifies the storage media for backups of application and VM data. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.appliance | String | The name of the Backup and DR appliance that captures, moves, and manages the lifecycle of backup data. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.backupType | String | The backup type of the Backup and DR image. |
| GoogleCloudSCC.FindingV2.backupDisasterRecovery.backupCreateTime | String | The timestamp at which the Backup and DR backup was created. |
| GoogleCloudSCC.FindingV2.securityPosture | Unknown | The security posture associated with the finding. |
| GoogleCloudSCC.FindingV2.securityPosture.name | String | Name of the posture, for example, CIS-Posture. |
| GoogleCloudSCC.FindingV2.securityPosture.revisionId | String | The version of the posture, for example, c7cfa2a8. |
| GoogleCloudSCC.FindingV2.securityPosture.postureDeploymentResource | String | The project, folder, or organization on which the posture is deployed, for example, projects/\{project_number\}. |
| GoogleCloudSCC.FindingV2.securityPosture.postureDeployment | String | The name of the posture deployment, for example, organizations/\{org_id\}/posturedeployments/\{posture_deployment_id\}. |
| GoogleCloudSCC.FindingV2.securityPosture.changedPolicy | String | The name of the updated policy, for example, projects/\{projectId\}/policies/\{constraint_name\}. |
| GoogleCloudSCC.FindingV2.securityPosture.policySet | String | The name of the updated policy set, for example, cis-policyset. |
| GoogleCloudSCC.FindingV2.securityPosture.policy | String | The ID of the updated policy, for example, compute-policy-1. |
| GoogleCloudSCC.FindingV2.securityPosture.policyDriftDetails | Unknown | The details about a change in an updated policy that violates the deployed posture. |
| GoogleCloudSCC.FindingV2.securityPosture.policyDriftDetails.field | String | The name of the updated field, for example constraint.implementation.policy_rules\\\[0\\\].enforce |
| GoogleCloudSCC.FindingV2.securityPosture.policyDriftDetails.expectedValue | String | The value of this field that was configured in a posture, for example, true or allowed_values=\{"projects/29831892"\}. |
| GoogleCloudSCC.FindingV2.securityPosture.policyDriftDetails.detectedValue | String | The detected value that violates the deployed posture, for example, false or allowed_values=\{"projects/22831892"\}. |
| GoogleCloudSCC.FindingV2.logEntries | Unknown | Log entries that are relevant to the finding. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry | Unknown | An individual entry in a log stored in Cloud Logging. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry.insertId | String | A unique identifier for the log entry. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry.logId | String | The type of the log \(part of logName. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry.resourceContainer | String | The organization, folder, or project of the monitored resource that produced this log entry. |
| GoogleCloudSCC.FindingV2.logEntries.cloudLoggingEntry.timestamp | String | The time the event described by the log entry occurred. |
| GoogleCloudSCC.FindingV2.loadBalancers | Unknown | The load balancers associated with the finding. |
| GoogleCloudSCC.FindingV2.loadBalancers.name | String | The name of the load balancer associated with the finding. |
| GoogleCloudSCC.FindingV2.cloudArmor | Unknown | Fields related to Google Cloud Armor findings. |
| GoogleCloudSCC.FindingV2.cloudArmor.securityPolicy | Unknown | Information about the Google Cloud Armor security policy relevant to the finding. |
| GoogleCloudSCC.FindingV2.cloudArmor.securityPolicy.name | String | The name of the Google Cloud Armor security policy, for example, "my-security-policy". |
| GoogleCloudSCC.FindingV2.cloudArmor.securityPolicy.type | String | The type of Google Cloud Armor security policy for example, 'backend security policy', 'edge security policy', 'network edge security policy', or 'always-on DDoS protection'. |
| GoogleCloudSCC.FindingV2.cloudArmor.securityPolicy.preview | Boolean | Whether or not the associated rule or policy is in preview mode. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests | Unknown | Information about incoming requests evaluated by Google Cloud Armor security policies. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests.ratio | Number | For 'Increasing deny ratio', the ratio is the denied traffic divided by the allowed traffic. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests.shortTermAllowed | Number | Allowed RPS \(requests per second\) in the short term. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests.longTermAllowed | Number | Allowed RPS \(requests per second\) over the long term. |
| GoogleCloudSCC.FindingV2.cloudArmor.requests.longTermDenied | Number | Denied RPS \(requests per second\) over the long term. |
| GoogleCloudSCC.FindingV2.cloudArmor.adaptiveProtection | Unknown | Information about potential Layer 7 DDoS attacks identified by Google Cloud Armor Adaptive Protection. |
| GoogleCloudSCC.FindingV2.cloudArmor.adaptiveProtection.confidence | Number | A score of 0 means that there is low confidence that the detected event is an actual attack. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack | Unknown | Information about DDoS attack volume and classification. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.volumePpsLong | String | Total PPS \(packets per second\) volume of attack. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.volumeBpsLong | String | Total BPS \(bytes per second\) volume of attack. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.classification | String | Type of attack, for example, 'SYN-flood', 'NTP-udp', or 'CHARGEN-udp'. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.volumePps | Number | Volume Pps. |
| GoogleCloudSCC.FindingV2.cloudArmor.attack.volumeBps | Number | Volume Bps. |
| GoogleCloudSCC.FindingV2.cloudArmor.threatVector | String | Distinguish between volumetric \\&amp; protocol DDoS attack and application layer attacks. |
| GoogleCloudSCC.FindingV2.cloudArmor.duration | String | Duration of attack from the start until the current moment \(updated every 5 minutes\). |
| GoogleCloudSCC.FindingV2.notebook | Unknown | Notebook associated with the finding. |
| GoogleCloudSCC.FindingV2.notebook.name | String | The name of the notebook. |
| GoogleCloudSCC.FindingV2.notebook.service | String | The source notebook service, for example, "Colab Enterprise". |
| GoogleCloudSCC.FindingV2.notebook.lastAuthor | String | The user ID of the latest author to modify the notebook. |
| GoogleCloudSCC.FindingV2.notebook.notebookUpdateTime | String | The most recent time the notebook was updated. |
| GoogleCloudSCC.FindingV2.toxicCombination | Unknown | Contains details about a group of security issues that, when combined, represent a greater risk than when the issues occur independently. |
| GoogleCloudSCC.FindingV2.toxicCombination.attackExposureScore | Number | The Attack exposure score of this toxic combination. |
| GoogleCloudSCC.FindingV2.toxicCombination.relatedFindings | Unknown | List of resource names of findings associated with this toxic combination. |
| GoogleCloudSCC.FindingV2.groupMemberships | Unknown | Contains details about groups of which this finding is a member. |
| GoogleCloudSCC.FindingV2.groupMemberships.groupType | String | Type of group. |
| GoogleCloudSCC.FindingV2.groupMemberships.groupId | String | ID of the group. |
| GoogleCloudSCC.FindingV2.disk | Unknown | Disk associated with the finding. |
| GoogleCloudSCC.FindingV2.disk.name | String | The name of the disk, for example, "<https://www.googleapis.com/compute/v1/projects/\{project-id\}/zones/\{zone-id\}/disks/\{disk-id\}>". |
| GoogleCloudSCC.FindingV2.dataAccessEvents | Unknown | Data access events associated with the finding. |
| GoogleCloudSCC.FindingV2.dataAccessEvents.eventId | String | Unique identifier for data access event. |
| GoogleCloudSCC.FindingV2.dataAccessEvents.principalEmail | String | The email address of the principal that accessed the data. |
| GoogleCloudSCC.FindingV2.dataAccessEvents.operation | String | The operation performed by the principal to access the data. |
| GoogleCloudSCC.FindingV2.dataAccessEvents.eventTime | String | Timestamp of data access event. |
| GoogleCloudSCC.FindingV2.dataFlowEvents | Unknown | Data flow events associated with the finding. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.eventId | String | Unique identifier for data flow event. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.principalEmail | String | The email address of the principal that initiated the data flow event. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.operation | String | The operation performed by the principal for the data flow event. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.violatedLocation | String | Non-compliant location of the principal or the data destination. |
| GoogleCloudSCC.FindingV2.dataFlowEvents.eventTime | String | Timestamp of data flow event. |
| GoogleCloudSCC.FindingV2.networks | Unknown | Represents the VPC networks that the resource is attached to. |
| GoogleCloudSCC.FindingV2.networks.name | String | The name of the VPC network resource, for example, //compute.googleapis.com/projects/my-project/global/networks/my-network. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents | Unknown | Data retention deletion events associated with the finding. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.eventDetectionTime | String | Timestamp indicating when the event was detected. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.dataObjectCount | String | Number of objects that violated the policy for this resource. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.maxRetentionAllowed | String | Maximum duration of retention allowed from the DRD control. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.minRetentionAllowed | String | The minimum duration that the resource associated with this finding must be retained, as enforced by the DSPM retention control. |
| GoogleCloudSCC.FindingV2.dataRetentionDeletionEvents.eventType | String | Type of the DRD event. |
| GoogleCloudSCC.FindingV2.affectedResources | Unknown | The details about a distinct count of resources affected by the finding. |
| GoogleCloudSCC.FindingV2.affectedResources.count | String | The count of resources affected by the finding. |
| GoogleCloudSCC.FindingV2.aiModel | Unknown | The AI model associated with the finding. |
| GoogleCloudSCC.FindingV2.aiModel.name | String | The name of the AI model, for example, "gemini:1.0.0". |
| GoogleCloudSCC.FindingV2.aiModel.domain | String | The domain of the model, for example, "image-classification". |
| GoogleCloudSCC.FindingV2.aiModel.library | String | The name of the model library, for example, "transformers". |
| GoogleCloudSCC.FindingV2.aiModel.location | String | The region in which the model is used, for example, "us-central1". |
| GoogleCloudSCC.FindingV2.aiModel.publisher | String | The publisher of the model, for example, "google" or "nvidia". |
| GoogleCloudSCC.FindingV2.aiModel.deploymentPlatform | String | The platform on which the model is deployed. |
| GoogleCloudSCC.FindingV2.aiModel.displayName | String | The user defined display name of model. |
| GoogleCloudSCC.FindingV2.aiModel.usageCategory | String | The purpose of the model, for example, "Interference" or "Training". |
| GoogleCloudSCC.FindingV2.chokepoint | Unknown | Contains details about a chokepoint, which is a resource or resource group where high-risk attack paths converge. |
| GoogleCloudSCC.FindingV2.chokepoint.relatedFindings | Unknown | List of resource names of findings associated with this chokepoint. |
| GoogleCloudSCC.FindingV2.complianceDetails | Unknown | Details about the compliance implications of the finding. |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks | Unknown | Details of Frameworks associated with the finding |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.name | String | Name of the framework associated with the finding |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.displayName | String | Display name of the framework. |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.category | Unknown | Category of the framework associated with the finding. |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.type | String | Type of the framework associated with the finding, to specify whether the framework is built-in \(pre-defined and immutable\) or a custom framework defined by the customer \(equivalent to security posture\) |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.controls | Unknown | The controls associated with the framework. |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.controls.controlName | String | Name of the Control |
| GoogleCloudSCC.FindingV2.complianceDetails.frameworks.controls.displayName | String | Display name of the control. |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl | Unknown | CloudControl associated with the finding |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl.cloudControlName | String | Name of the CloudControl associated with the finding. |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl.type | String | Type of cloud control. |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl.policyType | String | Policy type of the CloudControl |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControl.version | Number | Version of the Cloud Control |
| GoogleCloudSCC.FindingV2.complianceDetails.cloudControlDeploymentNames | Unknown | Cloud Control Deployments associated with the finding. |
| GoogleCloudSCC.FindingV2.vertexAi | Unknown | VertexAi associated with the finding. |
| GoogleCloudSCC.FindingV2.vertexAi.datasets | Unknown | Datasets associated with the finding. |
| GoogleCloudSCC.FindingV2.vertexAi.datasets.name | String | Resource name of the dataset, e.g. |
| GoogleCloudSCC.FindingV2.vertexAi.datasets.displayName | String | The user defined display name of dataset, e.g. |
| GoogleCloudSCC.FindingV2.vertexAi.datasets.source | String | Data source, such as a BigQuery source URI, e.g. |
| GoogleCloudSCC.FindingV2.vertexAi.pipelines | Unknown | Pipelines associated with the finding. |
| GoogleCloudSCC.FindingV2.vertexAi.pipelines.name | String | Resource name of the pipeline, e.g. |
| GoogleCloudSCC.FindingV2.vertexAi.pipelines.displayName | String | The user-defined display name of pipeline, e.g. |
| GoogleCloudSCC.FindingV2.cryptoKeyName | String | The name of the crypto key associated with the finding. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies | Unknown | Artifact Guard policies associated with the finding. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.resourceId | String | The ID of the resource that has policies configured. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.failingPolicies | Unknown | A list of artifact guard policies that the resource violated. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.failingPolicies.type | String | The type of the policy evaluation. |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.failingPolicies.policyId | String | The ID of the failing policy, for example, "organizations/3392779/locations/global/policies/prod-policy". |
| GoogleCloudSCC.FindingV2.artifactGuardPolicies.failingPolicies.failureReason | String | The reason for the policy failure, for example, "severity=HIGH AND max_vuln_count=2". |
| GoogleCloudSCC.FindingV2.secret | Unknown | Secret associated with the finding. |
| GoogleCloudSCC.FindingV2.secret.type | String | The type of secret, for example, GCP_API_KEY. |
| GoogleCloudSCC.FindingV2.secret.status | Unknown | The status of the secret. |
| GoogleCloudSCC.FindingV2.secret.status.lastUpdatedTime | String | Time that the secret was found. |
| GoogleCloudSCC.FindingV2.secret.status.validity | String | The validity of the secret. |
| GoogleCloudSCC.FindingV2.secret.environmentVariable | Unknown | The environment variable containing the secret. |
| GoogleCloudSCC.FindingV2.secret.environmentVariable.key | String | The environment variable name as a JSON encoded string. |
| GoogleCloudSCC.FindingV2.secret.filePath | Unknown | The file containing the secret. |
| GoogleCloudSCC.FindingV2.secret.filePath.path | String | Path to the file. |
| GoogleCloudSCC.FindingV2.externalExposure | Unknown | Represents the external exposure of the finding. |
| GoogleCloudSCC.FindingV2.externalExposure.privateIpAddress | String | Private IP address of the exposed endpoint. |
| GoogleCloudSCC.FindingV2.externalExposure.privatePort | String | Port number associated with private IP address. |
| GoogleCloudSCC.FindingV2.externalExposure.exposedService | String | The name and version of the service, for example, "Jupyter Notebook 6.14.0". |
| GoogleCloudSCC.FindingV2.externalExposure.publicIpAddress | String | Public IP address of the exposed endpoint. |
| GoogleCloudSCC.FindingV2.externalExposure.publicPort | String | Public port number of the exposed endpoint. |
| GoogleCloudSCC.FindingV2.externalExposure.exposedEndpoint | String | The resource which is running the exposed service, for example, "//compute.googleapis.com/projects/\{project-id\}/zones/\{zone\}/instances/\{instance\}". |
| GoogleCloudSCC.FindingV2.externalExposure.loadBalancerFirewallPolicy | String | The full resource name of the load balancer firewall policy, for example, "//compute.googleapis.com/projects/\{project-id\}/global/firewallPolicies/\{policy-name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.serviceFirewallPolicy | String | The full resource name of the firewall policy of the exposed service, for example, "//compute.googleapis.com/projects/\{project-id\}/global/firewallPolicies/\{policy-name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.forwardingRule | String | The full resource name of the forwarding rule, for example, "//compute.googleapis.com/projects/\{project-id\}/global/forwardingRules/\{forwarding-rule-name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.backendService | String | The full resource name of load balancer backend service, for example, "//compute.googleapis.com/projects/\{project-id\}/global/backendServices/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.instanceGroup | String | The full resource name of the instance group, for example, "//compute.googleapis.com/projects/\{project-id\}/global/instanceGroups/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.networkEndpointGroup | String | The full resource name of the network endpoint group, for example, "//compute.googleapis.com/projects/\{project-id\}/global/networkEndpointGroups/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.hostnameUri | String | Hostname of the exposed application, for example, <https://example.com/> |
| GoogleCloudSCC.FindingV2.externalExposure.pscServiceAttachment | String | The full resource name of the PSC \(Private Service Connect\) service attachment that the load balancer network endpoint group targets, for example, "//compute.googleapis.com/projects/\{project-id\}/regions/\{region\}/serviceAttachments/\{name\}" |
| GoogleCloudSCC.FindingV2.externalExposure.pscNetworkAttachment | String | The full resource name of the PSC \(Private Service Connect\) network attachment that network interface controller is attached to, for example, "//compute.googleapis.com/projects/\{project-id\}/regions/\{region\}/networkAttachments/\{name\}" |
| GoogleCloudSCC.FindingV2.externalExposure.internalBackendService | String | The full resource name of load balancer backend service in the internal project having resource exposed via PSC, for example, "//compute.googleapis.com/projects/\{project-id\}/global/backendServices/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.backendBucket | String | The full resource name of the load balancer backend bucket, for example, "//compute.googleapis.com/projects/\{project-id\}/global/backendBuckets/\{name\}" |
| GoogleCloudSCC.FindingV2.externalExposure.exposedApplication | String | The name and version of the exposed web application, for example, "Jenkins 2.184". |
| GoogleCloudSCC.FindingV2.externalExposure.networkIngressFirewallPolicy | String | The full resource name of the network ingress firewall policy, for example, "//compute.googleapis.com/projects/\{project-id\}/global/firewallPolicies/\{name\}". |
| GoogleCloudSCC.FindingV2.externalExposure.httpResponse | Unknown | The http response returned by the web application. |
| GoogleCloudSCC.FindingV2.externalExposure.httpResponse.statusCode | String | The http response code returned by the web application, for example, 200. |
| GoogleCloudSCC.FindingV2.externalExposure.httpResponse.path | String | The http path for which response code was returned by web application, for example, <https://example.com/example>. |
| GoogleCloudSCC.FindingV2.externalExposure.networkPathInsightsGenerationTime | String | The timestamp when the network reachability trace was generated or verified. |
| GoogleCloudSCC.FindingV2.policyViolationSummary | Unknown | Summary of the policy violations associated with the finding. |
| GoogleCloudSCC.FindingV2.policyViolationSummary.policyViolationsCount | String | Count of child resources in violation of the policy. |
| GoogleCloudSCC.FindingV2.policyViolationSummary.conformantResourcesCount | String | Total number of child resources that conform to the policy. |
| GoogleCloudSCC.FindingV2.policyViolationSummary.evaluationErrorsCount | String | Number of child resources for which errors during evaluation occurred. |
| GoogleCloudSCC.FindingV2.policyViolationSummary.outOfScopeResourcesCount | String | Total count of child resources which were not in scope for evaluation. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents | Unknown | Agent data access events associated with the finding. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents.eventId | String | Unique identifier for data access event. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents.principalSubject | String | The agent principal that accessed the data. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents.operation | String | The operation performed by the principal to access the data. |
| GoogleCloudSCC.FindingV2.agentDataAccessEvents.eventTime | String | Timestamp of data access event. |
| GoogleCloudSCC.FindingV2.discoveredWorkload | Unknown | The workload that this finding is associated with. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.workloadType | String | The type of workload. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.confidence | String | The confidence in detection of this workload. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.detectedRelevantPackages | Boolean | A boolean flag set to true if installed packages strongly predict the workload type. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.detectedRelevantKeywords | Boolean | A boolean flag set to true if associated keywords strongly predict the workload type. |
| GoogleCloudSCC.FindingV2.discoveredWorkload.detectedRelevantHardware | Boolean | A boolean flag set to true if associated hardware strongly predicts the workload type. |

#### Command Example

```!google-cloud-scc-finding-unmute name="organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a"```

#### Context Example

```json
{
    "GoogleCloudSCC": {
        "FindingV2": {
            "name": "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a",
            "canonicalName": "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a",
            "parent": "organizations/1094826489209/sources/5629340921983475201",
            "resourceName": "//compute.googleapis.com/projects/prod-webapp-284917/zones/us-central1-a/instances/web-server-01",
            "state": "ACTIVE",
            "category": "Malware: Cryptomining Bad IP",
            "externalUri": "https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/web-server-01?project=prod-webapp-284917",
            "sourceProperties": {
                "dst_zipcode": "94043",
                "browser": "Chrome",
                "dst_region": "California",
                "userkey": "jdoe@example.com",
                "traffic_type": "CloudApp",
                "count": "3",
                "dst_longitude": -122.0841,
                "src_region": "Maharashtra",
                "app": "Google Cloud Platform",
                "dst_latitude": 37.422,
                "object": "instances/web-server-01",
                "src_latitude": 19.076,
                "sv": "malsite",
                "os": "Linux",
                "src_geoip_src": "MaxMind",
                "dst_location": "Mountain View",
                "device": "Server",
                "srcip": "10.0.0.1"
            },
            "securityMarks": {
                "name": "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a/securityMarks",
                "marks": {
                    "priority": "P1",
                    "reviewed": "true"
                },
                "canonicalName": "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a/securityMarks"
            },
            "eventTime": "2020-02-18T07:26:42Z",
            "createTime": "2020-02-19T13:37:43.858Z",
            "severity": "CRITICAL",
            "mute": "UNMUTED",
            "muteInfo": {
                "staticMute": {
                    "state": "MUTED",
                    "applyTime": "2020-02-18T07:26:42Z"
                },
                "dynamicMuteRecords": [
                    {
                        "muteConfig": "organizations/1094826489209/muteConfigs/known-cryptomining-testrange",
                        "matchTime": "2020-02-18T07:26:42Z"
                    }
                ]
            },
            "findingClass": "THREAT",
            "indicator": {
                "ipAddresses": [
                    "10.0.0.1"
                ],
                "domains": [
                    "xmr-pool.badactor.example"
                ],
                "signatures": [
                    {
                        "signatureType": "SIGNATURE_TYPE_PROCESS",
                        "memoryHashSignature": {
                            "binaryFamily": "XMRig",
                            "detections": [
                                {
                                    "binary": "xmrig",
                                    "percentPagesMatched": 0.87
                                }
                            ]
                        },
                        "yaraRuleSignature": {
                            "yaraRule": "Cryptominer_XMRig_Generic"
                        }
                    }
                ],
                "uris": [
                    "http://xmr-pool.badactor.example:3333"
                ]
            },
            "vulnerability": {
                "cve": {
                    "id": "CVE-2021-44228",
                    "references": [
                        {
                            "source": "NVD",
                            "uri": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
                        }
                    ],
                    "cvssv3": {
                        "baseScore": 10.0,
                        "attackVector": "ATTACK_VECTOR_NETWORK",
                        "attackComplexity": "ATTACK_COMPLEXITY_LOW",
                        "privilegesRequired": "PRIVILEGES_REQUIRED_NONE",
                        "userInteraction": "USER_INTERACTION_NONE",
                        "scope": "SCOPE_CHANGED",
                        "confidentialityImpact": "IMPACT_HIGH",
                        "integrityImpact": "IMPACT_HIGH",
                        "availabilityImpact": "IMPACT_HIGH"
                    },
                    "upstreamFixAvailable": true,
                    "impact": "LOW",
                    "exploitationActivity": "WIDE",
                    "observedInTheWild": true,
                    "zeroDay": false,
                    "exploitReleaseDate": "2021-12-10T00:00:00Z",
                    "firstExploitationDate": "2021-12-10T00:00:00Z"
                },
                "offendingPackage": {
                    "packageName": "log4j-core",
                    "cpeUri": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                    "packageType": "MAVEN",
                    "packageVersion": "2.14.1"
                },
                "fixedPackage": {
                    "packageName": "log4j-core",
                    "cpeUri": "cpe:2.3:a:apache:log4j:2.17.1:*:*:*:*:*:*:*",
                    "packageType": "MAVEN",
                    "packageVersion": "2.17.1"
                },
                "securityBulletin": {
                    "bulletinId": "GCP-2021-021",
                    "submissionTime": "2021-12-11T00:00:00Z",
                    "suggestedUpgradeVersion": "2.17.1"
                },
                "providerRiskScore": "95",
                "reachable": true,
                "cwes": [
                    {
                        "id": "CWE-502",
                        "references": [
                            {
                                "source": "MITRE",
                                "uri": "https://dummyuser1@dummy.com/data/definitions/502.html"
                            }
                        ]
                    }
                ]
            },
            "muteUpdateTime": "2020-02-18T07:26:42Z",
            "externalSystems": {
                "jira": {
                    "name": "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a/externalSystems/jira",
                    "assignees": [
                        "secops@example.com"
                    ],
                    "externalUid": "SEC-4821",
                    "status": "In Progress",
                    "externalSystemUpdateTime": "2020-02-18T07:26:42Z",
                    "caseUri": "https://example.atlassian.net/browse/SEC-4821",
                    "casePriority": "High",
                    "caseSla": "2020-02-20T07:26:42Z",
                    "caseCreateTime": "2020-02-18T07:26:42Z",
                    "caseCloseTime": "2020-02-19T07:26:42Z",
                    "ticketInfo": {
                        "id": "SEC-4821",
                        "assignee": "secops@example.com",
                        "description": "Cryptomining activity detected on web-server-01",
                        "uri": "https://example.atlassian.net/browse/SEC-4821",
                        "status": "In Progress",
                        "updateTime": "2020-02-18T07:26:42Z"
                    }
                }
            },
            "mitreAttack": {
                "primaryTactic": "IMPACT",
                "primaryTechniques": [
                    "RESOURCE_HIJACKING"
                ],
                "additionalTactics": [
                    "COMMAND_AND_CONTROL"
                ],
                "additionalTechniques": [
                    "INGRESS_TOOL_TRANSFER"
                ],
                "version": "12"
            },
            "access": {
                "principalEmail": "jdoe@example.com",
                "callerIp": "10.0.0.1",
                "callerIpGeo": {
                    "regionCode": "IN"
                },
                "userAgentFamily": "curl",
                "userAgent": "curl/7.68.0",
                "serviceName": "compute.googleapis.com",
                "methodName": "v1.compute.instances.get",
                "principalSubject": "user:jdoe@example.com",
                "serviceAccountKeyName": "//iam.googleapis.com/projects/prod-webapp-284917/serviceAccounts/compute@prod-webapp-284917.iam.gserviceaccount.com/keys/a1b2c3d4",
                "serviceAccountDelegationInfo": [
                    {
                        "principalEmail": "compute@prod-webapp-284917.iam.gserviceaccount.com",
                        "principalSubject": "serviceAccount:compute@prod-webapp-284917.iam.gserviceaccount.com"
                    }
                ],
                "userName": "jdoe"
            },
            "connections": [
                {
                    "destinationIp": "10.0.0.1",
                    "destinationPort": 3333,
                    "sourceIp": "10.128.0.12",
                    "sourcePort": 51244,
                    "protocol": "TCP"
                }
            ],
            "muteInitiator": "secops@example.com",
            "processes": [
                {
                    "name": "xmrig",
                    "binary": {
                        "path": "/tmp/.cache/xmrig",
                        "size": "4194304",
                        "sha256": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                        "hashedSize": "4194304",
                        "partiallyHashed": false,
                        "contents": "ELF binary",
                        "diskPath": {
                            "partitionUuid": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                            "relativePath": "/tmp/.cache/xmrig"
                        },
                        "operations": [
                            {
                                "type": "EXECUTE"
                            }
                        ],
                        "fileLoadState": "LOADED_BY_PROCESS"
                    },
                    "libraries": [
                        {
                            "path": "/lib/x86_64-linux-gnu/libc.so.6",
                            "size": "2029224",
                            "sha256": "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe",
                            "hashedSize": "2029224",
                            "partiallyHashed": false,
                            "contents": "shared object",
                            "diskPath": {
                                "partitionUuid": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                                "relativePath": "/lib/x86_64-linux-gnu/libc.so.6"
                            },
                            "operations": [
                                {
                                    "type": "OPEN"
                                }
                            ],
                            "fileLoadState": "LOADED_BY_PROCESS"
                        }
                    ],
                    "script": {
                        "path": "/tmp/.cache/install.sh",
                        "size": "2048",
                        "sha256": "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface",
                        "hashedSize": "2048",
                        "partiallyHashed": false,
                        "contents": "#!/bin/bash",
                        "diskPath": {
                            "partitionUuid": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                            "relativePath": "/tmp/.cache/install.sh"
                        },
                        "operations": [
                            {
                                "type": "EXECUTE"
                            }
                        ],
                        "fileLoadState": "LOADED_BY_PROCESS"
                    },
                    "args": [
                        "./xmrig",
                        "-o",
                        "xmr-pool.badactor.example:3333"
                    ],
                    "argumentsTruncated": false,
                    "envVariables": [
                        {
                            "name": "HOME",
                            "val": "/root"
                        }
                    ],
                    "envVariablesTruncated": false,
                    "pid": "34521",
                    "parentPid": "1042",
                    "userId": "0"
                }
            ],
            "contacts": {
                "security": {
                    "contacts": [
                        {
                            "email": "security-admin@example.com"
                        }
                    ]
                }
            },
            "compliances": [
                {
                    "standard": "cis",
                    "version": "1.2.0",
                    "ids": [
                        "4.1"
                    ]
                }
            ],
            "parentDisplayName": "Event Threat Detection",
            "description": "The VM web-server-01 connected to a known cryptomining command-and-control IP address.",
            "exfiltration": {
                "sources": [
                    {
                        "name": "//compute.googleapis.com/projects/prod-webapp-284917/zones/us-central1-a/instances/web-server-01",
                        "components": [
                            "disk"
                        ]
                    }
                ],
                "targets": [
                    {
                        "name": "//storage.googleapis.com/exfil-bucket-badactor",
                        "components": [
                            "bucket"
                        ]
                    }
                ],
                "totalExfiltratedBytes": "1048576"
            },
            "iamBindings": [
                {
                    "action": "ADD",
                    "role": "roles/owner",
                    "member": "user:jdoe@example.com"
                }
            ],
            "nextSteps": "Isolate the affected VM, terminate the xmrig process, and rotate the associated service account keys.",
            "moduleName": "known_cryptomining_bad_ip",
            "containers": [
                {
                    "name": "web-app",
                    "uri": "gcr.io/prod-webapp-284917/web-app@sha256:baddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecaf",
                    "imageId": "sha256:baddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecaf",
                    "labels": [
                        {
                            "name": "app",
                            "value": "web"
                        }
                    ],
                    "createTime": "2020-02-18T07:26:42Z"
                }
            ],
            "kubernetes": {
                "pods": [
                    {
                        "ns": "default",
                        "name": "web-app-7d9f8c6b5-x2k4p",
                        "labels": [
                            {
                                "name": "app",
                                "value": "web"
                            }
                        ],
                        "containers": [
                            {
                                "name": "web-app",
                                "uri": "gcr.io/prod-webapp-284917/web-app@sha256:baddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecaf",
                                "imageId": "sha256:baddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecaf",
                                "labels": [
                                    {
                                        "name": "app",
                                        "value": "web"
                                    }
                                ],
                                "createTime": "2020-02-18T07:26:42Z"
                            }
                        ]
                    }
                ],
                "nodes": [
                    {
                        "name": "gke-prod-cluster-default-pool-a1b2c3d4-x9k2"
                    }
                ],
                "nodePools": [
                    {
                        "name": "default-pool",
                        "nodes": [
                            {
                                "name": "gke-prod-cluster-default-pool-a1b2c3d4-x9k2"
                            }
                        ]
                    }
                ],
                "roles": [
                    {
                        "kind": "ROLE",
                        "ns": "default",
                        "name": "pod-reader"
                    }
                ],
                "bindings": [
                    {
                        "ns": "default",
                        "name": "read-pods",
                        "role": {
                            "kind": "ROLE",
                            "ns": "default",
                            "name": "pod-reader"
                        },
                        "subjects": [
                            {
                                "kind": "USER",
                                "ns": "default",
                                "name": "jdoe@example.com"
                            }
                        ]
                    }
                ],
                "accessReviews": [
                    {
                        "group": "apps",
                        "ns": "default",
                        "name": "deployments",
                        "resource": "deployments",
                        "subresource": "",
                        "verb": "create",
                        "version": "v1"
                    }
                ],
                "objects": [
                    {
                        "group": "apps",
                        "kind": "Deployment",
                        "ns": "default",
                        "name": "web-app",
                        "containers": [
                            {
                                "name": "web-app",
                                "uri": "gcr.io/prod-webapp-284917/web-app@sha256:baddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecaf",
                                "imageId": "sha256:baddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecaf",
                                "labels": [
                                    {
                                        "name": "app",
                                        "value": "web"
                                    }
                                ],
                                "createTime": "2020-02-18T07:26:42Z"
                            }
                        ]
                    }
                ]
            },
            "database": {
                "name": "//cloudsql.googleapis.com/projects/prod-webapp-284917/instances/main-db",
                "displayName": "main-db",
                "userName": "app_user",
                "query": "SELECT * FROM users WHERE role = 'admin'",
                "grantees": [
                    "app_user"
                ],
                "version": "POSTGRES_14"
            },
            "attackExposure": {
                "score": 8.5,
                "latestCalculationTime": "2020-02-18T07:26:42Z",
                "attackExposureResult": "organizations/1094826489209/simulations/latest/attackExposureResults/6d7e8f9a",
                "state": "CALCULATED",
                "exposedHighValueResourcesCount": 3,
                "exposedMediumValueResourcesCount": 5,
                "exposedLowValueResourcesCount": 12
            },
            "files": [
                {
                    "path": "/tmp/.cache/xmrig",
                    "size": "4194304",
                    "sha256": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "hashedSize": "4194304",
                    "partiallyHashed": false,
                    "contents": "ELF binary",
                    "diskPath": {
                        "partitionUuid": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                        "relativePath": "/tmp/.cache/xmrig"
                    },
                    "operations": [
                        {
                            "type": "EXECUTE"
                        }
                    ],
                    "fileLoadState": "LOADED_BY_PROCESS"
                }
            ],
            "cloudDlpInspection": {
                "inspectJob": "projects/prod-webapp-284917/locations/global/dlpJobs/i-1234567890123456789",
                "infoType": "CREDIT_CARD_NUMBER",
                "infoTypeCount": "42",
                "fullScan": true
            },
            "cloudDlpDataProfile": {
                "dataProfile": "projects/prod-webapp-284917/locations/us/tableProfiles/9876543210",
                "parentType": "ORGANIZATION",
                "infoTypes": [
                    {
                        "name": "EMAIL_ADDRESS",
                        "version": "1",
                        "sensitivityScore": {
                            "score": "SENSITIVITY_LOW"
                        }
                    }
                ]
            },
            "kernelRootkit": {
                "name": "Diamorphine",
                "unexpectedCodeModification": true,
                "unexpectedReadOnlyDataModification": false,
                "unexpectedFtraceHandler": true,
                "unexpectedKprobeHandler": false,
                "unexpectedKernelCodePages": true,
                "unexpectedSystemCallHandler": true,
                "unexpectedInterruptHandler": false,
                "unexpectedProcessesInRunqueue": false
            },
            "orgPolicies": [
                {
                    "name": "organizations/1094826489209/policies/compute.requireShieldedVm"
                }
            ],
            "job": {
                "name": "projects/prod-webapp-284917/jobs/etl-nightly-run",
                "state": "PENDING",
                "errorCode": 0,
                "location": "us-central1"
            },
            "application": {
                "baseUri": "https://web-server-01.example.com",
                "fullUri": "https://web-server-01.example.com/api/v1/login"
            },
            "ipRules": {
                "direction": "INGRESS",
                "sourceIpRanges": [
                    "0.0.0.0/0"
                ],
                "destinationIpRanges": [
                    "10.0.0.1/20"
                ],
                "exposedServices": [
                    "ssh"
                ],
                "allowed": {
                    "ipRules": [
                        {
                            "protocol": "tcp",
                            "portRanges": [
                                {
                                    "min": "22",
                                    "max": "22"
                                }
                            ]
                        }
                    ]
                },
                "denied": {
                    "ipRules": [
                        {
                            "protocol": "tcp",
                            "portRanges": [
                                {
                                    "min": "3333",
                                    "max": "3333"
                                }
                            ]
                        }
                    ]
                }
            },
            "backupDisasterRecovery": {
                "backupTemplate": "gold-daily",
                "policies": [
                    "daily-30d-retention"
                ],
                "host": "web-server-01",
                "applications": [
                    "web-app"
                ],
                "storagePool": "primary-pool",
                "policyOptions": [
                    "compression"
                ],
                "profile": "production",
                "appliance": "bdr-appliance-01",
                "backupType": "Incremental",
                "backupCreateTime": "2020-02-18T07:26:42Z"
            },
            "securityPosture": {
                "name": "organizations/1094826489209/locations/global/postures/production-posture",
                "revisionId": "a1b2c3d4",
                "postureDeploymentResource": "organizations/1094826489209",
                "postureDeployment": "organizations/1094826489209/locations/global/postureDeployments/prod-deployment",
                "changedPolicy": "compute.requireShieldedVm",
                "policySet": "cis-gcp-1.2",
                "policy": "compute.requireShieldedVm",
                "policyDriftDetails": [
                    {
                        "field": "enableSecureBoot",
                        "expectedValue": "true",
                        "detectedValue": "false"
                    }
                ]
            },
            "logEntries": [
                {
                    "cloudLoggingEntry": {
                        "insertId": "1a2b3c4d5e6f",
                        "logId": "cloudaudit.googleapis.com%2Fdata_access",
                        "resourceContainer": "projects/prod-webapp-284917",
                        "timestamp": "2020-02-18T07:26:42Z"
                    }
                }
            ],
            "loadBalancers": [
                {
                    "name": "web-lb-frontend"
                }
            ],
            "cloudArmor": {
                "securityPolicy": {
                    "name": "prod-waf-policy",
                    "type": "CLOUD_ARMOR",
                    "preview": false
                },
                "requests": {
                    "ratio": 0.35,
                    "shortTermAllowed": 1200,
                    "longTermAllowed": 45000,
                    "longTermDenied": 3200
                },
                "adaptiveProtection": {
                    "confidence": 0.92
                },
                "attack": {
                    "volumePpsLong": "150000",
                    "volumeBpsLong": "120000000",
                    "classification": "HTTP_FLOOD",
                    "volumePps": 180000,
                    "volumeBps": 145000000
                },
                "threatVector": "HTTP_FLOOD",
                "duration": "300s"
            },
            "notebook": {
                "name": "projects/prod-webapp-284917/locations/us-central1/instances/analysis-notebook",
                "service": "Vertex AI Workbench",
                "lastAuthor": "data-scientist@example.com",
                "notebookUpdateTime": "2020-02-18T07:26:42Z"
            },
            "toxicCombination": {
                "attackExposureScore": 9.1,
                "relatedFindings": [
                    "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/aabbccddeeff00112233445566778899"
                ]
            },
            "groupMemberships": [
                {
                    "groupType": "GROUP_TYPE_TOXIC_COMBINATION",
                    "groupId": "toxic-combo-9a8b7c6d"
                }
            ],
            "disk": {
                "name": "//compute.googleapis.com/projects/prod-webapp-284917/zones/us-central1-a/disks/web-server-01"
            },
            "dataAccessEvents": [
                {
                    "eventId": "evt-a1b2c3d4",
                    "principalEmail": "jdoe@example.com",
                    "operation": "READ",
                    "eventTime": "2020-02-18T07:26:42Z"
                }
            ],
            "dataFlowEvents": [
                {
                    "eventId": "evt-e5f6a7b8",
                    "principalEmail": "jdoe@example.com",
                    "operation": "READ",
                    "violatedLocation": "asia-south1",
                    "eventTime": "2020-02-18T07:26:42Z"
                }
            ],
            "networks": [
                {
                    "name": "//compute.googleapis.com/projects/prod-webapp-284917/global/networks/default"
                }
            ],
            "dataRetentionDeletionEvents": [
                {
                    "eventDetectionTime": "2020-02-18T07:26:42Z",
                    "dataObjectCount": "15000",
                    "maxRetentionAllowed": "7776000s",
                    "minRetentionAllowed": "2592000s",
                    "eventType": "EVENT_TYPE_MAX_TTL_EXCEEDED"
                }
            ],
            "affectedResources": {
                "count": "3"
            },
            "aiModel": {
                "name": "projects/prod-webapp-284917/locations/us-central1/models/fraud-detector",
                "domain": "Fraud Detection",
                "library": "TensorFlow",
                "location": "us-central1",
                "publisher": "internal",
                "deploymentPlatform": "VERTEX_AI",
                "displayName": "Fraud Detector v3",
                "usageCategory": "Production"
            },
            "chokepoint": {
                "relatedFindings": [
                    "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/aabbccddeeff00112233445566778899"
                ]
            },
            "complianceDetails": {
                "frameworks": [
                    {
                        "name": "cis-gcp-foundation-1.2",
                        "displayName": "CIS Google Cloud Platform Foundation Benchmark v1.2.0",
                        "category": [
                            "SECURITY_BENCHMARKS"
                        ],
                        "type": "FRAMEWORK_TYPE_BUILT_IN",
                        "controls": [
                            {
                                "controlName": "4.1",
                                "displayName": "Ensure That Instances Are Not Configured To Use the Default Service Account"
                            }
                        ]
                    }
                ],
                "cloudControl": {
                    "cloudControlName": "shielded-vm-enabled",
                    "type": "BUILT_IN",
                    "policyType": "ORG_POLICY",
                    "version": 1
                },
                "cloudControlDeploymentNames": [
                    "organizations/1094826489209/locations/global/cloudControlDeployments/shielded-vm-enabled"
                ]
            },
            "vertexAi": {
                "datasets": [
                    {
                        "name": "projects/prod-webapp-284917/locations/us-central1/datasets/transactions",
                        "displayName": "transactions",
                        "source": "bq://prod-webapp-284917.analytics.transactions"
                    }
                ],
                "pipelines": [
                    {
                        "name": "projects/prod-webapp-284917/locations/us-central1/pipelineJobs/training-run-2020",
                        "displayName": "training-run-2020"
                    }
                ]
            },
            "cryptoKeyName": "projects/prod-webapp-284917/locations/us-central1/keyRings/prod-ring/cryptoKeys/data-key",
            "artifactGuardPolicies": {
                "resourceId": "gcr.io/prod-webapp-284917/web-app",
                "failingPolicies": [
                    {
                        "type": "VULNERABILITY",
                        "policyId": "block-critical-cves",
                        "failureReason": "Image contains CVE-2021-44228 with CVSS score 10.0"
                    }
                ]
            },
            "secret": {
                "type": "GCP_SERVICE_ACCOUNT_KEY",
                "status": {
                    "lastUpdatedTime": "2020-02-18T07:26:42Z",
                    "validity": "SECRET_VALIDITY_UNSUPPORTED"
                },
                "environmentVariable": {
                    "key": "GOOGLE_APPLICATION_CREDENTIALS"
                },
                "filePath": {
                    "path": "/etc/secrets/sa-key.json"
                }
            },
            "externalExposure": {
                "privateIpAddress": "10.128.0.12",
                "privatePort": "8080",
                "exposedService": "http",
                "publicIpAddress": "10.0.0.1",
                "publicPort": "80",
                "exposedEndpoint": "10.0.0.1:80",
                "loadBalancerFirewallPolicy": "prod-lb-fw-policy",
                "serviceFirewallPolicy": "prod-svc-fw-policy",
                "forwardingRule": "web-lb-forwarding-rule",
                "backendService": "web-backend-service",
                "instanceGroup": "web-server-ig",
                "networkEndpointGroup": "web-neg",
                "hostnameUri": "https://web-server-01.example.com",
                "pscServiceAttachment": "projects/prod-webapp-284917/regions/us-central1/serviceAttachments/web-psc",
                "pscNetworkAttachment": "projects/prod-webapp-284917/regions/us-central1/networkAttachments/web-na",
                "internalBackendService": "internal-web-backend",
                "backendBucket": "web-static-bucket",
                "exposedApplication": "web-app",
                "networkIngressFirewallPolicy": "prod-ingress-fw-policy",
                "httpResponse": [
                    {
                        "statusCode": "200",
                        "path": "/api/v1/login"
                    }
                ],
                "networkPathInsightsGenerationTime": "2020-02-18T07:26:42Z"
            },
            "policyViolationSummary": {
                "policyViolationsCount": "7",
                "conformantResourcesCount": "42",
                "evaluationErrorsCount": "1",
                "outOfScopeResourcesCount": "3"
            },
            "agentDataAccessEvents": [
                {
                    "eventId": "evt-c9d0e1f2",
                    "principalSubject": "serviceAccount:agent@prod-webapp-284917.iam.gserviceaccount.com",
                    "operation": "READ",
                    "eventTime": "2020-02-18T07:26:42Z"
                }
            ],
            "discoveredWorkload": {
                "workloadType": "MCP_SERVER",
                "confidence": "CONFIDENCE_HIGH",
                "detectedRelevantPackages": true,
                "detectedRelevantKeywords": true,
                "detectedRelevantHardware": false
            }
        }
    }
}
```

#### Human Readable Output

>### The finding has been unmuted successfully
>
>|Organization ID|Name|Mute|State|Severity|Category|Event Time (In UTC)|Create Time (In UTC)|External Uri|Resource Name|
>|---|---|---|---|---|---|---|---|---|---|
>| 123 | [organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a](https://console.cloud.google.com/security/command-center/findings?organizationId=123&resourceId=organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a) | UNMUTED | ACTIVE | CRITICAL | Malware: Cryptomining Bad IP | February 18, 2020 at 07:26:42 AM | February 19, 2020 at 01:37:43 PM | [https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/web-server-01?project=prod-webapp-284917](https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/web-server-01?project=prod-webapp-284917) | //compute.googleapis.com/projects/prod-webapp-284917/zones/us-central1-a/instances/web-server-01 |

### google-cloud-scc-mute-rule-get

***
Get a mute rule (mute config) of an organization using the Security Command Center v2 API.

#### Base Command

`google-cloud-scc-mute-rule-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The relative resource name of the mute rule (mute config) to retrieve.<br/>In the v2 API the name may include an optional "locations/{location}" segment. If no location is specified, the mute rule is assumed to be in "global".<br/><br/>Format: organizations/{organization_id}/muteConfigs/{config_id} or organizations/{organization_id}/locations/{location_id}/muteConfigs/{config_id}<br/><br/>Example: organizations/595779152576/locations/global/muteConfigs/mute-cryptomining-alerts.<br/><br/>Note: Users can retrieve the mute rule name from the "Mute Config" column in the output of the "google-cloud-scc-v2-finding-list" command. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudSCC.MuteRule.name | String | Identifier of the mute rule. Format: organizations/\{organization\}/muteConfigs/\{muteConfig\} or organizations/\{organization\}/locations/\{location\}/muteConfigs/\{muteConfig\}. |
| GoogleCloudSCC.MuteRule.description | String | A description of the mute rule. |
| GoogleCloudSCC.MuteRule.filter | String | An expression that defines the filter to apply across create/update events of findings. |
| GoogleCloudSCC.MuteRule.createTime | String | The time at which the mute rule was created. |
| GoogleCloudSCC.MuteRule.updateTime | String | The most recent time at which the mute rule was updated. |
| GoogleCloudSCC.MuteRule.mostRecentEditor | String | Email address of the user who last edited the mute rule. |
| GoogleCloudSCC.MuteRule.type | String | The type of the mute rule, which determines what type of mute state the rule affects \(MUTE_CONFIG_TYPE_UNSPECIFIED, STATIC, DYNAMIC\). |
| GoogleCloudSCC.MuteRule.expiryTime | String | The expiry of the mute rule. Only applicable for dynamic mute rules. |
| GoogleCloudSCC.MuteRule.cryptoKeyName | String | The resource name of the Cloud KMS CryptoKey used to encrypt this configuration data, if CMEK was enabled during Security Command Center activation. |

#### Command Example

```!google-cloud-scc-mute-rule-get name="organizations/1094826489209/locations/global/muteConfigs/mute-cryptomining-alerts"```

#### Context Example

```json
{
    "GoogleCloudSCC": {
        "MuteRule": {
            "name": "organizations/1094826489209/locations/global/muteConfigs/mute-cryptomining-alerts",
            "description": "Mute low severity cryptomining findings for the staging project.",
            "filter": "severity=\"LOW\" AND category=\"Malware: Cryptomining Bad IP\"",
            "createTime": "2020-02-18T07:26:42Z",
            "updateTime": "2020-02-19T13:37:43.858Z",
            "mostRecentEditor": "secops@example.com",
            "type": "DYNAMIC",
            "expiryTime": "2020-03-18T07:26:42Z",
            "cryptoKeyName": "projects/prod-webapp-284917/locations/us-central1/keyRings/prod-ring/cryptoKeys/data-key"
        }
    }
}
```

#### Human Readable Output

>### Mute rule details
>
>|Organization ID|Name|Description|Filter|Type|Most Recent Editor|Create Time (In UTC)|Update Time (In UTC)|Expiry Time (In UTC)|
>|---|---|---|---|---|---|---|---|---|
>| 123 | organizations/1094826489209/locations/global/muteConfigs/mute-cryptomining-alerts | Mute low severity cryptomining findings for the staging project. | severity="LOW" AND category="Malware: Cryptomining Bad IP" | DYNAMIC | <secops@example.com> | February 18, 2020 at 07:26:42 AM | February 19, 2020 at 01:37:43 PM | March 18, 2020 at 07:26:42 AM |

### google-cloud-scc-mute-rule-create

***
Create a mute rule (mute config) for an organization using the Security Command Center v2 API.

#### Base Command

`google-cloud-scc-mute-rule-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| muteConfigId | Unique identifier of the mute rule (mute config) within the parent scope.<br/>It must consist of only lowercase letters, numbers, and hyphens, must start with a letter, must end with either a letter or a number, and must be 63 characters or less.<br/><br/>Example: mute-cryptomining-alerts. | Required |
| filter | An expression that defines the filter to apply across create/update events of findings.<br/>While creating a filter string, be mindful of the scope in which the mute rule is being created. E.g., if a filter contains project = X but is created under the project = Y scope, it might not match any findings.<br/><br/>The following field and operator combinations are supported:<br/>1) severity: =, :<br/>2) category: =, :<br/>3) resource.name: =, :<br/>4) resource.project_name: =, :<br/>5) resource.project_display_name: =, :<br/>6) resource.folders.resource_folder: =, :<br/>7) resource.parent_name: =, :<br/>8) resource.parent_display_name: =, :<br/>9) resource.type: =, :<br/>10) findingClass: =, :<br/>11) indicator.ip_addresses: =, :<br/>12) indicator.domains: =, :<br/><br/>Example: severity="LOW" AND category="Malware: Cryptomining Bad IP". | Required |
| type | The type of the mute rule, which determines what type of mute state the rule affects. Immutable after creation.<br/><br/>STATIC: sets the static mute state of future matching findings to muted.<br/><br/>DYNAMIC: applied to existing and future matching findings, setting their dynamic mute state to muted. Possible values are: STATIC, DYNAMIC. | Required |
| description | A description of the mute rule. | Optional |
| expiryTime | The expiry of the mute rule. Only applicable for dynamic mute rules. If the expiry is set, when the mute rule expires, it is removed from all findings.<br/><br/>Format: YYYY-MM-ddTHH:mm:ss.sssZ<br/><br/>Example: 2026-07-22T07:10:02.782Z, 2026-06-02T15:01:23.045123456Z. | Optional |
| location | The location in which the mute rule is created. If no location is specified, the mute rule is created in "global".<br/><br/>Example: global, eu, us, me-central2. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudSCC.MuteRule.name | String | Identifier of the mute rule. Format: organizations/\{organization\}/muteConfigs/\{muteConfig\} or organizations/\{organization\}/locations/\{location\}/muteConfigs/\{muteConfig\}. |
| GoogleCloudSCC.MuteRule.description | String | A description of the mute rule. |
| GoogleCloudSCC.MuteRule.filter | String | An expression that defines the filter to apply across create/update events of findings. |
| GoogleCloudSCC.MuteRule.createTime | String | The time at which the mute rule was created. |
| GoogleCloudSCC.MuteRule.updateTime | String | The most recent time at which the mute rule was updated. |
| GoogleCloudSCC.MuteRule.mostRecentEditor | String | Email address of the user who last edited the mute rule. |
| GoogleCloudSCC.MuteRule.type | String | The type of the mute rule, which determines what type of mute state the rule affects \(MUTE_CONFIG_TYPE_UNSPECIFIED, STATIC, DYNAMIC\). |
| GoogleCloudSCC.MuteRule.expiryTime | String | The expiry of the mute rule. Only applicable for dynamic mute rules. |
| GoogleCloudSCC.MuteRule.cryptoKeyName | String | The resource name of the Cloud KMS CryptoKey used to encrypt this configuration data, if CMEK was enabled during Security Command Center activation. |

#### Command Example

```!google-cloud-scc-mute-rule-create muteConfigId="mute-cryptomining-alerts" filter="severity=\"LOW\" AND category=\"Malware: Cryptomining Bad IP\"" type="DYNAMIC" description="Mute low severity cryptomining findings for the staging project." expiryTime="2020-03-18T07:26:42Z" location="global"```

#### Context Example

```json
{
    "GoogleCloudSCC": {
        "MuteRule": {
            "name": "organizations/1094826489209/locations/global/muteConfigs/mute-cryptomining-alerts",
            "description": "Mute low severity cryptomining findings for the staging project.",
            "filter": "severity=\"LOW\" AND category=\"Malware: Cryptomining Bad IP\"",
            "createTime": "2020-02-18T07:26:42Z",
            "updateTime": "2020-02-18T07:26:42Z",
            "mostRecentEditor": "secops@example.com",
            "type": "DYNAMIC",
            "expiryTime": "2020-03-18T07:26:42Z"
        }
    }
}
```

#### Human Readable Output

>### The mute rule has been created successfully
>
>|Organization ID|Name|Description|Filter|Type|Most Recent Editor|Create Time (In UTC)|Update Time (In UTC)|Expiry Time (In UTC)|
>|---|---|---|---|---|---|---|---|---|
>| 123 | organizations/1094826489209/locations/global/muteConfigs/mute-cryptomining-alerts | Mute low severity cryptomining findings for the staging project. | severity="LOW" AND category="Malware: Cryptomining Bad IP" | DYNAMIC | <secops@example.com> | February 18, 2020 at 07:26:42 AM | February 18, 2020 at 07:26:42 AM | March 18, 2020 at 07:26:42 AM |

## Known Limitations

This integration supports only secure connection hence disabling SSL(Trust any certificate) support is not provided.

### Deprecated commands

The commands below are backed by the Security Command Center v1 API and have been replaced by their v2 counterparts. They remain available for backward compatibility - existing playbooks and automations continue to work unchanged - but they will not receive new functionality and may be removed in a future release. Migrate to the v2 commands.

| **Deprecated command** | **Use instead** | **Migration notes** |
| --- | --- | --- |
| google-cloud-scc-finding-list | [google-cloud-scc-v2-finding-list](#google-cloud-scc-v2-finding-list) | The v2 command adds the optional `location` argument (default `global`). The v1-only `compareDuration`, `readTime` and `fieldMask` arguments are not supported by the v2 API and have no v2 equivalent. |
| google-cloud-scc-finding-update | [google-cloud-scc-v2-finding-update](#google-cloud-scc-v2-finding-update) | Same arguments as v1. The `name` argument additionally accepts finding names that contain a `locations/{location}` segment. |
| google-cloud-scc-finding-state-update | [google-cloud-scc-v2-finding-state-update](#google-cloud-scc-v2-finding-state-update) | Same arguments as v1. The `name` argument additionally accepts finding names that contain a `locations/{location}` segment, and the request sets only the finding state (the v1 API's deprecated `startTime` field is not sent). |
| google-cloud-scc-asset-list | - | No v2 replacement. |

**Context output change:** the v1 commands write to `GoogleCloudSCC.Finding.*` while the v2 commands write to `GoogleCloudSCC.FindingV2.*`. Playbooks and automations that read the finding context must be updated to the new path when migrating.

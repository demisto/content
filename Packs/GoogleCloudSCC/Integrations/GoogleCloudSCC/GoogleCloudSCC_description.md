Security Command Center is a security and risk management platform for Google Cloud. This integration uses Pub/Sub to fetch the incidents. To set up the initial parameters of Google SCC in Cortex XSOAR, please follow the below instructions -

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
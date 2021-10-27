# Cyren Inbox Security Integration

Utilize this integration to import Cyren Inbox Security incidents into XSOAR where they can be filtered through playbooks to help automate extended processing and analysis of these incidents.

Requirements for execution in a production environment include a Cyren Inbox Security ("CIS") license. Please contact [https://www.cyren.com/inbox-security-free-trial](https://www.cyren.com/inbox-security-free-trial) to get your free trial today.

You may test this integration without a license by utilizing "sample" as a parameter value as shown in the integration's parameter instructions. Refer to *Sample Mode* for more information regarding this configuration.

## Configuration

To configure your instance of a Cyren inbox Security Integration, please configure the following:

* **Fetches Incidents**:  must be selected in order to retrieve incidents from Cyren
* **Classifier**:  must be "Cyren Inbox Security Classifier"
* **Mapper (incoming)**:  must be "Cyren Inbox Security Mapper"

* **Server URL**: The endpoint  provided by your Cyren Representative or "sample" to try it.
* **Client ID**: The client ID provided by your Cyren Representative or "sample" to try it.
* **Client Secret**: The client secret provided by your Cyren Representative or "sample" to try it.

## Sample Mode

Use Sample mode to generate a test or sample incident. This mode is useful to preview layouts and playbooks in action without a Cyren Inbox Security license. To configure the integration in sample mode, set the parameters of the integration as follows:  

* **Fetches Incidents**:  must be selected in order to generate a sample incident
* **Classifier**:  must be "Cyren Inbox Security Classifier"
* **Mapper (incoming)**:  must be "Cyren Inbox Security Mapper"

* **Server URL**: "sample"
* **Client ID**: "sample"
* **Client Secret**: "sample"

Under sample mode, only one incident will be generated when the system invokes the fetch-incident command, regardless of other parameter settings.

To generate another incident, click *Reset the "last run" timestamp* configuration option for this integration.

Please refer to [https://www.cyren.com/cyren-inbox-security](https://www.cyren.com/cyren-inbox-security) for more information regarding Cyren Inbox Security.

## Provisioning accounts from XSOAR into Salesforce

### Salesforce IAM Integration
You can retrieve, create, update, enable or disable Salesforce users using the Salesforce IAM integration. For further information on this integration, visit the [Salesforce IAM](https://xsoar.pan.dev/docs/reference/integrations/salesforce-iam) Integration documentation.

Apart from basic Salesforce accounts provided by default mapping fields in the ***User Profile - Salesforce*** outgoing mapper, it is possible to provision extended user information, permission sets, permission sets licenses, package licenses and freeze statuses - all based on their Org Level 1/2/3 fields, as well as other User Profile fields.


### Generate the salesforce-provisioning-settings list
This list is required in order to execute the extended provisioning successfully. To generate one, follow the instructions in [SalesforceLoadProvisioningRulesFromCSV](https://xsoar.pan.dev/docs/reference/scripts/salesforce-load-provisioning-rules-from-csv) Script documentation.

#### Requirements for CSV lists
* Column headers that are part of lookup key should be all lower case and match with indicator fields.
* Column headers that are part of Salesforce profile should exactly match with SFDC corresponding attribute name.
* Column headers that are neither can be in any format - there is no restriction, e.g.: profileDescription
* If there is a default mapping for the org, include a role with all keys as "default"..
* If the attribute needs to be defaulted to manager's data, include the value as "default_to_manager".


### Salesforce IAM - Sync User Playbook
This playbook allows to calculates your extended Salesforce user attributes based on the user's *Org Level 1/2/3* fields. The 
By default, there is no call to the ***Salesforce IAM - Sync User Playbook*** playbook during an execution of the ***IAM - Sync User*** playbook. To allow this, detach the ***IAM - Custom User Sync*** playbook and add it as a sub-playbook task.
For further information, visit the [Salesforce IAM - Sync User](https://xsoar.pan.dev/docs/reference/playbooks/salesforce-iam---sync-user) Playbook documentation.


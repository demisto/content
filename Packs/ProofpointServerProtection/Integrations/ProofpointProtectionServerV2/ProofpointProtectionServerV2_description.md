### Authentication
An administrator must have a role that includes access to a specific REST API. 

Proofpoint on Demand (PoD) administrators must file a support ticket to Proofpoint support to obtain a role with access to an API.

On premise administrators: Edit the **filter.cfg** file and set the following key to true: com.proofpoint.admin.apigui.enable=t

In the management interface, create a role of type API. Select the APIs under **Managed Modules** for the role and assign an administrator that role.

The following are the required managed modules for this integration:
 - pss
 - Quarantine
 
The operations are accessed through port 10000.
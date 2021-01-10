### Authentication
An administrator must have a Role that includes access to a specific REST API. 

Proofpoint on Demand (PoD) administrators must file a support ticket to Proofpoint support to obtain a role with access to an API.

On premise administrators: edit the **filter.cfg** file and set the following key to true: `com.proofpoint.admin.apigui.enable=t`

In the management interface, create a Role of Type API and select the APIs under ***Managed Modules*** for the Role so that you can give an administrator that Role.

The required managed modules for this integration:
 - pss
 - Quarantine
 
 TODO: add screenshot

The operations are accessed through port 10000.
## Nutanix

### Important:

The following commands requires cluster admin or higher permissions.
(Found in Nutanix Settings in "Users And Roles" Category)

##### nutanix-hypervisor-vm-powerstatus-change
##### nutanix-alert-acknowledge
##### nutanix-alert-resolve
##### nutanix-alerts-acknowledge-by-filter
##### nutanix-alerts-resolve-by-filter

###Available Alert Type Ids, Impact Types And Entity Types
In order to check the options for the mentioned above:
* Go inside Nutanix UI and click on the second tab on top left corner(where it says Alerts in the picture below).
* When dropdown opens, click on alerts.
* Click on Alert Policies tab on your left side.

After those steps, your screen should look like this image
![Nutanix Alert Policy](../../doc_files/Alert_Policy.png)

Alert Policies contains the list of all possible alerts in the system,
and their ID, Impact Type and Entity Type. 

* ID stands for Alert Type ID filter parameter for fetching alerts, or argument for command nutanix-alerts-list
* Impact Type stands for Impact Type filter parameter for fetching alerts, or argument for command nutanix-alerts-list
* Entity Type stands for Entity Type filter parameter for fetching alerts, or argument for command nutanix-alerts-list 

#### Some Entity Types are not supported. See the [Nutanix Hypervisor Documentation](https://github.com/demisto/content/blob/master/Packs/Nutanix/Integrations/Nutanix/README.md)


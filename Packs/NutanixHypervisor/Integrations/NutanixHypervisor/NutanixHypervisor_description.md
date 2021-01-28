## Nutanix

### Important:

The following commands requires cluster admin or higher permissions.
(Found in Nutanix Settings in "Users And Roles" Category)

##### nutanix-hypervisor-vm-powerstatus-change
##### nutanix-alert-acknowledge
##### nutanix-alert-resolve
##### nutanix-alerts-acknowledge-by-filter
##### nutanix-alerts-resolve-by-filter

### Available Alert Type IDs, Impact Types and Entity Types
In order to check the optional values for the mentioned above:
* Go to your Nutanix UI and navigate to the `Alerts` screen. (Can be found under the second tab on the top left corner, see image below)
* Navigate to the Alert Policies tab on the left sidebar.
You should see the following screen:
![Nutanix Alert Policy](../../doc_files/Alert_Policy.png)

Alert Policies contains the list of all possible alerts in the system,
and their ID, Impact Type and Entity Type. 

* An alert policy `ID` can be used as an `Alert Type ID` filter for fetching alerts, or for the **nutanix-alerts-list** command.
* An alert policy `Impact Type` can be used as `Impact Type` filter  for fetching alerts, or for the **nutanix-alerts-list** command.

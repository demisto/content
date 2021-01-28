## Nutanix

### Important:

The following commands require cluster admin or higher permissions.
(Found in Nutanix Settings in the *Users And Roles* category.)

- ***nutanix-hypervisor-vm-powerstatus-change***
- ***nutanix-alert-acknowledge***
- ***nutanix-alert-resolve***
- ***nutanix-alerts-acknowledge-by-filter***
- ***nutanix-alerts-resolve-by-filter***

### Available Alert Type IDs, Impact Types, and Entity Types
To check the options for the types mentioned above:
1. In the  UI, click the *Alerts* tab. (It is the second tab on top left corner.)
2. Click *alerts* in the dropdown menu. 
3. Click the *Alert Policies* tab on the left side.

After completing those steps, your screen should look like this image
![Nutanix Alert Policy](../../doc_files/Alert_Policy.png)

Alert Policies contains the list of all possible alerts in the system,
and their ID, impact type, and entity type. 

* *ID* is the alert type ID filter parameter for fetching alerts, or the argument for the ***nutanix-alerts-list*** command.
* *Impact Type* is the impact type filter parameter for fetching alerts, or the argument for the ***nutanix-alerts-list*** command. 
* *Entity Type* is the entity type filter parameter for fetching alerts, or the argument for the ***nutanix-alerts-list*** command.

Some entity types are not supported. See the [Nutanix Hypervisor Documentation](https://github.com/demisto/content/blob/master/Packs/Nutanix/Integrations/Nutanix/README.md)



---
[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/nutanix-hypervisor)

This pack includes XSIAM content.

## Manage the fields on the schema

part 1 - on the Mcafee EPO management console
  1. click on “Queries & Reports” and find the query of the schema
  2. click action --> edit
  3. on the nav bar click on "columns", there you can edit the fields.
  4. copy the sql.

part 2 - manage the schema on the mssql
  1. right click on the table that you want manage the fields and click on design.
  2. edit the sql and save the new design configurations.

  * Pay attention: Timestamp parsing is supported for the **EventTimeLocal** field with UTC format. To configure the format:
    1. Access your Mcafee ePO interface.
    2. At the main options bar at the top-left corner, under **Configuration** select **Personal Settings**.
    3. At the left bar, select **Time Zone Prefrence** and set the system time zone to UTC +00:00 format.
    
## Collect Events from Vendor

In order to use the collector, you can use one of the following options to collect events from the vendor:
 - [Broker VM](#broker-vm)

In either option, you will need to configure the vendor and product for this specific collector.

### Broker VM
You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).\
You can configure the specific vendor and product for this instance.
1. Navigate to **Settings** -> **Configuration** -> **Data Broker** -> **Broker VMs**. 
2. Right-click, and select **Syslog Collector** -> **Configure**.
3. When configuring the Syslog Collector, set:
   - vendor as Mcafee
   - product as EPO
   
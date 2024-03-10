# Imperva WAF Gateway SecureSphere 
 
<~XSIAM>
 
This pack includes Cortex XSIAM content.
 
## Configuration on Server Side

To configure Imperva SecureSphere log forwarding in format CEF using Syslog please follow the step below

1. Navigate to Admin &rarr; System Definitions &rarr; Action Interface
2. Create a new action interface, for more information click &rarr; [Configure Action Interface Parameters](https://docs.imperva.com/bundle/v14.7-database-activity-monitoring-user-guide/page/2404.htm)
    1. Name your new action interface, “Send Alert to XSIAM” e.g.
    2. Select type “Gateway Security System Log”
3. Open the action interface you created and mark only “Secondary Host” & “Secondary Port”
    1. Choose protocol
    2. Primary host can be either IP or domain of the Cortex Broker VM
    3. Primary port should be the listening port of Cortex Broker VM
    4. Select Log Level
    5. Message should be the CEF format 
    6. Facility can be anything you choose, default is “USER”
    7. Save
4. Navigate to Main &rarr; Policies &rarr; Action Sets, for more information click &rarr; [Creating Action Set](https://docs.imperva.com/bundle/v14.7-database-activity-monitoring-user-guide/page/2402.htm)
5. Create new action set 
    1. Name the new action set 
    2. Choose “Security Violation - All
6. Send the action interface to the top by clicking the green arrow
7. Insert name 
8. Save
9. To add the action set to a security policy, navigate to Policies &rarr; security and  select the security policy you want
10. Save and repeat for every desired policy


for further documentation and example on ArcSight and Azure Sentinal:

[ArcSight example](https://docs.imperva.com/bundle/v14.7-database-activity-monitoring-user-guide/page/2493.htm)

[Azure Sentinel example](https://community.imperva.com/blogs/craig-burlingame1/2020/11/13/steps-for-enabling-imperva-waf-gateway-alert )
 
## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.
 
### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).
 
You can configure the specific vendor and product for this instance.
 
1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**.
2. Go to the **Apps** column under the **Brokers** tab and add the **Syslog Collector** app for the relevant broker instance. If the app already exists, hover over it and click **Configure**.
3. Click **Add New** for adding a new syslog data source.
4. When configuring the new syslog data source, set the following values:
   | Parameter     | Value   
   | :---          | :---        
   | `Vendor`      | Enter **imperva_inc**.
   | `Product`     | Enter **securesphere**.
   | `<parameter>` | < Enter **<value>**. (Fill in additional paramas if necessary for this product)
 
</~XSIAM>
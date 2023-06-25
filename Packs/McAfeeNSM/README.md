
# McAfee NSM
This pack includes Cortex XSIAM content.

## McAfee NSM Syslog configuration
config Mcafee NSM syslog syslog event types:
* IPS Events
* Faults
* User Activity (audit logs)

*config IPS Events*
1. on McAfee NSM go to Manager -> Setup -> Notification -> IPS Events -> syslog
2. click *YES* on "Enable Syslog Notification"
3. bellow click on *+* and add Target server 
   * if you not configured target server alick add neer the "Target Server" and  fill the target server details.
   ![link](nsm_add_target_server.png)
4. on Facility choose "Log Alert (note 1)"
5. Severity mapping - not touch, need to be:
   ![link](nsm_severity_mapping)
6. click on the Checkbox to enable "Notify for all Alerts"



## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Go to the apps tab and add the **Syslog** app. If it already exists, click the **Syslog** app and then click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - mcafee
   - product as product - nsm
 
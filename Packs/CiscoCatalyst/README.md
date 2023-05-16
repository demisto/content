
# Cisco Catalyst
This pack includes Cortex XSIAM content.


## add timezone to the logs in Cisco Catalyst switch  
The only supported event time is the event time with timezone.
to add timezone to the logs run the following command:
```
logging timestamp UTC
```
This command sets the logging timestamp to UTC, indicating that the log messages will include the time zone information as UTC.

## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.


### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Go to the apps tab and add the **Syslog** app. If it already exists, click the **Syslog** app and then click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following values **(not relevant for CEF and LEEF formats)**:
   - vendor as vendor - cisco
   - product as product - catalyst
 
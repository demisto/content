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
   - vendor as vendor<- Cisco
   - product as product<- ASA

### config timeformat on Cisco ASA
In Cisco ASA product we support only iso8601 date format with timezone.
an example ofr the timestamp: "2023-04-09T16:30:00-07:00"

1. Access the Cisco ASA command-line interface (CLI) using a console connection or SSH session.
2. Enter privileged EXEC mode by typing ```enable``` and entering the enable password.
3. Enter global configuration mode by typing ```conf t```.
4. Enter the logging timestamp command to update the timestamp format to iso8601 by typeing
```logging timestamp iso8601```
5. Exit the logging configuration by typing ```exit```.
6. Save the configuration changes by typing ```write memory```.
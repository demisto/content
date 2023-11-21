
# Cisco Catalyst
This pack includes Cortex XSIAM content.


## Add timezone to the logs  
The only supported event time is an event time with the time zone.

1. Access the switch's command-line interface (CLI) using a terminal emulator or SSH.
2. Access privileged EXEC mode by entering the following command and providing the enable password:
```
enable
```
3. Enter global configuration mode:

```
configure terminal
```
4. Configure the logging timestamp and specify the desired time format with the time zone:
```
logging timestamp datetime UTC
```
5. Exit configuration mode:
```
exit
```
6. To save the configuration changes run the command:
```
write memory
```
**Note** The time format is: "May 16 2023 14:30:00 UTC"


## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.


### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Go to the apps tab and add the **Syslog** app. If it already exists, click the **Syslog** app and then click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - cisco
   - product as product - catalyst
 

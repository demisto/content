
# Cisco Catalyst
This pack includes Cortex XSIAM content.

## Enabling Timestamps with a Time Zone on Log Messages  
The timestamp parsing is supported only for timestamps including a time zone.  
Follow the steps below to enable time stamping of log messages including a UTC timezone: 

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
You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**. 
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the Syslog app already exists, hover over it and click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following parameters:
   | Parameter     | Value    
   | :---          | :---                    
   | `Port`        | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from Cisco Catalyst Devices. 
   | `Vendor`      | Enter **cisco**. 
   | `Product`     | Enter **catalyst**. 

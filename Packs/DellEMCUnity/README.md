
# Dell EMC Unity

<~XSIAM>  

This pack includes Cortex XSIAM content.  

## Configuration on Server Side

### Dell EMC Unisphere Remote Logging Configuration

Follow these steps on Dell EMC Unisphere to configure syslog messages forwarding from Dell EMC Unity to Cortex XSIAM.
 
1. Log into the Dell EMC Unisphere management console. 
2. Go to **Settings** and navigate to **Management** &rarr; **Remote Logging**.
3. Check the **Enable logging to a remote host** checkbox.
4. Fill in the following settings: 
   | Parameter  | Value   
   | :---       | :---        
   | `Address`  | Enter the IP address and port number of the target Cortex XSIAM Broker VM syslog server, separated by a colon: *\<Broker_VM_IP\>:\<Broker_VM_Port\>*, for e.g., *192.168.1.123:514.*
   | `Facility` | Select the type of log messages to forward to Cortex XSIAM. Dell EMC recommends using the **User-Level Messages** facility. See [Syslog Facility Values](https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.1) for additional details.
   | `Severity` | Select the minimum severity level of the events to send to Cortex XSIAM.
   | `Port Type`| Select the requested forwarding transport protocol (*UDP* or *TCP*). 
5. Click **OK**.

For additional details regarding remote logging configuration on Unisphere, check the [Dell EMC Unisphere](https://www.delltechnologies.com/content/dam/uwaem/images/documentation/en/unity-family/unity-p-security-config-guide/unity_p_security_config_guide_en-us.pdf#logging) documentation. 

#### Remark:
- If instead of working with the Unisphere UI, you prefer to configure the remote logging via the the Unisphere CLI (UEMCLI),
 see the [Create remote logging configuration](https://www.dell.com/support/manuals/en-us/unity-6500/unity_p_cli_user_guide/create-remote-logging-configuration?guid=guid-10561e1f-09d7-40b4-9ffc-1277255ff8e8&lang=en-us) section in the Dell Unisphere CLI user guide.


## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).
 
You can configure the specific vendor and product for this instance.
 
1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**. 
2. Go to the apps tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
3. When configuring the Syslog Collector, set the following parameters:
   | Parameter     | Value    
   | :---          | :---                    
   | `Protocol`    | Select **UDP** or **TCP**, in correspondence to the protocol defined on the Dell EMC Unisphere interface. 
   | `Port`        | Enter the syslog service port number that this Cortex XSIAM Broker VM should listen on for receiving forwarded events from Dell EMC Unity.  
   | `Format`      | Select **Auto-Detect**.
   | `Vendor`      | Enter **Dell_EMC**. 
   | `Product`     | Enter **Unity**. 

</~XSIAM>
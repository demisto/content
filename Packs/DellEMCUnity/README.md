
# Dell EMC Unity

<~XSIAM>  

This pack includes Cortex XSIAM content.  

## Configuration on Server Side

Follow these steps on Dell EMC Unisphere to configure syslog messages forwarding from Dell EMC Unity to Cortex XSIAM.
 
1. Log into the Dell EMC Unisphere management console. 
2. Go to **Settings** and navigate to **Management** &rarr; **Remote Logging**.
3. Check the **Enable logging to a remote host** check box.
4. Fill in the following settings: 
   | Parameter  | Value   
   | :---       | :---        
   | `Address`  | Enter the IP address and port number of the target Cortex XSIAM Broker VM syslog server, separated by a colon: *\<Broker_VM_IP\>:\<Broker_VM_Port\>*.
   | `Facility` | Select the type of log message that would be used to classify the forwarded syslog messages. Dell EMC recommends using the **User-Level Messages** facility. See [Syslog Facility Values](https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.1) for additional details.
   | `Severity` | Select the minimum severity level of the events to send to Cortex XSIAM.
   | `Port Type`| Select the requested forwarding transport protocol (*UDP* or *TCP*). 
5. Click **OK**.
   

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
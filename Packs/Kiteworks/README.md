# Kiteworks

<~XSIAM>
This pack includes Cortex XSIAM content.

## Configuration on Server Side
This section describes the configuration that needs to be done on the Kiteworks administration console in order to forward Syslog messages from Kiteworks to Cortex XSIAM. 

Follow the steps below from your Kiteworks admin console web interface:
1. Go to the **Locations** page ([https://\<your_kiteworks_instance_domain\>/admin/#/locations]()).  
   - If you are using the *legacy* admin user interface, navigate to **System** &rarr; **Locations**.
   - If you are using the *new* admin user interface, navigate to **System Setup** &rarr; **Locations**. 
2. Select the requested location and navigate to **External Services**.
3. Expand the **Syslog Settings** section.
4. Add a new syslog server configuration with the following properties - 
    - `Syslog Server` - Enter the IP address of the target [Cortex XSIAM Syslog Broker VM](#broker-vm). 
    - `Protocol` - Select **UDP** or **TCP**. Note: If you wish to use TLS, select **TCP**.
    - `Port` - Enter the syslog service port that the target Cortex XSIAM Broker VM would be listening on for receiving forwarded syslog messages from Kiteworks. 
    - `Use TLS` - Select this checkbox if the syslog messages should be transported over TLS. 
    - `Format` - Select **JSON Format**. 
   
## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**. 
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
3. When configuring the Syslog Collector, set the following parameters:
   | Parameter     | Value    
   | :---          | :---                    
   | `Protocol`    | Select the relevant protocol in correspondence to the protocol that was defined in the syslog configuration on Kiteworks - **UDP**, **TCP**, or **Secure TCP** if the syslog forwarding on Kiteworks was defined with the *Use TLS* option.  
   | `Port`        | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded syslog messages from Kiteworks. 
   | `Vendor`      | Enter **Kiteworks**. 
   | `Product`     | Enter **Kiteworks**. 

### Remarks
The timestamp on the Kiteworks forwarded messages is interpreted in the GMT 0 timezone. 
   
</~XSIAM>
 
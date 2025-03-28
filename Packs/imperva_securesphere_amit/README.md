<~XSIAM>
### This pack includes:
- This pack includes Cortex XSIAM content.
- Log Normalization - XDM mapping for key event types.
-
 
### Supported Event Types:
- Support all Security System Events.
***
 
## Data Collection
To configure Imperva SecureSphere to send logs to Cortex XSIAM, follow the below steps.
 
### Imperva SecureSphere side
1. Navigate to the Admin Interface:
    * Go to Admin -> System Definitions -> Action Interfaces.
2. Create a New Action Interface:
    * Click to add a new action interface.
    * Give it a name.
    * Choose "Gateway Security System Log" from the drop-down menu.
3. Set Up the Configuration
    * Protocol - UDP
    * Primary Host - set to the Broker VM IP
    * Port - Specify the appropriate port
    * Message - CEF
 
For more information (https://docs.imperva.com/).
 
### Cortex XSIAM side
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).
 
### Broker VM
Follow the below steps to configure the Broker VM to receive Imperva SecureSphere logs.

1. Navigate to **Settings** → **Configuration** → **Data Broker** → **Broker VMs**.
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following parameters:
 
    | Parameter    | Value                                                                                                                                           |
    |:-------------|:------------------------------------------------------------------------------------------------------------------------------------------------|                 
    | `Protocol`   | Select **UDP** for the default forwarding, **TCP** or **Secure TCP** (depends on the protocol you configured in Imperva SecureSphere).            |
    | `Port`       | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from Imperva SecureSphere.              |
    | `Vendor`     | Enter imperva.                                                                                                                                 |
    | `Product`    | Enter securesphere.                                                                                                                               |
5. After data start flowing into Cortex XSIAM, you could query the collected logs under the *`imperva_securesphere_raw`* dataset.
    
</~XSIAM>
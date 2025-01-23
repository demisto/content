<~XSIAM>
 
### This pack includes:
- Timestamp parsing.
- XML format field extraction.
- Log normalization - XDM mapping for key event types.
 
### Supported Event Types:
Key Mcafee/Trellix products event types - Threat Prevention, Virus Scan, DLP, ATP, Endpoint Security.
 
### Supported Timestamp Formats:
Timestamp is extracted from the GMTTime field with the following format - yyyy-mm-ddTHH:MM:SS
***
 
## Data Collection
To configure Trellix ePO to send logs to Cortex XSIAM, follow the steps below.
 
### Trellix ePO side
1. Log in to the Trellix ePO main console.
2. On the main menu, go to **Configuration** > **Registered Servers**.
3. Click **New Server** and select **Syslog Server** as the Server type, name it and click **Next**.
4. In the Server name field enter the IP address or fully qualified domain name (FQDN) of your broker-vm.
5. Specify the port through which the ePO will send logs to the broker-vm. The default port is 6514 and it only supports syslog event forwarding via TLS protocol.
6. Check **Enable event forwarding**.
7. Click **Test connection**. If the test was successful, click **Save**.

* Note that the test connection stage will only work after you finish the configuration on the broker-vm side and open the selected port on your firewall.
 
For more information, see [this article](https://kcm.trellix.com/corporate/index?page=content&id=KB87927).
 
### Cortex XSIAM side
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).
 
### Broker VM
Follow the steps below to configure the Broker VM to receive Trellix ePO logs.
 
1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**.
2. Go to the *APPS* column under the *Brokers* tab and add the Syslog app for the relevant broker instance. If the Syslog app already exists, hover over it and click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following parameters:
    -----------------------------------------------------------------------------------------------------------------------------------------------------------
    | Parameter: :            | Value :                                                                                                                       |
    |-------------------------|-------------------------------------------------------------------------------------------------------------------------------|                 
    | `Protocol`              | Select **Secure TCP**.                                                                                                        |
    | `Port`                  | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from Trellix ePO.   |
    | `Vendor`                | Enter trellix.                                                                                                                |
    | `Product`               | Enter epo.                                                                                                                    |
    | `Server Certificate`    | Select the .crt file you created. See the attached Trellix documentation for help with using openssl.                         |
    | `Private Key`           | Select the .key file you created.                                                                                             |
    | `Minimal TLS Version`   | Select 1.2.                                                                                                                   |
    ----------------------------------------------------------------------------------------------------------------------------------------------------------- 
5. After the data starts flowing into Cortex XSIAM, you can query the collected logs under the *`trellix_epo_raw`* dataset.
    
</~XSIAM>
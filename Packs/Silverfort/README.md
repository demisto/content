# SilverFort
<~XSOAR>
Whenever Cortex XSOAR runs an investigation that entails a suspicion of compromised user account it leverages Silverfort’s visibility to gain wider context of the investigated user account and applies Silverfort’s proactive protection capabilities such as requiring MFA or blocking access altogether as part of Cortex playbooks.

##### What does this pack do?
Mutual data enrichment on user’s risk and triggering protective actions:
- Cortex XSOAR queries Silverfort whether  an investigated user account is a service account or a human user
- Cortex XSOAR queries Silverfort’s risk score for investigates user accounts
- Cortex XSOAR actively updates users’ risk scores at Silverfort based on its automated investigation 
- Silverfort blocks user access to resources or requires MFA based on Cortex playbook

Add helpful, relevant links below 
- https://www.silverfort.com/
- https://www.silverfort.com/request-a-demo/
- https://www.silverfort.com/portfolio-item/form-blocking-identity-based-threats-with-silverfort-palo-alto-networks-cortex-xsoar-2/
</~XSOAR>

<~XSIAM>
This pack includes Cortex XSIAM content.
 
## Configuration on Server Side
You need to configure SilverFort Unified Identity Protection to forward Syslog messages in CEF format.
 
Go to **Setting** > **General** > **Syslog Servers**, and follow the instructions under **Add Server IP** to set up the connection using the following guidelines:
1. Set the **Server IP** with your syslog server IP.
2. Set the Syslog port to **514** or your agent port.
3. Set the Protocol to **TCP**
4. Set Info to send for: **All Authentication**.

## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.
 
### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).
 
You can configure the specific vendor and product for this instance.
 
1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**.
2. Go to the **Apps** column under the **Brokers** tab and add the **Syslog Collector** app for the relevant broker instance. If the app already exists, hover over it and click **Configure**.
3. Click **Add New** for adding a new syslog data source.
4. When configuring the new syslog data source, set the following values:
   | Parameter     | Value   
   | :---          | :---        
   | `Vendor`      | Enter **Silverfort**.
   | `Product`     | Enter **Admin_Console**.

</~XSIAM>
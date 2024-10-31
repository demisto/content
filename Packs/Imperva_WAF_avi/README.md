# Imperva WAF Avi

<~XSIAM>
 
### This pack includes:
- Log Normalization - XDM mapping for key event types.
 
### Supported Event Types:
- xdm.source.port,
- xdm.observer.action,
- xdm.event.type,
- xdm.network.rule,
- xdm.source.application.name,
- xdm.intermediate.agent.type,
- xdm.alert.description,
- xdm.target.ipv4,
- xdm.source.ipv4,
- xdm.target.user.username,
- xdm.network.ip_protocol,
- xdm.event.description,
- xdm.alert.subcategory,
- xdm.alert.severity,
- xdm.observer.vendor,
- xdm.observer.product,
- xdm.event.original_event_type
 
### Supported Timestamp Formats:
<Enter time format when pack contains time parsing>

## Data Collection
To configure <Vendor> <Product> to send logs to Cortex XSIAM, follow the below steps.
 
### <Vendor> <Product> side
1. In the Main workspace, select Policies > Action Sets.
2. In the Action Sets window, click New, the Action Set dialog box appears.
Create a new System Event Type Action Set with an intuitive name
[here](https://docs.imperva.com/bundle/v14.7-database-activity-monitoring-user-guide/page/2402.htm)
3. In the Main workspace, select Policies > Action Sets. The Action Sets window appears.
4. Select the new Action Set created in step 2 above. Available action interfaces are listed in the Action Interface pane.
5. Add the desired action interface to the Selected Actions pane by clicking on its green arrow. 
choose Firewall Security Event (System Log > Firewall Security Event): Logs firewall event to System Log (syslog) using the CEF standard.
6. Expand the selected CEF System Log action interface by clicking on the plus sign (+) to its right.
7. Configure it as follows:
- Name: Type a name for the Syslog event.
- Syslog Host: Type the IP or host name of the XSIAM server.
- Syslog Log level: Select the desired syslog log level from the dropdown list (info, warn, debug or error).
- Message: Type a message with placeholder information to be used by syslog to create a message readable by XSIAM.
This message must follow CEF guidelines.
For a description of the CEF syslog message, including syntax and available placeholders
For more information <Link to the official docs>.
8. In the Policies > Security window, select the action set created in step 2 from the followed action dropdown list of the policy you want to configure.
9. Click Save. Settings are saved. If you are in delayed activation mode, you need to activate these settings. For more information, see Activating Settings in the Imperva DAM User Guide.
When a violation occurs, an alert is generated and a syslog message is sent to XSIAM.
 
### Cortex XSIAM side
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).
 
### Broker VM
Follow the below steps to configure the Broker VM to receive <Vendor> <Product> logs.
 
1. Navigate to **Settings** → **Configuration** → **Data Broker** → **Broker VMs**.
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following parameters:
 
    | Parameter    | Value                                                                                                                                           |
    |:-------------|:------------------------------------------------------------------------------------------------------------------------------------------------|                 
    | `Protocol`   | Select **UDP** for the default forwarding, **TCP** or **Secure TCP** (depends on the protocol you configured in <Vendor> <Product>).            |
    | `Port`       | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from <Vendor> <Product>.              |
    | `Vendor`     | Enter <Vendor>.                                                                                                                                 |
    | `Product`    | Enter <Product>.                                                                                                                               |
5. After data start flowing into Cortex XSIAM, you could query the collected logs under the *`<Vendor>_<Product>_raw`* dataset.
    
</~XSIAM>
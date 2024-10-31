<~XSIAM>
 
### This pack includes:
- Log Normalization - XDM mapping for key event types.
 
### Supported Event Types:
- All Regular Security Events sent in the following cef format - https://docs.imperva.com/bundle/v14.7-waf-management-server-manager-user-guide/page/3683_1.htm
 
## Data Collection
To configure Imperva Securesphere to send logs to Cortex XSIAM, follow the below steps.
 
### Imperva Securesphere side
1.Access Action Interface Settings
    Go to Admin > System Definitions > Action Interfaces. This section allows you to create and configure new action interfaces to forward security events and alerts.

2.Create a New Action Interface
    a.Add Interface: Click the Add button (often shown as a “+” icon).
    b.Name and Type: Choose a descriptive name, like “Forward Alerts to XSIAM.” Select the log forwarding type that best matches your product’s supported integration.
    c.Save the Configuration.
3.Edit Interface Settings for Syslog Forwarding,Open the new interface configuration:
    a.Uncheck Unused Options: Leave only the necessary options checked (usually Secondary Host and Port).
    b.Protocol: Select TCP or UDP.
    c.Primary Host: Enter the IP address or fully qualified domain name (FQDN) of your broker-vm.
    d.Port: Specify the port through which SecureSphere will send logs to the broker-vm.
    e.Syslog Log Level and Facility: Leave these at default values.
    f.Message: paste the following format:

    CEF:0|Imperva Inc|SecureSphere|${SecureSphereVersion}| ${Alert.alertType}|${Alert.alertMetadata.alertName}|${Alert.severity} |act=${Alert.immediateAction} dst=${Event.destInfo.serverIp} dpt=${Event.destInfo.serverPort} duser=${Alert.username} src=${Event.sourceInfo.sourceIp} spt=${Event.sourceInfo.sourcePort} proto=${Event.sourceInfo.ipProtocol} rt=(${Alert.createTime}) cat=Alert cs1=${Rule.parent.displayName} cs1Label=Policy cs2=${Alert.serverGroupName} cs2Label=ServerGroup cs3=${Alert.serviceName} cs3Label=ServiceName cs4=${Alert.applicationName} cs4Label=ApplicationName cs5=${Alert.description} cs5Label=Description

4.Define and Assign an Action Set, create an action set that uses the new interface:
    a.Navigate to Main -> Policies -> Action Sets.
    b.Create New Action Set: Add a new action set and include the action interface configured in the previous step.
    c.Assign Action Set to Policies: Apply this action set to relevant security policies to ensure that alerts are sent to your broker-vm.

For more information <[Link to the official docs](https://docs.imperva.com/bundle/v14.7-database-activity-monitoring-user-guide/page/2493.htm)>.
 
### Cortex XSIAM side
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).
 
### Broker VM
Follow the below steps to configure the Broker VM to receive Imperva Securesphere logs.
 
1. Navigate to **Settings** → **Configuration** → **Data Broker** → **Broker VMs**.
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following parameters:
 
    | Parameter    | Value                                                                                                                                           |
    |:-------------|:------------------------------------------------------------------------------------------------------------------------------------------------|                 
    | `Protocol`   | Select **UDP** for the default forwarding, **TCP** or **Secure TCP** (depends on the protocol you configured in securesphere).            |
    | `Port`       | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from securesphere.              |
    | `Vendor`     | Enter imperva.                                                                                                                                 |
    | `Product`    | Enter securesphere.                                                                                                                               |
5. After data start flowing into Cortex XSIAM, you could query the collected logs under the *`imperva_securesphere_raw`* dataset.
    
</~XSIAM>
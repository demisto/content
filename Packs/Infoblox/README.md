# Infoblox NIOS

<~XSIAM>
This pack includes XSIAM content.

## Sample XQL Queries

The following XQL Queries demonstrate the XDM modeling for the ingested Infoblox syslog messages:

1. **DNS Queries**
   ```javascript
    config timeframe = 1H
   | datamodel dataset = infoblox_infoblox_raw
   | filter xdm.event.type = "DNS Query"
   | fields xdm.source.process.name, xdm.source.process.pid, xdm.alert.severity, xdm.event.log_level, xdm.event.type, xdm.event.description, xdm.source.ipv4, xdm.source.port, xdm.intermediate.ipv4, xdm.network.dns.dns_question.name, xdm.network.dns.dns_question.type, xdm.network.dns.dns_question.class, xdm.event.outcome, xdm.event.outcome_reason,  xdm.network.ip_protocol
    ```
2. **DNS Responses** 
    ```javascript
   config timeframe = 1H  
   | datamodel dataset = infoblox_infoblox_raw
   | filter xdm.event.type  = "DNS Response" 
   | fields xdm.source.process.name, xdm.source.process.pid, xdm.alert.severity, xdm.event.log_level, xdm.event.type, xdm.event.description, xdm.source.ipv4, xdm.source.port,  xdm.network.dns.authoritative,  xdm.network.dns.dns_question.name, xdm.network.dns.dns_question.class, xdm.network.dns.dns_question.type, xdm.network.dns.is_response,xdm.network.dns.is_truncated,  xdm.network.dns.response_code, xdm.network.dns.dns_resource_record.name, xdm.network.dns.dns_resource_record.value, xdm.network.dns.dns_resource_record.type,  xdm.network.dns.dns_resource_record.class, xdm.target.host.ipv4_addresses, xdm.target.host.ipv6_addresses, xdm.target.ipv4, xdm.target.ipv6, xdm.network.ip_protocol, xdm.event.outcome, xdm.event.outcome_reason
    ```
3. **DHCP Events** 
    ```javascript
   config timeframe = 1H  
   | datamodel dataset = infoblox_infoblox_raw
   | filter xdm.event.type  = "DHCP" and xdm.network.dhcp.message_type != null
   | fields xdm.source.process.name, xdm.source.process.pid, xdm.alert.severity, xdm.event.log_level, xdm.event.type, xdm.event.description, xdm.network.dhcp.message_type, xdm.source.host.mac_addresses, xdm.source.host.device_id, xdm.source.interface, xdm.source.ipv4, xdm.intermediate.ipv4, xdm.network.dhcp.giaddr, xdm.target.ipv4, xdm.network.dhcp.siaddr, xdm.network.dhcp.chaddr, xdm.network.dhcp.ciaddr, xdm.network.dhcp.client_hostname, xdm.network.dhcp.lease, xdm.network.dhcp.requested_address, xdm.network.dhcp.yiaddr, xdm.event.operation_sub_type, xdm.session_context_id, xdm.event.outcome, xdm.event.outcome_reason
    ```

## Configuration on Server Side
This section describes the configuration steps that need to be done on your Infoblox NIOS appliance for sending event logs to Cortex XSIAM Broker VM via syslog.

1. Login to the Infoblox NIOS appliance. 
2. From the **Grid** tab, Navigate to **Grid Manager** &rarr; **Members**, and then click **Grid Properties** &rarr; **Edit** from the Toolbar.
3. In the **Grid Properties** editor, select the **Monitoring** tab, and then complete the following: 
   1. Select **Log to External Syslog Servers** to enable the appliance to send messages to a specified syslog server.
   2. Click the **Add** icon to add a new syslog server configuration and complete the following:
      
   | Parameter                  | Value    
   | :---                       | :---                    
   | **`Address`**              | Enter the IP address of the Cortex XSIAM Broker VM Syslog server.
   | **`Transport`**            | Select whether the appliance should use **UDP**, **TCP**, or **Secure TCP** to connect to the Cortex XSIAM Broker VM. 
   | **`Server Certificate`**   | To transport the logs over **Secure TCP**, upload a self-signed or a CA-signed server certificate.
   | **`Interface`**            | Select the interface through which the appliance should send the syslog messages to the Cortex XSIAM Broker VM.
   | **`Source`**               | Select whether the appliance should send only **Internal** messages, **External** messages, or both (**Any**).
   | **`Node ID`**              | Specify the host or node identification string that would be used in the syslog message header to identify the appliance from which the syslog messages originated. 
   | **`Port`**                 | Enter the port number that the Cortex XSIAM Broker VM is listening on for receiving syslog messages from the Infoblox appliance.
   | **`Severity`**             | Select the severity level of which messages from this level and above should be sent to Cortex XSIAM.
   | **`Logging Category`**     | Select **Send selected categories** and use the arrows to move the requested logging categories from the **Available** table to the **Selected** table and vice versa. 
   4. Click **Add** to add the external syslog server information.
   5. Optionally, click the **Test** button to test the connection to the Cortex XSIAM syslog server.
4. If you want Audit logs to be forwarded to Cortex XSIAM Broker VM as well, select **Copy Audit Log Messages to Syslog** and select the facility that determines the processes and daemons from which the log messages are generated.
5. Save the configuration and click **Restart** if it appears at the top of the screen.

### Remark
Timestamp Parsing for syslog messages sent from Infoblox to Cortex XSIAM is supported in GMT time zone. The time zone configured on the grid member should be set accordingly. See [Using a Syslog Server](https://docs.infoblox.com/space/nios86/423493735/Using+a+Syslog+Server) and [Viewing the Syslog](https://docs.infoblox.com/space/NAG8/22252249/Using+a+Syslog+Server#Viewing-the-Syslog) Infoblox docs for additional details.

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
   | `Protocol`    | Select **UDP**, **TCP**, or **Secure TCP**, in accordance with the selected syslog transport method configured on the Infoblox appliance.
   | `Port`        | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from the Infoblox appliance. 
   | `Vendor`      | Enter **Infoblox**. 
   | `Product`     | Enter **Infoblox**. 

</~XSIAM>
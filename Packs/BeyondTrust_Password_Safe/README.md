# BeyondTrust Password Safe
Unified password and session management for seamless accountability and control over privileged accounts.

<~XSIAM>

## Cortex XSIAM SIEM Content

This pack includes Cortex XSIAM SIEM content for parsing and modeling the syslog events that are forwarded from BeyondTrust Beyond Safe. 

In addition, data is normalized to the Cortex Data Model (XDM).

Follow the configuration sections below for forwarding syslog events from BeyondTrust Password Safe and ingesting them in Cortex XSIAM. 

### Configuration on BeyondTrust BeyondInsight
This section describes the configuration that needs to be done on the BeyondTrust BeyondInsight platform in order to forward its event logs to Cortex XSIAM Broker VM via syslog.

Follow the steps below:
1. In BeyondInsight, go to *Configuration* &rarr; *General* &rarr; *Connectors*.
2. From the *Connectors* pane, click **Create New Connector**.
3. Enter a name for the connector, for e.g., "*Cortex XSIAM*". 
4. Select **Syslog Event Forwarder** under the *Connector Type* list.
5. Click **Create Connector** to open the *Syslog Event Forwarder* pane.
6. Leave **Active (yes)** enabled.
7. Provide the required details of the target Cortex XSIAM Broker VM syslog server:
   - *`Available Output Pipelines`* - Select the requested transmission protocol for forwarding the syslog messages: *TCP*, *TCP-SSL*, or *UDP*.
   - *`Host Name`* - Enter the IP address or hostname of the target Cortex XSIAM Broker VM syslog server.
   - *`Port`* - enter the port number that the target Broker VM Syslog service is listening on for receiving syslog messages from BeyondTrust Password Safe.
8. Select one of the following output formats: *Comma Delimited* or *Tab Delimited*. Other formats are currently unsupported.
9. Select an optional syslog *Facility* from the list.
10. Select **Format Specification**.
11. Select the events that you want to forward to Cortex XSIAM.
12. Click **Test Connector** to determine if the event forwarding configuration is successful.
13. Click **Create Connector**.

See BeyondTrust Password Safe [Enable Syslog Event Forwarding](https://www.beyondtrust.com/docs/beyondinsight-password-safe/bi/integrations/third-party/snmp-trap-and-syslog.htm#:~:text=Enable%20Syslog%20Event%20Forwarding) guide for additional details. Remark: The timestamps extracted from the BeyondTrust Password Safe events are interpreted in UTC timezone. 

### Configuration on Cortex XSIAM

This section describes the configuration that needs to be done on Cortex XSIAM for receiving forwarded syslog events from BeyondTrust Password Safe. 

In order to use the collector, use the [Broker VM](#broker-vm) option.

#### Broker VM
You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**. 
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the Syslog app already exists, hover over it and click **Configure**.
3. Click **Add New**.
3. When configuring the Syslog Collector, set the following parameters:
   | Parameter     | Value    
   | :---          | :---                    
   | `Protocol`    | Select the syslog forwarding transmission protocol in correspondence to the [output pipeline](https://www.beyondtrust.com/docs/beyondinsight-password-safe/bi/integrations/third-party/snmp-trap-and-syslog.htm#:~:text=Select%20the%20Available%20Output%20Pipeline%3ATCP%2C%20TCP%2DSSL%2C%20or%20UDP) configured on the BeyondTrust BeyondInsight platform for the Cortex XSIAM connector - **UDP**, **TCP** or **Secure TCP (for TCP-SSL)**.  
   | `Port`        | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from BeyondTrust Password Safe. 
   | `Vendor`      | Enter **beyondtrust**. 
   | `Product`     | Enter **passwordsafe**. 


### Sample XQL Queries 
After completing the configurations above, the forwarded event logs are searchable on Cortex XSIAM via an XQL Search on the *beyondtrust_passwordsafe_raw* dataset. 

The following XQL Queries demonstrate the parsing and XDM modeling for the BeyondTrust Password Safe events:

1. **AppAudit Login Events** 
    ```javascript
    config  timeframe = 1H
    | datamodel dataset = beyondtrust_passwordsafe_raw 
    | filter xdm.observer.type ~= "AppAudit" and xdm.event.type ~= "Login"
    | fields  xdm.observer.type, xdm.event.id, xdm.event.type, xdm.auth.auth_method, xdm.source.user.username, xdm.source.user.domain, xdm.source.user.groups, xdm.source.ipv4,   xdm.event.description, xdm.event.outcome, xdm.event.outcome_reason
    ```
2. **PowerBroker Password Safe (PBPS) Events** 
    ```javascript
    config  timeframe = 1H
    | datamodel dataset = beyondtrust_passwordsafe_raw 
    | filter xdm.observer.type = "PBPS"
    | fields  xdm.observer.type, xdm.observer.version, xdm.event.id, xdm.event.type, xdm.event.original_event_type, xdm.event.operation, xdm.event.description, xdm.event.outcome, xdm.event.outcome_reason, xdm.source.host.hostname, xdm.source.ipv4, xdm.source.user.username, xdm.source.user.domain, xdm.source.user.groups, xdm.target.resource.value
     ```

3. **All XDM Mapped Fields** 
    ```javascript
    config  timeframe = 1H
    | datamodel dataset = beyondtrust_passwordsafe_raw 
    | fields xdm.auth.auth_method, xdm.email.recipients, xdm.event.description, xdm.event.id, xdm.event.operation, xdm.event.original_event_type, xdm.event.outcome, xdm.event.outcome_reason, xdm.event.type, xdm.intermediate.host.hostname, xdm.observer.name, xdm.observer.type, xdm.observer.version, xdm.session_context_id, xdm.source.agent.identifier, xdm.source.agent.version, xdm.source.host.hostname, xdm.source.ipv4, xdm.source.ipv6, xdm.source.host.ipv4_addresses, xdm.source.host.ipv6_addresses, xdm.source.location.region, xdm.source.user.domain, xdm.source.user.groups, xdm.source.user.identifier, xdm.source.user.ou, xdm.source.user.username, xdm.target.application.name, xdm.target.process.command_line, xdm.target.file.directory, xdm.target.file.filename, xdm.target.file.path, xdm.target.host.hostname, xdm.target.host.os, xdm.target.host.os_family, xdm.target.port, xdm.target.resource.id, xdm.target.resource.name, xdm.target.resource.type, xdm.target.resource.value, xdm.target.resource.parent_id, xdm.target.user.domain, xdm.target.user.identifier, xdm.target.user.groups, xdm.target.user.username
    | view column order = populated 
    ```
   
</~XSIAM>

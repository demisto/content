Note: Support for this Pack was moved to Partner starting October 10, 2022. 
Please contact the partner directly via the support link on the right.

Armis is an agentless, enterprise-class security platform to address the threat landscape of unmanaged and IoT devices. We discover every managed, unmanaged, and IoT device on and off of your network, analyze device behavior to identify risks or attacks, and protect your critical business information and systems. This Pack contains Armis incident fields and provides the ability to interface with the Armis system

##### What does this pack do?

The Integrations and Playbooks in this pack provide the following functionality:
- Fetch incidents from an Armis instance.
- Search for Armis Alerts.
- Search for Devices connected to an Alert.
- Tag and Untag Devices.
- Set the status of Armis Alerts.
- Enrich an Alert with the details of the related Devices.

<~XSIAM>

## Cortex XSIAM SIEM Content

This pack includes Cortex XSIAM SIEM content, which is supported directly by *Palo Alto Networks*. 

### Supported Datasets

The SIEM content contains modeling rules for the following Armis event types: 

| Event Type      | Target Dataset   
| :---            | :---        
| **Alerts**      | `armis_security_raw`
| **Activities**  | `armis_security_activities_raw`
| **Devices**     | `armis_security_devices_raw`

### Sample XQL Queries

The following XQL Queries demonstrate the XDM modeling for the supported datasets:

1. **Alerts**
   ```javascript
    config timeframe = 1H 
    | datamodel dataset = armis_security_raw
    | fields xdm.event.type, xdm.alert.category, xdm.alert.severity, xdm.alert.original_alert_id, xdm.alert.name, xdm.alert.description,xdm.event.outcome, xdm.event.is_completed,    xdm.source.host.device_id,  xdm.event.id, xdm.alert.original_threat_id, xdm.alert.original_threat_name,  xdm.event.tags,  xdm.network.rule, xdm.network.session_id
    ```
2. **Activities** 
    ```javascript
    config timeframe = 1H
    | datamodel dataset = armis_security_activities_raw
    | fields xdm.source.zone, xdm.observer.name, xdm.observer.type,xdm.event.id, xdm.event.type, xdm.event.description, xdm.source.host.device_id, xdm.source.host.hostname, xdm.source.ipv4, xdm.source.ipv6, xdm.source.user_agent, xdm.target.host.hostname, xdm.target.ipv4,xdm.target.host.ipv4_addresses, xdm.target.ipv6, xdm.target.port, xdm.network.tls.cipher, xdm.network.tls.protocol_version, xdm.event.duration, xdm.network.http.method, xdm.network.ip_protocol, xdm.network.session_id, xdm.target.user.username, xdm.source.application.name, xdm.source.application.version
    ```
3. **Devices** 
    ```javascript
    config timeframe = 1D 
    | datamodel dataset = armis_security_devices_raw 
    | fields xdm.source.host.device_id, xdm.source.host.hostname, xdm.source.host.device_category, xdm.source.host.manufacturer, xdm.source.host.device_model, xdm.source.host.os, xdm.source.host.os_family, xdm.source.host.mac_addresses, xdm.source.ipv4, xdm.source.ipv6, xdm.source.user.identifier, xdm.observer.name, xdm.observer.type, xdm.source.zone, xdm.alert.severity, xdm.event.tags
    ```
   
</~XSIAM>
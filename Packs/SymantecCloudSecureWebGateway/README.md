# Symantec Cloud Secure Web Gateway (SWG)


## Cortex XSIAM SIEM Content

This pack includes Cortex XSIAM SIEM content for parsing and modeling the access logs that are ingested via the Symantec Cloud SWG Event Collector integration. 

After configuring the Symantec Cloud SWG Event Collector integration in Cortex XSIAM, the access logs are searchable in XQL Search using the **symantec_swg_raw** dataset. 

In addition, data is normalized to the Cortex Data Model (XDM).

The following XQL Queries demonstrate the parsing and XDM modeling for the Symantec Cloud SWG Access Logs:

1. **XDM Mapped Fields (Implicit)** 
    ```javascript
    config  timeframe = 1H
    | datamodel dataset = symantec_swg_raw 
    | fields *
    | view column order = populated 
    ```
2. **XDM Mapped Fields (Explicit)** 
    ```javascript
    config  timeframe = 1H
    | datamodel dataset = symantec_swg_raw 
    | fields _time, xdm.observer.type, xdm.source.agent.type, xdm.observer.action, xdm.alert.original_threat_id, xdm.alert.risks, xdm.alert.severity, 
              xdm.event.duration, xdm.event.id, xdm.event.operation, xdm.event.operation_sub_type, xdm.event.outcome, xdm.event.outcome_reason, 
              xdm.intermediate.cloud.zone, xdm.intermediate.host.device_id, xdm.intermediate.host.hostname, xdm.intermediate.host.ipv4_addresses, xdm.intermediate.host.ipv6_addresses, xdm.intermediate.ipv4, xdm.intermediate.ipv6, xdm.intermediate.is_proxy, xdm.intermediate.location.country, 
              xdm.network.application_protocol, xdm.network.http.content_type, xdm.network.http.http_header.header, xdm.network.http.http_header.value, xdm.network.http.method, xdm.network.http.referrer, xdm.network.http.response_code, xdm.network.http.url, xdm.network.http.url_category, xdm.network.rule, xdm.network.tls.cipher, xdm.network.tls.client_certificate.subject, xdm.network.tls.protocol_version, xdm.network.tls.server_certificate.issuer, xdm.network.tls.server_certificate.subject, xdm.network.tls.server_name, 
              xdm.source.agent.version, xdm.source.host.device_category, xdm.source.host.device_id, xdm.source.host.hostname, xdm.source.host.os, xdm.source.host.os_family, xdm.source.ipv4, xdm.source.ipv6, xdm.source.location.country, xdm.source.sent_bytes, xdm.source.user.domain, xdm.source.user.groups, xdm.source.user.username, xdm.source.user_agent, 
              xdm.target.application.name, xdm.target.file.extension, xdm.target.host.hostname, xdm.target.host.ipv4_addresses, xdm.target.host.ipv6_addresses, xdm.target.ipv4, xdm.target.ipv6, xdm.target.location.country, xdm.target.port, xdm.target.resource.value, xdm.target.sent_bytes, xdm.target.url
    ```


**Remark**: As documented in the [Access Log Formats](https://techdocs.broadcom.com/us/en/symantec-security-software/web-and-network-security/cloud-swg/help/wss-reference/accesslogformats-ref.html) Cloud SWG reference, the **date** and **time** fields are interpreted in GMT time.

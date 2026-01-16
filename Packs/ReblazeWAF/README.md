<~XSIAM>

## Overview

Reblaze offers a next-generation, cloud-native Web Application Firewall (WAF) providing comprehensive security for your digital assets.  
It protects websites, applications, and APIs in real-time from OWASP Top 10 threats, zero-day attacks, and malicious bots.  
As a fully managed solution, Reblaze ensures maximum protection with minimal false positives, tailored by security experts.

## This pack includes

Data normalization capabilities:

* Data modeling rules normalize Reblaze WAF logs that are ingested via Broker VM to Cortex XSIAM.
* Ingested logs can be queried in XQL Search using the *`reblaze_waf_raw`* dataset.

## Supported log categories

* Access

### Supported timestamp formats

* yyyy-MM-ddTHH:mm:ssTZ

Example:
2025-07-22T09:53:39+00:00

***

## Data Collection

### Reblaze WAF side

#### Configuring Log Export to Cortex XSIAM (Reblaze versions 2.12 and above)

For customers using Reblaze versions 2.12 and above (excluding version 5), the configuration of SIEM log exporting is managed by the Reblaze support team.  
To initiate this process, please submit a support request with the following information:

* SIEM Endpoint: The destination IP address or FQDN.
* Destination Port: The specific port Cortex XSIAM is listening on.
* Security Certificate: The endpoint's public SSL certificate in PEM format.

Once this information is provided, the support team will finalize the configuration on your behalf.

For more information, please see the official Reblaze documentation available at the following link:  
[Set Up SIEM Integration](https://waap.docs.link11.com/v2.20.4/using-the-product/how-do-i.../set-up-siem-soc-integration)

#### Configuring Log Export to Cortex XSIAM (Reblaze version 5)

Customers using Reblaze version 5 can stream Reblaze WAF security events to Cortex XSIAM by configuring a new Log Exporter in the Reblaze interface as described in the following steps:

1. From the main menu, navigate to System > Log Exporters.
2. Click the Create Log Exporter button.
3. In the configuration dialog, populate the following fields:  

    * Name: Provide a descriptive name (e.g., "Cortex XSIAM Integration").
    * Transport: Select a protocol (TCP, UDP, or TCP and TLS).  
        For a secure connection, TCP and TLS is recommended, which requires providing an SSL certificate.
    * Endpoint: Enter your Cortex XSIAM endpoint's IP address or hostname, followed by the listening port (e.g., 192.168.1.100:514).
    * Mode: Choose which events to forward—"Blocked only" (default) or "All" for comprehensive logging.  

4. Click Save to activate the exporter.

**Note:**  
Reblaze transmits logs using the Syslog (RFC 5424) protocol.  
The message body contains a detailed, structured JSON object representing the security event.

For more information on how to configure Log Exporter in version 5, see [Configure Log Exporter](https://waap.docs.link11.com/console-walkthrough/system/log-exporters).

### Cortex XSIAM side - Broker VM

To create or configure the Broker VM, see [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Set-up-and-configure-Broker-VM#).

Follow these steps to configure the Broker VM to receive Reblaze WAF logs.

1. Navigate to **Settings** → **Configuration** → **Data Broker** → **Broker VMs**.
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance.  
    If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following parameters:

   | Parameter     | Value
   | :---          | :---
   | `Protocol`    |  Choose a protocol over which the Syslog will be sent: UDP, TCP, or Secure TCP according to what you defined in Reblaze WAF.
   | `Port`        | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from Reblaze WAF (Default port is 514).
   | `Vendor`      | Enter **Reblaze**.
   | `Product`     | Enter **WAF**.

</~XSIAM>

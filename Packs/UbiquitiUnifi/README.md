# Ubiquiti Unifi

Ubiquiti UniFi is an integrated network management and security platform that provides centralized control of Wi-Fi access points, switches, gateways, and other devices. It offers unified monitoring, configuration, and security features through an intuitive cloud-based interface for businesses and organizations.

<~XSIAM>

## What does this pack contain?

- Modeling rules for Monitoring, Security, System, Internet and Power events.
- Supported CEF logs.
- Log syslog integration.

### Broker VM

For more information, see [here](https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration).
You can configure the specific vendor and product for this instance.

1. In Cortex XSIAM, navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**.
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - ubiquiti
   - product as product - unifi

### UniFi Log Export

To configure log export:

Go to *Settings* > *Control Plane* > *Integrations* > *Activity Logging*.
Select **Broker VM Server** as the destination.
Choose the log categories you wish to export (e.g., security, system, client activity).
Enter the **IP Address** and **Port** used by your SIEM or external syslog server.

NOTE: The types of logs supported in this package are **CEF** only.

For more information, see [here](https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration).  

</~XSIAM>

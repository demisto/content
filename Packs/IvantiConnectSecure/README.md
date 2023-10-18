
# Ivanti Connect Secure
<~XSIAM>
This pack includes Cortex XSIAM content.


## Configuration on Server Side
This section describes the mandatory steps you should perform on Ivanti Connect Secure admin console in order to configure logging for the various system events and forwarding them via Syslog to Cortex XSIAM.

### Configure Events to Log and Syslog forwarding 
1. Log in to your Ivanti Connect Secure admin web console. 
2. Select **System** > **Log/Monitoring**.
3. Click the **Settings** tab to display the configuration page.
4. For each local event log category that you are interested in logging (_System_ events, _User Access_ events, _Admin Access_ events & _Sensors_ events), perform the following steps: 
     - Go to the **Select Events to Log** section, and select the requested event types you wish to log. See [Select Events to Log](https://help.ivanti.com/ps/help/en_US/PCS/9.1R13/pcsag/logging_n_monitoring.htm#log_events_set) for a description of the various types for each event category. 
     - Go to the  **Syslog Server** section, and define a server configuration for the Cortex XSIAM Broker VM with the following settings (see [Configuring Syslog](https://help.ivanti.com/ps/help/en_US/PCS/9.1R13/pcsag/logging_n_monitoring.htm#logging_and_monitoring_1494202195_1023612) for full documentation): 
         | Parameter          | Value    
         | :---               | :---                    
         | `Server name/IP`   | Enter the [Cortex XSIAM Broker VM](#broker-vm) server's IP address or FQDN.    
         | `Type`             | Select **UDP**.   
         | `Filter`           | Select **Standard** (the default).   
   
5. Click **Save Changes** for saving the configuration.
  
If you are interested in alternative or advanced settings, such as configuring fault tolerance support, logging client-side events, or forwarding the syslog events via a secure communication channel over TCP with TLS, refer to the documentation in the following links:
- [Configuring an External Syslog Server](https://help.ivanti.com/ps/help/en_US/PPS/9.1R14/ag/configuring_an_external_syslog_server.htm).
- [Configuring Advanced Settings](https://help.ivanti.com/ps/help/en_US/PCS/9.1R13/pcsag/logging_n_monitoring.htm#logging_and_monitoring_1494202195_1023706). 
- [Enabling Client-Side Logging](https://help.ivanti.com/ps/help/en_US/PCS/9.1R13/pcsag/logging_n_monitoring.htm#logging_and_monitoring_1494202195_1022619).

* Pay attention: Timestamp parsing is supported for [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339) of the following formats:
  * %Y-%m-%dT%H:%M:%SZ - UTC +00:00 format.
  * %Y-%m-%dT%H:%M:E3SZ - UTC +00:00 format with 3 digits of fractional precision.
  * %Y-%m-%dT%H:%M:E*SZ - UTC +00:00 format with 6 digits of fractional precision. 
  * %Y-%m-%d{Key}%H:%M:%S%Ez - RFC 3339 numeric time zone (+HH:MM or -HH:MM).
  * %Y-%m-%d{Key}%H:%M:%E3S%Ez - RFC 3339 numeric time zone (+HH:MM or -HH:MM) with 3 digits of fractional precision.
  * %Y-%m-%d{Key}%H:%M:%E*S%Ez - RFC 3339 numeric time zone (+HH:MM or -HH:MM) with 6 digits of fractional precision.


## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Go to the apps tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and then click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following values:
   | Parameter     | Value    
   | :---          | :---                    
   | `Protocol`    | **_UDP_** (The protocol that was defined in the [Syslog forwarding configuration on the Ivanti admin console](#configure-events-to-log-and-syslog-forwarding)).
   | `Port`        | **_514_**.   
   | `Vendor`      | Enter **_Ivanti_**. 
   | `Product`     | Enter **_Connect Secure_**. 

</~XSIAM>
 
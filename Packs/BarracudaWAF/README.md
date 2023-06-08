# Barracuda WAF
This pack includes Cortex XSIAM content. 
## Configuration on Server Side
In Barracuda WAF appliance:
1. Go to the **ADVANCED** > **Export Logs** page.
2.  In the Export Logs section, click **Add Export Log Server**. The Add Export Log Server window opens. Specify values for the following:
   - Name – Enter a name for the syslog NG server. 
   - Log Server Type – **Select Syslog NG**.
   - IP Address or Hostname – Enter the IP address or the hostname of the syslog NG server. 
   - Port – Enter the port associated with the IP address of the syslog NG server. 
   - Connection Type – Select the connection type to transmit the logs from the Barracuda Web Application Firewall to the syslog server. UDP is the default port for syslog communication. UDP, TCP, or SSL can be used in case of NG syslog server. 
   - Validate Server Certificate – Set to Yes to validate the syslog server certificate using the internal bundle of Certificate Authority's (CAs) certificates packaged with the system. If set to No, any certificate from the syslog server is accepted. 
   - Client Certificate – When set to Yes, the Barracuda Web Application Firewall presents the certificate while connecting to the syslog server. 
   - Certificate – Select a certificate for the Barracuda Web Application Firewall to present when connecting to the syslog server. Certificates can be uploaded on the **BASIC** > **Certificates** page. For more information on how to upload a certificate, see [How to Add an SSL Certificate](https://campus.barracuda.com/product/webapplicationfirewall/doc/4259930/how-to-add-an-ssl-certificate/). 
   - Log Timestamp and Hostname – Set to Yes if you want to log the date and time of the event, and the hostname configured in the **BASIC** > **IP Configuration** > **Domain Configuration** section.  
3. In the Logs Format section, specify values for the following fields:
   - Syslog Header –  ArcSight Log Header 
   - Web Firewall Logs Format –  HPE ArcSight CEF:0 
   - Access Logs Format – HPE ArcSight CEF:0 
   - Audit Logs Format – HPE ArcSight CEF:0 
   - Network Firewall Logs Format - HPE ArcSight CEF:0 
   - System Logs Format - HPE ArcSight CEF:0 
4. Click **Save**.
## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.


1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - barracuda
   - product as product - waf
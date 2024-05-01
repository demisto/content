# Delinea Secret Server
(Formly known as "Thycotic Software Secret Server")
This pack includes XSIAM content.

Secret Server is the only fully featured Privileged Account Management (PAM) solution available both on premise and in the cloud. It empowers security and IT ops teams to secure and manage all types of privileged accounts and offers the fastest time to value of any PAM solution. Palo Alto Networks and Delinea integrations allow you to manage credentials for applications, databases, CI/CD tools, and services without causing friction in the development process

This integration allows to secure privileges for service, application, root and administrator accounts across the enterprise. This updated package has the following:

- Obtain a secret with the required fields for subsequent authentication
- Methods for working with objects Secret: create, update, search, delete, check-in/check-out
- Methods for working with objects Folder: create, update, search, delete
- Methods for working with objects Users: create, update, search, delete
- Fetch updated data from secret for usage in owner automate process.
<~XSIAM>
## Configuration on Server Side

1. Navigate to **Admin** > **Configuration**.
2. Click the **General** tab.
3. Click the **Edit** button at the bottom of the page.
4. Go to the **Application Settings** section.
5. Click to select the *Enable Syslog/CEF Logging* checkbox. A syslog/CEF section will appear.
6. Type the IP address or name for the XSIAM broker VM in the Syslog/CEF Server text box.
7. Type the port number where the logging information will be passed (6514 is the default port for secure TCP syslog) in the Syslog/CEF Port text box.
8. Click the Syslog/CEF Protocol dropdown list and select *Secure TCP*. Secure TCP means either TLS v1.2 or v1.1 because other versions of SSL, such as SSL v3 and TLS v1.0, have known weaknesses.
9. Click to select *Syslog/CEF Time Zone* list box to UTC Time or Server Time, depending on your preference.
10. Click the **Save** button.
 
 More information on SIEM integrations can be found [here](https://docs.thycotic.com/ss/11.1.0/events-and-alerts/secure-syslog-cef) and [here](https://docs.delinea.com/int/current/splunk/splunk-on-prem/config/event-log-analysis.md)

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.


1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - thycotic_software
   - product as product - secret_server
</~XSIAM>
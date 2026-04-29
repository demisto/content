# Delinea Secret Server / Platform

This pack includes XSIAM content.

Secret Server and Platform are the fully featured Privileged Account Management (PAM) solution available both on premise and in the cloud. They empowers security and IT operations teams to secure and manage all types of privileged accounts, offering the fastest time to value of any PAM solution. Integrations between Palo Alto Networks and Delinea allow you to manage credentials for applications, databases, CI/CD tools, and services without disrupting the development process.

This integration allows to secure privileges for service, application, root and administrator accounts across the enterprise. This updated package has the following:

- Retrieve a secret with the necessary fields for subsequent authentication, supported for both Secret Server and Platform.
- Methods for managing Secret objects (Secret Server and Platform): create, update, search, delete, check-in/check-out.
- Methods for managing Folder objects (Secret Server and Platform): create, update, search, delete.
- Methods for managing User objects (Platform): create, update, search, delete.
- Methods for managing User objects (Platform): create, update, search, delete, search by text
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

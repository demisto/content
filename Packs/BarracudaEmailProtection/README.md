# Barracuda Email Protection

### The world′s most comprehensive email protection, made radically easy.

See <https://www.barracuda.com/products/email-protection> for more information on this prouct.

## Configuration on Server Side

To configure the Mail syslog, using the Barracuda Email Security Gateway web interface:

1. Navigate to **Settings** > **Advanced** > **Advanced Networking**.
1. Enter the IP address and port of the syslog server to which syslog data related to mail flow should be sent. You can also specify the protocol – TCP or UDP – over which syslog data should be transmitted. TCP is recommended.

Syslog data is the same information as that used to build the Message Log in the Barracuda Email Security Gateway and includes data such as the connecting IP Address, envelope 'From' address, envelope 'To' address, and the spam score for the messages transmitted. This syslog data appears on the mail facility at the debug priority level on the specified syslog server. As the Barracuda Email Security Gateway uses the syslog messages internally for its own message logging, it is not possible to change the facility or the priority level. See the **Syslog** section of the **ADVANCED** > **Troubleshooting** page in the Barracuda Email Security Gateway web interface to open a window and view the Mail syslog output.

If you are running syslog on a UNIX machine, be sure to start the syslog daemon process with the “-r” option so that it can receive messages from sources other than itself. Windows users will have to install a separate program to utilize syslog since the Windows OS doesn’t include syslog capability. Kiwi Syslog is a popular solution, but there are many others available to choose from, both free and commercial.

Syslog messages are sent via either TCP or UDP to the standard syslog port of 514. If there are any firewalls between the Barracuda Email Security Gateway and the server receiving the syslog messages, make sure that port 514 is open on the firewalls.

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM

To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
1. Right-click, and select **Syslog Collector** > **Configure**.
1. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - barracuda
   - product as product - email_protection

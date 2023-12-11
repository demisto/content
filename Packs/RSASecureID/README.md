# RSA SecureID
<~XSIAM>
 
This pack includes Cortex XSIAM content.
 
## Configuration on Server Side
You need to configure RSA SecureID to forward Syslog messages.
 
In RSA Authentication Manager 8.4 there is rsyslog instead of syslog-ng.
In the configuration file in /etc/rsyslog.d/remote.conf you define the syslog server(s) to which you want to connect.
There is /etc/rsylog.conf for rest of the configuration related to rsyslog.
1. Launch an SSH client, such as PuTTY.
2. Login to the primary Authentication Manager server as **rsaadmin** and enter the operating system password.
3. Changes the privileges of **rsaadmin**.
4. Enter the operating system password when prompted.
5. Go to **/etc/rsyslog.d/** and make a copy of the **remote.conf** file.
6. Edit the **remote.conf** configuration file using an editor such as vi.
7. Append the remote syslog servers in the **/etc/rsyslog.d/remote.conf** file.
8. Restart the syslog daemon and verify the status with commands (described in the documentation).
9. Configure Security Console Logging to send to localhost **127.0.0.1**.
10. Monitor the outgoing traffic to the remote syslog server.
11. Once done with the primary, please repeat steps 1 through 9 above on each replica server in your deployment.  Be sure to complete the tasks on one before moving to the other(s).

* To configure RSA Authentication Manager 8.4 or later to send data to remote syslog servers, refer to the full documentation provided by [RSA] (https://community.rsa.com/t5/securid-knowledge-base/how-to-configure-rsa-authentication-manager-8-4-or-later-to-send/ta-p/2823).
  
* To configure RSA Authentication Manager 8.1, 8.2, 8.3 to send data to remote syslog servers, refer to the full documentation provided by [RSA] (https://community.rsa.com/t5/securid-knowledge-base/how-to-configure-rsa-authentication-manager-8-1-8-2-8-3-to-send/ta-p/2525).
  
## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.
 
### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).
 
You can configure the specific vendor and product for this instance.
 
1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**.
2. Go to the **Apps** column under the **Brokers** tab and add the **Syslog Collector** app for the relevant broker instance. If the app already exists, hover over it and click **Configure**.
3. Click **Add New** for adding a new syslog data source.
4. When configuring the new syslog data source, set the following values:
   | Parameter     | Value   
   | :---          | :---        
   | `Vendor`      | Enter **RSA**.
   | `Product`     | Enter **SecureID**.
 
</~XSIAM>
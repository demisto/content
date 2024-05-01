

# VMware vCenter

<~XSIAM>
This pack includes Cortex XSIAM content.
  
## Configuration on Server Side
This section describes the configuration required on the VMware vCenter server to forward its event logs to Cortex XSIAM Broker VM via syslog.
 
1. Log in to the vCenter Server Management Interface as user root.
2. In the vCenter Server Management Interface, select **Syslog**.
3. In the *Forwarding Configuration* section - 
   * If you have not yet configured any remote syslog hosts, click **Configure**. 
   * If you configured hosts previously, click **Edit**.
4. From the **Protocol** drop-down menu, select the requested protocol for the syslog forwarding (for example *UDP*).
5. In the **Port** text box, enter the port number that would be used for communication with the target Cortex XSIAM Broker VM syslog server.
6. In the *Create Forwarding Configuration* pane, click **Add** to enter another remote syslog server.
7. Click **Save**.
 
For additional details, see [Forward vCenter Server Log Files to Remote Syslog Server](https://docs.vmware.com/en/VMware-vSphere/7.0/com.vmware.vsphere.monitoring.doc/GUID-9633A961-A5C3-4658-B099-B81E0512DC21.html)

## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).
You can configure the specific vendor and product for this instance.
1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**. 
2. Right-click, and select **Syslog Collector** &rarr; **Configure**.
3. When configuring the Syslog Collector, set the following parameters:
   | Parameter     | Value    
   | :---          | :---                    
   | `Protocol`    | Should be aligned with the selected *protocol* value in the vCenter Server Management Interface syslog configuration, as described in the [Configuration on Server Side](#configuration-on-server-side) section above.   
   | `Port`        | Should be aligned with the *port* defined in the vCenter Server Management Interface syslog configuration as described in the [Configuration on Server Side](#configuration-on-server-side) section above.   
   | `Format`      | Select **Auto-Detect**. 
   | `Vendor`      | Enter **VMware**.
   | `Product`     | Enter **vCenter**.

</~XSIAM>	

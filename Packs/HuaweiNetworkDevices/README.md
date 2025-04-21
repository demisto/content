# Huawei Network Devices
<~XSIAM>
This pack includes Cortex XSIAM content.

## Important Notes
* This pack is supported for Huawei S Series Switches and Huawei AR Series Routers.
* Timestamp parsing support is under the assumption that a UTC +0000 format is being used.

## Configuration on Server Side
This section describes the configuration that needs to be done on a Huawei S Series Switch or AR Series Router, in order to forward its event logs to Cortex XSIAM Broker VM via syslog.

1. Log in to your Huawei S Series Switch/AR Series Router command line Interface (CLI).
2. Type the following command to access the system view:
    ```bash
    system-view
    ```
3. Type the following command to enable the information center:
   ```bash
   info-center enable
    ```
4. Type the following command to send informational level log messages to the default channel:
    ```bash
    info-center source default channel loghost log level informational debug state off trap state off
    ```
5. **Optional:** To verify your Huawei S Series Switch/AR Series Router source configuration, type the command:
    ```bash
    display channel loghost
    ```
6. Type the following command to configure the IP address for ***Broker-VM*** as the log host:
    ```bash
    info-center loghost <IP address> facility <local>
    ```
    *\<IP address\>* is the IP address of the Broker-VM.

    *\<local\>* is the syslog facility, for example, local0.  
    <br>
7. Type the following command to exit the configuration:
    ```bash
    quit
    ```
## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.


### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Go to the apps tab and add the **Syslog** app. If it already exists, click the **Syslog** app and then click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following values:
   | Parameter     | Value   
   | :---          | :---        
   | `Vendor`      | Enter **Huawei**.
   | `Product`     | Enter **Network Devices**.

</~XSIAM>
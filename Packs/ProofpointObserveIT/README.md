# Proofpoint ObserveIT
This pack includes Cortex XSIAM content. 

## Configuration on Server Side
You need to configure Proofpoint ObserveIT CEF log integration.

Follow the below steps to configure CEF log integration:
1. Go to **Configuration** > **Integrations** > **Integrated SIEM**.
2. Click the **SIEM Log Integration** tab.
3. Select the **Enable export to ARCSight format** checkbox.
4. In the **Log data** section, select **Activity Alerts** (should be selected by default).
5. In the **Log file properties** section, accept the default log file location and name:
   - Path: C:\Program File\ObserveIT\NotificationService\LogFiles\ArcSight
   - Name: Observeit_activity_log.cef
6. In the **Log file cleanup** section, schedule the frequency for clearing the log file.
7. Click **Save**.

More information can be found [here](https://documentation.observeit.com/configuration_guide/configuring_cef_log_integration.htm)

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Add the **Files and Folders Collector** app.
3. Configure the folder path that contains the logs. Make sure to reference the hostname in the path.
4. Specify a username that has permission to the folder and fill its password.
5. Make sure that the **Log Format** is set to CEF.
6. Set the below values under **Data Source Mapping**:
   - Vendor - ObserveIT
   - Product - ObserveIT
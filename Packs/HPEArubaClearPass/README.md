# HPE Aruba ClearPass
This pack includes Cortex XSIAM content.
<~XSIAM>
## Collect Events from Product
You need to configure Aruba ClearPass to forward Syslog messages in CEF format.

Open your Aruba ClearPass UI and follow these instructions:
### Adding Syslog Targets 
* ***[Product Documentation](https://www.arubanetworks.com/techdocs/ClearPass/6.8/PolicyManager/Content/CPPM_UserGuide/Admin/syslogTargets.html)***
1. Navigate to **Administration** > **External Servers** > **Syslog Targets**.
2. Click the **Add** link.
3. Specify the server credentials at the prompt window.
4. Click **Save**.

### Adding a Syslog Export Filter 
* ***[Product Documentation](https://www.arubanetworks.com/techdocs/ClearPass/6.8/PolicyManager/Content/CPPM_UserGuide/Admin/syslogExportFilters_add_syslog_filter_general.htm)***
1. Navigate to **Administration** > **External Servers** > **Syslog Export Filters**.
2. From the **Syslog Export Filters** page, click **Add**.
   * Under **Export Event Format Type**, choose the **Comma Event Format (CEF)**.
   * Under **Syslog Servers**, choose the relevant server config for XSIAM.
3. Save your filter.

* Pay attention: Timestamp parsing is supported for the **rt** field in Epoch 13 digits (MILLIS) timestamp format.
</~XSIAM>

Use this content pack to help automate adding devices in the network to a block list in response to security events, such as a stolen or compromised device.

## What does this pack do?
The integration in this pack enables you to:
- Get a list of endpoints.
- Update fields of an endpoint.
- Get a list of attributes.
- Create, update, or delete an attribute.
- Get a list of active sessions.
- Disconnect an active session.

# Box
<~XSIAM>

This pack includes Cortex XSIAM content. 

### This pack includes:
- Collection of Box event log messages.
- Log Normalization - XDM mapping for key event types.

## Supported Event Types:
- All event types from [./2.0/events](https://developer.box.com/reference/get-events/) API call.

## Time Zone support for XSIAM
For supporting Time Zone parsing, time should be set to UTC +0000 [Product documentation](https://support.box.com/hc/en-us/articles/360044194253-Language-and-Time-Zones):
1. Sign into your Box account.
2. Click your initials in the top-right corner to open the **Account Menu**.
3. Click **Account Settings**.
4. The **Account** tab should open by default. Locate the **General Options** section.
5. Select your preferred timezone from the pulldown menu under **Time Zone**.
6. Click **Save Changes** in the top right to save your settings.

## Enabling Box Event Collector
To configure the Box Event Collector to receive log messages:
1. Make sure you have the Box pack installed on your Cortex XSIAM tenant.
2. Go to **Settings** &rarr; **Configurations** &rarr; **Automation & Feed Integrations**.
3. In the search bar, type **Box** and click **+ Add instance**.
4. Follow the integration steps to send logs from Box to your Cortex XSIAM tenant.
   
</~XSIAM>
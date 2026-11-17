Cisco Secure Email Threat Defense (ETD) is a cloud-native email security service that detects and remediates threats such as phishing, business email compromise, and malware.

## Enable Log Export in Cisco ETD

Events are only available after log export is enabled in the Cisco ETD UI.

1. Sign in to the Cisco Secure Email Threat Defense portal.
2. Navigate to **Administration > Business**.
3. In the **Export Log Preferences** section, select the log types you want to collect: message event logs, audit logs, and blocked connection logs.
4. Wait for the first export files to be generated: 15 minutes for audit and connection logs, 20 minutes for message event logs.

Blocked connection logs require Inline Mode and an ETD Advantage license.

## Obtain API Credentials

1. In the Cisco Secure Email Threat Defense portal, navigate to **Administration > API Clients**.
2. Create a new API client.
3. Record the **Client ID**, **Client Secret**, and **API Key**. The Client Secret is shown only once.

## Configure the Instance

1. Set **ETD API Base URL** to the endpoint for your region:

   | Region | Base URL |
   | --- | --- |
   | Americas | `https://api.us.etd.cisco.com` |
   | Europe | `https://api.de.etd.cisco.com` |
   | Australia | `https://api.au.etd.cisco.com` |
   | India | `https://api.in.etd.cisco.com` |
   | UAE | `https://api.ae.etd.cisco.com` |

2. Enter the **ETD API Key**, **Client ID**, and **Client Secret** recorded above.
3. Select the **Event Types** to collect. These must match the log types enabled in the ETD UI.
4. Enable **Fetch events**.
5. Click **Test** to verify connectivity, then **Save**.

## Collection Behavior

Cisco ETD publishes logs as hourly export files, and the hour currently in progress cannot be retrieved. Events therefore appear in Cortex XSIAM with a delay of up to roughly 90 minutes. On the first fetch only the most recent completed hour is collected; historical data is not backfilled.

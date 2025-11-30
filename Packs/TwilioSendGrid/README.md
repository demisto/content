# Twilio SendGrid

This pack includes Cortex XSIAM content for collecting and analyzing email activity events from Twilio SendGrid.

## What does this pack do?

Twilio SendGrid is a cloud-based email platform designed to help businesses send and manage both transactional and marketing emails reliably and at scale. This pack enables you to:

- Collect email activity events from Twilio SendGrid's Email Activity Feed API
- Monitor email delivery, opens, clicks, bounces, and other email engagement metrics
- Analyze email security events and potential threats
- Track email campaign performance and user engagement
- Investigate email-related incidents and anomalies

The pack provides an event collector integration that automatically fetches email activity data and ingests it into Cortex XSIAM for analysis, correlation, and alerting.

## Prerequisites

Before using this pack, ensure you have:

1. **Twilio SendGrid Account**: An active SendGrid account with API access
2. **Email Activity History Add-on**: You must purchase [additional email activity history](https://app.sendgrid.com/settings/billing/addons/email_activity) to access the Email Activity Feed API
3. **API Key**: A SendGrid API key with Email Activity read permissions

## Configuration

### Generate a SendGrid API Key

1. Log in to your [SendGrid account](https://app.sendgrid.com/)
2. Navigate to **Settings** > **API Keys**
3. Click **Create API Key**
4. Provide a name for your API key (e.g., "XSIAM Event Collector")
5. Select **Restricted Access** and grant the following permission:
   - **Email Activity**: Read Access
6. Click **Create & View**
7. Copy the API key immediately (it will only be shown once)

### Configure the Integration in Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Integrations**
2. Search for **Twilio SendGrid Event Collector**
3. Click **Add instance** to create and configure a new integration instance
4. Configure the following parameters:

   | Parameter | Description | Required |
   |-----------|-------------|----------|
   | Server URL | The SendGrid API base URL (default: `api.sendgrid.com`) | Yes |
   | API Secret Key | Your SendGrid API key with Email Activity read permissions | Yes |
   | Maximum Email Activity Messages per fetch | Maximum number of events to fetch per API call (1-10000, default: 10000) | No |
   | Events Fetch Interval | How often to fetch events (default: 1 minute) | No |
   | Trust any certificate (not secure) | Enable to trust any certificate (not recommended for production) | No |
   | Use system proxy settings | Enable to use system proxy settings | No |

5. Click **Test** to validate the connection
6. Click **Save & Exit** to save the configuration

## What's Included

### Integrations

- **Twilio SendGrid Event Collector**: Fetches email activity events from the SendGrid Email Activity Feed API and ingests them into Cortex XSIAM

### Commands

- **twilio-sendgrid-get-events**: Manually retrieve email activity events for testing and debugging purposes

## Use Cases

- **Email Security Monitoring**: Track suspicious email activity, bounces, and spam reports
- **Email Delivery Analytics**: Monitor email delivery rates, open rates, and click-through rates
- **Incident Investigation**: Investigate email-related security incidents and user complaints
- **Compliance and Auditing**: Maintain records of email communications for compliance purposes
- **Campaign Performance**: Analyze marketing email campaign effectiveness

## Additional Information

For more information about Twilio SendGrid and the Email Activity Feed API, refer to:
- [SendGrid Documentation](https://docs.sendgrid.com/)
- [Email Activity Feed API](https://docs.sendgrid.com/api-reference/e-mail-activity/filter-all-messages)

## Support

This pack is supported by Cortex XSOAR. For support, please contact [Palo Alto Networks Support](https://www.paloaltonetworks.com/cortex).
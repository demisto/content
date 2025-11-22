## Twilio SendGrid Event Collector

This integration collects email activity events from Twilio SendGrid for monitoring and analysis in Cortex XSIAM.

### Prerequisites

Before configuring the integration, you need:

1. **Twilio SendGrid Account**: An active SendGrid account with email activity history enabled
2. **API Key**: A SendGrid API key with appropriate permissions

### Generating an API Key

1. Log in to your [SendGrid account](https://app.sendgrid.com/)
2. Navigate to **Settings** > **API Keys**
3. Click **Create API Key**
4. Enter a name for your API key (e.g., "XSIAM Event Collector")
5. Select **Full Access** or create a custom key with at least the following permissions:
   - **Email Activity** - Read access
6. Click **Create & View**
7. **Important**: Copy the API key immediately - you won't be able to see it again
8. Store the API key securely

### Configuration

1. Navigate to **Settings** > **Integrations** > **Servers & Services**
2. Search for **Twilio SendGrid Event Collector**
3. Click **Add instance**
4. Configure the following parameters:

#### Required Parameters

- **Server URL**: The SendGrid API base URL (default: `api.sendgrid.com`)
- **API Secret Key**: Paste the API key you generated earlier

#### Optional Parameters

- **Maximum Email Activity Messages per fetch**: Number of events to fetch per API call (1-1000, default: 10)
- **Events Fetch Interval**: How often to fetch events in minutes (default: 1)

5. Click **Test** to verify the connection
6. Click **Save & exit**

### Email Activity History Requirement

**Important**: You must purchase [additional email activity history](https://app.sendgrid.com/settings/billing/addons/email_activity) to access the Email Activity Feed API. Without this add-on, the integration will not be able to fetch events.

### Troubleshooting

#### Authentication Errors

If you receive authentication errors:
- Verify your API key is correct
- Ensure the API key has the necessary permissions for Email Activity
- Check that the API key hasn't been deleted or revoked in SendGrid

#### No Events Returned

If no events are being collected:
- Verify you have the Email Activity History add-on enabled
- Check that your SendGrid account is actively sending emails
- Use the debug command to manually test: `!twilio-sendgrid-get-events from_date="7 days" limit=10 should_push_events=false`

#### Rate Limiting

If you encounter rate limit errors:
- Reduce the "Maximum Email Activity Messages per fetch" value
- Increase the "Events Fetch Interval" to fetch less frequently
- Contact SendGrid support to understand your account's rate limits

### Debug Command

Use the `twilio-sendgrid-get-events` command for testing and debugging:

```
!twilio-sendgrid-get-events from_date="3 days" limit=100 should_push_events=false
```

Parameters:
- `from_date`: Start time (e.g., "3 days", "2024-01-15T10:00:00Z")
- `to_date`: End time (optional)
- `limit`: Maximum events to retrieve (1-1000)
- `should_push_events`: Set to `true` to send events to XSIAM, `false` to only display

**Note**: This command is for development/debugging only and should be used with caution to avoid event duplication.

### Support

For issues related to:
- **Integration configuration**: Contact Palo Alto Networks support
- **SendGrid API or account**: Contact [Twilio SendGrid support](https://support.sendgrid.com/)
- **Email Activity add-on**: Contact SendGrid billing support
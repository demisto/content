## Twilio SendGrid

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
2. Search for **Twilio SendGrid**
3. Click **Add instance**
4. Configure the following parameters:
5. Click **Test** to verify the connection
6. Click **Save & exit**

### Email Activity History Requirement

**Important**: You must purchase [additional email activity history](https://app.sendgrid.com/settings/billing/addons/email_activity) to access the Email Activity Feed API. Without this add-on, the integration will not be able to fetch events.

### Support

For issues related to:
- **Integration configuration**: Contact Palo Alto Networks support
- **SendGrid API or account**: Contact [Twilio SendGrid support](https://support.sendgrid.com/)
- **Email Activity add-on**: Contact SendGrid billing support
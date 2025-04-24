
# Threat Vault Feed

This integration uses the Threat Vault API to fetch predefined EDL (External Dynamic List) lists.

## Configuration

1. Navigate to **Settings** > **Integrations**
2. Search for PANW Threat Vault Feed.
3. Click **Add instance** to create and configure a new integration instance.

### Required Parameters
* **API Key**: Your PANW Threat Vault API key.
* **Base URL**: The base URL for the PANW Threat Vault API.
* **Fetch Interval**: How often to fetch new data from the feed (in minutes).

## Usage

Once configured, the integration will automatically fetch the specified EDL lists at the defined interval. The fetched data can be used in playbooks, indicators, and other Cortex XSOAR features.

### Commands
* **threatvault-get-indicators**: Manually fetch indicators from the PANW Threat Vault feed.

## Troubleshooting

If you encounter any issues:
1. Verify your API key is correct and has the necessary permissions.
2. Check the integration's logs for any error messages.
3. Ensure your network allows outbound connections to the PANW Threat Vault API endpoint.

For more information on using this integration, refer to the PANW Threat Vault documentation.

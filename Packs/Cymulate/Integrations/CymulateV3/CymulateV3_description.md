# Cymulate v3 Integration

Cymulate is a Multi-Vector Cyber Attack, Breach and Attack Simulation (BAS) platform that continuously validates security posture by simulating real-world threats across multiple security controls.

This integration fetches findings from completed Cymulate assessments as Cortex XSOAR incidents using the V2 Assessment API.

## How It Works

1. The integration periodically queries the Cymulate V2 API for completed assessments.
2. For each new assessment, it retrieves all findings.
3. Only findings with status **"Not Prevented"** are created as XSOAR incidents.
4. The **Fetch category** parameter allows filtering to only **Threat Feed IOC** tagged findings.

## Obtaining Your API Key

To generate an API key from your Cymulate instance:

1. Connect to your Cymulate instance.
2. Go to your **profile** > **Settings** > **Cymulate API**.
3. Click **Add API key** button.
4. Give the API key a name.
5. Enable the required API endpoints.
6. Copy the generated API key.

## Configuration Parameters

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API token | Cymulate API token used for authentication (sent as `x-token`). | False |
| Base URL | Cymulate API base URL (for example: `https://api.app.cymulate.com`). | False |
| Fetch incidents | When enabled, fetches Cymulate assessment findings as Cortex XSOAR incidents. | False |
| Fetch category | **All** fetches all "Not Prevented" findings. **Threat Feed IOCs** fetches only findings tagged as Threat Feed IOC. Default: All. | False |
| First fetch timestamp | First time to fetch incidents from (e.g., `12 hours`, `7 days`). | False |
| Max Fetch | Maximum number of incidents to return per fetch run. Default: 200. | False |
| Trust any certificate (not secure) | If checked, SSL certificate verification is disabled. | False |
| Use system proxy settings | Use the system proxy settings for HTTP/S requests. | False |
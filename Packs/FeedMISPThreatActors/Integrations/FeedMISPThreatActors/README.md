# MISP Threat Actors Feed Integration

## Overview
This integration fetches threat actor information from the MISP Threat Actors Galaxy and creates indicators in Cortex TIM. It provides valuable threat intelligence about various threat actors, including their aliases, targets, origin countries, and related information.

## Use Cases
- Fetch and update threat actor information regularly.
- Enrich your threat intelligence with detailed information about known threat actors.
- Create relationships between threat actors and their targets or aliases.

## Configuration
1. Navigate to **Settings** > **Integrations** > **Instances**.
2. Search for MISP Threat Actors Feed.
3. Click **Add instance** to create and configure a new integration instance.
    - **Name**: A meaningful name for the integration instance.
    - **URL**: The URL to fetch the MISP Threat Actors Galaxy file (default: https://raw.githubusercontent.com/MISP/misp-galaxy/main/galaxies/threat-actor.json)
    - **Feed Fetch Interval**: How often the feed should be fetched and indicators created or updated.
    - **Reliability**: Reliability of the feed source.
    - **TLP Color**: Traffic Light Protocol color for the indicators.
    - **Feed Tags**: Tags to be added to each indicator fetched from the feed.
    - **Bypass exclusion list**: Whether to bypass the exclusion list when creating indicators.
4. Click **Test** to validate the URLs and connection.
5. Save and exit the integration instance.

## Commands
This integration works in the background to fetch indicators and does not have any specific commands to execute manually.

### fetch-indicators
This command runs in the background at the specified feed fetch interval to create and update threat actor indicators.

## Additional Information
- The integration fetches the latest version of the MISP Threat Actors Galaxy file and only processes new updates.
- Indicators are created with rich metadata, including descriptions, aliases, targeted sectors and countries, and origin information when available.
- The integration creates relationships between threat actors and their aliases, targets, and attributed countries.

## Troubleshooting
- If the integration fails to fetch data, ensure the provided URL is accessible and the network settings (including proxy if used) are correctly configured.
- Check the integration logs for any error messages or debugging information.

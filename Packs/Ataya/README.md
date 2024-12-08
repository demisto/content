# Ataya Harmony Interface for Cortex XSOAR of Palo Alto Networks

## Summary
The Webhook interface can be enabled in the Ataya's Harmony Platform. Once done, the Ataya's 5G core network will publish the clients’ session events to XSOAR, which can notify the Palo Alto firewall gateway to apply the desired policy to the client connections.

## Requirement
The following content is necessary for complete the integration.
- Ataya Harmony
- Generic Webhook
- Palo Alto Networks PAN-OS

## Configuration
The configuration instruction of Generic Webhook application and Ataya Harmony Platform.

### Generic Webhook
1. Choose _Ataya_ as the incident type
2. Choose _Ataya Mapping_ as the incident type
3. Configure the webhook server setting (listen port and credentials)

### Palo Alto Networks PAN-OS
1. Configure the server URL and the API key of the NGFW

### Ataya Harmony
1. Configure the Harmony URL and the API access Token

## How to generate token from Ataya Harmony

### Webhook Token
1. Login to Ataya Harmony
2. Navigate to **Organization** > **Setting** > **Webhook**.
3. Right-click **+Webhook**, and fill the configuration related to Generic Webhook server.

#### Supported Published Events
- Session Create
- Session Modification
- Session Delete
- Session EventType

### API Access Token
1. Login to Ataya Harmony
2. Navigate to **Organization** > **Setting** > **API Access Control**.
3. Right-click **+API Access Key**, and fill the configuration related to API Access Token.

_Check [Ataya Inc.](https://www.ataya.io/) for product details on Ataya Harmony Platform_

[![Ataya Overview](doc_files/Blue_svg.png)](https://www.ataya.io/)

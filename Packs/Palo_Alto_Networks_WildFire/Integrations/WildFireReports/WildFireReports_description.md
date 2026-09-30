This integration is set up by default on Cortex XSOAR with the Threat Intel Module (TIM). It is designed for internal use with the TIM Sample Analysis feature. To run ad hoc CLI commands to generate WildFire reports, use the Palo Alto Networks WildFire v2 integration instead.

#### How to retrieve a Palo Alto Networks WildFire Reports API key

Note: If you have a TIM license that is up-to-date, you do not need to set up an API key.
The required information is automatically retrieved from your Cortex XSOAR TIM license.
This API key is used in the *API Key* field in the integration configuration.

1. Navigate to your [WildFire Account](https://wildfire.paloaltonetworks.com/wildfire/account).
2. Log in to your *WildFire* account.
3. Select the *Account* tab from the menu.
4. Copy the API key.

#### Troubleshooting: Override Agent (Advanced)

The *Override Agent* advanced parameter is available for cases where the automatic agent detection fails (e.g., API requests return errors or the **Test** button fails due to an incorrect agent header). By default, the integration auto-detects the correct agent based on the platform. Only change this setting if instructed to do so by support or if auto-detection is not working correctly.

Available options:
- **auto** (default) — Auto-detect based on the platform.
- **xdr** — Cortex XSIAM.
- **xsoartim** — XSOAR TIM API Key.
- **pcc** — Prisma Cloud Compute.
- **prismaaccessapi** — Prisma Access.
- **other** — NGFW or WildFire API.

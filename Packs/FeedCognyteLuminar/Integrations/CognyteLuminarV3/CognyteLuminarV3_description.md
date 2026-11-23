## Cognyte Luminar V3 Feed

Use this feed integration to fetch intelligence-based IOCs and customer-related leaked records identified by Luminar,
using the Luminar TAXII 2.1 external API (STIX 2.1).

## How to get Luminar credentials

1. Contact Cognyte at luminar@cognyte.com to register for Luminar API access.
2. Cognyte provisions an API account (TAXII realm), a Client ID, and a Client Secret for your tenant.
3. In the integration instance, enter the **Luminar API Account ID**, the **Client ID** in the credentials identifier field, and the **Client Secret** in the credentials password field.

## Permissions

The provided credentials must have the `externalAPI/stix.readonly` scope (granted by default to Luminar API accounts).

## Troubleshooting

- **"Luminar realm does not exist"**: verify the Luminar API Account ID and Luminar Base URL parameters.
- **"Authentication with the Luminar API failed"**: verify the Client ID and Client Secret.
- **406 errors from the TAXII endpoints**: the Luminar API accepts only the Authorization header on TAXII requests - this is handled by the integration.

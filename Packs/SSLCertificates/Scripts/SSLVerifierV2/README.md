Use this automation to check for validity of your SSL certificate and get the time until expiration.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utilities |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| URL | URL to check |
| Port | Port to check |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| SSLVerifierV2.Certificate.ExpirationDate | Date Certificate Expires | string |
| SSLVerifierV2.Certificate.Site | Site that was checked | string |
| SSLVerifierV2.Certificate.TimeToExpiration | Days to expiration | string |

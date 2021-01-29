This pack introduces the Certificate indicator type for handling X509 Certificates in Cortex XSOAR. 

## Default Indicator Type

This pack includes the Certificate indicator type.

## Indicator Fields

This following are the indicator fields for the Certificate indicator layout.

- Certificate Names
- Certificate Signature
- Certificate Validation Checks
- Extension
- Issuer DN (Issuer Distinguished Name)
- PEM (Certificate in PEM format)
- Public Key
- Serial Number
- SPKI SHA256
- SHA256 fingerprint of Subject Public Key Info
- Subject Alternative Names
- Subject DN (Subject Distinguished Name)
- Validity Not After (End of certificate validity period)
- Validity Not Before (Starting of certificate validity period)

## Automation
This pack includes the following 2 Automations.

- **CertificateExtract** - Extracts all the certificate fields from a X509 certificate in PEM or DER format.
- **CertificateReputation** - Enriches and calculates the reputation of a Certificate indicator.

## Layout

The default Certificate Indicator layout includes information about the indicators on both the Info page and the Details page. 

### The Info Page
The following information appears in the Info page.
- Creation date, modified date, expiration date of the indicator.
- Reputation of the indicator sources.
- The date, event, and source of the indicators.
- Certificate information, validation checks, Subject Alternative Name (SAN), and fingerprints of the indicators
- Related incidents.

It also includes [action buttons](#action-buttons) for Analysts to utilize in their day to day.

### The Details Page
The following information appears in the Details page. 
- Extensions 
- Public key
- The raw certificate
- Extended details

### Action Buttons

The following action button scripts appear in the Certificate Indicator layout:
- Enrich - Enriches the indicators.
- Expire - Allows a user to expire an indicator. When an indicator is expired, it remains in the indicator's table with the status of expired.




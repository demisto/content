This Python script is designed to analyze a PFX (Personal Information Exchange) file for various suspicious or noteworthy characteristics from a security perspective.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| fileEntryId | The ID of the file entry from the incident context that contains the PFX file. |
| pfxPassword | Password for the PFX file \(if encrypted\). |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PFXAnalysis.Private_Key_Present | True if a private key was found in the PFX. | boolean |
| PFXAnalysis.Key_Type | Type of the private key \(e.g., RSA, ECC\). | string |
| PFXAnalysis.Key_Size | Size of the private key in bits \(for RSA\) or curve name \(for ECC\). | number |
| PFXAnalysis.Certificate_Present | True if a certificate was found in the PFX. | boolean |
| PFXAnalysis.Common_Name | Common Name from the certificate's subject. | string |
| PFXAnalysis.Issuer | Common Name of the certificate's issuer. | string |
| PFXAnalysis.Validity_Start | Certificate validity start date/time \(UTC\). | date |
| PFXAnalysis.Validity_End | Certificate validity end date/time \(UTC\). | date |
| PFXAnalysis.Validity_Days | Total number of days the certificate is valid for. | number |
| PFXAnalysis.Self_Signed | True if the certificate is self-signed. | boolean |
| PFXAnalysis.Trusted_Issuer | True if the certificate's issuer is in the predefined trusted list. | boolean |
| PFXAnalysis.CRL_URIs | List of CRL Distribution Point URIs. | string |
| PFXAnalysis.OCSP_URIs | List of OCSP Access Method URIs. | string |
| PFXAnalysis.Suspicious_Keywords_in_CN | True if suspicious keywords were found in the Common Name. | boolean |
| PFXAnalysis.Reasons | A list of all identified suspicious reasons. | string |
| PFXAnalysis.Is_Suspicious | Overall boolean indicator if the PFX is considered suspicious. | boolean |

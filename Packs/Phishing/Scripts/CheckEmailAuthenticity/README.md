Checks the authenticity of an email based on the email's SPF, DMARC, and DKIM.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | phishing, ews, email |
| Cortex XSOAR Version | 5.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* Agari Message Remediation - Agari Phishing Defense
* Email Headers Check - Generic
* Phishing - Generic v3
* Phishing Investigation - Generic v2
* Report Categorization - Cofense Triage v3

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| headers | A list of dictionaries of headers in the form of "Header name":"Header value". |
| original_authentication_header | The header that holds the original Authentication-Results header value. This can be used when an intermediate server changes the original email and holds the original header value in a different header. Note - Use this only if you trust the server creating this header. |
| SPF_override_none | Override value for SPF=None. |
| SPF_override_neutral | Override value for SPF=neutral. |
| SPF_override_pass | Override value for SPF=pass. |
| SPF_override_fail | Override value for SPF=fail. |
| SPF_override_softfail | Override value for SPF=softfail. |
| SPF_override_temperror | Override value for SPF=temperror. |
| SPF_override_permerror | Override value for SPF=permerror.  |
| DKIM_override_none | Override value for DKIM=none. |
| DKIM_override_pass | Override value for DKIM=pass. |
| DKIM_override_fail | Override value for DKIM=fail. |
| DKIM_override_policy | Override value for DKIM=policy. |
| DKIM_override_neutral | Override value for DKIM=neutral. |
| DKIM_override_temperror | Override value for DKIM=temperror. |
| DKIM_override_permerror | Override value for DKIM=permerror. |
| DMARC_override_none | Override value for DMARC=none. |
| DMARC_override_pass | Override value for DMARC=pass. |
| DMARC_override_fail | Override value for DMARC=fail. |
| DMARC_override_temperror | Override value for DMARC=temperror. |
| DMARC_override_permerror | Override value for DMARC=permerror. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Email.SPF.MessageID | SPF ID | String |
| Email.SPF.Validation-Result | Validation Result. Possible values are "None", "Neutral", "Pass", "Fail", "SoftFail", "TempError", and "PermError".  | String |
| Email.SPF.Reason | Reason for the SPF result, which is located in the headers of the email. | String |
| Email.SPF.Sender-IP | Email sender IP address. | String |
| Email.DKIM.Message-ID | DKIM ID. | String |
| Email.DKIM.Reason | DKIM reason \(if found\). | String |
| Email.DMARC.Message-ID | DMARC ID. | String |
| Email.DMARC.Validation-Result | DMARC reason. Possible values are "None", "Pass", "Fail", "Temperror", and "Permerror". | String |
| Email.DMARC.Tags | DMARC Tags \(if found\) | String |
| Email.DMARC.From-Domain | Sender's Domain | String |
| Email.DKIM.Signing-Domain | Sender's Domain | String |
| Email.AuthenticityCheck | Possible values are be: Fail / Suspicious / Undetermined / Pass | Unknown |
| Email.DKIM | DKIM information extracted from the email. | Unknown |
| Email.SPF | SPF information extracted from the email. | Unknown |
| Email.DMARC | DMARC information extracted from the email. | Unknown |
| Email.DKIM.Validation-Result | Validation result. Possible values are "None", "Pass", "Fail", "Policy", "Neutral", "Temperror", and "Permerror". | Unknown |

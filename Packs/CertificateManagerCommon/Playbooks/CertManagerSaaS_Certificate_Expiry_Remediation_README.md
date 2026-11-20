# CertManagerSaaS Certificate Expiry Remediation

Triages a CyberArk Certificate Manager SaaS certificate-expiry issue: resolves the certificate, records it on the case, sets severity from time to expiry, then either requests a replacement or hands the case to the certificate owner or an assignee role.

Hydration comes first by design. The fetched incident already carries the certificate's fields, but the lookup refreshes them - the certificate may have been renewed or revoked since the fetch - and resolves the fingerprint the later steps need.

Severity thresholds are playbook inputs so they can be aligned with the tenant-global Certificate Manager SaaS expiry thresholds, which are customer-configured and cannot be shipped in this pack. If the two disagree they disagree silently.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* CertManagerSaaS Certificate Request

### Integrations

* CyberArk Certificate Manager SaaS
* Next-Gen Trust Security

### Scripts

* AssignAnalystToIncident
* DeleteContext
* Print
* Set

### Commands

* cmsaas-certificate-get
* cmsaas-certificate-search
* ngts-certificate-get
* ngts-certificate-search
* setIncident

## Playbook Inputs

| Name | Description | Default Value | Required |
| --- | --- | --- | --- |
| Fingerprint | The certificate fingerprint, as mapped onto the incident by the fetch mapper. Preferred: it identifies exactly one certificate. | `${incident.certmanagersaasfingerprint}` | Optional |
| CommonName | The certificate common name, as mapped onto the incident by the fetch mapper. | `${incident.certmanagersaascommonname}` | Optional |
| CriticalThresholdDays | Certificates expiring within this many days are raised to Critical. | `7` | Optional |
| HighThresholdDays | Certificates expiring within this many days, but outside the critical threshold, are raised to High. | `30` | Optional |
| AutoRenew | Set to true to request a replacement certificate automatically. Any other value assigns the case to the certificate owner or AssigneeRole instead (or leaves it unassigned when neither is set). | `false` | Optional |
| CertificateOwnerEmail | The email of the certificate owner, who gets the case. When empty, a member of AssigneeRole gets it; when both are empty, the case stays unassigned. |  | Optional |
| AssigneeRole | A role whose least busy member gets the case when no CertificateOwnerEmail is set. When both are empty, the case stays unassigned. |  | Optional |
| ApplicationID | The identifier of the Certificate Manager SaaS application the replacement certificate is requested for. Required for Certificate Manager SaaS when auto-renewal is on; not used by Next-Gen Trust Security. |  | Optional |
| CertificateIssuingTemplateID | The identifier of the Certificate Manager SaaS issuing template the replacement is issued under. Required by the request sub-playbook when auto-renewal is on. |  | Optional |
| ValidityPeriod | The requested validity of the replacement certificate, as an ISO 8601 duration. Leave empty to use the issuing template default. |  | Optional |

## Playbook Outputs

| Path | Description | Type |
| --- | --- | --- |
| CertManagerSaaS.Certificate.Fingerprint | The fingerprint of the expiring certificate. | string |
| CertManagerSaaS.Certificate.DaysUntilExpiry | Whole days remaining until the certificate expires. | number |
| CertManagerSaaS.CertificateRequest.Succeeded | Whether a replacement certificate was issued. | boolean |
| CertManagerSaaS.CertificateRequest.ID | The identifier of the replacement certificate request. | string |

## Hydration comes first

The fetched incident names the certificate, but its fields are a snapshot from fetch time. So the
first thing this playbook does is look the certificate up again in every enabled integration - by
the mapped fingerprint (`*-certificate-get`, an exact match), or by common name when no fingerprint
is mapped - and write the fresh data onto the case.

Everything after that acts only when **exactly one** certificate was resolved: none, or several
(a renewed certificate shares the common name), goes to manual triage. An automatic renewal is
requested through the integration and instance that returned the certificate (`SourceBrand`,
`SourceInstance`).

## Assignment

With auto-renewal off, the case goes to `CertificateOwnerEmail` when it is set, otherwise to the
least busy member of `AssigneeRole`. XSIAM assigns cases to a user, not a role, so a role means
one of its members is assigned. With both inputs empty the case stays unassigned rather than
landing on an analyst who does not own certificates.

## Severity

Severity is computed explicitly, in a condition task, with the thresholds exposed as playbook
inputs. `SOC Calculate Severity - Generic v2` cannot be used here - it merges a closed set of
hard-coded severity keys and ignores a custom one without raising an error.

| Time to expiry | Severity |
| --- | --- |
| At or below `CriticalThresholdDays` (default 7) | Critical |
| At or below `HighThresholdDays` (default 30) | High |
| Anything else | Medium |

The bottom rung is Medium, not Low: a Low issue creates neither a case nor a grouping.

The Certificate Manager SaaS expiry thresholds themselves are tenant-global and configured by the
customer, and this pack cannot ship them. Align them with these inputs, or the two will disagree
silently.

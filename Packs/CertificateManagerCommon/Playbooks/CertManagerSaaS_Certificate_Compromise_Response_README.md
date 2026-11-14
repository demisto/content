# CertManagerSaaS Certificate Compromise Response

Responds to a compromised certificate: resolves it from an indicator, enriches it, asks an analyst to confirm, revokes it and requests a replacement - all recorded on the same case. It also runs on a "CertManagerSaaS Revocation Failed" issue, where it retries a key-compromise revocation that the CA did not complete.

Revocation is gated behind an explicit analyst decision because it is irreversible and immediately breaks every service still presenting the certificate; the machine installations and TLS endpoints written onto the case before the question is asked are the blast radius the analyst is accepting.

A certificate that cannot be resolved is never treated as proof of absence: a malformed fingerprint comes back from the API as an ordinary empty result, indistinguishable from a deleted certificate.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* CertManagerSaaS Certificate Request

### Integrations

* CyberArk Certificate Manager SaaS
* Next-Gen Trust Security

### Scripts

* DeleteContext
* GetErrorsFromEntry
* Print

### Commands

* certificate
* cmsaas-certificate-get
* cmsaas-certificate-revoke
* cmsaas-certificate-search
* ngts-certificate-get
* ngts-certificate-revoke
* ngts-certificate-search
* setIncident

## Playbook Inputs

| Name | Description | Default Value | Required |
| --- | --- | --- | --- |
| CertificateFingerprint | The SHA-1 fingerprint of the compromised certificate. Defaults to the fingerprint mapped onto a fetched issue. The natural key, and the only digest revocation accepts - prefer it over the common name. | `${incident.certmanagersaasfingerprint}` | Optional |
| CertificateCommonName | The common name to search on when no fingerprint is available. | `${incident.certmanagersaascommonname}` | Optional |
| RevocationReason | The revocation reason, passed to the command's "reason" argument. Certificate Manager SaaS accepts UNSPECIFIED, KEY_COMPROMISE, AFFILIATION_CHANGED, SUPERSEDED and CESSATION_OF_OPERATION. Other RFC 5280 reasons are rejected by the API. | `KEY_COMPROMISE` | Optional |
| RevocationComment | Free text stored with the revocation, passed to the command's "comment" argument. Carries the Cortex case identifier so the action is traceable from Certificate Manager SaaS back to Cortex. The Next-Gen Trust Security gateway's web filter rejects some wordings (for example "Revoked in Cortex case 123"), so test a changed comment before relying on it. | `Revoked by Cortex (case ${incident.id})` | Optional |
| AutoRequestReplacement | Set to true to request a replacement certificate as soon as the revocation succeeds. | `true` | Optional |
| ApplicationID | The identifier of the Certificate Manager SaaS application the replacement certificate is requested for. Required for Certificate Manager SaaS; not used by Next-Gen Trust Security. |  | Optional |
| CertificateIssuingTemplateID | The identifier of the Certificate Manager SaaS issuing template the replacement is issued under. Required by the request sub-playbook. |  | Optional |

## Playbook Outputs

| Path | Description | Type |
| --- | --- | --- |
| CertManagerSaaS.Certificate.Fingerprint | The fingerprint of the certificate that was acted on. | string |
| CertManagerSaaS.Certificate.Status | The Certificate Manager SaaS status of the certificate after revocation. | string |
| CertManagerSaaS.CertificateRequest.Succeeded | Whether a replacement certificate was issued. | boolean |
| CertManagerSaaS.CertificateRequest.ID | The identifier of the replacement certificate request. | string |

## What this playbook does

It revokes a compromised certificate and requests a replacement, with both results recorded on
the same case.

1. Resolve the certificate in every enabled integration. A fingerprint gets an exact lookup;
   anything else falls back to a common-name search. Fingerprint is the natural key - the
   certificate identifier is not filterable upstream.
2. Enrich the indicator with the `certificate` reputation command.
3. Write the certificate, its owning application, its machine installations and its TLS endpoints
   onto the case.
4. Offer revocation only when exactly one certificate was resolved. Several matches - for example
   a renewed certificate that shares the common name - stop here with a note to re-run with the
   exact fingerprint.
5. Ask an analyst to confirm revocation.
6. Revoke through the integration and instance that returned the certificate (`SourceBrand`,
   `SourceInstance`), then optionally call the reusable certificate-request sub-playbook for a
   replacement, routed the same way.
7. If the revoke fails, write "Revoke failed" and the reason into the case summary, and request no
   replacement.

## Why revocation is gated behind an analyst

Revocation is irreversible and immediately breaks every service still presenting the certificate.
The installations written onto the case in step 3 are the blast radius the analyst is being asked
to accept, which is why they are recorded before the question is asked rather than after.

## Revocation reasons

Certificate Manager SaaS accepts exactly five: `UNSPECIFIED`, `KEY_COMPROMISE`,
`AFFILIATION_CHANGED`, `SUPERSEDED`, `CESSATION_OF_OPERATION`. Other RFC 5280 reasons -
`CA_COMPROMISE`, `CERTIFICATE_HOLD`, `PRIVILEGE_WITHDRAWN`, `AA_COMPROMISE`, `REMOVE_FROM_CRL` -
are rejected by the API.

## A not-found answer is weak evidence

A malformed or mistyped fingerprint returns an ordinary empty result, not an error -
indistinguishable from a certificate that was genuinely deleted. This playbook never treats an
empty result as proof of absence; it reports it to the analyst instead.

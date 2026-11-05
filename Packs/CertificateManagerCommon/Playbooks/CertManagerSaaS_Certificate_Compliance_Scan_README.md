# CertManagerSaaS Certificate Compliance Scan

Scans the CyberArk Certificate Manager SaaS inventory for certificates that violate policy: self-signed, weak public key, deprecated signature hash algorithm, or excessive validity period.

Every rule is a filter over one inventory read, so the whole scan costs one pass rather than one call per rule. The four violation sets are written to separate context keys so a calling playbook can act on each independently.

Scope limits worth knowing: the upstream page size is capped at 100 and deep pagination is best-effort, so on a large tenant MaxPages is load-bearing and a scan is a sample unless it is raised. The weak-key rule evaluates RSA and DSA key lengths only - elliptic-curve certificates report a curve name instead of a length.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* CyberArk Certificate Manager SaaS
* Next-Gen Trust Security

### Scripts

* DeleteContext
* Print
* SetAndHandleEmpty

### Commands

* cmsaas-certificate-search
* ngts-certificate-search

## Playbook Inputs

| Name | Description | Default Value | Required |
| --- | --- | --- | --- |
| CertificateStatus | Restricts the scan to certificates in this Certificate Manager SaaS status. Leave empty to scan every status. | `ACTIVE` | Optional |
| MaxCertificates | Maximum number of certificates to evaluate. | `500` | Optional |
| MaxPages | Maximum number of 100-certificate pages to scan. The upstream page size is capped at 100, so a large tenant needs this raised. | `50` | Optional |
| MinimumKeySize | Minimum acceptable public key length, in bits. Certificates below it are flagged. | `2048` | Optional |
| DeprecatedSignatureHashAlgorithms | Comma-separated signature hash algorithms treated as deprecated. | `md5,sha1` | Optional |
| MaximumValidityPeriodSeconds | Maximum permitted validity period, in seconds. Certificate Manager SaaS reports validity in seconds and there is no arithmetic available in a filter, so the threshold is given in the same unit. The default of 34387200 is 398 days. | `34387200` | Optional |

## Playbook Outputs

| Path | Description | Type |
| --- | --- | --- |
| CertManagerSaaS.ComplianceScan.SelfSigned | Certificates that are self-signed. | unknown |
| CertManagerSaaS.ComplianceScan.WeakKey | Certificates whose public key is shorter than the configured minimum. | unknown |
| CertManagerSaaS.ComplianceScan.DeprecatedSignatureAlgorithm | Certificates signed with a deprecated signature hash algorithm. | unknown |
| CertManagerSaaS.ComplianceScan.ExcessiveValidity | Certificates whose validity period exceeds the configured maximum. | unknown |

## Policy rules

| Rule | Output key | Test |
| --- | --- | --- |
| Self-signed | `CertManagerSaaS.ComplianceScan.SelfSigned` | `IsSelfSigned` is true |
| Weak key | `CertManagerSaaS.ComplianceScan.WeakKey` | Public key length below `MinimumKeySize` |
| Deprecated signature algorithm | `CertManagerSaaS.ComplianceScan.DeprecatedSignatureAlgorithm` | Signature hash algorithm in `DeprecatedSignatureHashAlgorithms` |
| Excessive validity | `CertManagerSaaS.ComplianceScan.ExcessiveValidity` | Validity period longer than `MaximumValidityPeriodSeconds` |

All four rules are filters over a single inventory read, so the whole scan costs one pass rather
than one call per rule. Each violation set lands on its own context key, so a calling playbook can
act on them independently.

## Scope limits

* The upstream page size is capped at 100 and deep pagination is best-effort, so on a large tenant
  `MaxPages` is load-bearing. Left at the default, a scan of a large tenant is a sample, not a
  census.
* The weak-key rule evaluates RSA and DSA key lengths. Elliptic-curve certificates report a curve
  name rather than a length and are not flagged by it.
* Validity is expressed in seconds because that is the unit Certificate Manager SaaS reports and
  there is no arithmetic available inside a playbook filter. The default, 34387200 seconds, is
  398 days.

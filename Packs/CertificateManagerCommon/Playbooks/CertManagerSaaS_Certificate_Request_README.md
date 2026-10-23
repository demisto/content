# CertManagerSaaS Certificate Request

Requests a new certificate from CyberArk Certificate Manager SaaS, waits for it to be issued and returns the outcome to the caller.

This is a reusable building block: it is meant to be called as a sub-playbook from server provisioning, vulnerability response, certificate expiry remediation and incident response playbooks rather than run on its own.

Calling contract:

- CommonName and CertificateIssuingTemplateID are required; the sub-playbook checks them before calling out. Certificate Manager SaaS also requires ApplicationID: without it the request API rejects the request and the sub-playbook reports failure.
- Set SourceIntegration, and SourceInstance when the integration has several instances. With both integrations enabled and no SourceIntegration, the sub-playbook refuses to pick one and reports failure.
- CertManagerSaaS.CertificateRequest.Succeeded is set on every path, so a caller never has to distinguish 'failed' from 'never ran'.
- Set DownloadPrivateKey to true to also download the private key and chain (VSatellite-generated keys only), encrypted with KeystorePassphrase. CertManagerSaaS.CertificateRequest.KeystoreDownloaded then reports the result; the private key is never written to context.
- Add this playbook to a parent as a sub-playbook task and set its outputs to Shared globally. Private to sub-playbook is the platform default and returns nothing to the parent. In the YAML that toggle is the task's separatecontext key: false means shared.
- After changing these inputs or outputs, refresh the parent playbook's page. Saving and reopening does not pick the change up.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

- GenericPolling

### Integrations

- CyberArk Certificate Manager SaaS
- Next-Gen Trust Security

### Scripts

- DeleteContext
- GetErrorsFromEntry
- IsIntegrationAvailable
- Print
- Set

### Commands

- cmsaas-certificate-download
- cmsaas-certificate-keystore-download
- cmsaas-certificate-request
- cmsaas-certificate-request-status
- ngts-certificate-download
- ngts-certificate-keystore-download
- ngts-certificate-request
- ngts-certificate-request-status

## Playbook Inputs

| Name | Description | Default Value | Required |
| --- | --- | --- | --- |
| SourceIntegration | The integration to request through: CertificateManagerSaaS or NextGenTrustSecurity (the SourceBrand of the certificate being replaced). When empty, the only enabled integration is used; with both enabled, the sub-playbook stops and reports failure rather than pick one. |  | Optional |
| SourceInstance | The integration instance to send the request, status polling and download to - the SourceInstance of the certificate being replaced. Set it when the integration has several instances; when empty, the commands run on every enabled instance of that integration. |  | Optional |
| CommonName | The subject common name for the new certificate. Required - the sub-playbook reports failure without calling out if it is empty. |  | Required |
| ApplicationID | The identifier of the Certificate Manager SaaS application the certificate is requested for. Required by Certificate Manager SaaS; ignored by Next-Gen Trust Security, which doesn't use applications. |  | Optional |
| CertificateIssuingTemplateID | The identifier of the Certificate Manager SaaS issuing template to issue under. Required by the API. |  | Required |
| SubjectAlternativeNames | A comma-separated list of DNS subject alternative names for the new certificate. |  | Optional |
| ValidityPeriod | The requested validity as an ISO 8601 duration - P1Y for a year, P90D for ninety days. Leave empty to use the issuing template default. |  | Optional |
| ExistingCertificateFingerprint | The SHA-1 fingerprint of the certificate being replaced, when this request is a renewal. Links the new certificate to the old one in Certificate Manager SaaS. A renewal keeps the old certificate's subject and subject alternative names. |  | Optional |
| PollingInterval | How often the request status is polled, in minutes. | `1` | Optional |
| PollingTimeout | How long to poll the request before giving up, in minutes. | `30` | Optional |
| DownloadPrivateKey | Set to true to also download the issued certificate's private key and chain to the War Room, encrypted with KeystorePassphrase. Works only when a VSatellite generated the key. A failed download does not fail the request. | `false` | Optional |
| KeystoreFormat | The keystore format when DownloadPrivateKey is true: PEM (an encrypted private key file and a chain file, leaf first) or PKCS12 (one .p12 file). | `PEM` | Optional |
| KeystorePassphrase | Used when DownloadPrivateKey is true. The passphrase that encrypts the downloaded private key. Leave it empty to use the integration instance's Keystore passphrase setting, which can come from a saved credential (recommended). Don't type the passphrase here or save it as a default value. |  | Optional |

## Playbook Outputs

| Path | Description | Type |
| --- | --- | --- |
| CertManagerSaaS.CertificateRequest.Succeeded | Whether a certificate was issued. Always set, on every path through the sub-playbook. | boolean |
| CertManagerSaaS.CertificateRequest.ID | The identifier of the certificate request. | string |
| CertManagerSaaS.CertificateRequest.Status | The final status of the certificate request. | string |
| CertManagerSaaS.CertificateRequest.CertificateIDs | The identifiers of the certificates the request produced. | string |
| CertManagerSaaS.CertificateRequest.SubjectDN | The subject distinguished name of the certificate request. | string |
| CertManagerSaaS.CertificateRequest.ErrorMessage | Why the request failed, when it did. | string |
| CertManagerSaaS.CertificateContents.Contents | The PEM content of the issued certificate, when the download succeeded. | string |
| File.EntryID | The war room entry identifier of the downloaded certificate file, and of the keystore files when DownloadPrivateKey is true. | string |
| File.Name | The name of the downloaded certificate file, and of the keystore files when DownloadPrivateKey is true. | string |
| CertManagerSaaS.CertificateRequest.KeystoreDownloaded | Whether the private key and chain were downloaded. Set only when DownloadPrivateKey is true and the certificate was issued. | boolean |
| CertManagerSaaS.CertificateRequest.KeystoreErrorMessage | Why the private key download failed, when it did. | string |
| CertManagerSaaS.Keystore.CertificateID | The identifier of the certificate whose keystore was downloaded. | string |
| CertManagerSaaS.Keystore.Format | The keystore format, PEM or PKCS12. | string |
| CertManagerSaaS.Keystore.PrivateKeyFileName | The name of the War Room file that holds the encrypted private key (PEM format). | string |
| CertManagerSaaS.Keystore.ChainFileName | The name of the War Room file that holds the certificate chain, leaf first (PEM format). | string |
| CertManagerSaaS.Keystore.KeystoreFileName | The name of the War Room .p12 file (PKCS12 format). | string |

## How to call this playbook

This playbook is the reusable certificate-request workflow. It is built to be called from other
playbooks - server provisioning, vulnerability response, certificate expiry remediation,
certificate compromise response - rather than run on its own.

1. Drag it onto the parent playbook as a sub-playbook task.
2. Map `CommonName` and `CertificateIssuingTemplateID`, plus `ApplicationID` for Certificate
   Manager SaaS (Next-Gen Trust Security doesn't use applications), and whichever optional inputs your
   issuing template needs.
3. When the request replaces an existing certificate, map `SourceIntegration` to
   `CertManagerSaaS.Certificate.SourceBrand` and `SourceInstance` to
   `CertManagerSaaS.Certificate.SourceInstance`, so the request, the status polling and the
   download go to the instance that holds that certificate. Left empty, `SourceIntegration`
   defaults to the only enabled integration. With both integrations enabled the sub-playbook does
   not guess: it prints a message asking for `SourceIntegration` (and `SourceInstance`) and
   reports failure.
4. **Set the task's outputs to "Shared globally".** "Private to sub-playbook" is the platform
   default, and with it this playbook returns nothing to its parent - the declared outputs below
   never reach the parent's context. In the task YAML the toggle is `separatecontext`: `false`
   means shared, `true` means private.
5. If you change this playbook's inputs or outputs afterwards, **refresh the parent playbook's
   page**. Saving and reopening the parent is not enough to pick the change up.

`CertManagerSaaS.CertificateRequest.Succeeded` is written on every path through the playbook,
including the paths where no request was ever submitted. A caller can branch on that single key
instead of trying to tell "the request failed" apart from "the sub-playbook returned nothing".
When the service rejects the request or its status can't be read, `ErrorMessage` holds the
error, for example "Only existing certificate with CURRENT version can be specified" for a
renewal of a certificate that was already replaced.

## Downloading the private key

Set `DownloadPrivateKey` to `true` to get the private key with the certificate. After the
certificate is issued and downloaded, the playbook downloads its keystore through the same
integration and instance that issued it.

- **PEM** (default): two War Room files, `<common name>.key` (the private key, encrypted with
  `KeystorePassphrase`) and `<common name>.pem` (the chain, leaf first).
- **PKCS12**: one War Room file, `<common name>.p12`, protected by `KeystorePassphrase`.

The private key is never written to context. `CertManagerSaaS.Keystore` holds only the file names,
and `File` holds the War Room entries. `CertManagerSaaS.CertificateRequest.KeystoreDownloaded`
tells the caller whether the download worked, and `KeystoreErrorMessage` says why it didn't.

- **VSatellite-generated keys only.** Only a key that a VSatellite generated can be exported. A
  certificate issued from a CSR has no private key in the service.
- **Keep the passphrase out of the playbook.** Set it in the integration instance's **Keystore
  passphrase** setting, from a saved credential, and leave `KeystorePassphrase` empty.
- **A failed key download doesn't fail the request.** The certificate is still issued, so
  `Succeeded` stays `true`; only `KeystoreDownloaded` is `false`.

## Notes

- Polling runs through `GenericPolling`, which must have its own private context. The final
  request status is therefore re-read by a task in this playbook's own context, so that it lands
  in the declared outputs.
- A failed download does not fail the playbook. The certificate has still been issued, and the
  content can be fetched again.

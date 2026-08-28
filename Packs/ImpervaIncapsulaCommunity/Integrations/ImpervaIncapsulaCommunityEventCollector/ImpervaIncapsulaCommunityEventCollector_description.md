## Imperva Incapsula Community Event Collector

**This is a community-maintained integration. It is not developed, reviewed, or supported by Imperva or
Palo Alto Networks.** Validate it thoroughly against your own tenant before relying on it in production.

This integration is for Imperva Cloud WAF (Incapsula) accounts using **Retrieve (Pull mode)** log
integration — what the Log Configuration screen itself labels the **Imperva API** connection type.
Imperva writes your logs to a short-lived cloud repository (kept up to 48 hours or 500 MB) that this
integration polls and downloads from. If your account instead uses one of Imperva's push modes (Amazon
S3, SFTP, or Splunk HEC), use the native ingestion path documented in the `Imperva Incapsula` pack
instead — this integration does not apply to those connection types.

### Get your Log Server URI, API ID, and API Key

1. In the Imperva Cloud Security Console, go to **Account Management → SIEM Logs → Log Configuration**
   and confirm the connection is Retrieve (Pull mode) / Imperva API.
2. Copy the **Log Server URI** shown there (for example `https://logs1.incapsula.com/1234_12345/`).
3. Get the **API ID** and **API Key** from your account's API settings page. These authenticate every
   request via HTTP Basic auth — enter them separately here and the integration handles the encoding.

### If log encryption is enabled

Some accounts encrypt the log buffer using a two-layer scheme: events are encrypted with a per-file
AES-128 symmetric key, which is itself encrypted with an RSA-2048 public key you provided to Imperva. If
yours does, you will also need:
- The **RSA private key** (PEM) matching the public key you uploaded to Imperva.
- The numeric **Public Key ID** Imperva assigned to that key when you uploaded it (keys are numbered
  starting at 1, incrementing on each upload; the log file header's `publicKeyId` field identifies which
  key decrypts a given file).

Leave both fields blank if your account does not use log encryption.

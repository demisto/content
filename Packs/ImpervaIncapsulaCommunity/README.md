# Imperva Incapsula (Community)

> **Community pack — not an official Imperva or Palo Alto Networks integration.** It is not developed,
> reviewed, tested, or supported by Imperva or Palo Alto Networks. Use at your own risk and validate
> thoroughly against your own tenant before relying on it in production.

This pack provides an **agentless, Cloud-to-Cloud** path for ingesting Imperva Cloud WAF (Incapsula)
logs into Cortex XSIAM, for accounts whose Imperva SIEM Logs connection type is **"Imperva API"**
(the short-term log buffer fronted by `https://logs<N>.incapsula.com/`), rather than "Amazon S3".

If your account's connection type is Amazon S3, use the native ingestion path documented in the
[`Imperva Incapsula`](https://xsoar.pan.dev/marketplace/details/Incapsula) pack instead — that path
does not need this pack.

## What this pack replaces

Historically, accounts on the Imperva API connection type ran Imperva's open-source
[`incapsula-logs-downloader`](https://github.com/imperva/incapsula-logs-downloader) on a self-managed
host: a long-running daemon that polled the log buffer, decrypted/decompressed files to local disk, and
forwarded them to a SIEM over syslog or Splunk HEC. That requires a host to patch and monitor, a
syslog/HEC hop into XSIAM, and private key material sitting on a filesystem.

This pack runs the same fetch-decrypt-decompress logic **inside the XSIAM tenant** as a standard Event
Collector integration: no broker VM, no on-prem host, no files on disk. Decrypted, decompressed log
lines are sent to XSIAM as raw text and land in the `imperva_incapsula_raw` dataset.

## How it works

1. **Imperva Incapsula Community Event Collector** integration polls `logs.index` on your configured
   Imperva Logs URL, downloads any new `<account>_<counter>.log` files, decrypts (if your account has
   log encryption enabled) and decompresses each one, and sends the decoded CEF lines to XSIAM with
   `vendor=imperva`, `product=incapsula`, and no forced `data_format` — each line lands verbatim in
   `_raw_log` in the `imperva_incapsula_raw` dataset.
2. A **Parsing Rule** extracts the CEF header and extension fields from `_raw_log` into structured
   columns, and sets `_time` from the event's `start` field.
3. A **Modeling Rule** maps those fields to Cortex XDM, adapted from the XDM mapping already shipped in
   the `Incapsula` pack's modeling rule (same CEF field set, different dataset).

## Setup

### On the Imperva side

1. In the Imperva Cloud WAF console: **SIEM Logs → Log Configuration**. Confirm the connection type is
   **Imperva API** (not Amazon S3) — this pack only works with the former.
2. Note the **Logs URL** (e.g. `https://logs1.incapsula.com/123456_456789/`), the **API ID**, and the
   **API Key** from the account's API settings page.
3. If log encryption is enabled for the account, obtain the RSA private key file and the numeric
   **Public Key ID** associated with it.

### In Cortex XSIAM

1. Install this pack.
2. Create a new instance of **Imperva Incapsula Community Event Collector**:
   - **Logs URL** — the Imperva Logs URL from above.
   - **API ID** / **API Key** — credentials.
   - **Private key (PEM)** — only if log encryption is enabled on the account.
   - **Public Key ID** — only if log encryption is enabled on the account.
   - **Number of files to backfill on first run** — how many of the most recent index entries to fetch
     the first time the collector runs. Default: 10.
   - **Maximum files per fetch cycle** — a ceiling on how many files one fetch cycle downloads. Default: 50.
3. Click **Test** to confirm the credentials can read `logs.index`.
4. Enable **Fetches events**.

## Verifying ingestion

```xql
dataset = imperva_incapsula_raw
| fields _time, _raw_log, cefName, cn1, src, request
| limit 20
```

If `_raw_log` is populated but the other fields are null, see the integration README's troubleshooting
section — this usually means the parsing rule's key-boundary regex needs adjustment for a CEF field this
pack's author did not have sample data for.

## Known limitations

- Only the Imperva API connection type is supported; Amazon S3 accounts should use the native ingestion
  path.
- Imperva's log buffer retains files for a short, account-configurable window. If the collector is
  disabled for longer than that window, files that aged out before it resumed are permanently lost —
  there is no way to recover them retroactively.
- This is a community pack: no SLA, no vendor support channel. File issues against the pull request or
  fork where you obtained this pack.

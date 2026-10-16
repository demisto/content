# Imperva Incapsula (Community)

> **Community pack — not an official Imperva or Palo Alto Networks integration.** It is not developed,
> reviewed, tested, or supported by Imperva or Palo Alto Networks. Validate it thoroughly against your
> own tenant before relying on it in production.

## What this is

Imperva Cloud WAF logs — [Security events and Access events](https://docs-cybersec.thalesgroup.com/bundle/cloud-application-security/page/settings/log-integration.htm),
in CEF, LEEF, or W3C format — can reach a SIEM through several **log integration modes**. This pack
covers one of them: **Retrieve (Pull mode)**, Imperva's own term for what its Log Configuration screen
labels the **Imperva API** connection type. In this mode Imperva writes your logs to a dedicated,
short-lived cloud repository (kept **up to 48 hours or 500 MB**, whichever comes first, on a
first-in-first-deleted cycle) that you poll and download yourself — as opposed to **Receive (Push
mode)**, where Imperva pushes logs directly to an SFTP server, Amazon S3 bucket, or Splunk HEC endpoint
you control.

If your account is configured for the push modes, use the native ingestion path documented in the
[`Imperva Incapsula`](https://xsoar.pan.dev/marketplace/details/Incapsula) pack instead (Amazon S3 →
XSIAM's built-in S3 collector) — that path does not need this pack, and this pack does not apply to it.

## What this pack replaces

Retrieve/Pull mode requires *something* to poll the repository and download files — Imperva's own docs
point to a [sample Python connector script](https://github.com/imperva/incapsula-logs-downloader),
open-source and community-maintained, not maintained by Imperva itself. Historically that script ran as
a long-running daemon on a self-managed host: polling the log buffer, decrypting/decompressing files to
local disk, and forwarding them to a SIEM over syslog or Splunk HEC. That requires a host to patch and
monitor, a syslog/HEC hop into XSIAM, and private key material sitting on a filesystem.

This pack runs the same fetch → decrypt → decompress logic **inside the XSIAM tenant** as a standard
Event Collector integration instead: no broker VM, no on-prem host, no files on disk. Decoded log lines
are sent to XSIAM as raw text and land in the `imperva_incapsula_raw` dataset, where a Parsing Rule and
Modeling Rule take over from there.

## How it works

1. **Imperva Incapsula Community Event Collector** integration polls `logs.index` at your configured
   **Log Server URI**, downloads any new `<API_ID>_<sequence>.log` files (the filename format Imperva
   documents — the number is a per-account sequence, not the account ID), decrypts (if your account has
   log encryption enabled) and decompresses each one, and sends the decoded CEF lines to XSIAM with
   `vendor=imperva`, `product=incapsula`, and no forced `data_format` — each line lands verbatim in
   `_raw_log` in the `imperva_incapsula_raw` dataset. Raw text (not XSIAM's built-in CEF parser) is a
   deliberate choice: the original line stays queryable next to whatever the Parsing Rule extracted from
   it, so a mapping bug is visible as "field wrong, `_raw_log` right" instead of an opaque black box.
2. A **Parsing Rule** extracts the CEF header and the [56 documented event fields](https://docs-cybersec.thalesgroup.com/bundle/cloud-application-security/page/more/log-file-structure.htm)
   from `_raw_log` into structured columns, and sets `_time` from the event's `start` field. The field
   list and every field name below come directly from that page, not from guessing at sample data — see
   [Field extraction](#field-extraction-and-known-imperva-documentation-inconsistencies) below for the
   real-world quirks that page's own examples exposed and how this rule handles them.
3. A **Modeling Rule** maps the fields that also exist in the traffic-log CEF schema to Cortex XDM,
   reusing the mapping logic already shipped in the `Incapsula` pack's own modeling rule (same field
   set, different dataset, since both packs describe the same Imperva CEF log format).

## Setup

### On the Imperva side

1. In the Imperva Cloud Security Console: **Account Management → SIEM Logs → Log Configuration**.
   Confirm the connection is configured for **Retrieve (Pull mode) / Imperva API**, not Amazon S3, SFTP,
   or Splunk HEC.
2. Under that connection, note the **Log Server URI** (e.g. `https://logs1.incapsula.com/1234_12345/`)
   and get the **API ID** / **API Key** from the account's API settings page. Authentication is HTTP
   Basic auth — `Authorization: Basic base64(api_id:api_key)` — sent on every request; this pack's
   integration parameters accept the ID and key separately and handle the encoding.
3. If log encryption is enabled for the account, obtain the RSA private key (2048-bit) and the numeric
   **Public Key ID** shown for it — Imperva numbers keys starting at 1, incrementing on each upload, and
   the log file header's `publicKeyId` field tells you which one decrypts a given file.
4. Confirm **Compress logs** is enabled for this connection (Imperva's default). This pack's decoder
   handles both compressed and uncompressed files automatically, but Imperva's own reference connector
   errors on uncompressed files in pull mode, so it's worth confirming your account's actual setting
   rather than assuming.

### In Cortex XSIAM

1. Install this pack.
2. Create a new instance of **Imperva Incapsula Community Event Collector**:
   - **Logs URL** — the Log Server URI from above.
   - **API ID** / **API Key** — credentials.
   - **Private key (PEM)** — only if log encryption is enabled on the account.
   - **Public Key ID** — only if log encryption is enabled on the account.
   - **Number of files to backfill on first run** — how many of the most recent index entries to fetch
     the first time the collector runs. Default: 10.
   - **Maximum files per fetch cycle** — a ceiling on how many files one fetch cycle downloads. Default: 50.
3. Click **Test** to confirm the credentials can read `logs.index`.
4. Enable **Fetch events**.

## Field extraction and known Imperva documentation inconsistencies

Imperva's own [Log File Structure](https://docs-cybersec.thalesgroup.com/bundle/cloud-application-security/page/more/log-file-structure.htm)
page states plainly: *"We highly recommend accessing specific fields in the message according to the
field name, as opposed to accessing the field by its sequence number or position."* That page's field
table is the source of truth this parsing rule is built from — but its own worked examples on the
[Example Logs](https://docs-cybersec.thalesgroup.com/bundle/cloud-application-security/page/more/example-logs.htm)
page are internally inconsistent about field-name **casing**: the same account example uses `fileid`
(lowercase) where the table says `fileId`, `requestmethod` where the table says `requestMethod`, and
`deviceExternalID` where the table says `deviceExternalId`. This is not a hypothetical concern raised
speculatively — every key boundary in this rule is matched **case-insensitively**, confirmed by running
the actual generated rule logic against Imperva's own official example line through a live XSIAM tenant
before this was committed. The stored column always uses the table's documented canonical casing
regardless of which casing appeared on the wire.

One more thing that same validation caught: every `cs1`–`cs11` field is immediately followed on the wire
by a same-numbered `csNLabel` field (e.g. `cs2=true cs2Label=Javascript Support`) that Imperva's field
table doesn't document at all. Without a boundary marker for those label fields, extracting `cs2` bleeds
straight into `cs2Label`'s text — and since attack-info fields with labels are the common case for
security events, not a rare edge case, this rule includes all eleven `csNLabel` fields as their own
columns specifically to keep the `csN` fields clean.

## Verifying ingestion

Layer-by-layer, since the raw-text design means each stage is independently checkable:

```xql
dataset = imperva_incapsula_raw | fields _raw_log | limit 5
```

Confirms the collector itself is working — each row should be a complete `CEF:0|Incapsula|...` line.

```xql
dataset = imperva_incapsula_raw
| fields _time, cefName, cn1, src, request, ver, cs2, cs2Label
| limit 20
```

Confirms the Parsing Rule. Specifically check that `ver` keeps its full `TLSv1.2 ECDHE-...` value (proves
space-containing values survived boundary extraction) and that `cs2`/`cs2Label` are split cleanly rather
than one bleeding into the other.

```xql
dataset = imperva_incapsula_raw
| fields xdm.source.ipv4, xdm.target.url, xdm.network.http.method, xdm.network.http.response_code
| limit 20
```

Confirms the Modeling Rule's XDM mapping.

If a layer is null while the one before it is populated, the problem is isolated to that specific stage.

## Known limitations

- Only the Retrieve (Pull mode) / Imperva API connection type is supported; accounts on the push modes
  (Amazon S3, SFTP, Splunk HEC) should use the relevant native ingestion path instead.
- This pack's parsing and modeling rules describe the **CEF traffic-log format** (`Incapsula|SIEMintegration`
  in the CEF header) — the format documented on Imperva's Log File Structure page linked above. Some
  Imperva accounts and add-on products (for example, Attack Analytics) can be configured to deliver a
  *different* CEF format through the same Retrieve/Pull mechanism and Log Server URI. If your account
  sends a different `Device Product` in the CEF header, `_raw_log` still captures the line intact, but
  none of the structured fields will populate — check the CEF header's vendor/product segments in
  `_raw_log` against `Incapsula|SIEMintegration` if fields come back unexpectedly empty.
- `additionalReqHeaders` / `additionalResHeaders` carry JSON values; if a header value inside that JSON
  contains a space, this rule's space-delimited boundary extraction can truncate it early. These two
  fields also require separate enablement by Imperva Support before they appear in logs at all.
- Imperva's log buffer retains files for up to 48 hours or 500 MB, whichever comes first. If the
  collector is disabled for longer than that, files that aged out before it resumed are permanently
  lost — there is no way to recover them retroactively.
- This is a community pack: no SLA, no vendor support channel. File issues against the pull request or
  fork where you obtained this pack.

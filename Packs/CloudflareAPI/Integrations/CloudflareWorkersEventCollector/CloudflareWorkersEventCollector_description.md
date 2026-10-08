## Cloudflare Workers Event Collector

Collects the Workers script inventory from the Cloudflare API and ingests it into the
`cloudflare_workers_raw` dataset.

### Prerequisites

- A Cloudflare API Token with the **Workers Scripts Read** permission, scoped to the accounts
  being collected. Provide it in the **API Token** field.
- One or more Cloudflare account IDs.

### What this adds over the audit log

The account audit log already records that a Worker script changed. It does not say what exists
now, what a script's bindings give it access to, or which hostname it answers on. A Worker is
code running on Cloudflare's edge in front of a hostname, so those three facts are what make a
change assessable.

### Collection behaviour

- Workers are current configuration, so each run sends the full snapshot per account. Comparing
  snapshots over time is what surfaces a script that appeared, gained a binding, or changed the
  hostname it serves.
- A snapshot is three calls per account: the script inventory, the hostname to script mapping,
  and one settings call per script for its bindings.
- The scripts endpoint accepts pagination parameters and ignores them, returning the full list
  regardless, so it is requested once and never paged.
- A script whose settings cannot be read is still inventoried. The entry matters more than its
  bindings.

### Bindings

A binding is how a Worker reaches a secret, a KV namespace, an R2 bucket, a D1 database, a queue
or another service, so the binding set describes the blast radius of that code. Binding types and
names are collected and flattened into columns; binding VALUES are not collected. Cloudflare does
not return a secret's value, and the remainder is configuration detail that would add volume
without adding detection.

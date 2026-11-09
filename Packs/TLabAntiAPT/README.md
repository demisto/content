# tLab Anti-APT

Detonate files and URLs in the tLab Anti-APT malware sandbox, enrich file
reputation from its verdicts, ingest sandbox verdicts as incidents, and pull
sandbox-derived indicators into Threat Intel Management.

tLab Anti-APT is an on-premises malware analysis platform by tLab Technologies. It
performs static, dynamic, antivirus and MITRE ATT&CK analysis and returns a
score-based verdict per sample.

## What this pack contains

| Integration | Purpose | Minimum tLab role |
| --- | --- | --- |
| tLab Anti-APT Sandbox | Detonation, polling, reports, artifacts | admin or developer for artifacts; user to submit |
| tLab Anti-APT Lookup | File reputation and past analyses, read only | user |
| tLab Anti-APT Feed | Sandbox observables as Threat Intel Management indicators | user |
| tLab Anti-APT Verdicts | Finished analyses as incidents (pull mode) | admin or developer, see below |

### Playbooks

| Playbook | Use |
| --- | --- |
| Detonate File - tLab Anti-APT | Sub-playbook. Follows the Detonate File - Generic contract, so it drops into any playbook that already calls a detonation sub-playbook. |
| Detonate URL - tLab Anti-APT | Sub-playbook. The sandbox fetches the URL itself; nothing in XSOAR downloads the target. |
| tLab Anti-APT - File Reputation | Sub-playbook. Asks what tLab already knows, without submitting. Run it before a detonation: a sample already analyzed needs no second analysis. |
| tLab Anti-APT - Handle Verdict Incident | Triage. Default playbook for the tLab Anti-APT Verdict incident type. Enriches, then closes benign analyses and leaves the rest for an analyst. |

The detonation sub-playbooks do not loop. Polling lives inside the command, which
on XSOAR 6.2.0 and later suspends the task and resumes on a schedule rather than
holding a worker for the length of an analysis.

The split is driven by roles rather than tidiness. An instance is the unit of
credential in XSOAR, so keeping lookup separate means enrichment playbooks can
run on a restricted account while detonation keeps a privileged one.

## Before you start

### 1. Create a tLab account for XSOAR

The pack calls the tLab Anti-APT API from outside the tLab host. By default each
instance logs in to **tlab-auth** with a tLab account — the same login the
omni-center portal uses — and sends the token to the sandbox as
`Authorization: Bearer`. The session is cached per instance and refreshed before
it expires.

* Create a dedicated account (see the roles below) and **turn off password
  expiry and forced password change** for it: tlab-auth rejects an expired
  password, and every command starts failing.
* **Server URL** is the sandbox (tlab-server): `https://<tlab-host>/api`
  through the tLab web server, or `http://<tlab-host>:8080` directly.
* **Auth server URL** is tlab-auth. Leave it empty to use
  `https://<Server URL host>:8002/api`, the omni-center portal, which forwards
  `/api` to tlab-auth over TLS (enable **Trust any certificate** if its
  certificate is self-signed). It is never `https://<host>/api` — on a sandbox
  host that path is tlab-server.

Several sandboxes on different servers are simply several instances, each with
its own Server URL, Auth server URL and account.

A source key (omni-center source keys, type `CORTEX_XSOAR`) needs the
source-key gateway and covers submissions only, so it is not enough for lookup,
feed or verdicts. Do not use the tlab-server `Internal` token for a remote
XSOAR: the server accepts it only from `127.0.0.1`
(`tokenAuth.allowedRemoteAddresses`).

### 2. Pick the right role

Authentication and authorization are separate concerns here, and a role that is
too low fails quietly rather than loudly:

* Submitting samples and polling their status work with any authenticated role.
  Polling in particular needs no credentials at all, because the status endpoint
  is public.
* Artifact endpoints — PCAP, memory dump, dropped files, extra logs — require
  `admin` or `developer` and return 403 otherwise.
* Listing reports with working filters requires `admin` or `developer`. With a
  lower role the server **silently drops** the verdict, score and source
  filters instead of rejecting them, so a query appears to succeed while
  returning everything.

The integration's Test button reports the role it detected and warns when
artifacts will not be reachable.

### 3. Decide how incidents reach XSOAR

Sandbox verdicts can become XSOAR incidents in one of two ways, and enabling
both produces duplicates:

* **Pull** — the pack's Verdicts integration fetches them. Requires network
  access from XSOAR to the tLab API.
* **Push** — the tlab-xsoar-connector service on the tLab side creates them
  through the XSOAR REST API. Requires network access in the opposite
  direction and an XSOAR API key stored on the tLab side.

Choose one. The connector enforces its own side only; the pack side is turned
off by the XSOAR administrator.

If both run against the same tenant during a migration, three settings must be
identical or the duplicates will not be recognisable as duplicates:

| Verdicts integration | Connector |
| --- | --- |
| Installation ID | `INSTALLATION_UUID` |
| Incident name template | `INCIDENT_NAME_TEMPLATE` |
| Severity map | `SEVERITY_MAP` |

Every incident records which half created it in the `tLab Delivery Mode` field.
The connector also searches for incidents carrying the pack's brand and logs a
warning when it finds them while running in push mode; it cannot switch the
pack off, because an integration has no API for disabling another integration's
fetch.

## Verdicts

tLab Anti-APT exposes two verdict vocabularies on the same payload, and this
pack normalizes both onto one:

| Server field | Enumeration | Values |
| --- | --- | --- |
| `verdict` | ScoreLevel | UNKNOWN, SUSPICIOUS, MALICIOUS, OK, CLEAN, WHITELIST |
| `file.fileVerdict` | FileVerdict | UNKNOWN, SUSPICIOUS, MALWARE, OK, WHITELIST |

`MALICIOUS` and `MALWARE` mean the same thing. `CLEAN` and `OK` do not: the
server separates a score of exactly zero from a low non-zero score. Command
output keeps both raw values alongside the canonical `Verdict`.

Score bands follow the product defaults and are configurable per instance:

| Score | Verdict | DBot score |
| --- | --- | --- |
| no score | UNKNOWN | 0 Unknown |
| 0 | CLEAN | 1 Good |
| 0 – 50 | OK | 1 Good |
| 50 – 85 | SUSPICIOUS | 2 Suspicious |
| above 85 | MALWARE | 3 Bad |

`WHITELIST` is an analyst decision on the tLab side and is never overridden by a
recomputed score.

## Known limitations

* **No URL, domain or IP reputation commands.** tLab Anti-APT stores verdicts
  keyed on file hashes only. URL verdicts come from detonating the URL.
* **Screenshots cannot be listed without the admin role**, because the only
  endpoint that enumerates them is the admin-only dynamic report.
* **PDF rendering is synchronous** with no status endpoint, so a large report
  can approach the command timeout. The render timeout is configurable.
* **Polling on servers below XSOAR 6.2.0** cannot use scheduled commands and
  falls back to an inline loop that holds a worker. On those servers prefer
  `tlab-submit-file` followed by a scheduled `tlab-get-submission-status`.

## Air-gapped installation

1. Obtain `TLabAntiAPT.zip`, or build it with
   `demisto-sdk zip-packs -i Packs/TLabAntiAPT -o dist`.
2. On an internet-connected host, pull and save the Docker image the pack runs
   in, and record its digest:
   `docker pull demisto/python3:3.12.12.5490952 && docker save -o demisto-python3.tar demisto/python3:3.12.12.5490952`
3. Transfer both files into the isolated network.
4. `docker load` the image on the XSOAR server **and on every engine** that will
   run these integrations. Verify the digest matches: a mismatch means XSOAR
   tries to pull at command time and fails then rather than at install time.
5. In XSOAR, go to Marketplace and upload the zip.
6. Create an instance, then press Test.

# GitBook API

Collects the access and exposure surface of a GitBook organisation into the Cortex Platform, so
that who can reach the documentation, what is published publicly, and where content can leave
become answerable questions.

## What this pack ships

| Content | Purpose |
| --- | --- |
| GitBook Organisation Members Event Collector | Member roster from `GET /v1/orgs/{organizationId}/members` into `gitbook_members_raw`, full snapshot per run. |
| GitBook Link Invites Event Collector | Standing invite links from `GET /v1/orgs/{organizationId}/link-invites` into `gitbook_invites_raw`, full snapshot per run. |
| GitBook Sites Event Collector | Site visibility and published state from `GET /v1/orgs/{organizationId}/sites` into `gitbook_sites_raw`, full snapshot per run. |
| GitBook Integration Installations Event Collector | Installed third-party integrations from `GET /v1/orgs/{organizationId}/installations` into `gitbook_installations_raw`, full snapshot per run. |
| GitBook Space Git Sync Event Collector | Per-space Git sync configuration into `gitbook_git_sync_raw`, full snapshot per run. |

| GitBook API Modeling Rule | Maps `gitbook_invites_raw` to the Cortex XDM data model. |

Correlation content is not shipped in this version, and the remaining four datasets are not yet
modelled. Both are authored against observed data rather than from the API specification, and
follow once each collector has run long enough to model against.

### What the modelling rule does with an invite

| Source | XDM |
| --- | --- |
| `id` | `xdm.event.id` |
| `object` | `xdm.target.resource.type` |
| `role` | `xdm.target.resource.sub_type` |
| `invite_target` | `xdm.target.resource.value` |
| `organization_id` | `xdm.target.resource.parent_id` |
| `source_log_type` | `xdm.event.type` |

The rule claims no event story. An invite record carries neither an actor nor a network peer, so
tagging it as authentication or network would promise fields that cannot be filled. It is tagged
SAAS, which is what it honestly is. The operation and outcome fields are deliberately left unset,
because the record describes a standing state rather than something that happened.

Two source fields are deliberately NOT mapped. `redundant` is defined by the API relative to the
REQUESTING token rather than to the invite, so it describes whoever collected the record and would
mislead anyone reading it as a property of the invite. `is_privileged_role` is a convenience
boolean the collector derives from the role, and is fully recoverable from
`xdm.target.resource.sub_type`, so mapping it would store the same fact twice and let the two
disagree.

## What each collector answers

**Members** carry the whole access story for a person: the role held, whether they authenticate
through single sign-on, whether the account is disabled, when they joined and when they were last
seen. The administrator-without-single-sign-on combination is resolved at collection into
`is_privileged_role` and `uses_sso`, rather than in every rule that needs it.

**Link invites** are standing URLs that grant entry to the organisation. Anyone holding one can
join, they name no recipient, and they keep working until somebody revokes them. They are a live
access path rather than a historical record, which is why an inventory of them is worth holding.

**Sites** are the public face of documentation. Visibility and published state decide whether
internal material is reachable from the internet, so this is the public-exposure surface.

**Installations** are third-party code with standing access to content. The inventory answers
which third parties are connected and what they can reach, which is a supply-chain question
rather than a user-access one.

**Git sync** connects a space to an external repository, so it is a content egress and ingress
path: content can leave the platform into a repository, and content can be pushed into published
documentation from one. There is no list endpoint for Git installations, so this collector walks
the spaces and asks each one, emitting a record per space either way with `git_sync_configured`.

## What this pack cannot see

**GitBook exposes no audit log through its API.** There is no record of who did what and when.
The only enumerable event endpoint covers an integration publisher's own install lifecycle and is
not readable without publishing rights, site insights is an analytics query rather than a log, and
content revisions cannot be listed because every revision path requires an identifier you must
already hold.

This is therefore a **posture** pack rather than an audit pack. It reports the state of access,
and a change is found by comparing one snapshot against the next. A detection built on it can say
that something is now different; it cannot say who changed it.

## Getting started

Create a personal access token in GitBook under `User Settings > Developer > Personal access
tokens`. The token owner needs an administrator role in the organisation, because the member
roster is not readable otherwise.

Take the organisation identifier from the application URL, which has the form
`https://app.gitbook.com/o/<organizationId>/`.

Configure each collector in the Cortex Platform under `Settings > Data Sources > Add Instance`,
with an hourly fetch interval. These are snapshots of configuration rather than event streams, and
configuration changes rarely, so an hourly interval keeps ingestion proportionate to what it can
tell you.

## References

- GitBook API reference: https://gitbook.com/docs/developers/gitbook-api/api-reference
- GitBook OpenAPI specification: https://api.gitbook.com/openapi.json

## About GoCortex

GoCortexIO builds open content for the Palo Alto Networks Cortex ecosystem. This pack is released
under the AGPL-3.0-or-later licence.

## Version History (Managed by GoCortex Spellbook)

<!-- spellbook:version-history:start -->
### 1.1.7

- Add the contributors file that every pack in this repository carries at its root, and remove wording that read as a description of source data rather than of the product.

### 1.1.6

- Add the first posture worklist, reporting a privileged member who signs in with GitBook credentials rather than through the identity provider. The members model now exposes the sign-in method as a field rather than only as description prose, because a value a detection selects on has to reach a field. A second worklist covering dormant privileged accounts is written but held back, because the age arithmetic its query needs does not return on the platform, and a rule whose query hangs is indistinguishable from a rule that is correctly quiet.

### 1.1.5

- Declare the git sync columns the collector writes only where sync is configured. The pack failed to install because a data model rule is validated against the dataset schema, and the repository name had never been written by any record, so a rule reading it was rejected as an unknown field. The schema file beside the rule is authoritative, so declaring the conditional columns there lets the rule install before the estate has reached that state.

### 1.1.4

- Model the remaining four datasets. Members, sites, installations and git sync join the link invites rule, so a query can now ask which accounts hold privileged roles, which sites are publicly visible, what scopes an installed integration holds, and which spaces sync to an external repository. Git sync also corrects a field set that had been guessed from expected names rather than read from the specification, which would have left the repository name uncaptured and two normalised columns permanently null.

### 1.1.3

- Give each collector its own label image. All five shipped displaying the Grafana data sources label, having been copied from the exemplar directory and never replaced, so the Cortex Platform console showed another vendor's name on every GitBook collector. Also removes the empty TestPlaybooks directory the integration template scaffolds, which held nothing but a placeholder and no playbooks are shipped.

### 1.1.2

- Name the pack GitBook API, matching the other API-sourced packs, and document the modelling rule in the README. The README still said modelling content was not shipped, which stopped being true when the link invites rule went live.

### 1.1.1

- Model the link invites dataset. The rule maps the role an invite confers, what it grants entry to, and the organisation holding it, so a standing URL that makes its holder an organisation administrator is visible as a field rather than as a value buried in a blob. It claims no story, because the record carries neither an actor nor a network peer and tagging it into one would promise fields nothing can fill, and it leaves the operation and outcome verbs unset because the record is a standing state rather than something that happened. The redundant flag is documented as unmapped, since the API defines it relative to the requesting token rather than to the invite.

### 1.1.0

- Add four collectors alongside the member roster, and rename the pack to match the convention the other API-sourced packs follow. Link invites are standing URLs that grant entry to the organisation, name no recipient, and keep working until somebody revokes them. Sites carry the visibility and published state that decide whether internal material is reachable from the internet. Installations are third-party code holding standing access to content. Git sync connects a space to an external repository, so content can leave the platform into one and be pushed into published documentation from one. The Git sync collector walks the spaces and asks each in turn, because the API offers no list of Git installations, and it treats a 404 from that per-space call as the answer that no sync is configured rather than as a failure.

### 1.0.0

- Initial release.

<!-- spellbook:version-history:end -->

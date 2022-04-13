This playbook will tag internal assets and Massive IOCs (TLD Wildcards and CIDRs) to be avoided by the EDL. The playbook will do the following according to indicator type:

CIDRs - If the CIDR prefix is larger than the set max prefix it will tag it as a `Massive_CIDR` and also with `skip_edl`

TLD Wildcards - If a domainglob is a TLD wildcard (i.e. - *.net) it will be tagged as `TLD_Wildcard` and also with `skip_edl`.

Internal IPs - If an IP is internal and also part of the CIDR configured by the user in the "Internal Assets" list it will be checked as `internal` and tagged with `skip_edl`.

Internal Domains - If a domain is a subdomain of the domains configured in the "Internal Assets" list it will be checked as `internal` and tagged with `skip_edl`.


## Playbook Inputs

---
| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator Query | This query will retrieve the following indicator types - IP, IPv6, CIDR, IPv6CIDR | type:CIDR or type:IP or type:DomainGlob or type:IPv6CIDR or type:Domain | Optional |
| Internal Assets | A list of internal assets consisting of CIDRs and domains that belong to the user.  | lists.Internal assets | Optional |
| Maximum CIDR Prefix | The maximum Prefix to allow, any prefix bigger than the specified will be tagged to be ignored by the EDL. | 8 | Optional |


## Playbook Image

---

![Tag massive and internal IOCs to avoid EDL listing](../doc_files/Tag_massive_and_internal_IOCs_to_avoid_EDL_listing.png)

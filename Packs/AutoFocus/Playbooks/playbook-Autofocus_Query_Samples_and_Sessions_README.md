Queries the PANW Threat Intelligence Autofocus System. The playbook accepts indicators such as IP addresses, hashes, domains to run basic queries or mode advanced queries that can leverage several query parameters. In order to run the more advanced queries it is recommended to use the [Autofocus UI](https://autofocus.paloaltonetworks.com/#/dashboard/organization) to create a query and then use the export search button. The result can be used as a playbook input.

The playbook supports searching both the Samples API and the sessions API.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
AutoFocusPolling

## Integrations
This playbook does not use any integrations.

## Scripts
This playbook does not use any scripts.

## Commands
* autofocus-search-sessions
* autofocus-search-samples
* autofocus-top-tags-search

## Playbook Inputs
---

| **Name** | **Description** |**Required** |
| --- | --- | --- | 
| Scope | The scope can be, "Private" , "Public", or "Global". |  Optional | 
| SampleQuery | The query needs to be provided in order to determine what to search for. The query is currently only in JSON format which can be extracted from the Autofocus web console API radio button.

Query example for searching hashes can be

\{"operator":"any","children":\[\{"field":"sample.sha256","operator":"is","value":"4f79697b40d0932e91105bd496908f8e02c130a0e36f6d3434d6243e79ef82e0"\},\{"field":"sample.sha256","operator":"is","value":"7e93723c0c34ef98444e5ce9013fef220975b96291a79053fd4c9b3d3550aeb3"\}\]\}

Another example for searching for an IP
\{"operator":"any","children":\[\{"field":"sample.src\_ip","operator":"is","value":"1.1.1.1"\},\{"field":"sample.dst\_ip","operator":"is","value":"1.1.1.1"\},\{"field":"sample.src\_ip","operator":"is","value":"2.2.2.2"\},\{"field":"sample.dst\_ip","operator":"is","value":"2.2.2.2"\}\]\}
 | Optional |
| SessionQuery | The query that needs to be provided in order to determine what to search for. The query is currently only in JSON format which can be extracted from the Autofocus web console API radio button.

Query example for searching hashes can be

\{"operator":"any","children":\[\{"field":"session.sha256","operator":"is","value":"4f79697b40d0932e91105bd496908f8e02c130a0e36f6d3434d6243e79ef82e0"\},\{"field":"session.sha256","operator":"is","value":"7e93723c0c34ef98444e5ce9013fef220975b96291a79053fd4c9b3d3550aeb3"\}\]\}

Another example for searching for an IP
\{"operator":"any","children":\[\{"field":"session.src\_ip","operator":"is","value":"1.1.1.1"\},\{"field":"session.dst\_ip","operator":"is","value":"1.1.1.1"\},\{"field":"session.src\_ip","operator":"is","value":"2.2.2.2"\},\{"field":"session.dst\_ip","operator":"is","value":"2.2.2.2"\}\]\}
 |Optional |
| IP | The IP address to query. |Optional |
| Hash | The hash to query. |Optional |
| URL | The URL to query. |Optional |
| Domain | The domain to query. |Optional |
| Search Type | The values can be, "session", "sample", "tag", or "all".| Required |
| Wildfire Verdict | The values can be "Malware", "Benign", "Phishing",or "Greyware". |Optional |
| Sessions time before | The timestamp in the following format 2019-09-12T00:00:00. This parameter checks for sessions prior to this timestamp. |Optional |
| Sessions time after | The timestamp in the following format 2019-09-12T00:00:00. This parameter checks for sessions after this timestamp. | Optional |
| Sample first seen | The timestamp in the following format 2019-09-12T00:00:00. This parameter checks for when the sample was first seen after this date. |Optional |
| Sample last modified | The timestamp in the following format 2019-09-12T00:00:00. This parameter checks for when the sample was last modified after this date. |Optional |
| Tags scope | The values can be "industry", "organization", "all", or "global". |Optional |
| Tags class | The values can be "Actor", "Campaign", "Exploit", "Malicious Behavior", or "Malware Family". |Optional |
| Tags private | The values can be "True" or "False". If true the search will only focus on private (non public) objects. The default is false. | Optional |
| Tags public | The values can be "True" or "False". If true the search will only focus on public (non private) objects. The default is false. |Optional |
| Commodity | The values can be "True" or "False". The default is false. |Optional |
| Unit 42 | The values can be "True" or "False". The default is false. This parameter refers to objects that have been analyzed by Palo Alto's Unit 42 global threat intelligence team. | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AutoFocus.SessionsResults | \The results of Autofocus sessions search. | string |
| AutoFocus.SamplesResults | The results of Autofocus samples search. | string |
| AutoFocus.TopTagResults | The results of Autofocus tags search. | string |

## Playbook Image
---

![Autofocus_Query_Samples__Sessions_and_Tags](https://github.com/demisto/content/raw/cc9fb76a907ec5e86d6cdac7a8820d1828c52e02/Packs/AutoFocus/doc_files/Autofocus_Query_Samples__Sessions_and_Tags.png)

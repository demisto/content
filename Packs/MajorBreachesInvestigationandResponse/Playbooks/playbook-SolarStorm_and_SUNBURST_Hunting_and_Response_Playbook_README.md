This playbook does the following:
Collect indicators to aid in your threat hunting process
- Retrieve IOCs of SUNBURST (a trojanized version of the SolarWinds Orion plugin) - Retrieve C2 domains and URLs associated with Sunburst - Discover IOCs of associated activity related to the infection - Generate an indicator list to block indicators with SUNBURST tags
Hunt for the SUNBURST backdoor
- Query firewall logs to detect network activity - Search endpoint logs for Sunburst hashes to detect presence on hosts
If compromised hosts are found then:
- Notify security team to review and trigger remediation response actions - Fire off sub-playbooks to isolate/quarantine infected hosts/endpoints and await further actions from the security team.
Note: This is a beta pack, which lets you implement and test pre-release software. Since the pack is beta, it might contain bugs. Updates to the pack during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the pack to help us identify issues, fix them, and continually improve.
Supported Cortex XSOAR versions: 6.0.0 and later.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Search Endpoints By Hash - Generic V2
* Search Endpoint by CVE - Generic
* Panorama Query Logs
* Palo Alto Networks - Hunting And Threat Detection
* Block IP - Generic v2
* Isolate Endpoint - Generic
* CVE Enrichment - Generic v2
* Block Indicators - Generic v2

### Integrations
This playbook does not use any integrations.

### Scripts
* http
* UnEscapeURLs
* SearchIncidentsV2
* FileCreateAndUpload
* UnEscapeIPs
* CreateIndicatorsFromSTIX

### Commands
* expanse-get-issues
* appendIndicatorField
* expanse-list-risk-rules
* createNewIndicator
* expanse-get-risky-flows
* closeInvestigation
* extractIndicators

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ThreatIDs | Threat IDs to hunt through NGFW Threat Logs | 86246,86237,34801,39934,58049,38399,55378,37582,36709,37781,38388,56269 | Optional |
| IsolateEndpointAutomatically | Whether to automatically isolate endpoints, or opt for manual user approval. True means isolation will be done automatically. | False | Optional |
| BlockIndicatorsAutomatically | Whether to automatically indicators involved with SolarStorm. | False | Optional |
| CVEs | Related CVEs to SUNBURST and SolarStorm. | CVE-2020-14005,CVE-2020-13169 | Optional |
| SunBurstSTIX | Hard coded STIX file of SUNBURST and SolarStorm indicators | {"id":"bundle--60aab587-660c-4b58-89d0-efcf9cbdf8dd","type":"bundle","spec_version":"2.0","objects":[{"created":"2020-12-17T16:50:49.000Z","id":"indicator--180de847-a4c8-4e76-b719-138ac9c9b58e","labels":["file sha-256"],"modified":"2020-12-17T16:50:49.000Z","pattern":"[file:hashes.sha256 = '019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134']","score":"High","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.12709Z"},{"created":"2020-12-17T16:51:42.000Z","id":"indicator--8d217031-22f6-4d86-bd42-0519032d93bc","labels":["file sha-256"],"modified":"2020-12-17T16:51:42.000Z","pattern":"[file:hashes.sha256 = '439bcd0a17d53837bc29fb51c0abd9d52a747227f97133f8ad794d9cc0ef191e']","score":"Medium","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.144865Z"},{"created":"2020-12-17T16:58:27.000Z","id":"indicator--ff3c830a-dbe2-45ec-bfbc-dd357ae040fc","labels":["domain"],"modified":"2020-12-17T16:58:27.000Z","pattern":"[domain-name:value = 'thedoccloud.com']","score":"High","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.146129Z"},{"created":"2020-12-17T16:52:06.000Z","id":"indicator--514f2faf-9572-44e3-8f67-ea782206335f","labels":["file sha-256"],"modified":"2020-12-17T16:52:06.000Z","pattern":"[file:hashes.sha256 = 'a25cadd48d70f6ea0c4a241d99c5241269e6faccb4054e62d16784640f8e53bc']","score":"High","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.149043Z"},{"created":"2020-12-17T16:50:28.000Z","id":"indicator--2e3e39c2-757d-496f-82b1-a715e44fb682","labels":["file sha-256"],"modified":"2020-12-17T16:50:28.000Z","pattern":"[file:hashes.sha256 = 'abe22cf0d78836c3ea072daeaf4c5eeaf9c29b6feb597741651979fc8fbd2417']","score":"High","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.150253Z"},{"created":"2020-12-17T16:59:49.000Z","id":"indicator--a444b6e0-da14-4a6e-8024-15cda0061a6e","labels":["domain"],"modified":"2020-12-17T16:59:49.000Z","pattern":"[domain-name:value = 'databasegalore.com']","score":"High","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.151314Z"},{"created":"2020-12-17T16:54:00.000Z","id":"indicator--1fbf05cb-270c-4c0b-aac1-1ae960fb166a","labels":["file sha-256"],"modified":"2020-12-17T16:54:00.000Z","pattern":"[file:hashes.sha256 = 'c15abaf51e78ca56c0376522d699c978217bf041a3bd3c71d09193efa5717c71']","score":"High","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.152749Z"},{"created":"2020-12-17T16:51:14.000Z","id":"indicator--18561b05-1cbe-42ab-b4ae-b315e8709c02","labels":["file sha-256"],"modified":"2020-12-17T16:51:14.000Z","pattern":"[file:hashes.sha256 = 'ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6']","score":"High","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.15395Z"},{"created":"2020-12-17T16:49:45.000Z","id":"indicator--85ebd471-202b-4086-93fb-e075f70f506d","labels":["file sha-256"],"modified":"2020-12-17T16:49:45.000Z","pattern":"[file:hashes.sha256 = '53f8dfc65169ccda021b72a62e0c22a4db7c4077f002fa742717d41b3c40f2c7']","score":"High","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.155011Z"},{"created":"2020-12-17T16:52:27.000Z","id":"indicator--57f6e856-0188-4ab8-b563-f3633ec093fb","labels":["file sha-256"],"modified":"2020-12-17T16:52:27.000Z","pattern":"[file:hashes.sha256 = 'd3c6785e18fba3749fb785bc313cf8346182f532c59172b69adfb31b96a5d0af']","score":"High","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.156195Z"},{"created":"2020-12-17T16:57:26.000Z","id":"indicator--bf705330-2adb-4dfa-a844-d5d1176a0ad0","labels":["url"],"modified":"2020-12-17T16:57:26.000Z","pattern":"[url:value = 'mhdosoksaccf9sni9icp.appsync-api.eu-west-1.avsvmcloud.com \t']","score":"Medium","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.157272Z"},{"created":"2020-12-17T16:57:06.000Z","id":"indicator--2c1cfda2-2481-498f-8123-47ac1276f799","labels":["url"],"modified":"2020-12-17T16:57:06.000Z","pattern":"[url:value = 'k5kcubuassl3alrf7gm3.appsync-api.eu-west-1.avsvmcloud.com \t']","score":"Medium","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.159475Z"},{"created":"2020-12-17T16:59:33.000Z","id":"indicator--a64f9a04-d494-40ee-bb54-9b9406b76372","labels":["domain"],"modified":"2020-12-17T16:59:33.000Z","pattern":"[domain-name:value = 'incomeupdate.com']","score":"High","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.160553Z"},{"created":"2020-12-17T16:52:52.000Z","id":"indicator--8683f37c-2ea9-4253-b8c5-e138ddff40c3","labels":["file sha-256"],"modified":"2020-12-17T16:52:52.000Z","pattern":"[file:hashes.sha256 = '292327e5c94afa352cc5a02ca273df543f2020d0e76368ff96c84f4e90778712']","score":"Medium","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.161572Z"},{"created":"2020-12-17T16:46:31.000Z","id":"indicator--cc6f08e1-3475-43bc-ab4e-e5818e5b37b2","labels":["file sha-256"],"modified":"2020-12-17T16:46:31.000Z","pattern":"[file:hashes.sha256 = '32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77']","score":"High","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.162783Z"},{"created":"2020-12-17T16:47:35.000Z","id":"indicator--9ca400a7-257b-4cf3-91a8-b2c9a565266b","labels":["file sha-256"],"modified":"2020-12-17T16:47:35.000Z","pattern":"[file:hashes.sha256 = 'd0d626deb3f9484e649294a8dfa814c5568f846d5aa02d4cdad5d041a29d5600']","score":"High","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.163984Z"},{"created":"2020-12-17T17:00:14.000Z","id":"indicator--ea44dc42-e516-4307-9225-21ccb22a7cc2","labels":["domain"],"modified":"2020-12-17T17:00:14.000Z","pattern":"[domain-name:value = 'panhardware.com']","score":"High","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.165095Z"},{"created":"2020-12-17T16:56:41.000Z","id":"indicator--45f9a437-c4ee-4a24-9ffa-35a1202d62d5","labels":["url"],"modified":"2020-12-17T16:56:41.000Z","pattern":"[url:value = 'ihvpgv9psvq02ffo77et.appsync-api.us-east-2.avsvmcloud.com']","score":"High","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.166111Z"},{"created":"2020-12-17T16:55:40.000Z","id":"indicator--242b1ad9-6309-4752-bad4-abf73f641297","labels":["url"],"modified":"2020-12-17T16:55:40.000Z","pattern":"[url:value = '7sbvaemscs0mc925tb99.appsync-api.us-west-2.avsvmcloud.com \t']","score":"Medium","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.167169Z"},{"created":"2020-12-17T16:55:18.000Z","id":"indicator--b96ee095-a7d4-40a8-a4b4-9e7c080f5a44","labels":["url"],"modified":"2020-12-17T16:55:18.000Z","pattern":"[url:value = '6a57jk2ba1d9keg15cbg.appsync-api.eu-west-1.avsvmcloud.com']","score":"High","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.168384Z"},{"created":"2020-12-17T16:59:14.000Z","id":"indicator--e03d0075-7880-43cd-86b1-18325470be45","labels":["domain"],"modified":"2020-12-17T16:59:14.000Z","pattern":"[domain-name:value = 'highdatabase.com']","score":"High","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.169586Z"},{"created":"2020-12-17T16:58:56.000Z","id":"indicator--8942bb33-e898-4a10-bfb3-64530bd973ab","labels":["domain"],"modified":"2020-12-17T16:58:56.000Z","pattern":"[domain-name:value = 'websitetheme.com']","score":"High","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.170584Z"},{"created":"2020-12-17T16:56:08.000Z","id":"indicator--2be41276-00d3-4438-bbf0-4fcc56dc3076","labels":["url"],"modified":"2020-12-17T16:56:08.000Z","pattern":"[url:value = 'gq1h856599gqh538acqn.appsync-api.us-west-2.avsvmcloud.com']","score":"High","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.171575Z"},{"created":"2020-12-17T16:58:10.000Z","id":"indicator--8cd838ae-6330-4fbf-b5b4-07b77d46438d","labels":["domain"],"modified":"2020-12-17T16:58:10.000Z","pattern":"[domain-name:value = 'freescanonline.com']","score":"High","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.172676Z"},{"created":"2020-12-17T16:57:52.000Z","id":"indicator--646c5771-6904-4176-813f-a2ca357f0e42","labels":["domain"],"modified":"2020-12-17T16:57:52.000Z","pattern":"[domain-name:value = 'deftsecurity.com']","score":"High","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.173695Z"},{"created":"2020-12-17T16:47:15.000Z","id":"indicator--4069cf11-f617-40f2-8f7f-534e225aa33b","labels":["file sha-256"],"modified":"2020-12-17T16:47:15.000Z","pattern":"[file:hashes.sha256 = 'efbec6863f4330dbb702cc43a85a0a7c29d79fde0f7d66eac9a3be43493cab4f']","score":"Medium","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.174561Z"},{"created":"2020-12-17T17:00:41.000Z","id":"indicator--026307f7-449c-4858-a112-fc4b73c31593","labels":["domain"],"modified":"2020-12-17T17:00:41.000Z","pattern":"[domain-name:value = 'zupertech.com']","score":"High","source":"","type":"indicator","valid_from":"2020-12-17T17:01:35.175745Z"}]} | Optional |
| KnownRelatedIOCs | Additional known IOCs relates to SUNBURST and SolarStorm. | d0d626deb3f9484e649294a8dfa814c5568f846d5aa02d4cdad5d041a29d5600, efbec6863f4330dbb702cc43a85a0a7c29d79fde0f7d66eac9a3be43493cab4f, d0d626deb3f9484e649294a8dfa814c5568f846d5aa02d4cdad5d041a29d5600, efbec6863f4330dbb702cc43a85a0a7c29d79fde0f7d66eac9a3be43493cab4f, 32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77, d0d626deb3f9484e649294a8dfa814c5568f846d5aa02d4cdad5d041a29d5600, efbec6863f4330dbb702cc43a85a0a7c29d79fde0f7d66eac9a3be43493cab4f, 32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77, 019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134, ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6 | Optional |
| LogForwarding | PAN-OS Log Forwarding Profile Name |  | Optional |
| AutoCommit | This input establishes whether to commit the configuration automatically in PAN-OS.<br/>Yes - Commit automatically.<br/>No - Commit manually. | No | Optional |
| AutoBlockSolarWindsServer | This input establishes whether to block the SolarWinds server automatically in PAN-OS.<br/>True - Commit automatically.<br/>False - Commit manually. | False | Optional |
| DeviceGroup | Target Device Group \(Panorama only\)  |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![SolarStorm and SUNBURST Hunting and Response Playbook](Insert the link to your image here)
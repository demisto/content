PolySwarm - Real-time threat intelligence from a crowdsourced network of security experts and antivirus companies.

## Detailed Description

PolySwarm is a crowdsourced malware threat intelligence and scanning platform. Our Cortex XSOAR integration allows you to use PolySwarm's dataset over millions of malware samples to enrich your existing indicators. This integration is updated and ready mfor PolySwarm API version 2.

##### What does this pack do?
- Submit a File, URL, IP or Domain, and get enriched threat intelligence information about the artifact.
- Provide a hash (SHA1, MD5, SHA256) and search artifacts in the PolySwarm dataset.

## Configure PolySwarm on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for PolySwarm.
3.  Click **Add instance** to create and configure a new integration instance.
    - **Name**: a textual name for the integration instance.
    - **PolySwarm API Key** - Get yours at: https://polyswarm.network
    - **The Base URL to connect to**
    - **PolySwarm Community**
4.  Click **Test** to validate the new instance.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

1. **polyswarm-get-report**: Returns a report from the Hash.
2. **file**: Queries PolySwarm for file reputation information.
3. **ip**: Queries PolySwarm for IP reputation information.
4. **url**: Queries PolySwarm for URL reputation information.
5. **domain**: Queries PolySwarm for Domain reputation information.
6. **url-scan**: Uploads a URL to PolySwarm and retrieves analysis results.
7. **file-rescan**: Rescans uploaded artifact by hash.
8. **get-file**: Downloads a file from PolySwarm.
9. **file-scan**: Uploads a file to PolySwarm and retrieves analysis results.

<!-- -->

### 1\. polyswarm-get-report

---

Returns a report from the Hash.

##### Base Command

`polyswarm-get-report`

<!-- -->

##### Input

| **Argument Name** | **Description**   | **Required**      |
| ----------------- | ----------------- | ----------------- |
| scan\_uuid        | Hash string       | Required          |



##### Context Output

| **Path**                                | **Type**                                | **Description**                         |
| --------------------------------------- | --------------------------------------- | --------------------------------------- |
| PolySwarm.Permalink                     | String                                  | The results of the PolySwarm Permalink. |
| PolySwarm.Positives                     | Number                                  | The total Positives found.              |
| PolySwarm.Scan_UUID                     | String                                  | The PolySwarm Scan UUID.                |
| PolySwarm.Total                         | Number                                  | The total scan.                         |
| PolySwarm.Artifact                      | String                                  | The artifact queried.                   |
| 

##### Command Example

`!polyswarm-get-report scan_uuid="25e755c8957163376b3437ce808843c1c2598e0fb3c5f31dc958576cd5cde63e"`  
`!polyswarm-get-report scan_uuid="25e755c8957163376b3437ce808843c1c2598e0fb3c5f31dc958576cd5cde63e, 2410907a92b16dbd23a88d6bbd5037eae20eea809279f370293b587e1996eafe"`


### 2\. file

---

Queries Polyswarm for file reputation information.

##### Base Command

`file`

##### Input

| **Argument Name**                                                                   | **Description**                                                                     | **Required**                                                                        |
| ----------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| hash                                                                                | The hash for the file reputation information. Can be: "SHA256", "SHA1" or "MD5". | Required                                                                            |


##### Context Output

| **Path**                     | **Type**                     | **Description**              |
| ---------------------------- | ---------------------------- | ---------------------------- |
| PolySwarm.Permalink          | String                       | PolySwarm Permalink results. |
| PolySwarm.Positives          | Number                       | Total Positives found.       |
| PolySwarm.Scan_UUID          | String                       | The PolySwarm scan UUID.     |
| PolySwarm.Total              | Number                       | The total Scan.              |
| PolySwarm.Artifact           | String                       | The artifact queried.        |


##### Command Example

`!file hash="2410907a92b16dbd23a88d6bbd5037eae20eea809279f370293b587e1996eafe"`  
`!file hash="2410907a92b16dbd23a88d6bbd5037eae20eea809279f370293b587e1996eafe, 1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a"`


### 3\. ip

---

Queries Polyswarm for IP reputation information.

##### Base Command

`ip`


##### Input

| **Argument Name**                              | **Description**                                | **Required**                                   |
| ---------------------------------------------- | ---------------------------------------------- | ---------------------------------------------- |
| ip                                             | The IP Address for the reputation information. | Required                                       |



##### Context Output

| **Path**                     | **Type**                     | **Description**              |
| ---------------------------- | ---------------------------- | ---------------------------- |
| PolySwarm.Permalink          | String                       | PolySwarm Permalink Results. |
| PolySwarm.Positives          | Number                       | Total Positives Found.       |
| PolySwarm.Total              | Number                       | The total Scan.              |
| PolySwarm.Scan_UUID          | String                       | PolySwarm Scan UUID.         |
| PolySwarm.Artifact           | String                       | The artifact queried.        |
| DBotScore.Type               | String                       | The indicator type.          |
| IP.MalwareFamily             | String                       | The malware family of the IP.|
| DBotScore.Indicator          | String                       | The indicator was tested.    |
| DBotScore.Vendor             | String                       | The vendor for the score.    |
| DBotScore.Score              | Number                       | The actual score.            |
| IP.Address                   | String                       | The IP address.              |
| IP.Malicious.Vendor          | String                       | The vendor of the decision.  |
| IP.Tags                      | String                       | Tags associated with the IP. |


##### Command Example

`!ip ip="8.8.8.8"`  
`!ip ip="8.8.8.8, 4.4.4.4"`


### 4\. url

---

Queries Polyswarm for URL reputation information.

##### Base Command

`url`


##### Input

| **Argument Name**               | **Description**                 | **Required**                    |
| ------------------------------- | ------------------------------- | ------------------------------- |
| url                             | URL for reputation information. | Required                        |


##### Context Output

| **Path**                     | **Type**                     | **Description**              |
| ---------------------------- | ---------------------------- | ---------------------------- |
| PolySwarm.Permalink          | String                       | PolySwarm Permalink Results. |
| PolySwarm.Positives          | Number                       | Total Positives Found.       |
| PolySwarm.Total              | Number                       | The total Scan.              |
| PolySwarm.Scan_UUID          | String                       | PolySwarm Scan UUID.         |
| PolySwarm.Artifact           | String                       | The artifact queried.        |


##### Command Example

`!url url="https://polyswarm.io"`  
`!url url="https://polyswarm.io, https://polyswarm.network"`


### 5\. domain

---

Queries Polyswarm for Domain reputation information.

##### Base Command

`domain`


##### Input

| **Argument Name**                      | **Description**                        | **Required**                           |
| -------------------------------------- | -------------------------------------- | -------------------------------------- |
| domain                                 | Domain for the reputation information. | Required                               |


##### Context Output

| **Path**                     | **Type**                     | **Description**              |
| ---------------------------- | ---------------------------- | ---------------------------- |
| PolySwarm.Permalink          | String                       | PolySwarm Permalink Results. |
| PolySwarm.Positives          | Number                       | Total Positives Found.       |
| PolySwarm.Total              | Number                       | The total Scan.              |
| PolySwarm.Scan_UUID          | String                       | PolySwarm Scan UUID.         |
| PolySwarm.Artifact           | String                       | The artifact queried.        |


##### Command Example

`!domain domain="polyswarm.io"`  
`!domain domain="polyswarm.io, polyswarm.network"`


### 6\. url-scan

---

Uploads a URL to Polyswarm and retrieves analysis results.

##### Base Command

`url-scan`


##### Input

| **Argument Name** | **Description**   | **Required**      |
| ----------------- | ----------------- | ----------------- |
| url               | The URL to scan.  | Required          |


##### Context Output

| **Path**                     | **Type**                     | **Description**              |
| ---------------------------- | ---------------------------- | ---------------------------- |
| PolySwarm.Permalink          | String                       | PolySwarm Permalink Results. |
| PolySwarm.Positives          | Number                       | Total Positives Found.       |
| PolySwarm.Total              | Number                       | The total Scan.              |
| PolySwarm.Scan_UUID          | String                       | PolySwarm Scan UUID.         |
| PolySwarm.Artifact           | String                       | The artifact queried.        |

##### Command Example

`!url-scan url="https://polyswarm.io"`  
`!url-scan url="https://polyswarm.io, https://polyswarm.network"`


### 7\. file-rescan

---

Rescans the uploaded artifact by hash.

##### Base Command

`file-rescan`


##### Input

| **Argument Name**                                       | **Description**                                         | **Required**                                            |
| ------------------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------- |
| hash                                                    | The hash to rescan. Can be: "SHA256", "SHA1", or "MD5". | Required                                                |



##### Context Output

| **Path**                     | **Type**                     | **Description**              |
| ---------------------------- | ---------------------------- | ---------------------------- |
| PolySwarm.Permalink          | String                       | PolySwarm Permalink Results. |
| PolySwarm.Positives          | Number                       | Total Positives Found.       |
| PolySwarm.Total              | Number                       | The total Scan.              |
| PolySwarm.Scan_UUID          | String                       | PolySwarm Scan UUID.         |
| PolySwarm.Artifact           | String                       | The artifact queried.        |



##### Command Example

`!file-rescan hash="2410907a92b16dbd23a88d6bbd5037eae20eea809279f370293b587e1996eafe"`  
`!file-rescan hash="2410907a92b16dbd23a88d6bbd5037eae20eea809279f370293b587e1996eafe, 25e755c8957163376b3437ce808843c1c2598e0fb3c5f31dc958576cd5cde63e"`


### 8\. get-file

---

Downloads a file from Polyswarm.

##### Base Command

`get-file`


##### Input

| **Argument Name**                                              | **Description**                                                | **Required**                                                   |
| -------------------------------------------------------------- | -------------------------------------------------------------- | -------------------------------------------------------------- |
| hash                                                           | The hash file to download. Can be: "SHA256", "SHA1", or "MD5". | Required                                                       |



##### Context Output

| **Path**                           | **Type**                           | **Description**                    |
| ---------------------------------- | ---------------------------------- | ---------------------------------- |
| File.Size                          | Number                             | The file size.                     |
| File.SHA1                          | String                             | The SHA1 hash of the file.         |
| File.SHA256                        | String                             | The SHA256 hash of the file.       |
| File.Name                          | String                             | The sample name.                   |
| File.SSDeep                        | String                             | The SSDeep hash of the file.       |
| File.EntryID                       | String                             | The War-Room Entry ID of the file. |
| File.Info                          | String                             | Basic information of the file.     |
| File.Type                          | String                             | File type. For example, "PE".      |
| File MD5                           | String                             | MD5 hash of the file.              |
| File.Extension                     | String                             | The file extension.                |
| PolySwarm.FileID                   | String                             | The File ID.                       |



##### Command Example

`!get-file hash="2410907a92b16dbd23a88d6bbd5037eae20eea809279f370293b587e1996eafe`


### 9\. file-scan

---

Uploads a file to Polyswarm and retrieves analysis results.

##### Base Command

`file-scan`


##### Input

| **Argument Name**      | **Description**        | **Required**           |
| ---------------------- | ---------------------- | ---------------------- |
| entryID                | The War-room Entry ID. | Required               |



##### Context Output

| **Path**                     | **Type**                     | **Description**              |
| ---------------------------- | ---------------------------- | ---------------------------- |
| PolySwarm.Permalink          | String                       | PolySwarm Permalink Results. |
| PolySwarm.Positives          | Number                       | Total Positives Found.       |
| PolySwarm.Total              | Number                       | The total Scan.              |
| PolySwarm.Scan_UUID          | String                       | PolySwarm Scan UUID.         |
| PolySwarm.Artifact           | String                       | The artifact queried.        |


##### Command Example

`!file-scan entryID="995@0c42ee2d-57ff-4ccf-88ef-8d51c7936595"`

The Rubrik Security Cloud integration will fetch the Rubrik Anomaly Event and is rich with commands to perform the on-demand scans, backups, recoveries and many more features to manage and protect the organizational data.
This integration was integrated and tested with version 1.0.0 of Rubrik Security Cloud

## Configure Rubrik Security Cloud in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Service Account JSON |  | False |
| Rubrik Account (e.g. ${rubrikAccount}.my.rubrik.com) |  | False |
| Email |  | False |
| Password |  | False |
| Fetch incidents |  | False |
| Incident type |  | False |
| First fetch time | The time interval for the first fetch \(retroactive\). Examples of supported values can be found at https://dateparser.readthedocs.io/en/latest/\#relative-dates. | False |
| Fetch Limit (Maximum of 1000) | Maximum number of incidents to fetch every time. The maximum value is 1000. | False |
| Anomaly Event Critical Severity Level Mapping | When a Anomaly event of Critical severity is detected and fetched, this setting indicates what severity will get assigned within XSOAR. | False |
| Anomaly Event Warning Severity Level Mapping | When a Anomaly event of Warning severity is detected and fetched, this setting indicates what severity will get assigned within XSOAR. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | False |
| Use system proxy settings | Whether to use XSOAR's system proxy settings to connect to the API. | False |
| Trust any certificate (not secure) | Whether to allow connections without verifying SSL certificates validity. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### rubrik-radar-analysis-status
***
Check the Radar Event for updates.


#### Base Command

`rubrik-radar-analysis-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| activitySeriesId | The ID of the Polaris Event Series. When used in combination with \"Rubrik Radar Anomaly\" incidents, this value will automatically be looked up using the incident context. Otherwise it is a required value.<br/><br/>Note: Users can retrieve the list of the activity series IDs by executing the \"rubrik-event-list\" command. | Required | 
| clusterId | The ID of the CDM cluster. When used in combination with \"Rubrik Radar Anomaly\" incidents, this value will automatically be looked up using the incident context. Otherwise, it is a required value.<br/><br/>Note: Users can retrieve the list of the cluster IDs by executing the \"rubrik-gps-cluster-list\" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rubrik.Radar.EventComplete | Boolean | Flag that indicates whether Radar has finished analysing the object. | 
| Rubrik.Radar.Message | Unknown | The text, ID, and timestamp of each message in the Activity Series. | 
| Rubrik.Radar.ActivitySeriesId | String | The ID of the Rubrik Polaris Activity Series. | 
| Rubrik.Radar.ClusterId | String | The ID of the cluster. | 


#### Command Example
```!rubrik-radar-analysis-status activitySeriesId="" clusterId="cc19573c-db6c-418a-9d48-067a256543ba"```

#### Human Readable Output
### Radar Analysis Status
|Activity Series ID|Cluster ID|Message|Event Complete|
|---|---|---|---|
| ec9c48ce-5faf-474a-927c-33667355aecd | cc19573c-db6c-418a-9d48-067a256543ba | Completed backup of the transaction log for SQL Server database 'AdventureWorks2012' from 'sx1-sql12-1\MSSQLSERVER'. | True |



### rubrik-sonar-sensitive-hits
***
Find data classification hits on an object.


#### Base Command

`rubrik-sonar-sensitive-hits`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| objectName | The name of the Rubrik object to check for sensitive hits.  When used in combination with "Rubrik Radar Anomaly" incidents, this value will automatically be looked up using the incident context. Otherwise it is a required value.<br/><br/>Note: Users can get the list of the object names by executing the "rubrik-polaris-object-list" or "rubrik-polaris-object-search" command. | Optional | 
| searchTimePeriod | The number of days in the past to look for sensitive hits. If no value is provided, then today's data will be returned and, if there is no data for today then the argument will default to 7 days.<br/> Default is 7. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rubrik.Sonar.totalHits | String | The total number of data classification hits found on the provided object. | 
| Rubrik.Sonar.id | String | ID of the sensitive hits object. | 
| Rubrik.Sonar.policy_hits | Unknown | Information of the policy analyzer group of the sensitive hits object. | 
| Rubrik.Sonar.filesWithHits | Number | The total number of files with hits of the object. | 
| Rubrik.Sonar.openAccessFiles | Number | The total number of open access files of the object. | 
| Rubrik.Sonar.openAccessFilesWithHits | Number | The total number of open access files with hits of the object. | 
| Rubrik.Sonar.openAccessFolders | Number | The total number of open access folders of the object. | 
| Rubrik.Sonar.staleFiles | Number | The total number of stale files of the object. | 
| Rubrik.Sonar.staleFilesWithHits | Number | The total number of stale files with hits of the object. | 
| Rubrik.Sonar.openAccessStaleFiles | Number | The total number of open access stale files of the object. | 
| Rubrik.Radar.Message | Unknown | The text, ID, and timestamp of each message in the Activity Series. | 
| Rubrik.Radar.ActivitySeriesId | String | The ID of the Rubrik Polaris Activity Series. | 


#### Command Example
```!rubrik-sonar-sensitive-hits objectName="sx1-radar15"```

#### Human Readable Output
### Sensitive Hits
|ID|Total Hits|
|---|---|
| afc0f6f0-148a-54c5-9927-c24c7cde1608 | 49684 |



### rubrik-cdm-cluster-location
***
Find the CDM GeoLocation of a CDM Cluster.


#### Base Command

`rubrik-cdm-cluster-location`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| clusterId | The ID of the CDM cluster. When used in combination with "Rubrik Radar Anomaly" incidents, this value will automatically be looked up using the incident context. Otherwise, it is a required value.<br/><br/>Note: Users can retrieve the list of the cluster IDs by executing the "rubrik-gps-cluster-list" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rubrik.CDM.Cluster.Location | String | The GeoLocation of the Rubrik CDM Cluster. | 
| Rubrik.CDM.ClusterId | String | The ID of the cluster. | 


#### Command Example
```!rubrik-cdm-cluster-location clusterId="cc19573c-db6c-418a-9d48-067a256543ba"```

#### Human Readable Output
### CDM Cluster Location
|Location|
|---|
| San Francisco, CA, USA |



### rubrik-cdm-cluster-connection-state
***
Find the CDM Connection State of a CDM Cluster.


#### Base Command

`rubrik-cdm-cluster-connection-state`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| clusterId | The ID of the CDM cluster. When used in combination with "Rubrik Radar Anomaly" incidents, this value will automatically be looked up using the incident context. Otherwise, it is a required value.<br/><br/>Note: Users can retrieve the list of the cluster IDs by executing the "rubrik-gps-cluster-list" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rubrik.CDM.Cluster.ConnectionState | String | The Connection State of the Rubrik CDM Cluster. | 
| Rubrik.CDM.ClusterId | String | The ID of the cluster. | 


#### Command Example
```!rubrik-cdm-cluster-connection-state clusterId="cc19573c-db6c-418a-9d48-067a256543ba"```

#### Human Readable Output
### CDM Cluster Connection State
|Connection State|
|---|
| Connected |



### rubrik-polaris-object-search
***
Search for Rubrik discovered objects of any type, return zero or more matches.


#### Base Command

`rubrik-polaris-object-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Number of results to retrieve in the response. Maximum size allowed is 1000. Default is 50. | Optional | 
| object_name | The name of the object to search for. | Required | 
| sort_by | Specify the field to use for sorting the response.<br/><br/>Note: Supported values are "ID" and "NAME" only. For any other values, the obtained result is sorted or not is not confirmed. Default is ID. | Optional | 
| sort_order | Specify the order to sort the data in.<br/><br/>Possible values are: "ASC", "DESC". Default is ASC. | Optional | 
| next_page_token | The next page cursor to retrieve the next set of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.GlobalSearchObject.id | String | The ID of the object. | 
| RubrikPolaris.GlobalSearchObject.name | String | The name of the object. | 
| RubrikPolaris.GlobalSearchObject.objectType | String | The type of the object. | 
| RubrikPolaris.GlobalSearchObject.physicalPath.fid | String | The FID of the physical path of the object. | 
| RubrikPolaris.GlobalSearchObject.physicalPath.name | String | The name of the physical path where the object relies. | 
| RubrikPolaris.GlobalSearchObject.physicalPath.objectType | String | The object type of the physical path where the object relies. | 
| RubrikPolaris.GlobalSearchObject.azureRegion | String | The azure region of the object. | 
| RubrikPolaris.GlobalSearchObject.awsRegion | String | The aws region of the object. | 
| RubrikPolaris.GlobalSearchObject.emailAddress | String | The email address of the object. | 
| RubrikPolaris.GlobalSearchObject.isRelic | Boolean | Whether the object is relic \(historical\) or not. | 
| RubrikPolaris.GlobalSearchObject.effectiveSlaDomain.id | String | The effective SLA domain ID of the object. | 
| RubrikPolaris.GlobalSearchObject.effectiveSlaDomain.name | String | The effective SLA domain name of the object. | 
| RubrikPolaris.GlobalSearchObject.effectiveSlaDomain.description | String | The effective SLA domain description of the object. | 
| RubrikPolaris.GlobalSearchObject.effectiveSlaDomain.fid | String | The FID of the object's effective SLA domain. | 
| RubrikPolaris.GlobalSearchObject.effectiveSlaDomain.cluster.id | String | The cluster ID of the object's effective SLA domain. | 
| RubrikPolaris.GlobalSearchObject.effectiveSlaDomain.cluster.name | String | The cluster name of the object's effective SLA domain. | 
| RubrikPolaris.GlobalSearchObject.physicalChildConnection.count | String | The count of physical child connection of the object. | 
| RubrikPolaris.GlobalSearchObject.physicalChildConnection.edges.node.id | String | The ID of physical child connection of the object. | 
| RubrikPolaris.GlobalSearchObject.physicalChildConnection.edges.node.name | String | The name of the physical child connection of the object. | 
| RubrikPolaris.GlobalSearchObject.physicalChildConnection.edges.node.replicatedObjects.cluster.id | String | The cluster ID of the replicated objects of physical child connection of the object. | 
| RubrikPolaris.GlobalSearchObject.physicalChildConnection.edges.node.replicatedObjects.cluster.name | String | The cluster name of the replicated objects of physical child connection of the object. | 
| RubrikPolaris.GlobalSearchObject.cluster.id | String | The cluster ID related to the object. | 
| RubrikPolaris.GlobalSearchObject.cluster.name | String | The name of the cluster related to the object. | 
| RubrikPolaris.GlobalSearchObject.primaryClusterLocation.id | String | The primary cluster location ID of the object. | 
| RubrikPolaris.GlobalSearchObject.gcpZone | String | The gcp zone of the object. | 
| RubrikPolaris.GlobalSearchObject.gcpRegion | String | The gcp region of the object. | 
| RubrikPolaris.GlobalSearchObject.gcpNativeProject.name | String | The gcp native project name of the object. | 
| RubrikPolaris.PageToken.GlobalSearchObject.next_page_token | String | Next page token. | 
| RubrikPolaris.PageToken.GlobalSearchObject.name | String | Name of the command. | 
| RubrikPolaris.PageToken.GlobalSearchObject.has_next_page | Boolean | Whether the result has the next page or not. | 


#### Command Example
```!rubrik-polaris-object-search object_name="admin" limit=2```

#### Human Readable Output
### Global Objects
|Object ID|Object Name|Type|SLA Domain|
|---|---|---|---|
| 0f667954-9052-42c8-ac20-2149da4d0ec4 | Hoang-Admin Nguyen | O365Mailbox | UNPROTECTED |
| 3e5d0800-71f6-4e42-badc-ae8b98c8a808 | Admin o365 | O365Mailbox | UNPROTECTED |

 Note: To retrieve the next set of results use, "next_page_token" = xyz


### rubrik-sonar-policies-list
***
Retrieve the list of all the available Sonar policies.


#### Base Command

`rubrik-sonar-policies-list`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.SonarPolicy.id | String | Unique ID of the policy. | 
| RubrikPolaris.SonarPolicy.name | String | Name of the policy. | 
| RubrikPolaris.SonarPolicy.description | String | Descriptive name of the policy. | 
| RubrikPolaris.SonarPolicy.creator.email | String | Email of the user who created the policy. | 
| RubrikPolaris.SonarPolicy.totalObjects | Number | Number of total objects present in the policy. | 
| RubrikPolaris.SonarPolicy.numAnalyzers | Number | Number of analyzers present in the policy. | 
| RubrikPolaris.SonarPolicy.objectStatuses.id | String | ID of the object present in the policy. | 
| RubrikPolaris.SonarPolicy.objectStatuses.latestSnapshotResult.snapshotFid | String | Snapshot ID of the object present in the policy. | 
| RubrikPolaris.SonarPolicy.objectStatuses.policyStatuses.policyId | String | Policy ID. | 
| RubrikPolaris.SonarPolicy.objectStatuses.policyStatuses.status | String | Policy status. | 


#### Command Example
```!rubrik-sonar-policies-list ```

#### Human Readable Output
### Sonar Policies
|ID|Name|Description|Analyzers|Objects|Creator Email|
|---|---|---|---|---|---|
| bdb8c043-ee89-43ef-a3e2-73e94b5b3900 | CCPA | California Consumer Privacy Act | 5 | 3 | dummy.email@rubrik.com |
| 53e447ed-9114-4fcd-b5a6-7ac759980fde | GLBA | U.S. Gramm-Leach-Bliley Act | 4 | 3 |  |



### rubrik-sonar-policy-analyzer-groups-list
***
List the analyzer group policies.


#### Base Command

`rubrik-sonar-policy-analyzer-groups-list`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.SonarAnalyzerGroup.id | String | The analyzer group ID. | 
| RubrikPolaris.SonarAnalyzerGroup.name | String | The name of the analyzer group. | 
| RubrikPolaris.SonarAnalyzerGroup.groupType | String | The analyzer group type. | 
| RubrikPolaris.SonarAnalyzerGroup.analyzers.id | String | The ID of the analyzers belong to the group. | 
| RubrikPolaris.SonarAnalyzerGroup.analyzers.name | String | The name of the analyzers belong to the group. | 
| RubrikPolaris.SonarAnalyzerGroup.analyzers.analyzerType | String | The type of the analyzers belong to the group. | 


#### Command Example
```!rubrik-sonar-policy-analyzer-groups-list ```

#### Human Readable Output
### Sonar Policy Analyzer Groups
|ID|Name|Group Type|Analyzers|
|---|---|---|---|
| 97c6a54a-acfc-5ab2-a24a-6a7f3a9a1553 | GLBA | GLBA | id: ed30dfa0-334f-55ff-a1b7-03b6bdd7849b, Name: Credit Card, Analyzer Type: CREDIT_CARD<br/><br/>id: 3e60a612-3e97-5f03-b3a1-cfb7a6a67e8f, Name: US Bank Acct, Analyzer Type: US_BANK_ACCT<br/><br/>id: 03b3dc9e-81c1-561c-8235-17cf2fc1c729, Name: US ITIN, Analyzer Type: US_ITIN<br/><br/>id: d5ce3ae5-f530-562a-85b1-4a84264a350a, Name: US SSN, Analyzer Type: US_SSN |
| 543dd5e0-c72c-50e2-a3d9-1688343f472c | HIPAA | HIPAA | id: 9da675b3-944b-5da3-a2da-ed149d300075, Name: US/UK Passport, Analyzer Type: PASSPORT<br/><br/>id: 18665533-c28c-5a40-b747-4b6508fecdfa, Name: US NPI, Analyzer Type: US_HEALTHCARE_NPI<br/><br/>id: 03b3dc9e-81c1-561c-8235-17cf2fc1c729, Name: US ITIN, Analyzer Type: US_ITIN<br/><br/>id: d5ce3ae5-f530-562a-85b1-4a84264a350a, Name: US SSN, Analyzer Type: US_SSN<br/><br/>id: 6bcc8e4e-0ec9-5538-b91d-a506dac47ec6, Name: US DEA, Analyzer Type: DEA_NUMBER |
| 16bd3864-bad6-513b-b38d-a108e648cf4a |  | PCI_DSS |  |
| c8c8072a-9454-5e68-9a23-bbcb9824838e | U.S. Financials | US_FINANCE | id: bb9a929b-3f29-5d3f-a768-de74e8ee5a9c, Name: n/a, Analyzer Type: CUSIP_NUMBER |



### rubrik-polaris-vm-object-metadata-get
***
Retrieve details for a Vsphere object based on the provided object ID.


#### Base Command

`rubrik-polaris-vm-object-metadata-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | The ID of the object to get details.<br/><br/>Note: Users can get the list of the object IDs by executing the "rubrik-polaris-vm-objects-list" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.VSphereVm.id | String | Unique ID of the object. | 
| RubrikPolaris.VSphereVm.metadata.authorizedOperations | Unknown | List of operations performed by the object. | 
| RubrikPolaris.VSphereVm.metadata.name | String | The name of the object. | 
| RubrikPolaris.VSphereVm.metadata.isRelic | Boolean | Whether the object is relic or not. | 
| RubrikPolaris.VSphereVm.metadata.effectiveSlaDomain.id | String | ID of the SLA domain. | 
| RubrikPolaris.VSphereVm.metadata.effectiveSlaDomain.name | String | Name of the SLA domain. | 
| RubrikPolaris.VSphereVm.metadata.effectiveSlaDomain.cluster.id | String | ID of the cluster of the SLA domain. | 
| RubrikPolaris.VSphereVm.metadata.effectiveSlaDomain.cluster.name | String | Name of the cluster of the SLA domain. | 
| RubrikPolaris.VSphereVm.metadata.effectiveSlaSourceObject.fid | String | SLA Source object FID. | 
| RubrikPolaris.VSphereVm.metadata.effectiveSlaSourceObject.name | String | SLA source object name. | 
| RubrikPolaris.VSphereVm.metadata.effectiveSlaSourceObject.objectType | String | SLA source object type. | 
| RubrikPolaris.VSphereVm.metadata.protectionDate | String | Protection date of the object. | 
| RubrikPolaris.VSphereVm.metadata.reportSnappable.id | String | The ID of the snappable for a particular report related to an object. Snappable supports backups or filesets of physical machines using the rubrik connector. | 
| RubrikPolaris.VSphereVm.metadata.reportSnappable.logicalBytes | Number | Logical bytes of snappable report. | 
| RubrikPolaris.VSphereVm.metadata.reportSnappable.physicalBytes | Number | The physical byte of the snappable for a particular report related to an object. | 
| RubrikPolaris.VSphereVm.metadata.reportSnappable.archiveStorage | Number | The archived storage of the snappable for a particular report related to an object. | 
| RubrikPolaris.VSphereVm.metadata.cluster.id | String | Unique ID of the cluster which is the datastore for the recovered virtual machine. | 
| RubrikPolaris.VSphereVm.metadata.cluster.name | String | Cluster name of the VM to which the object belongs. | 
| RubrikPolaris.VSphereVm.metadata.cluster.status | String | Cluster status of the VM to which the object belongs. | 
| RubrikPolaris.VSphereVm.metadata.cluster.version | String | Cluster version of the VM to which the object belongs. | 
| RubrikPolaris.VSphereVm.metadata.cluster.lastConnectionTime | String | Last time when the vm was connected to the cluster. | 
| RubrikPolaris.VSphereVm.metadata.cluster.defaultAddress | String | Default address where the cluster is stored. | 
| RubrikPolaris.VSphereVm.metadata.cluster.clusterNodeConnection.nodes.id | String | Node ID of the node connection related to cluster. | 
| RubrikPolaris.VSphereVm.metadata.cluster.clusterNodeConnection.nodes.status | String | Node status of the node connection related to cluster. | 
| RubrikPolaris.VSphereVm.metadata.cluster.clusterNodeConnection.nodes.ipAddress | String | IP address of the node connection related to cluster. | 
| RubrikPolaris.VSphereVm.metadata.cluster.state.connectedState | String | Connected state of the cluster. | 
| RubrikPolaris.VSphereVm.metadata.cluster.state.clusterRemovalState | String | State of the cluster if it is registered for removal or not. | 
| RubrikPolaris.VSphereVm.metadata.cluster.passesConnectivityCheck | Boolean | Whether the cluster passes connectivity check or not. | 
| RubrikPolaris.VSphereVm.metadata.cluster.globalManagerConnectivityStatus.urls.url | String | URL of Global Manager Connectivity Status. | 
| RubrikPolaris.VSphereVm.metadata.cluster.globalManagerConnectivityStatus.urls.isReachable | Boolean | Whether the url in global Manager Connectivity Status is reachable or not. | 
| RubrikPolaris.VSphereVm.metadata.cluster.connectivityLastUpdated | String | Date time when the connectivity status of the cluster is lastly updated. | 
| RubrikPolaris.VSphereVm.metadata.primaryClusterLocation.id | String | The location ID of the primary cluster to which the object belongs. | 
| RubrikPolaris.VSphereVm.metadata.primaryClusterLocation.name | String | The location name of the primary cluster to which the object belongs. | 
| RubrikPolaris.VSphereVm.metadata.arrayIntegrationEnabled | Boolean | Whether the array integration is enabled or not. | 
| RubrikPolaris.VSphereVm.metadata.snapshotConsistencyMandate | String | Data consistency in recovery points is the snapshot consistency mandate. It is broadly classified into 3 categories: inconsistent, crash-consistent, app-consistent. | 
| RubrikPolaris.VSphereVm.metadata.agentStatus.agentStatus | String | The status of an agent related to an object. In Rubrik agents are connectors also known as Rubrik Backup Service. | 
| RubrikPolaris.VSphereVm.metadata.logicalPath.fid | String | The logical path ID of the node to which the object belongs. | 
| RubrikPolaris.VSphereVm.metadata.logicalPath.objectType | String | The logical object type of the node to which the object belongs. | 
| RubrikPolaris.VSphereVm.metadata.logicalPath.name | String | The logical name of the node to which the object belongs. | 
| RubrikPolaris.VSphereVm.metadata.physicalPath.fid | String | The physical path of where the VM resides. | 
| RubrikPolaris.VSphereVm.metadata.physicalPath.objectType | String | The physical path object type of the VM. | 
| RubrikPolaris.VSphereVm.metadata.physicalPath.name | String | The physical Name of the VM. | 
| RubrikPolaris.VSphereVm.metadata.vsphereTagPath.fid | String | FID of Vsphere tag. | 
| RubrikPolaris.VSphereVm.metadata.vsphereTagPath.objectType | String | Object type of Vsphere tag. | 
| RubrikPolaris.VSphereVm.metadata.vphereTagPath.name | String | Name of Vsphere tag. | 
| RubrikPolaris.VSphereVm.metadata.oldestSnapshot.id | String | The ID of the oldest snapshot. | 
| RubrikPolaris.VSphereVm.metadata.oldestSnapshot.date | String | The date when the oldest snapshot was generated. | 
| RubrikPolaris.VSphereVm.metadata.oldestSnapshot.isIndexed | Boolean | Whether the oldest snapshot is indexed or not. | 
| RubrikPolaris.VSphereVm.metadata.totalSnapshots.count | Number | Total snapshot counts. | 
| RubrikPolaris.VSphereVm.metadata.replicatedObjects.id | String | The ID of the object which is replicated in the VM. | 
| RubrikPolaris.VSphereVm.metadata.replicatedObjects.primaryClusterLocation.id | String | The primary cluster location ID where the replicated object resides. | 
| RubrikPolaris.VSphereVm.metadata.replicatedObjects.primaryClusterLocation.name | String | The primary cluster location name where the replicated object resides. | 
| RubrikPolaris.VSphereVm.metadata.replicatedObjects.cluster.name | String | The cluster name where the replicated object resides. | 
| RubrikPolaris.VSphereVm.metadata.replicatedObjects.cluster.id | String | The cluster ID where the replicated object resides. | 
| RubrikPolaris.VSphereVm.metadata.newestArchivedSnapshot.id | String | ID of the newest archived snapshot. | 
| RubrikPolaris.VSphereVm.metadata.newestArchivedSnapshot.date | String | The date when the newest archived snapshot was generated. | 
| RubrikPolaris.VSphereVm.metadata.newestArchivedSnapshot.isIndexed | Boolean | Whether the newest archived snapshot is indexed or not. | 
| RubrikPolaris.VSphereVm.metadata.newestArchivedSnapshot.archivalLocations.id | String | ID of the archival location of the newest archived snapshot. | 
| RubrikPolaris.VSphereVm.metadata.newestArchivedSnapshot.archivalLocations.name | String | Name of the archival location of the newest archival snapshot. | 
| RubrikPolaris.VSphereVm.metadata.newestReplicatedSnapshot.id | String | The ID of the newest replicated snapshot. | 
| RubrikPolaris.VSphereVm.metadata.newestReplicatedSnapshot.date | String | The date when the newest replicated snapshot was generated. | 
| RubrikPolaris.VSphereVm.metadata.newestReplicatedSnapshot.isIndexed | Boolean | Whether the newest replicated snapshot is indexed or not. | 
| RubrikPolaris.VSphereVm.metadata.newestReplicatedSnapshot.replicationLocations.id | String | The ID of the replication locations of the newest replicated snapshot. | 
| RubrikPolaris.VSphereVm.metadata.newestReplicatedSnapshot.replicationLocations.name | String | The name of the replication locations of the newest replicated snapshot. | 
| RubrikPolaris.VSphereVm.metadata.newestSnapshot.id | String | The ID of the newest snapshot. | 
| RubrikPolaris.VSphereVm.metadata.newestSnapshot.date | String | The date when the newest snapshot was generated. | 
| RubrikPolaris.VSphereVm.metadata.newestSnapshot.isIndexed | Boolean | Whether the newest snapshot is indexed or not. | 
| RubrikPolaris.VSphereVm.metadata.onDemandSnapshotCount | Number | Count of how many on demand snapshot created in a VM. | 
| RubrikPolaris.VSphereVm.metadata.vmwareToolsInstalled | Boolean | Whether the Vmware tools are installed or not. | 
| RubrikPolaris.VSphereVm.metadata.cdmLink | String | The Cloud Data Management link to navigate to the VM on cloud. | 


#### Command Example
```!rubrik-polaris-vm-object-metadata-get object_id="e060116b-f9dc-56a1-82a6-1b968d2f6cef"```

#### Human Readable Output
### VM Object Data
|Object ID|Name|Snappable ID|SLA Domain|Cluster Name|Total Snapshots|Oldest Snapshot Date|Latest Snapshot Date|
|---|---|---|---|---|---|---|---|
| e060116b-f9dc-56a1-82a6-1b968d2f6cef | Kali-VM | VirtualMachine:::ae4484c6-b4c0-4ce8-b2ba-206a4184540b-vm-521 | DO_NOT_PROTECT | sand2-rbk01 | 42 | 2019-04-24T16:21:12.000Z | 2020-02-12T14:00:36.000Z |



### rubrik-polaris-vm-objects-list
***
Retrieve a list of all the objects of the Vsphere Vm known to the Rubrik.


#### Base Command

`rubrik-polaris-vm-objects-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| is_relic | Filter based on whether VM objects are moved to relic/archive or not.<br/><br/>Possible values are: "True", "False". | Optional | 
| is_replicated | Filter based on whether VM objects are replicated or not.<br/><br/>Possible values are: "True", "False". | Optional | 
| limit | Number of results to retrieve in the response. Maximum size allowed is 1000. Default is 50. | Optional | 
| sort_by | Specify the field to use for sorting the response.<br/><br/>Note: Supported values are "ID" and "NAME" only. For any other values, the obtained result is sorted or not is not confirmed. Default is ID. | Optional | 
| sort_order | Specify the order to sort the data in.<br/><br/>Possible values are: "ASC", "DESC". Default is ASC. | Optional | 
| next_page_token | The next page cursor to retrieve the next set of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.VSphereVm.id | String | Unique ID of the object. | 
| RubrikPolaris.VSphereVm.name | String | Name of the node to which the object belongs. | 
| RubrikPolaris.VSphereVm.objectType | String | Object type of the node to which the object belongs. | 
| RubrikPolaris.VSphereVm.replicatedObjectCount | Number | Number of objects replicated in the node in which the object relies. | 
| RubrikPolaris.VSphereVm.cluster.id | String | ID of the cluster which is the datastore for the recovered virtual machine. | 
| RubrikPolaris.VSphereVm.cluster.name | String | Cluster name of the node to which the object belongs. | 
| RubrikPolaris.VSphereVm.cluster.version | String | Cluster version of the node to which the object belongs. | 
| RubrikPolaris.VSphereVm.cluster.status | String | Cluster status of the node to which the object belongs. | 
| RubrikPolaris.VSphereVm.effectiveSlaDomain.id | String | ID of the SLA domain which is simply a set of policies that define at what frequencies backups should be performed of the protected objects within Rubrik and for how long they should be either locally or a replication partner or on the archival location. | 
| RubrikPolaris.VSphereVm.effectiveSlaDomain.name | String | Descriptive name of the SLA domain. | 
| RubrikPolaris.VSphereVm.effectiveSlaDomain.description | String | Description of the SLA domain. | 
| RubrikPolaris.VSphereVm.effectiveSlaDomain.fid | String | FID of the SLA domain. | 
| RubrikPolaris.VSphereVm.effectiveSlaDomain.cluster.id | String | ID of the cluster related to the effective SLA domain. | 
| RubrikPolaris.VSphereVm.effectiveSlaDomain.cluster.name | String | Name of the cluster related to the effective SLA domain. | 
| RubrikPolaris.VSphereVm.effectiveSlaSourceObject.fid | String | SLA source object FID. | 
| RubrikPolaris.VSphereVm.effectiveSlaSourceObject.name | String | SLA source object name. | 
| RubrikPolaris.VSphereVm.effectiveSlaSourceObject.objectType | String | SLA source object type. | 
| RubrikPolaris.VSphereVm.slaAssignment | String | A SLA rule when referred at assignment is SLA assignment. | 
| RubrikPolaris.VSphereVm.isRelic | Boolean | Whether the object is relic or not. | 
| RubrikPolaris.VSphereVm.authorizedOperations | Unknown | List of operations that can be performed on the object. | 
| RubrikPolaris.VSphereVm.primaryClusterLocation.id | String | The location ID of the primary cluster to which the object belongs. | 
| RubrikPolaris.VSphereVm.primaryClusterLocation.name | String | The location name of the primary cluster to which the object belongs. | 
| RubrikPolaris.VSphereVm.logicalPath.fid | String | The logical path ID of the node to which the object belongs. | 
| RubrikPolaris.VSphereVm.logicalPath.name | String | The logical path name of the node to which the object belongs. | 
| RubrikPolaris.VSphereVm.logicalPath.objectType | String | The logical object type of the node to which the object belongs. | 
| RubrikPolaris.VSphereVm.snapshotDistribution.id | String | Rubrik uses a snapshot for powerful data protection. Snapshot distribution ID is the ID of the snapshot distribution node related to a particular object. | 
| RubrikPolaris.VSphereVm.snapshotDistribution.onDemandCount | Number | The demand count of distribution of snapshot related to an object. | 
| RubrikPolaris.VSphereVm.snapshotDistribution.retrievedCount | Number | The retrieved count of distribution of snapshot related to an object. | 
| RubrikPolaris.VSphereVm.snapshotDistribution.scheduledCount | Number | The scheduled count of distribution of snapshot related to an object. | 
| RubrikPolaris.VSphereVm.snapshotDistribution.totalCount | Number | The total count of distribution of snapshot related to an object. | 
| RubrikPolaris.VSphereVm.reportSnappable.id | String | The ID of the snappable for a particular report related to an object. Snapple supports backups or filesets of physical machines using the rubrik connector. | 
| RubrikPolaris.VSphereVm.reportSnappable.archieveStorage | Number | The archived storage of the snappable for a particular report related to an object. | 
| RubrikPolaris.VSphereVm.reportSnappable.physicalBytes | Number | The physical byte of the snappable for a particular report related to an object. | 
| RubrikPolaris.VSphereVm.vmwareToolsInstalled | Boolean | Whether the vm tools are installed or not. | 
| RubrikPolaris.VSphereVm.agentStatus.agentStatus | String | The status of an agent related to an object. The Rubrik agents are connectors also known as Rubrik Backup Service. | 
| RubrikPolaris.VSphereVm.agentStatus.disconnectReason | String | Displays the reason if the agent disconnects. | 
| RubrikPolaris.PageToken.VSphereVm.next_page_token | String | Next page token. | 
| RubrikPolaris.PageToken.VSphereVm.name | String | Name of the command. | 
| RubrikPolaris.PageToken.VSphereVm.has_next_page | Boolean | Whether the result has the next page or not. | 


#### Command Example
```!rubrik-polaris-vm-objects-list limit=2```

#### Human Readable Output
### Objects List
|Object ID|Name|Snappable ID|Cluster|Object Type|SLA Domain|Assignment|Snapshots|RBS Status|Source Storage|Archival Storage|
|---|---|---|---|---|---|---|---|---|---|---|
| 0242e84c-773a-5877-b955-1d52765ac852 | sx1-ganebala-l1 | VirtualMachine:::868aa03d-4145-4cb1-808b-e10c4f7a3741-vm-206037 | sand1-rbk01 | VmwareVirtualMachine | DO_NOT_PROTECT | Direct | 0 | Unregistered | 0 | 0 |
| 0556f691-b750-556c-baea-800dbb2920e7 | linux-a-Fri Feb 15 2019 04:43:40 GMT+0000 (Greenwich Mean Time)-9P4t | VirtualMachine:::d2f41f4b-5d53-4063-a618-25046a0f4c7d-vm-35806 | sand1-rbk01 | VmwareVirtualMachine | UNPROTECTED | Unassigned | 34 | Unregistered | 0 | 1.115023609 GB |

 Note: To retrieve the next set of results use, "next_page_token" = xyz


### rubrik-sonar-ondemand-scan
***
Trigger an on-demand scan of a system. Supports "Vsphere VM" object type only.

Note: To know the scan status use the "rubrik-sonar-ondemand-scan-status" command. To download the completed request use the "rubrik-sonar-ondemand-scan-result" command.


#### Base Command

`rubrik-sonar-ondemand-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_name | Name of the scan. If not provided, it defaults to "&lt;today's date&gt; Classification". | Optional | 
| sonar_policy_analyzer_groups | List of sonar policies to scan.<br/><br/>Note: Users can get the list of analyzer groups by executing the "rubrik-sonar-policy-analyzer-groups-list" command. <br/><br/>Format Accepted: <br/>[<br/>        {<br/>            "id": "543dd5e0-c72c-50e2-a3d9-1688343f472c",<br/>            "name": "HIPAA",<br/>            "groupType": "HIPAA",<br/>            "analyzers": [<br/>                {<br/>                    "id": "9da675b3-944b-5da3-a2da-ed149d300075",<br/>                    "name": "US/UK Passport",<br/>                    "analyzerType": "PASSPORT"<br/>                },<br/>                {<br/>                    "id": "18665533-c28c-5a40-b747-4b6508fecdfa",<br/>                    "name": "US NPI",<br/>                    "analyzerType": "US_HEALTHCARE_NPI"<br/>                }<br/>            ]<br/>      }<br/>]. | Required | 
| objects_to_scan | List of VM object IDs to scan.<br/><br/>Note: Users can get the list of VM object IDs by executing the "rubrik-polaris-vm-objects-list" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.SonarOndemandScan.crawlId | String | Unique crawl ID. | 


#### Command Example
```!rubrik-sonar-ondemand-scan scan_name="GLBA Scan for new user" sonar_policy_analyzer_groups='[{"id":"97c6a54a-acfc-5ab2-a24a-6a7f3a9a1553","name":"GLBA","groupType":"GLBA","analyzers":[{"id":"ed30dfa0-334f-55ff-a1b7-03b6bdd7849b","name":"CreditCard","analyzerType":"CREDIT_CARD"},{"id":"3e60a612-3e97-5f03-b3a1-cfb7a6a67e8f","name":"BANK_ACCT","analyzerType":"US_BANK_ACCT"},{"id":"03b3dc9e-81c1-561c-8235-17cf2fc1c729","name":"USITIN","analyzerType":"US_ITIN"},{"id":"d5ce3ae5-f530-562a-85b1-4a84264a350a","name":"USSSN","analyzerType":"US_SSN"}]}]' objects_to_scan="0887e71c-56ac-59f7-8763-54b726e64dd6, a82e888c-2440-5af9-8c2a-447a97f6746c"```

#### Human Readable Output
### Sonar On-Demand Scan
|Crawl ID|
|---|
| bb4eedc0-594b-4566-b06d-24de0bf752ca |



### rubrik-sonar-ondemand-scan-status
***
Retrieve the status of a scanned system.

Note: To download the completed request use the "rubrik-sonar-ondemand-scan-result" command.


#### Base Command

`rubrik-sonar-ondemand-scan-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| crawl_id | ID for which scanning status is to be obtained.<br/><br/>Note: Users can get the crawl ID by executing the "rubrik-sonar-ondemand-scan" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.SonarOndemandScan.crawlId | String | Crawl ID of the scan for which the rubrik-sonar-ondemand-scan command is hit. | 
| RubrikPolaris.SonarOndemandScan.Status.error | String | Error description if any. | 
| RubrikPolaris.SonarOndemandScan.Status.snappable.id | String | Snappable ID of the scanned object. | 
| RubrikPolaris.SonarOndemandScan.Status.snappable.name | String | Snappable Name of the scanned object. | 
| RubrikPolaris.SonarOndemandScan.Status.snappable.objectType | String | Snappable object type of the scanned object. | 
| RubrikPolaris.SonarOndemandScan.Status.snapshotTime | Number | Time when the snapshot is taken. | 
| RubrikPolaris.SonarOndemandScan.Status.status | String | Status of the scanning or scanned object. | 
| RubrikPolaris.SonarOndemandScan.Status.progress | Number | Count of objects that are in progress. | 
| RubrikPolaris.SonarOndemandScan.Status.totalHits | Number | Number of total hits obtained from an object that is scanned. | 
| RubrikPolaris.SonarOndemandScan.Status.analyzerGroupResults.analyzerGroup.groupType | String | Group type of the analyzer. | 
| RubrikPolaris.SonarOndemandScan.Status.analyzerGroupResults.analyzerGroup.id | String | Group ID of the analyzer. | 
| RubrikPolaris.SonarOndemandScan.Status.analyzerGroupResults.analyzerGroup.name | String | Group Name of the analyzer. | 
| RubrikPolaris.SonarOndemandScan.Status.analyzerGroupResults.analyzerResults.hits.totalHits | Number | Number of total hits obtained from an analyzer that is scanned. | 
| RubrikPolaris.SonarOndemandScan.Status.analyzerGroupResults.analyzerResults.hits.violations | Number | Number of violations obtained from an analyzer that is scanned. | 
| RubrikPolaris.SonarOndemandScan.Status.analyzerGroupResults.analyzerResults.hits.permittedHits | Number | Number of permitted hits obtained from an analyzer that is scanned. | 
| RubrikPolaris.SonarOndemandScan.Status.analyzerGroupResults.analyzerResults.analyzer.id | String | ID of the analyzer that is scanned. | 
| RubrikPolaris.SonarOndemandScan.Status.analzerGroupResults.analyzerResults.analyzer.name | String | Name of the analyzer that is scanned. | 
| RubrikPolaris.SonarOndemandScan.Status.analyzerGroupResults.analyzerResults.analyzer.analyzerType | String | Type of the analyzer that is scanned. | 
| RubrikPolaris.SonarOndemandScan.Status.analyzerGroupResults.hits.totalHits | Number | Number of total hits obtained from an analyzer group. | 
| RubrikPolaris.SonarOndemandScan.Status.analyzerGroupResults.hits.violations | Number | Number of violations obtained from an analyzer group. | 
| RubrikPolaris.SonarOndemandScan.Status.analyzerGroupResults.hits.permittedHits | Number | Number of permitted hits obtained from an analyzer group. | 
| RubrikPolaris.SonarOndemandScan.Status.analyzerGroupResults.hits.violationsDelta | Number | Number of violation delta obtained from an analyzer group. | 
| RubrikPolaris.SonarOndemandScan.Status.analyzerGroupResults.hits.totalHitsDelta | Number | Number of total hits delta obtained from an analyzer group. | 
| RubrikPolaris.SonarOndemandScan.Status.cluster.id | String | Cluster ID in which the object is getting scanned. | 
| RubrikPolaris.SonarOndemandScan.Status.cluster.name | String | Cluster name in which the object is getting scanned. | 
| RubrikPolaris.SonarOndemandScan.Status.cluster.type | String | Cluster type in which the object is getting scanned. | 


#### Command Example
```!rubrik-sonar-ondemand-scan-status crawl_id="bb4eedc0-594b-4566-b06d-24de0bf752ca" ```

#### Human Readable Output
### Sonar On-Demand Scan Status
Final status of scan with crawl ID bb4eedc0-594b-4566-b06d-24de0bf752ca is IN_PROGRESS

|Object ID|Object Name|Scan Status|
|---|---|---|
| 6e307121-e5dc-5e6a-9a6b-37e1c9afd6b1 | AllTheThings | COMPLETE |
| a82e888c-2440-5af9-8c2a-447a97f6746c | /tmp | IN_PROGRESS |



### rubrik-polaris-vm-object-snapshot-list
***
Search for a Rubrik snapshot of an object based on the provided snapshot ID, exact timestamp, or specific value like earliest/latest, or closest before/after a timestamp.


#### Base Command

`rubrik-polaris-vm-object-snapshot-list`
#### Input

| **Argument Name** | **Description**                                                                                                                                                                                              | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| object_id | The object ID for which the snapshots are to be searched.<br/><br/>Note: Users can get the list of the object IDs by executing the "rubrik-polaris-vm-objects-list" command.                                 | Required | 
| snapshot_group_by | Grouping the snapshots on the basis of the selected value.<br/><br/>Possible values are: "Month", "Day", "Year", "Week", "Hour", "Quarter". Default is Day.                                                  | Optional | 
| missed_snapshot_group_by | Grouping the missed snapshots on the basis of the selected value.<br/><br/>Possible values are: "MONTH", "DAY", "YEAR", "WEEK", "HOUR", "QUARTER". Default is DAY.                                           | Optional | 
| start_date | The start date to get snapshots from.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, etc.                                              | Required | 
| end_date | The end date to get snapshots until.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, etc.                                               | Required | 
| timezone_offset | The timezone offset from UTC changes to match the configured time zone. Use this argument to filter the data according to the provided timezone offset.<br/><br/>Formats accepted: 1, 1.5, 2, 2.5, 5.5, etc. | Required | 
| cluster_connected | Whether the cluster is connected or not.<br/><br/>Possible values are: "True", "False". Default is True.                                                                                                     | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.VSphereVm.id | String | Unique ID of the object. | 
| RubrikPolaris.VSphereVm.Snapshot.snapshotGroupByConnection.nodes.groupByInfo.unit | String | Unit of snapshot group by connection nodes. | 
| RubrikPolaris.VSphereVm.Snapshot.snapshotGroupByConnection.nodes.groupByInfo.start | String | Start date of snapshot group by connection nodes. | 
| RubrikPolaris.VSphereVm.Snapshot.snapshotGroupByConnection.nodes.groupByInfo.end | String | End date of snapshot group by connection nodes. | 
| RubrikPolaris.VSphereVm.Snapshot.snapshotGroupByConnection.nodes.snapshotConnection.count | Number | Count of snapshot connections related to the object. | 
| RubrikPolaris.VSphereVm.Snapshot.snapshotGroupByConnection.nodes.snapshotConnection.nodes.id | String | ID of snapshot connection related to the object. | 
| RubrikPolaris.VSphereVm.Snapshot.snapshotGroupByConnection.nodes.snapshotConnection.nodes.isIndexed | Boolean | Whether the node is indexed or not. | 
| RubrikPolaris.VSphereVm.Snapshot.snapshotGroupByConnection.nodes.snapshotConnection.nodes.isUnindexable | Boolean | Whether the node is unindexable or not. | 


#### Command Example
```!rubrik-polaris-vm-object-snapshot-list object_id="86db05d1-292f-5973-b616-2ae3977f4428" start_date="2020-05-19T18:30:00.000000Z" end_date="2020-05-20T18:30:00.000000Z" timezone_offset=5.5 ```

#### Human Readable Output
### VM Object Snapshots
|Snapshot Details|Snapshot IDs|
|---|---|
| Total Snapshots: 2<br/>Date Range: From 2020-05-19T22:30:00.000Z to 2020-05-20T22:29:59.999Z | 33060f59-9c99-5c48-8305-8d1edfe402d2,<br/>57eac609-9529-5cb5-845a-b7cc78998222 |



### rubrik-sonar-ondemand-scan-result
***
Retrieve the download link for the requested scanned file.


#### Base Command

`rubrik-sonar-ondemand-scan-result`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| crawl_id | ID for which file needs to be downloaded.<br/><br/>Note: Users can get the crawl_id by executing the "rubrik-sonar-ondemand-scan" command. | Required | 
| file_type | The type of the file that needs to be downloaded.<br/><br/>Possible values are: "ANY", "HITS", "STALE", "OPEN_ACCESS", "STALE_HITS", "OPEN_ACCESS_HITS". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.SonarOndemandScan.crawlId | String | Crawl ID of the file that needs to be downloaded. | 
| RubrikPolaris.SonarOndemandScan.Result.downloadLink | String | Link to download the file when scan status is complete. | 


#### Command Example
```!rubrik-sonar-ondemand-scan-result crawl_id="bb4eedc0-594b-4566-b06d-24de0bf752ca" file_type="HITS" ```

#### Human Readable Output
### Sonar On-Demand Scan Result
|Scan result CSV Download Link|
|---|
| Download the [CSV](https://www.example.com/csv_file) file to see the result. |



### rubrik-radar-anomaly-csv-analysis
***
Request for the analysis and retrieve the download link or directly download file for the Radar CSV analyzed file.


#### Base Command

`rubrik-radar-anomaly-csv-analysis`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The unique ID of the cluster.<br/><br/>Note: Users can retrieve the list of the cluster IDs by executing the "rubrik-gps-cluster-list" command. | Required | 
| snapshot_id | The CDM snapshot ID.<br/><br/>Note: Users can retrieve the list of snapshot IDs by executing the "rubrik-polaris-vm-object-snapshot-list" command.<br/>Use the "rubrik-radar-suspicious-file-list" command to retrieve the actual CDM ID from the Anomaly ID.<br/>Example format to get the snapshot CDM ID from Anomaly ID: "&lt;Cluster-ID&gt;:::VirtualMachine:::&lt;Snappable-ID&gt;:::&lt;CDM-ID&gt;". | Required | 
| object_id | The VM object ID (Snappable ID).<br/><br/>Note: Users can retrieve the list of Snappable IDs by executing the "rubrik-polaris-vm-objects-list" command.<br/>Example format to get the Snappable ID: "VirtualMachine:::&lt;Snappable-ID&gt;". | Required | 
| download_file | If set to True, the command downloads the anomaly analysis CSV file directly on XSOAR server.<br/><br/>Possible values are: True, False. Default is False. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.RadarAnomalyCSV.clusterId | String | Cluster ID of the CSV. | 
| RubrikPolaris.RadarAnomalyCSV.snapshotId | String | Snapshot ID of the CSV. | 
| RubrikPolaris.RadarAnomalyCSV.objectId | String | Object ID of the CSV. | 
| RubrikPolaris.RadarAnomalyCSV.investigationCsvDownloadLink.downloadLink | String | The download link of the CSV analysis. | 
| File.Size | String | File size in bytes. | 
| File.SHA1 | String | SHA1 hash of file. | 
| File.SHA256 | String | SHA256 hash of file. | 
| File.SHA512 | String | SHA512 hash of file. | 
| File.Name | String | File name. | 
| File.SSDeep | String | SSDeep hash of the file. | 
| File.EntryID | Unknown | The entry ID of the file. | 
| File.Info | String | File information. | 
| File.Type | String | The file type. | 
| File.MD5 | String | MD5 hash of the file. | 
| File.Extension | String | The file extension. | 


#### Command Example
```!rubrik-radar-anomaly-csv-analysis cluster_id="0000-000-000-000-0000" snapshot_id="0000-000-000-000-0000" object_id="0000-000-000-000-vm-0000" download_file=True```

#### Human Readable Output
>### Radar Anomaly CSV Analysis
>|CSV Download Link|
>|---|
>| Download the analyzed [CSV](https://www.example.com/snapshot_000-000-000-000.csv) file. |

>Uploaded file: snapshot_000-000-000-000.csv Download
>
>|Property|Value|
>|---|---|
>| Type | text/csv; charset=utf-8 |
>| Size | 10,069 bytes |
>| Info | ASCII text, with very long lines |
>| MD5 | 10000000000000000000000000 |
>| SHA1 | 1000000000000000000000000000000 |
>| SHA256 | 1000000000000000000000000000000000000000000000000000000000 |
>| SHA512 | 10000000000000000000000000000000000000000000000000000000000000000000000 |
>| SSDeep | 1:100000000000000000000000000000000000000000000000000000000: |



### rubrik-sonar-csv-download
***
Request to download the Sonar CSV Snapshot results file.

Note: To know the ID and status of the download, use the "rubrik-user-downloads-list" command. To download the file, use the "rubrik-sonar-csv-result-download" command.


#### Base Command

`rubrik-sonar-csv-download`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| snapshot_id | ID of the snapshot.<br/><br/>Note: Users can retrieve the list of snapshot IDs by executing the "rubrik-polaris-vm-object-snapshot-list"  command. | Required | 
| object_id | Object ID.<br/><br/>Note: Users can retrieve the list of object IDs by executing "rubrik-polaris-vm-objects-list" command. | Required | 
| file_type | The type of the file that needs to be downloaded.<br/><br/>Possible values are: "ANY", "HITS", "STALE", "OPEN_ACCESS", "STALE_HITS", "OPEN_ACCESS_HITS". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.SonarCSVDownload.snapshotId | String | Snapshot ID of the CSV requested to download. | 
| RubrikPolaris.SonarCSVDownload.objectId | String | Object ID of the CSV requested to download. | 
| RubrikPolaris.SonarCSVDownload.downloadSnapshotResultsCsv.isSuccessful | Boolean | The status of the download. | 


#### Command Example
```!rubrik-sonar-csv-download snapshot_id="c38ec074-0c45-5c72-b611-3322cbd46776" object_id="ac0a6844-a2fc-52b0-bb71-6a55f43677be" ```

#### Human Readable Output
### Sonar CSV Download
|Download Status|
|---|
| Success |



### rubrik-gps-snapshot-files-list
***
Retrieve the list of the available files that can be downloaded.

Note: To initiate the file download request use the "rubrik-gps-snapshot-files-download" command.


#### Base Command

`rubrik-gps-snapshot-files-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| snapshot_id | The Snapshot ID of the file that needs to be downloaded.<br/><br/>Note: Users can retrieve the list of the snapshot IDs by executing the "rubrik-polaris-vm-object-snapshot-list" command. | Required | 
| path | The path of the folder to list the sub-files. If not provided the root directory files will be returned.<br/><br/>Format accepted : "/&lt;directory name&gt;/&lt;sub directory name or file name&gt;"<br/><br/>Example: "/C:", "/C:/Users". | Optional | 
| search_prefix | Provide a keyword to search in the file names.<br/><br/>Example: "admin". | Optional | 
| limit | Number of results to retrieve in the response. Maximum size allowed is 1000. Default is 50. | Optional | 
| next_page_token | The next page cursor to retrieve the next set of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.GPSSnapshotFile.snapshotId | String | Snapshot ID provided as an argument to retrieve the files. | 
| RubrikPolaris.GPSSnapshotFile.node.absolutePath | String | The absolute path of the file. | 
| RubrikPolaris.GPSSnapshotFile.node.displayPath | String | The display path of the file. | 
| RubrikPolaris.GPSSnapshotFile.node.path | String | The path of the file. | 
| RubrikPolaris.GPSSnapshotFile.node.filename | String | The name of the file. | 
| RubrikPolaris.GPSSnapshotFile.node.fileMode | String | The mode of the file. | 
| RubrikPolaris.GPSSnapshotFile.node.size | String | The size of the file. | 
| RubrikPolaris.GPSSnapshotFile.node.lastModified | String | The last modified time of the file. | 
| RubrikPolaris.PageToken.GPSSnapshotFile.next_page_token | String | Next page token. | 
| RubrikPolaris.PageToken.GPSSnapshotFile.name | String | Name of the command. | 
| RubrikPolaris.PageToken.GPSSnapshotFile.has_next_page | Boolean | Whether the result has the next page or not. | 


#### Command Example
```!rubrik-gps-snapshot-files-list snapshot_id=90858c2f-e572-5b9c-b455-ba309d50c1a2 ```

#### Human Readable Output
### GPS Snapshot Files
|File Name|Absolute Path|Path|File Mode|Last Modified|
|---|---|---|---|---|
| C: | /C: | C: | DIRECTORY | 2020-10-05T18:56:18.000Z |
| disk_0_part_1 | /disk_0_part_1 |  | DIRECTORY | 2018-06-14T00:47:18.000Z |

Note: To retrieve the next set of results use, "next_page_token" = xyz


### rubrik-gps-vm-export
***
Request to initiate an export of a snapshot of a virtual machine.

Note: To know about the exported VM's status, use the "rubrik-gps-async-result" command.


#### Base Command

`rubrik-gps-vm-export`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vm_name | Name given to the VM that runs the snapshot. If not provided the name will be "&lt;Snapshot VM Name&gt; &lt;MM/DD of snapshot creation&gt; &lt;hh/mm of snapshot creation&gt; &lt;Num&gt;". | Optional | 
| object_id | The VM object ID whose snapshot needs to be exported.<br/><br/>Note: Users can get the list of object IDs by executing the "rubrik-polaris-vm-objects-list" command. | Required | 
| snapshot_id | The ID of the snapshot that is to be exported.<br/><br/>Note: Users can get the list of snapshot IDs by executing the "rubrik-polaris-vm-object-snapshot-list" command. | Required | 
| datastore_id | The ID of the datastore which will be used by the new VM.<br/><br/>Note: Users can get the list of  datastore IDs by executing the "rubrik-gps-vm-datastore-list" command. | Required | 
| host_id | The ID of the Vsphere ESXi host on which the new VM will be made. Either host_id or host_compute_cluster_id must be provided.<br/><br/>Note: Users can get the list of host IDs by executing the "rubrik-gps-vm-host-list" command. | Optional | 
| host_compute_cluster_id | The ID of the VSphere Compute Cluster of a host. Either host_id or host_compute_cluster_id must be provided. <br/><br/>Note: Users can get the list of Compute Cluster IDs by executing the "rubrik-gps-vm-host-list" command. The ID must belong to the VSphereComputeCluster objectType. | Optional | 
| power_on | Whether to turn on the new VM or not.<br/><br/>Possible values are: "True", "False". | Optional | 
| keep_mac_addresses | Whether the mac addresses of network devices of the new VM be removed or not.<br/><br/>Possible values are: "True", "False". | Optional | 
| remove_network_devices | Whether the network devices on the original VM be kept or not.<br/><br/>Possible values are: "True", "False". | Optional | 
| recover_tags | Whether to keep vSphere tags associated with the original VM or not.<br/><br/>Possible values are: "True", "False". | Optional | 
| disable_network | Whether to disable networking on the new VM or not.<br/><br/>Possible values are: "True", "False". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.GPSVMSnapshotExport.id | String | Snapshot export request ID. | 


#### Command Example
```!rubrik-gps-vm-export object_id=d39e956f-a3c9-5307-865b-58ed045b59c5 snapshot_id=07fa66e1-137a-5473-8a8e-825547075d7b datastore_id=5fe3a92a-d848-5325-a1a2-ef6cf7a16376 host_compute_cluster_id=0dc88a78-0d46-57d7-86c6-f1bd97ff979f```

#### Human Readable Output
### GPS VM Export
|Snapshot Export Request ID|
|---|
| dummy_id |



### rubrik-user-downloads-list
***
Retrieve the user downloads. This would return the current and past download history.

Note: To download the requested Sonar CSV Snapshot results file use the "rubrik-sonar-csv-result-download" command.


#### Base Command

`rubrik-user-downloads-list`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.UserDownload.id | Number | The ID of the download. | 
| RubrikPolaris.UserDownload.name | String | The name of the download. | 
| RubrikPolaris.UserDownload.status | String | The status of the download. | 
| RubrikPolaris.UserDownload.progress | Number | The progress of the download. | 
| RubrikPolaris.UserDownload.identifier | String | The identifier of the download or the type of download requested. | 
| RubrikPolaris.UserDownload.createTime | String | The creation time of the download. | 
| RubrikPolaris.UserDownload.completeTime | String | The completion time of the download. | 


#### Command Example
```!rubrik-user-downloads-list ```

#### Human Readable Output
### User Downloads
|Download ID|Name|Status|Identifier|Creation Time|Completion Time|
|---|---|---|---|---|---|
| 156 | GDIT-billing-test-oct10 | COMPLETED | SONAR_DOWNLOAD | 2021-10-06T07:25:51.676432470Z | 2021-10-06T07:25:51.856374014Z |



### rubrik-gps-sla-domain-list
***
Enumerates the available SLA Domains to apply to the on-demand snapshot as a retention policy.


#### Base Command

`rubrik-gps-sla-domain-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the SLA Domain to search for. | Optional | 
| cluster_id | Cluster, the SLA domain is managed by.<br/><br/>Note: Users can retrieve the list of the cluster IDs by executing the "rubrik-gps-cluster-list" command. | Optional | 
| object_type | Filters SLA domain based on the provided object types. Supports comma separated values. <br/><br/>Possible values are: "FILESET_OBJECT_TYPE", "VSPHERE_OBJECT_TYPE". | Optional | 
| show_cluster_slas_only | Whether to show Cluster SLAs and not Global SLAs. "False" value will result in showing only Global SLAs. <br/><br/>Possible values are: "True", "False". Default is True. | Optional | 
| sort_by | Specify the field to use for sorting the response.<br/><br/>Possible values are: "NAME", "PROTECTED_OBJECT_COUNT". Default is NAME. | Optional | 
| sort_order | Specify the order to sort the data in.<br/><br/>Possible values are: "ASC", "DESC". Default is ASC. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.GPSSLADomain.name | String | Name of the SLA domain. | 
| RubrikPolaris.GPSSLADomain.id | String | ID of the SLA domain. | 
| RubrikPolaris.GPSSLADomain.description | String | Description of the SLA domain. | 
| RubrikPolaris.GPSSLADomain.protectedObjectCount | Number | Number of objects under the SLA Domain. | 
| RubrikPolaris.GPSSLADomain.baseFrequency.duration | Number | Base snapshot frequency duration. | 
| RubrikPolaris.GPSSLADomain.baseFrequency.unit | String | Base snapshot frequency unit \(HOURS, DAYS etc\). | 
| RubrikPolaris.GPSSLADomain.archivalSpec.archivalLocationName | String | Location where the archives are stored. | 
| RubrikPolaris.GPSSLADomain.archivalSpecs.storageSetting.id | String | ID of the archival target. | 
| RubrikPolaris.GPSSLADomain.archivalSpecs.storageSetting.name | String | Name of the archival target. | 
| RubrikPolaris.GPSSLADomain.archivalSpecs.storageSetting.groupType | String | Group type of the archival target. | 
| RubrikPolaris.GPSSLADomain.archivalSpecs.storageSetting.targetType | String | Target type of the archival target. | 
| RubrikPolaris.GPSSLADomain.replicationSpec.replicationType | String | Enum value representing the type of replication. Values: UNKNOWN_REPLICATION_TYPE, UNIDIRECTIONAL_REPLICATION_TO_CLUSTER, REPLICATION_TO_CLOUD_REGION, REPLICATION_TO_CLOUD_LOCATION. | 
| RubrikPolaris.GPSSLADomain.replicationSpec.specificReplicationSpec.unidirectionalSpec.replicationTargetName | String | Cloud replication target name. | 
| RubrikPolaris.GPSSLADomain.replicationSpec.specificReplicationSpec.cloudRegionSpec.replicationTargetRegion | String | Cloud replication target region. | 
| RubrikPolaris.GPSSLADomain.replicationSpec.specificReplicationSpec.cloudRegionSpec.cloudProvider | String | Cloud replication service provider. Values:  AWS, AZURE. | 
| RubrikPolaris.GPSSLADomain.replicationSpec.specificReplicationSpec.cloudLocationSpec.targetMapping.id | String | ID of the cloud target where replication takes place. | 
| RubrikPolaris.GPSSLADomain.replicationSpec.specificReplicationSpec.cloudLocationSpec.targetMapping.name | String | Name of the cloud target where replication takes place. | 
| RubrikPolaris.GPSSLADomain.replicationSpecsV2.cluster.id | String | ID of the cluster where replication takes place. | 
| RubrikPolaris.GPSSLADomain.replicationSpecsV2.cluster.name | String | Name of the cluster where replication takes place. | 
| RubrikPolaris.GPSSLADomain.replicationSpecsV2.awsTarget.accountId | String | Account ID on AWS where the replication happens. | 
| RubrikPolaris.GPSSLADomain.replicationSpecsV2.awsTarget.accountName | String | Account name on AWS where the replication happens. | 
| RubrikPolaris.GPSSLADomain.replicationSpecsV2.awsTarget.region | String | Account region on AWS where the replication happens. | 
| RubrikPolaris.GPSSLADomain.replicationSpecsV2.azureTarget.region | String | Account region on Azure where the replication happens. | 
| RubrikPolaris.GPSSLADomain.replicationSpecsV2.retentionDuration.duration | Number | Replication retention duration. | 
| RubrikPolaris.GPSSLADomain.replicationSpecsV2.retentionDuration.unit | String | Replication retention duration unit. | 
| RubrikPolaris.GPSSLADomain.replicationSpecsV2.targetMapping.id | String | ID of the object target where replication takes place. | 
| RubrikPolaris.GPSSLADomain.replicationSpecsV2.targetMapping.name | String | Name of the object target where replication takes place. | 
| RubrikPolaris.GPSSLADomain.localRetentionLimit.duration | Number | Local retention limit duration. | 
| RubrikPolaris.GPSSLADomain.localRetentionLimit.unit | String | Local retention limit duration unit. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.minute.basicSchedule.frequency | Number | Snapshot frequency every minute. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.minute.basicSchedule.retention | Number | Snapshot retention value per minute snapshots. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.minute.basicSchedule.retentionUnit | String | Snapshot retention time unit per minute snapshots. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.hourly.basicSchedule.frequency | Number | Snapshot hourly frequency. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.hourly.basicSchedule.retention | Number | Snapshot retention value per hour snapshots. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.hourly.basicSchedule.retentionUnit | String | Snapshot retention time unit per hour snapshots. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.daily.basicSchedule.frequency | Number | Snapshot daily frequency. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.daily.basicSchedule.retention | Number | Snapshot retention value per day snapshots. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.daily.basicSchedule.retentionUnit | String | Snapshot retention unit per day snapshots. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.weekly.basicSchedule.frequency | Number | Snapshot weekly frequency. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.weekly.basicSchedule.retention | Number | Snapshot retention value per week snapshots. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.weekly.basicSchedule.retentionUnit | String | Snapshot retention unit per week snapshots. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.weekly.dayOfWeek | String | Starting day of the weekly snapshot. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.monthly.basicSchedule.frequency | Number | Snapshot monthly frequency. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.monthly.basicSchedule.retention | Number | Snapshot retention value per month snapshots. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.monthly.basicSchedule.retentionUnit | String | Snapshot retention unit per month snapshots. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.monthly.dayOfMonth | String | Starting day of the month snapshot. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.quarterly.basicSchedule.frequency | Number | Snapshot quarterly frequency. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.quarterly.basicSchedule.retention | Number | Snapshot retention value per quarter snapshots. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.quarterly.basicSchedule.retentionUnit | String | Snapshot retention unit per quarter snapshots. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.quarterly.dayOfQuarter | String | Starting day of the quarterly snapshot. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.quarterly.quarterStartMonth | String | Starting month of the quarterly snapshot. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.yearly.basicSchedule.frequency | Number | Snapshot yearly frequency. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.yearly.basicSchedule.retention | Number | Snapshot retention value per year snapshots. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.yearly.basicSchedule.retentionUnit | String | Snapshot retention unit per year snapshots. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.yearly.dayOfYear | String | Starting day of the yearly snapshot. | 
| RubrikPolaris.GPSSLADomain.snapshotSchedule.yearly.yearStartMonth | String | Starting month of the yearly snapshot. | 
| RubrikPolaris.GPSSLADomain.objectSpecificConfigs.awsRdsConfig.logRetention.duration | Number | Duration of retentioning AWS Relational database logs. | 
| RubrikPolaris.GPSSLADomain.objectSpecificConfigs.awsRdsConfig.logRetention.unit | String | Unit of duration of retentioning AWS Relational database logs. | 
| RubrikPolaris.GPSSLADomain.objectSpecificConfigs.sapHanaConfig.incrementalFrequency.duration | Number | Duration of retentioning SAP HANA incremental backups. | 
| RubrikPolaris.GPSSLADomain.objectSpecificConfigs.sapHanaConfig.incrementalFrequency.unit | String | Unit of duration of retentioning SAP HANA incremental backups. | 
| RubrikPolaris.GPSSLADomain.objectSpecificConfigs.sapHanaConfig.differentialFrequency.duration | Number | Duration of retentioning SAP HANA differential backups. | 
| RubrikPolaris.GPSSLADomain.objectSpecificConfigs.sapHanaConfig.differentialFrequency.unit | String | Unit of duration of retentioning SAP HANA differential backups. | 
| RubrikPolaris.GPSSLADomain.objectSpecificConfigs.sapHanaConfig.logRetention.duration | Number | Duration of retensioning SAP HANA Database logs. | 
| RubrikPolaris.GPSSLADomain.objectSpecificConfigs.sapHanaConfig.logRetention.unit | String | Unit of duration of retentioning SAP HANA Database logs. | 
| RubrikPolaris.GPSSLADomain.objectSpecificConfigs.vmwareVmConfig.logRetentionSeconds | Number | Seconds of retentioning VMWare virtual machine logs. | 
| RubrikPolaris.GPSSLADomain.objectTypes | Unknown | List of object types associated with this SLA Domain. | 


#### Command Example
```!rubrik-gps-sla-domain-list cluster_id=4d4a41d5-8910-4e4d-9dca-0798f5fc6d61 limit=2```

#### Human Readable Output
### GPS SLA Domains
|SLA Domain ID|SLA Domain Name|Base Frequency|Protected Object Count|Archival Location|Description|Replication Target 1|Replication Target 2|
|---|---|---|---|---|---|---|---|
| 00000000-0000-0000-0000-000000000002 | Bronzecd | 1 Days | 0 | AWS S3:bucket-1234 | Rubrik default Bronze level SLA Domain policy | sand2-rbk01 | sand2-rbk02 |
| 00000000-0000-0000-0000-000000000000 | Gold | 4 Hours | 0 |  | Rubrik default Gold level SLA Domain policy | sand2-rbk01 |  |



### rubrik-sonar-csv-result-download
***
Retrieve the download link for the requested Sonar CSV Snapshot file.


#### Base Command

`rubrik-sonar-csv-result-download`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| download_id | The ID of the download, requested using "rubrik-sonar-csv-download" command.<br/><br/>Note: Users can retrieve the list of downloads containing ID by executing the "rubrik-user-downloads-list" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.SonarCSVDownload.downloadId | String | The download ID of the download request. | 
| RubrikPolaris.SonarCSVDownload.getDownloadUrl.url | String | The link of the file that needs to be downloaded. | 


#### Command Example
```!rubrik-sonar-csv-result-download download_id=65```

#### Human Readable Output
### Sonar CSV Result
|Download URL|
|---|
| Download the [CSV](https://www.example.com/csv_file) file to see the result. |



### rubrik-gps-vm-snapshot-create
***
Triggers an on-demand snapshot of a system.

Note: To know about the status of the on-demand snapshot creation, use the "rubrik-gps-async-result" command.


#### Base Command

`rubrik-gps-vm-snapshot-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | The ID of the object whose snapshot is to be created. <br/><br/>Note: Users can get the list of object IDs by executing the "rubrik-polaris-vm-objects-list" command. | Required | 
| sla_domain_id | The ID of the SLA domain retention policy to be applied on the object.<br/><br/>Note: Users can get the list of SLA Domain IDs by executing the "rubrik-gps-sla-domain-list" command. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.GPSOndemandSnapshot.id | String | ID of the requested snapshot. | 
| RubrikPolaris.GPSOndemandSnapshot.status | String | Status of the requested snapshot. | 


#### Command Example
```!rubrik-gps-vm-snapshot-create object_id=ac0a6844-a2fc-52b0-bb71-6a55f43677be```

#### Human Readable Output
### GPS VM Snapshot
|On-Demand Snapshot Request ID|Status|
|---|---|
| dummy_id | QUEUED |



### rubrik-gps-snapshot-files-download
***
Request to download the snapshot file from the backup.

Note: To know about the file information and which file can be downloaded, use the "rubrik-gps-snapshot-files-list" command. To know about the status of the downloadable files, use the "rubrik-gps-async-result" command.


#### Base Command

`rubrik-gps-snapshot-files-download`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| snapshot_id | The Snapshot ID of the file that needs to be downloaded.<br/><br/>Note: Users can retrieve the list of the snapshot IDs by executing the "rubrik-polaris-vm-object-snapshot-list" command. | Required | 
| file_path | The absolute path of the file to be downloaded. A list of files can be downloaded as a zip folder. Multiple file paths can be separated with comma(,).<br/><br/>Note: Users can retrieve the list of the files with absolute path by executing the "rubrik-gps-snapshot-files-list" command.<br/><br/>Format accepted: "/&lt;directory name&gt;/&lt;sub directory name or file name&gt;"<br/><br/>Example: "/C:/PerfLogs/Admin", "/C:/Windows/Microsoft.NET". | Required | 
| object_type | The type of object for which the file to be downloaded.<br/><br/>Possible values are: "WindowsFileset", "LinuxFileset", "VolumeGroup", "VmwareVm". Default is VmwareVm. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.GPSSnapshotFileDownload.id | String | The ID of the download. | 
| RubrikPolaris.GPSSnapshotFileDownload.status | String | Status of the download. | 
| RubrikPolaris.GPSSnapshotFileDownload.links.href | String | Link of the download. | 
| RubrikPolaris.GPSSnapshotFileDownload.links.rel | String | Relationship of the download. | 


#### Command Example
```!rubrik-gps-snapshot-files-download snapshot_id=3765b5b5-827b-5588-8c34-5cb737a28685 file_path="/.autorelabel" ```

#### Human Readable Output
### Snapshot File Request ID
|ID|Status|
|---|---|
| dummy_id | QUEUED |



### rubrik-gps-vm-livemount
***
Performs a live mount of a virtual machine snapshot.

Note: To know about the live mount status, use the "rubrik-gps-async-result" command.


#### Base Command

`rubrik-gps-vm-livemount`
#### Input

| **Argument Name** | **Description**                                                                                                                                                                             | **Required** |
| --- |---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| snappable_id | The snappable ID.                                                                                                                                                                           | Required | 
| should_recover_tags | Whether to keep vSphere tags associated with the VM or not.<br/><br/>Possible values are: "True", "False". Default is True.                                                                 | Optional |
| power_on | Whether to power on the mount or not.<br/><br/>Possible values are: "True", "False". Default is True.                                                                                       | Optional |
| keep_mac_addresses | Whether the mac addresses of network devices be removed or not.<br/><br/>Possible values are: "True", "False". Default is False.                                                            | Optional |
| remove_network_devices | Whether the network devices of the original VM be kept.<br/><br/>Possible values are: "True", "False". Default is False.                                                                    | Optional |
| host_id | The ID of the Vsphere ESXi host on which the new VM will be mounted.<br/><br/>Note: Users can get the list of host IDs by executing the "rubrik-gps-vm-host-list" command.                  | Optional | 
| cluster_id | ID of the compute cluster where the new VM will be mounted.<br/><br/>Note: Users can retrieve the list of the cluster IDs by executing the "rubrik-gps-cluster-list" command.               | Optional |
| resource_pool_id | ID of the resource pool where the new VM will be mounted.                                                                                                                                   | Optional |
| snapshot_fid | ID of the snapshot to recover.                                                                                                                                                              | Optional |
| vm_name | Name given to the VM that runs the snapshot. If not provided the name will be "&lt;Snapshot VM Name&gt; &lt;MM/DD of snapshot creation&gt; &lt;hh/mm of snapshot creation&gt; &lt;Num&gt;". | Optional |
| vnic_bindings | List of network bindings for vNIC of the VM.  <br/><br/> e.g. [{"networkDeviceInfo":{"key":2000,"name":"Network adapter"},"backingNetworkInfo":{"moid":"db68871d-0fbf-5551-97de-4c234885766b","name":"Router"}}]            | Optional |
| recovery_point | Point in time to recover to, e.g.: "2023-03-04T05:06:07.890".                                                                                                                               | Optional |



#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.GPSVMLiveMount.id | String | ID of the Live mount request. | 


#### Command Example
```!rubrik-gps-vm-livemount snapshot_id=d680b484-0084-5231-a05d-18e9cd5402fc vm_name=live-mount-demo ```

#### Human Readable Output
### GPS VM Livemount
|VM Live Mount Request ID|
|---|
| dummy_id |



### rubrik-gps-vm-host-list
***
Retrieve the list of available Vsphere Hosts.


#### Base Command

`rubrik-gps-vm-host-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the host to search for. | Optional | 
| cluster_id | To list hosts from the specific cluster.<br/><br/>Note: Users can retrieve the list of the cluster IDs by executing the "rubrik-gps-cluster-list" command. | Optional | 
| limit | Number of results to retrieve in the response. Maximum size allowed is 1000. Default is 50. | Optional | 
| next_page_token | The next page cursor to retrieve the next set of results. | Optional | 
| sort_by | Specify the field to use for sorting the response.<br/><br/>Note: Supported values are "ID" and "NAME" only. For any other values, the obtained result is sorted or not is not confirmed. Default is ID. | Optional | 
| sort_order | Specify the order to sort the data in.<br/><br/>Possible values are: "ASC", "DESC". Default is ASC. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.GPSVMHost.id | String | ID of the Vsphere host. | 
| RubrikPolaris.GPSVMHost.name | String | Name of the Vsphere host. | 
| RubrikPolaris.GPSVMHost.physicalPath.fid | String | ID of a physical path of a node. | 
| RubrikPolaris.GPSVMHost.physicalPath.name | String | Name of a physical path of a node. | 
| RubrikPolaris.GPSVMHost.physicalPath.objectType | String | Type of a physical path of a node, for example, VSphereComputeCluster, VSphereDatacenter etc. | 
| RubrikPolaris.PageToken.GPSVMHost.next_page_token | String | Next page token. | 
| RubrikPolaris.PageToken.GPSVMHost.name | String | Name of the command. | 
| RubrikPolaris.PageToken.GPSVMHost.has_next_page | Boolean | Whether the result has the next page or not. | 


#### Command Example
```!rubrik-gps-vm-host-list ```

#### Human Readable Output
### GPS VM Hosts
|VSphere Host ID|Name|Physical Host|
|---|---|---|
| f57bfebf-c7c9-5310-a5fd-1f0aeea5ba25 | sjc-40302-sand1-esx02.rubrikdemo.com | {'id': '72480b29-0eaa-57a9-8c5c-45b7e1c2c826', 'name': 'Sandbox-1 SJC Cluster', 'objectType': 'VSphereComputeCluster'},<br/>{'id': '3f3a92de-c7f3-57f7-989f-3731db83aeab', 'name': 'Sandbox-1 Datacenter', 'objectType': 'VSphereDatacenter'},<br/>{'id': '415859e2-fd22-53ea-8de1-041d99298fe3', 'name': 'sand1-vcsa.rubrikdemo.com', 'objectType': 'VSphereVCenter'} |



### rubrik-gps-vm-datastore-list
***
Retrieve the list of the available datastores on a Vsphere Host.


#### Base Command

`rubrik-gps-vm-datastore-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the datastore to search for. | Optional | 
| host_id | The ID of a Vsphere host whose datastores are to be listed.<br/><br/>Note: Users can get the list of host IDs by executing the "rubrik-gps-vm-host-list" command. | Required | 
| limit | Number of results to retrieve in the response. Maximum size allowed is 1000. Default is 50. | Optional | 
| next_page_token | The next page cursor to retrieve the next set of results. | Optional | 
| sort_by | Specify the field to use for sorting the response.<br/><br/>Note: Supported values are "ID" and "NAME" only. For any other values, the obtained result is sorted or not is not confirmed. Default is ID. | Optional | 
| sort_order | Specify the order to sort the data in.<br/><br/>Possible values are: "ASC", "DESC". Default is ASC. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.GPSVMHost.id | String | ID of the Vsphere host. | 
| RubrikPolaris.GPSVMHost.Datastore.id | String | ID of the Vsphere datastore. | 
| RubrikPolaris.GPSVMHost.Datastore.name | String | Name of the Vsphere datastore. | 
| RubrikPolaris.GPSVMHost.Datastore.capacity | Number | Datastore capacity in bytes. | 
| RubrikPolaris.GPSVMHost.Datastore.isLocal | Boolean | Whether the datastore is local or remote. | 
| RubrikPolaris.GPSVMHost.Datastore.freeSpace | Number | Free space on the datastore in bytes. | 
| RubrikPolaris.GPSVMHost.Datastore.datastoreType | String | Type of datastore, for example, "NFS",  "VMFS" etc. | 
| RubrikPolaris.PageToken.GPSVMHost.Datastore.next_page_token | String | Next page token. | 
| RubrikPolaris.PageToken.GPSVMHost.Datastore.name | String | Name of the command. | 
| RubrikPolaris.PageToken.GPSVMHost.Datastore.has_next_page | Boolean | Whether the result has the next page or not. | 


#### Command Example
```!rubrik-gps-vm-datastore-list ```

#### Human Readable Output
### GPS VM Datastores
|VSphere Datastore ID|Name|Capacity|Free Space|Datastore Type|
|---|---|---|---|---|
| dummy_datastore_id | dummy-repo | 0.53362190336 TB | 0.188318314496 TB | NFS |



### rubrik-event-list
***
Retrieve the list of events.


#### Base Command

`rubrik-event-list`
#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| activity_status | Filter the events based on the provided activity statuses. Supports comma separated values.<br/><br/>Possible values are: "UNKNOWN_EVENT_STATUS", "SUCCESS", "FAILURE", "INFO", "CANCELED", "RUNNING", "WARNING", "CANCELING", "TASK_SUCCESS", "QUEUED", "TASK_FAILURE", "PARTIAL_SUCCESS".                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Optional | 
| activity_type | Filter the events based on provided activity types. Supports comma separated values.<br/><br/>Possible values are: "UNKNOWN_EVENT_TYPE", "ARCHIVE", "AUTH_DOMAIN", "AWS_EVENT", "BACKUP", "CLASSIFICATION", "CLOUD_NATIVE_SOURCE", "CLOUD_NATIVE_VIRTUAL_MACHINE", "CLOUD_NATIVE_VM", "CONFIGURATION", "CONVERSION", "CONNECTION", "DIAGNOSTIC", "DISCOVERY", "DOWNLOAD", "FAILOVER", "FILESET", "HARDWARE", "HDFS", "HOST_EVENT", "HYPERV_SCVMM", "HYPERV_SERVER", "INDEX", "INSTANTIATE", "LEGAL_HOLD", "LOCAL_RECOVERY", "MAINTENANCE", "NUTANIX_CLUSTER", "RANSOMWARE_INVESTIGATION_ANALYSIS", "RECOVERY", "REPLICATION", "RESOURCE_OPERATIONS", "ANOMALY", "STORAGE", "STORAGE_ARRAY", "STORM_RESOURCE", "SUPPORT", "SYNC", "SYSTEM", "TEST_FAILOVER", "THREAT_HUNT", "TPR", "LOCK_SNAPSHOT", "UPGRADE", "VCENTER", "VCD", "VOLUME_GROUP", "EMBEDDED_EVENT", "ISOLATED_RECOVERY", "OWNERSHIP", "LOG_BACKUP", "K8S".                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Optional | 
| severity | Filter the events based on provided severities. Supports comma separated values.<br/><br/>Possible values are: "SEVERITY_INFO", "SEVERITY_CRITICAL", "SEVERITY_WARNING".                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Optional | 
| object_name | Filter out events based on object name.<br/><br/>Note: Users can get the object names by executing the "rubrik-polaris-vm-objects-list" or "rubrik-polaris-object-search" command.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Optional | 
| object_type | Filter the events based on provided object types. Supports comma separated values.<br/><br/>Possible values are: "UNKNOWN_EVENT_OBJECT_TYPE", "RUBRIK_SAAS_ACCOUNT", "APP_BLUEPRINT", "APP_FLOWS", "OBJECT_TYPE_AUTH_DOMAIN", "AWS_ACCOUNT", "AWS_EVENT_TYPE", "AZURE_NATIVE_SUBSCRIPTION", "AZURE_NATIVE_VM", "AZURE_NATIVE_DISK", "AZURE_SQL_DATABASE", "AZURE_SQL_MANAGED_INSTANCE", "AZURE_SQL_DATABASE_SERVER", "AZURE_SQL_MANAGED_INSTANCE_DATABASE", "CAPACITY_BUNDLE", "OBJECT_TYPE_CLOUD_NATIVE_VIRTUAL_MACHINE", "OBJECT_TYPE_CLOUD_NATIVE_VM", "CERTIFICATE", "CLUSTER", "COMPUTE_INSTANCE", "DATA_LOCATION", "DB2_DATABASE", "DB2_INSTANCE", "EC2_INSTANCE", "ENVOY", "FAILOVER_CLUSTER_APP", "EXOCOMPUTE", "EXCHANGE_DATABASE", "OBJECT_TYPE_HDFS", "HOST", "OBJECT_TYPE_HYPERV_SCVMM", "OBJECT_TYPE_HYPERV_SERVER", "HYPERV_VM", "JOB_INSTANCE", "LDAP", "LINUX_FILESET", "LINUX_HOST", "MANAGED_VOLUME", "MSSQL", "NAS_FILESET", "WEBHOOK", "NAS_HOST", "NAS_SYSTEM", "OBJECT_TYPE_NUTANIX_CLUSTER", "NUTANIX_VM", "O365_CALENDAR", "O365_MAILBOX", "O365_ONEDRIVE", "O365_SITE", "O365_SHARE_POINT_DRIVE", "O365_SHARE_POINT_LIST", "O365_TEAM", "O365_ORGANIZATION", "O365_GROUP", "OBJECT_PROTECTION", "ORACLE", "ORACLE_DB", "ORACLE_HOST", "ORACLE_RAC", "AWS_NATIVE_ACCOUNT", "AWS_NATIVE_EBS_VOLUME", "AWS_NATIVE_EC2_INSTANCE", "RUBRIK_SAAS_EBS_VOLUME", "RUBRIK_SAAS_EC2_INSTANCE", "PUBLIC_CLOUD_MACHINE_INSTANCE", "SAML_SSO", "SAP_HANA_DB", "SAP_HANA_SYSTEM", "SHARE_FILESET", "SLA_DOMAIN", "SMB_DOMAIN", "SNAP_MIRROR_CLOUD", "OBJECT_TYPE_STORAGE_ARRAY", "STORAGE_ARRAY_VOLUME_GROUP", "STORAGE_LOCATION", "STORM", "SUPPORT_BUNDLE", "USER", "OBJECT_TYPE_UPGRADE", "OBJECT_TYPE_VCD", "VCD_VAPP", "OBJECT_TYPE_VCENTER", "VMWARE_COMPUTE_CLUSTER", "VMWARE_VM", "OBJECT_TYPE_VOLUME_GROUP", "WINDOWS_FILESET", "WINDOWS_HOST", "GCP_NATIVE_PROJECT", "AWS_NATIVE_RDS_INSTANCE", "GCP_NATIVE_GCE_INSTANCE", "GCP_NATIVE_DISK", "KUPR_CLUSTER", "KUPR_NAMESPACE", "CASSANDRA_COLUMN_FAMILY", "CASSANDRA_KEYSPACE", "CASSANDRA_SOURCE", "MONGODB_COLLECTION", "MONGODB_DATABASE", "MONGODB_SOURCE", "CLOUD_DIRECT_NAS_EXPORT", "MONGO_COLLECTION", "MONGO_DATABASE", "MONGO_SOURCE", "CERTIFICATE_MANAGEMENT", "AWS_NATIVE_S3_BUCKET", "AZURE_STORAGE_ACCOUNT", "K8S_CLUSTER", "K8S_RESOURCE_SET", "AZURE_AD_TENANT". | Optional | 
| cluster_id | Filter the events based on provided cluster IDs. Supports comma separated values.<br/><br/>Note: Users can get the list of cluster IDs by executing the "rubrik-gps-cluster-list" command.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Optional | 
| start_date | The start date to fetch updated events from.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, etc.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Optional | 
| end_date | The end date to fetch updated events until.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, etc.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Optional | 
| limit | Number of results to retrieve in the response. Maximum size allowed is 1000. Default is 50.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Optional | 
| next_page_token | The next page cursor to retrieve the next set of results.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Optional | 
| sort_by | Specify the field to use for sorting the response.<br/><br/>Note: Possible values are: "LAST_UPDATED", "LOCATION", "OBJECT_TYPE", "CLUSTER_NAME", "OBJECT_NAME", "START_TIME", "ACTIVITY_TYPE", "SEVERITY", "ACTIVITY_STATUS". Default is LAST_UPDATED.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Optional | 
| sort_order | Specify the order to sort the data in.<br/><br/>Possible values are: "ASC","DESC". Default is DESC.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Optional | 



#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.Event.id | Number | ID of the event. | 
| RubrikPolaris.Event.startTime | String | Start time of the event. | 
| RubrikPolaris.Event.fid | String | FID of the event. | 
| RubrikPolaris.Event.activitySeriesId | String | Activity Series ID of the event. | 
| RubrikPolaris.Event.lastUpdated | String | Date time when the event was last updated. | 
| RubrikPolaris.Event.lastActivityType | String | Last Activity Type of the event. | 
| RubrikPolaris.Event.lastActivityStatus | String | Last Activity Status of the event. | 
| RubrikPolaris.Event.location | String | Location of the event. | 
| RubrikPolaris.Event.objectId | String | ID of the object. | 
| RubrikPolaris.Event.objectName | String | Name of the object. | 
| RubrikPolaris.Event.objectType | String | Type of the object. | 
| RubrikPolaris.Event.severity | String | Severity of the event. | 
| RubrikPolaris.Event.progress | String | Progress of the event. | 
| RubrikPolaris.Event.cluster.id | String | The ID of the cluster. | 
| RubrikPolaris.Event.cluster.name | String | The name of the cluster. | 
| RubrikPolaris.Event.activityConnection.nodes.id | String | ID of the activity connection. | 
| RubrikPolaris.Event.activityConnection.nodes.message | String | Message of the activity connection. | 
| RubrikPolaris.Event.activityConnection.nodes.severity | String | Severity of the activity connection. | 
| RubrikPolaris.Event.activityConnection.nodes.time | String | Date time when the activity connection was last updated. | 
| RubrikPolaris.PageToken.Event.next_page_token | String | Next page token. | 
| RubrikPolaris.PageToken.Event.name | String | Name of the command. | 
| RubrikPolaris.PageToken.Event.has_next_page | Boolean | Whether the result has the next page or not. | 


#### Command Example
```!rubrik-event-list limit=1```

#### Human Readable Output
### Events
|Event ID|Activity Series ID|Cluster ID|Object ID|Object Name|Severity|Start Time|Last Updated|Last Activity Type|Last Activity Status|
|---|---|---|---|---|---|---|---|---|---|
| 7739500 | 422d17c0-737d-44df-98a0-a7fa9f714c0d | cc19573c-db6c-418a-9d48-067a256543ba | Fileset:::f2666679-5b94-4116-9cbf-6ab69e575522 | AllTheThings | Info | 2021-10-25T12:15:36.911Z | 2021-10-25T12:16:10.212Z | Index | Success |

 Note: To retrieve the next set of results use, "next_page_token" = xyz



### rubrik-polaris-object-list
***
Retrieve the list of Rubrik objects, based on the provided filters.


#### Base Command

`rubrik-polaris-object-list`
#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| type_filter | Filter the objects based on the provided object types. Supports comma separated values.<br/><br/>Possible values are: "MONGODB_DATABASE", "FilesetTemplate", "VcdOrgVdc", "ShareFileset", "KuprNamespace", "O365Group", "AwsNativeEbsVolume", "OracleDatabase", "O365Mailbox", "MONGO_DB", "AzureNativeResourceGroup", "AZURE_SQL_MANAGED_INSTANCE_DB", "Db2Database", "HOST_FAILOVER_CLUSTER", "VolumeGroup", "AzureNativeVm", "VcdOrg", "Db2Instance", "PhysicalHost", "AwsNativeRdsInstance", "AzureSqlManagedInstanceServer", "O365Site", "VmwareVirtualMachine", "O365User", "ORACLE_DATA_GUARD_GROUP", "AwsNativeEc2Instance", "MssqlInstance", "NutanixVirtualMachine", "CASSANDRA_COLUMN_FAMILY", "MONGO_COLLECTION", "O365Org", "OracleHost", "NAS_FILESET", "SapHanaDatabase", "AllSubHierarchyType", "AWS_NATIVE_S3_BUCKET", "NasSystem", "O365Teams", "VSphereFolder", "VSphereResourcePool", "GcpNativeDisk", "AwsNativeAccount", "VSphereDatacenter", "AZURE_STORAGE_ACCOUNT", "VSphereComputeCluster", "HypervCluster", "CASSANDRA_SOURCE", "VSphereTag", "VcdVapp", "RubrikEbsVolume", "NasVolume", "NasNamespace", "Vcd", "VcdVimServer", "AZURE_SQL_DATABASE_DB", "VSPHERE_VIRTUAL_DISK", "MssqlDatabaseBatchMaintenance", "EXCHANGE_SERVER", "CLOUD_DIRECT_NAS_EXPORT", "VcdCatalog", "O365File", "HypervSCVMM", "Blueprint", "AzureSqlDatabaseServer", "FeldsparSite", "CloudNativeTagRule", "Mssql", "MONGO_SOURCE", "HostShare", "SnapMirrorCloud", "O365Calendar", "O365SharePointDrive", "VSphereNetwork", "Fileset", "SapHanaSystem", "O365Onedrive", "Hdfs", "Ec2Instance", "WindowsCluster", "GcpNativeProject", "MONGODB_COLLECTION", "MONGO_DATABASE", "VSphereDatastore", "AZURE_AD_TENANT", "HypervServer", "VSphereHost", "AppBlueprint", "MssqlAvailabilityGroup", "LinuxFileset", "MANAGED_VOLUME_EXPORT", "CASSANDRA_KEYSPACE", "HypervVirtualMachine", "GcpNativeGCEInstance", "StorageArrayVolumeGroup", "O365SharePointList", "ExchangeDatabase", "NutanixCluster", "AzureNativeManagedDisk", "AzureNativeSubscription", "VSPHERE_DATASTORE_CLUSTER", "ManagedVolume", "FAILOVER_CLUSTER_APP", "VSphereVCenter", "NasShare", "EXCHANGE_DAG", "KuprCluster", "OracleRac", "MONGODB_SOURCE", "ORCHESTRATED_APPLICATION_RECOVERY_BLUEPRINT", "VSphereTagCategory", "ORCHESTRATED_APPLICATION_RECOVERY_PLAN", "WindowsVolumeGroup", "RubrikEc2Instance", "WindowsFileset". | Required | 
| cluster_id | Filter the objects based on the provided cluster IDs. Supports comma separated values.<br/><br/>Note: Users can get the list of cluster IDs by executing the "rubrik-gps-cluster-list" command.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Optional | 
| limit | Number of results to retrieve in the response. Maximum size allowed is 1000. Default is 50.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Optional | 
| next_page_token | The next page cursor to retrieve the next set of results.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Optional | 
| sort_by | Specify the field to use for sorting the response.<br/><br/>Note: Supported values are "ID" and "NAME" only. For any other values, the obtained result is sorted or not is not confirmed. Default is ID.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Optional | 
| sort_order | Specify the order to sort the data in.<br/><br/>Possible values are: "ASC", "DESC". Default is ASC.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.Object.id | String | ID of the object. | 
| RubrikPolaris.Object.effectiveSlaDomain.name | String | Name of the SLA domain of the object. | 
| RubrikPolaris.Object.effectiveSlaDomain.id | String | ID of the SLA domain of the object. | 
| RubrikPolaris.Object.effectiveSlaDomain.description | String | Description of the SLA domain of the object. | 
| RubrikPolaris.Object.effectiveSlaDomain.cluster.id | String | Cluster ID of effective SLA domain of the object. | 
| RubrikPolaris.Object.effectiveSlaDomain.cluster.name | String | Cluster name of effective SLA domain of the object. | 
| RubrikPolaris.Object.effectiveSlaDomain.fid | String | FID of effective SLA domain of the object. | 
| RubrikPolaris.Object.isPassthrough | Boolean | Whether the object is passthrough or not. | 
| RubrikPolaris.Object.cluster.id | String | Cluster ID of the object. | 
| RubrikPolaris.Object.cluster.name | String | Cluster name of the object. | 
| RubrikPolaris.Object.primaryClusterLocation.id | String | ID of the primary cluster location of the object. | 
| RubrikPolaris.Object.logicalPath.name | String | Name of the logical path of the object. | 
| RubrikPolaris.Object.logicalPath.objectType | String | Object Type of the logical path of the object. | 
| RubrikPolaris.Object.physicalPath.name | String | Name of the physical path of the object. | 
| RubrikPolaris.Object.physicalPath.objectType | String | Object Type of the physical path of the object. | 
| RubrikPolaris.Object.name | String | Name of the object. | 
| RubrikPolaris.Object.objectType | String | Type of the object. | 
| RubrikPolaris.PageToken.Object.has_next_page | Boolean | Whether the result has the next page or not. | 
| RubrikPolaris.PageToken.Object.name | String | Name of the command. | 
| RubrikPolaris.PageToken.Object.next_page_token | String | Next page token. | 


#### Command Example
```!rubrik-polaris-object-list limit=1```

#### Human Readable Output
### Objects
|Object ID|Object Name|Object Type|Location|Cluster Name|SLA Domain Name|
|---|---|---|---|---|---|
| 0014037c-70ae-4c53-b1cf-df6926b88968 | Christian LeCorre | O365User | Rubrik Demo\EMEA Users\AMER Users | x | UNPROTECTED |

 Note: To retrieve the next set of results use, "next_page_token" = xyz



### rubrik-polaris-object-snapshot-list
***
Retrieve Rubrik snapshot(s) of an object, based on the provided object ID.


#### Base Command

`rubrik-polaris-object-snapshot-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | The object ID for which the snapshots are to be searched.<br/><br/>Note: Users can get the list of the object IDs by executing the "rubrik-polaris-object-list" command. | Required | 
| start_date | The start date to get snapshots from.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, etc.<br/><br/>Note: start_date and end_date both or none must be initialized. | Optional | 
| end_date | The end date to get snapshots until.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, etc.<br/><br/>Note: start_date and end_date both or none must be initialized. | Optional | 
| limit | Number of results to retrieve in the response. Maximum size allowed is 1000. Default is 50. | Optional | 
| next_page_token | The next page cursor to retrieve the next set of results. | Optional | 
| snapshot_type | List of snapshot types to filter snapshots. Supports comma separated values.<br/><br/>Possible values are: "SCHEDULED", "ON_DEMAND", "DOWNLOADED". | Optional | 
| sort_order | Specify the order to sort the data in.<br/><br/>Possible values are: "Asc", "Desc". Default is Asc. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.Object.id | String | ID of the object. | 
| RubrikPolaris.Object.Snapshot.id | String | ID of the snapshot. | 
| RubrikPolaris.Object.Snapshot.date | String | Date of the snapshot. | 
| RubrikPolaris.Object.Snapshot.isArchivalCopy | Boolean | Whether the snapshot is an archival copy or not. | 
| RubrikPolaris.Object.Snapshot.isReplica | Boolean | Whether the snapshot is a replica or not. | 
| RubrikPolaris.Object.Snapshot.isOnDemandSnapshot | Boolean | Whether the snapshot is on demand or not. | 
| RubrikPolaris.Object.Snapshot.isDownloadedSnapshot | Boolean | Whether the snapshot is downloaded or not. | 
| RubrikPolaris.Object.Snapshot.cluster.id | String | Cluster ID of the snapshot. | 
| RubrikPolaris.Object.Snapshot.cluster.name | String | Cluster name of the snapshot. | 
| RubrikPolaris.Object.Snapshot.cluster.version | String | Cluster version of the snapshot. | 
| RubrikPolaris.Object.Snapshot.cluster.status | String | Cluster status of the snapshot. | 
| RubrikPolaris.Object.Snapshot.slaDomain.name | String | Name of the SLA domain of the snapshot. | 
| RubrikPolaris.Object.Snapshot.slaDomain.fid | String | FID of the SLA domain of the snapshot. | 
| RubrikPolaris.Object.Snapshot.slaDomain.cluster.id | String | Cluster ID of the SLA domain of the snapshot. | 
| RubrikPolaris.Object.Snapshot.slaDomain.cluster.name | String | Cluster name of the SLA domain of the snapshot. | 
| RubrikPolaris.Object.Snapshot.slaDomain.id | String | ID of the SLA domain of the snapshot. | 
| RubrikPolaris.Object.Snapshot.snapshotRetentionInfo.archivalInfos.name | String | Archival name of snapshot retention of the snapshot. | 
| RubrikPolaris.Object.Snapshot.snapshotRetentionInfo.archivalInfos.isExpirationDateCalculated | String | Whether archival expiration date of snapshot retention of the snapshot is calculated or not. | 
| RubrikPolaris.Object.Snapshot.snapshotRetentionInfo.archivalInfos.expirationTime | String | Archival expiration time of snapshot retention of the snapshot. | 
| RubrikPolaris.Object.Snapshot.snapshotRetentionInfo.localInfo.name | String | Name of snapshot retention of the snapshot. | 
| RubrikPolaris.Object.Snapshot.snapshotRetentionInfo.localInfo.isExpirationDateCalculated | Boolean | Whether the expiration date is calculated or not. | 
| RubrikPolaris.Object.Snapshot.snapshotRetentionInfo.localInfo.expirationTime | String | Expiration time of snapshot retention of the snapshot. | 
| RubrikPolaris.PageToken.Object.Snapshot.has_next_page | Boolean | Whether the result has the next page or not. | 
| RubrikPolaris.PageToken.Object.Snapshot.name | String | Name of the command. | 
| RubrikPolaris.PageToken.Object.Snapshot.next_page_token | String | Next Page Token. | 


#### Command Example
```!rubrik-polaris-object-snapshot-list object_id=06515737-388a-57aa-9c8e-54b3f1ee5d8b limit=1```

#### Human Readable Output
### Object Snapshots
|Snapshot ID|Creation Date|Cluster Name|SLA Domain Name|
|---|---|---|---|
| a7adc499-b896-5ad6-bfc2-0aae0ed99459 | 2021-10-28T19:35:52.000Z | sand2-rbk01 | 12hr-30d-AWS |

 Note: To retrieve the next set of results use, "next_page_token" = xyz



### rubrik-radar-ioc-scan
***
Triggers an IOC scan of a system.

Note: To know the results of the scan use the "rubrik-radar-ioc-scan-results" command and to list the running/completed IOC scans on a cluster use the "rubrik-radar-ioc-scan-list" command.


#### Base Command

`rubrik-radar-ioc-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | ID of the cluster on which to perform a scan.<br/><br/>Note: Users can retrieve the list of the cluster IDs by executing the "rubrik-gps-cluster-list" command. | Required | 
| object_id | Object ID of the system on which to perform the scan. Supports comma separated values.<br/><br/>Note: Users can get the list of object IDs by executing the "rubrik-polaris-vm-objects-list" command. | Required | 
| scan_name | Name of the scan. Default is PAXSOAR-1.1.0.| Optional | 
| ioc_type | The type of the indicator to scan for.<br/><br/>Possible values are: "INDICATOR_OF_COMPROMISE_TYPE_PATH_OR_FILENAME", "INDICATOR_OF_COMPROMISE_TYPE_HASH", "INDICATOR_OF_COMPROMISE_TYPE_YARA_RULE".<br/><br/>Note: To provide multiple IOCs use the argument "advance_ioc". | Optional | 
| ioc_value | Value of the indicator to scan for.<br/><br/>Note: To provide multiple IOCs use the argument "advance_ioc". | Optional | 
| advance_ioc | Json encoded Indicators Of Compromise to scan. Json keys signify the type of IOC and the corresponding list of values are the values of the IOC's. If provided, will ignore the ioc_type and ioc_value arguments.<br/><br/>Possible keys to indicate type of indicator: <br/>INDICATOR_OF_COMPROMISE_TYPE_PATH_OR_FILENAME, INDICATOR_OF_COMPROMISE_TYPE_HASH, INDICATOR_OF_COMPROMISE_TYPE_YARA_RULE<br/><br/>Format Accepted:<br/>{<br/>"&lt;ioc_type1&gt;": ["&lt;ioc_value1&gt;", "&lt;ioc_value2&gt;"],<br/>"&lt;ioc_type2&gt;": "&lt;ioc_value2&gt;"<br/>}<br/><br/>Example:<br/>{<br/>"INDICATOR_OF_COMPROMISE_TYPE_PATH_OR_FILENAME": ["C:\Users\Malware_Executible.ps1", "\bin\Malware_Executible"],<br/>"INDICATOR_OF_COMPROMISE_TYPE_HASH": ["e5c1b9c44be582f895eaea3d3738c5b4", "f541b9844be897f895eaea3d3738cfb2"],<br/>"INDICATOR_OF_COMPROMISE_TYPE_YARA_RULE": "rule match_everything {condition:true}"<br/>}. | Optional | 
| start_date | Filter the snapshots from the provided date. Any snapshots taken before the provided date-time will be excluded.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, etc.<br/><br/>Examples of more supported values can be found at https://dateparser.readthedocs.io/en/latest/#relative-dates. | Optional | 
| end_date | Filter the snapshots until the provided date. Any snapshots taken after the provided date-time will be excluded.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, etc.<br/><br/>Examples of more supported values can be found at https://dateparser.readthedocs.io/en/latest/#relative-dates. | Optional | 
| max_snapshots_per_object | Maximum number of snapshots to scan per object. | Optional | 
| max_file_size | Maximum size of the file in bytes that will be included in the scan. The maximum allowed size is 15000000 bytes. Default is 5000000. | Optional | 
| snapshot_id | Provide comma separated snapshot IDs on which to perform a scan separated by colon for each object ID (in the same order). Supports comma separated values.<br/><br/>Format accepted:<br/>object_1_snapshot_id_1, object_1_snapshot_id_2: object_2_snapshot_id_1<br/><br/>Example:<br/>B405e8c0-1fcd-401c-a6f6-42f758aad6df, e179eb47-534b-4624-b155-f33d188902e2: 1e1681bf-4479-4339-a4bb-59901598caa5<br/><br/>Note: Users can retrieve the list of snapshot IDs by executing the "rubrik-polaris-vm-object-snapshot-list" command.<br/><br/>Note: Do not provide "snapshot_start_date", "snapshot_end_date" and, "max_snapshots_per_object" arguments if snapshot ID is provided. | Optional | 
| paths_to_include | Paths to include in the scan. Supports comma separated values.<br/><br/>Format accepted:<br/>path_to_include_1, path_to_include_2. | Optional | 
| paths_to_exclude | Paths to exclude from the scan. Supports comma separated values.<br/><br/>Format accepted:<br/>path_to_exclude_1, path_to_exclude_2. | Optional | 
| paths_to_exempt | Paths to exempt from exclusion. Supports comma separated values.<br/><br/>Format accepted:<br/>path_to_exempt_1, path_to_exempt_2. | Optional | 
| requested_hash_types | The type of hash values of the matched files to return in the result. Supports comma separated values.<br/><br/>Possible values are: "HASH_TYPE_M_D5", "HASH_TYPE_SH_A1", "HASH_TYPE_SH_A256". | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.RadarIOCScan.id | String | ID of the IOC scan. | 
| RubrikPolaris.RadarIOCScan.status | String | Status of the IOC scan trigger request. | 


#### Command Example
```!rubrik-radar-ioc-scan scan_name="Revil Ransomware Scan" ioc_type="INDICATOR_OF_COMPROMISE_TYPE_PATH_OR_FILENAME" ioc_value="revil.exe" cluster_id="052bf7af-93a3-44e9-a7d7-bc8dad4d6b43" object_id="868aa03d-4145-4cb1-808b-e10c4f7a3741" ```

#### Human Readable Output
### Radar IOC Scan
|Scan ID|Status|
|---|---|
| dummy-ioc-id | RUNNING |



### rubrik-radar-ioc-scan-results
***
Retrieves the results of IOC scan of a system.

Note: To initiate a scan use the "rubrik-radar-ioc-scan" command and to list the running/completed scans on a cluster use the "rubrik-radar-ioc-scan-list" command.


#### Base Command

`rubrik-radar-ioc-scan-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | ID of the IOC scan whose results are to be retrieved.<br/><br/>Note: Users can get the scan ID by executing the "rubrik-radar-ioc-scan" command. | Required | 
| cluster_id | ID of the cluster on which the scan was performed.<br/><br/>Note: Users can retrieve the list of the cluster IDs by executing the "rubrik-gps-cluster-list" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.RadarIOCScan.id | String | ID of the IOC scan. | 
| RubrikPolaris.RadarIOCScan.status | String | Overall status of the scan. | 
| RubrikPolaris.RadarIOCScan.indicatorsOfCompromise.iocType | String | Type of IOC that was scanned. | 
| RubrikPolaris.RadarIOCScan.indicatorsOfCompromise.iocValue | String | Value of the IOC that was scanned. | 
| RubrikPolaris.RadarIOCScan.results.objectId | String | ID of the system that was scanned. | 
| RubrikPolaris.RadarIOCScan.results.snapshotResults.status | String | Status of the scan on the snapshot. Values: MALWARE_SCAN_IN_SNAPSHOT_STATUS_PENDING, MALWARE_SCAN_IN_SNAPSHOT_STATUS_FINISHED, MALWARE_SCAN_IN_SNAPSHOT_STATUS_ERROR. | 
| RubrikPolaris.RadarIOCScan.results.snapshotResults.snapshotDate | String | The date-time at which the snapshot was taken. | 
| RubrikPolaris.RadarIOCScan.results.snapshotResults.snapshotId | String | ID of the snapshot that was scanned. | 
| RubrikPolaris.RadarIOCScan.results.snapshotResults.scanStats.numFiles | Number | Number of files encountered during scan. | 
| RubrikPolaris.RadarIOCScan.results.snapshotResults.scanStats.numFilesScanned | Number | Number of files that were scanned on that snapshot. | 
| RubrikPolaris.RadarIOCScan.results.snapshotResults.scanStats.totalFilesScannedSizeBytes | Number | The total file size of the files scanned. | 
| RubrikPolaris.RadarIOCScan.results.snapshotResults.matches.indicatorIndex | Number | Index of indicator in inputs for the scan. | 
| RubrikPolaris.RadarIOCScan.results.snapshotResults.matches.paths.aclDetails | String | JSON encoded file access control list \(ACL\) information. | 
| RubrikPolaris.RadarIOCScan.results.snapshotResults.matches.paths.creationTime | String | File creation date-time. | 
| RubrikPolaris.RadarIOCScan.results.snapshotResults.matches.paths.modificationTime | String | File modification date-time. | 
| RubrikPolaris.RadarIOCScan.results.snapshotResults.matches.paths.path | String | File path that matched the malware Indicator Of Compromise. | 
| RubrikPolaris.RadarIOCScan.results.snapshotResults.matches.paths.yaraMatchDetails.name | String | The name of the matching YARA rule. | 
| RubrikPolaris.RadarIOCScan.results.snapshotResults.matches.paths.yaraMatchDetails.tags | Unknown | Optional YARA tags. Described in https://yara.readthedocs.io/en/latest/writingrules.html\#rule-tags. | 
| RubrikPolaris.RadarIOCScan.results.snapshotResults.matches.paths.requestedHashDetails.hashType | String | Hash algorithm type. | 
| RubrikPolaris.RadarIOCScan.results.snapshotResults.matches.paths.requestedHashDetails.hashValue | String | Hash value of the content at path. | 


#### Command Example
```!rubrik-radar-ioc-scan-results scan_id="bf687fcf-84d7-47f6-8bd1-54e8cf439680" cluster_id="052bf7af-93a3-44e9-a7d7-bc8dad4d6b43"```

#### Human Readable Output
### Radar IOC Scan Results
Scan ID: bf687fcf-84d7-47f6-8bd1-54e8cf439680
Status: FINISHED

|Snapshot ID|Snapshot Date|Object ID|Snapshot Scan Status|Scan Statistics|Matches|
|---|---|---|---|---|---|
| b7d6b871-796e-4e7c-99cf-328007c9d5c1 | 2021-10-29T07:03:30.669Z | VirtualMachine:::868aa03d-4145-4cb1-808b-e10c4f7a3741-vm-81407 | MALWARE_SCAN_IN_SNAPSHOT_STATUS_FINISHED | Number of Files: 142630, Number of Files Scanned: 0, Total Files Scanned In Bytes: 0 | 1 |
| 3779a895-94bf-437e-b63a-61e73e215901 | 2021-10-28T07:00:09.297Z | VirtualMachine:::868aa03d-4145-4cb1-808b-e10c4f7a3741-vm-81407 | MALWARE_SCAN_IN_SNAPSHOT_STATUS_FINISHED | Number of Files: 142630, Number of Files Scanned: 0, Total Files Scanned In Bytes: 0 | 1 |
| a871683f-f4fa-475f-806c-58f06e6782dc | 2021-10-26T07:04:07.139Z | VirtualMachine:::868aa03d-4145-4cb1-808b-e10c4f7a3741-vm-81407 | MALWARE_SCAN_IN_SNAPSHOT_STATUS_FINISHED | Number of Files: 142630, Number of Files Scanned: 0, Total Files Scanned In Bytes: 0 | 1 |
| 129f22f4-0359-4e7d-aa53-9edf4e33cff1 | 2021-10-29T12:01:43.383Z | VirtualMachine:::868aa03d-4145-4cb1-808b-e10c4f7a3741-vm-72277 | MALWARE_SCAN_IN_SNAPSHOT_STATUS_FINISHED | Number of Files: 142138, Number of Files Scanned: 0, Total Files Scanned In Bytes: 0 | 1 |
| b9264942-c71c-4b91-b9a7-74a7ba0f6166 | 2021-10-29T08:01:39.388Z | VirtualMachine:::868aa03d-4145-4cb1-808b-e10c4f7a3741-vm-72277 | MALWARE_SCAN_IN_SNAPSHOT_STATUS_FINISHED | Number of Files: 142138, Number of Files Scanned: 0, Total Files Scanned In Bytes: 0 | 1 |
| 9f12b533-b740-4fb9-af94-4411b0aee01d | 2021-10-29T00:01:04.357Z | VirtualMachine:::868aa03d-4145-4cb1-808b-e10c4f7a3741-vm-72277 | MALWARE_SCAN_IN_SNAPSHOT_STATUS_FINISHED | Number of Files: 142139, Number of Files Scanned: 0, Total Files Scanned In Bytes: 0 | 1 |



### rubrik-gps-async-result
***
Retrieve the result of an asynchronous request. This command will retrieve the result of requests made by commands "rubrik-gps-snapshot-files-download", "rubrik-gps-vm-livemount", "rubrik-gps-vm-export", "rubrik-gps-vm-snapshot-create", and "rubrik-gps-vm-recover-files".


#### Base Command

`rubrik-gps-async-result`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | ID of the request.<br/><br/>Note: Users can get the request ID by executing any of the commands that make a request. Possible commands are mentioned in the command description. | Required | 
| cluster_id | ID of the cluster on which request was made.<br/><br/>Note: Users can retrieve the list of the cluster IDs by executing the "rubrik-gps-cluster-list" command. | Required | 
| cluster_ip_address | IP address of the cluster node to access the download link. Only required to retrieve the results of the command "rubrik-gps-snapshot-files-download".<br/><br/>Note: Users can retrieve the list of the IP addresses by executing the "rubrik-gps-cluster-list" command. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.GPSAsyncResult.id | String | The ID of the request. | 
| RubrikPolaris.GPSAsyncResult.status | String | Status of the request. | 
| RubrikPolaris.GPSAsyncResult.nodeId | String | ID of the node. | 
| RubrikPolaris.GPSAsyncResult.progress | Number | Progress of the request in range 0 to 100. | 
| RubrikPolaris.GPSAsyncResult.error.message | String | JSON stringified message object when an error occurs. | 
| RubrikPolaris.GPSAsyncResult.links.href | String | Link to a resource. | 
| RubrikPolaris.GPSAsyncResult.links.rel | String | Type of the resource pointed by the link. | 


#### Command Example
```!rubrik-gps-async-result request_id="EXPORT_VMWARE_SNAPSHOT_6e101218-141f-4101-b334-3c1bf440bfee_466b7d74-0d13-4e54-9a57-2ea4d7b00a0c:::0" cluster_id="052bf7af-93a3-44e9-a7d7-bc8dad4d6b43" ```

#### Human Readable Output
### GPS Asynchronous Request Result
|ID|Status|Node ID|Links|
|---|---|---|---|
| dummy_id | FAILED | cluster:::RVMHM219S004941 | [self](https://www.example.com/)<br/> |



### rubrik-gps-cluster-list
***
Retrieve the list of the available rubrik clusters.


#### Base Command

`rubrik-gps-cluster-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Filter out clusters based on their type. Supports comma separated values.<br/><br/>Possible values are: "Cloud", "Robo", "ExoCompute", "OnPrem", "Polaris", "Unknown". | Optional | 
| name | Filter out clusters based on name. Supports comma separated values. | Optional | 
| sort_by | Specify the field to use for sorting the response.<br/><br/>Possible values are: "ClusterName", "ClusterType", "RegisteredAt", "ESTIMATED_RUNWAY". Default is ClusterName. | Optional | 
| sort_order | Specify the order to sort the data in.<br/><br/>Possible values are: "Asc", "Desc". Default is Asc. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.GPSCluster.id | String | ID of the cluster. | 
| RubrikPolaris.GPSCluster.name | String | Name of the cluster. | 
| RubrikPolaris.GPSCluster.type | String | Type of the cluster. Values are Cloud, Robo, ExoCompute, OnPrem, Unknown, Polaris. | 
| RubrikPolaris.GPSCluster.status | String | Status of the cluster. Values are Connected, Disconnected, Initializing. | 
| RubrikPolaris.GPSCluster.version | String | Version of the cluster. | 
| RubrikPolaris.GPSCluster.defaultAddress | String | Default address assigned to the cluster. | 
| RubrikPolaris.GPSCluster.cdmUpgradeInfo.clusterStatus.message | String | Message about the cluster upgrade/current condition. | 
| RubrikPolaris.GPSCluster.cdmUpgradeInfo.clusterStatus.status | String | Upgrade/current status of the cluster. It provides information like -- upgrading, upgrade scheduled, stable, downloading packages, pre-checks running and many more. | 
| RubrikPolaris.GPSCluster.cdmUpgradeInfo.overallProgress | Number | Progress \(in percentage\) of an upgrade, if running. | 
| RubrikPolaris.GPSCluster.cdmUpgradeInfo.scheduleUpgradeAt | String | Shows the date-time of a scheduled upgrade. | 
| RubrikPolaris.GPSCluster.cdmUpgradeInfo.downloadedVersion | String | The version that was downloaded but not yet installed. | 
| RubrikPolaris.GPSCluster.cdmUpgradeInfo.version | String | The current version of the cluster. | 
| RubrikPolaris.GPSCluster.productType | String | The product type. Values are CDM, DATOS, POLARIS. | 
| RubrikPolaris.GPSCluster.estimatedRunway | Number | Estimated number of days remaining before additional data storage space is required on the cluster. | 
| RubrikPolaris.GPSCluster.snapshotCount | Number | The total number of snapshots that are taken of different objects in the cluster. | 
| RubrikPolaris.GPSCluster.geoLocation.address | String | Geological address of the cluster. | 
| RubrikPolaris.GPSCluster.lastConnectionTime | String | Time when the cluster was last polled. | 
| RubrikPolaris.GPSCluster.metric.totalCapacity | Number | Total storage capacity of the cluster in Bytes. | 
| RubrikPolaris.GPSCluster.metric.availableCapacity | Number | Available storage capacity of the cluster in Bytes. | 
| RubrikPolaris.GPSCluster.snappableConnection.count | Number | The number of objects in the cluster whose snapshots can be taken. | 
| RubrikPolaris.GPSCluster.state.connectedState | String | Status of the cluster. Values are Connected, Disconnected, Initializing. | 
| RubrikPolaris.GPSCluster.state.clusterRemovalState | String | State of the cluster when it is being removed from the platform. Values are DATA_DELETING, WAITING_FOR_DATA_DELETION, UNREGISTERED, FAILED, DISCONNECTING, REGISTERED. | 
| RubrikPolaris.GPSCluster.clusterNodeConnection.nodes.id | String | ID of a node in a cluster. | 
| RubrikPolaris.GPSCluster.clusterNodeConnection.nodes.status | String | Status of a node in a cluster. | 
| RubrikPolaris.GPSCluster.clusterNodeConnection.nodes.ipAddress | String | IP Address of a node in a cluster. | 
| RubrikPolaris.GPSCluster.passesConnectivityCheck | Boolean | Whether the cluster passes the connectivity check. | 
| RubrikPolaris.GPSCluster.globalManagerConnectivityStatus.urls.url | String | URL of a global manager of the cluster. | 
| RubrikPolaris.GPSCluster.globalManagerConnectivityStatus.urls.isReachable | Boolean | Whether the global manager is reachable. | 
| RubrikPolaris.GPSCluster.connectivityLastUpdated | String | The date-time of when the cluster was last polled for connectivity. | 
| RubrikPolaris.GPSCluster.lambdaFeatureHistory.wasRadarEverEnabled | Boolean | Whether Polaris Radar was ever enabled on the cluster. | 
| RubrikPolaris.GPSCluster.lambdaFeatureHistory.wasSonarEverEnabled | Boolean | Whether Polaris Sonar was ever enabled on the cluster. | 


#### Command Example
```!rubrik-gps-cluster-list name="sand1"```

#### Human Readable Output
### GPS Clusters
|Cluster ID|Cluster Name|Connection Status|Cluster Location|Total Capacity|Free Space|Protected Objects|Cluster Version|IP Address|
|---|---|---|---|---|---|---|---|---|
| cc19573c-db6c-418a-9d48-067a256543ba | sand1-rbk01 | Connected | San Francisco, CA, USA | 52.605821063168 TB | 45.484602130432 TB | 205 | 7.0.0-EA1-14307 | X.X.X.X, X.X.X.X |



### rubrik-radar-ioc-scan-list
***
Lists the running/completed IOC scans on a cluster.

Note: To know the results of the scan use the "rubrik-radar-ioc-scan-results" command. To initiate a scan use the "rubrik-radar-ioc-scan" command.


#### Base Command

`rubrik-radar-ioc-scan-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | ID of the cluster whose IOC scans are to be listed.<br/><br/>Note: Users can retrieve the list of the cluster IDs by executing the "rubrik-gps-cluster-list" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.RadarIOCScan.id | String | ID of the IOC scan. | 
| RubrikPolaris.RadarIOCScan.startTime | String | Start time of the scan. | 
| RubrikPolaris.RadarIOCScan.endTime | String | End time of the scan. | 
| RubrikPolaris.RadarIOCScan.snapshots.id | String | Object ID of the system. | 
| RubrikPolaris.RadarIOCScan.snapshots.snapshots | Unknown | List of snapshot IDs that are included in the scan. | 


#### Command Example
```!rubrik-radar-ioc-scan-list cluster_id="052bf7af-93a3-44e9-a7d7-bc8dad4d6b43"```

#### Human Readable Output
### Radar IOC Scans
|Scan ID|Start Time|End Time|Scanned Objects|
|---|---|---|---|
| fcac511b-20b4-472d-9b65-9198cff8cd49 | 2021-10-12T04:52:08.777Z | Not Finished | VirtualMachine:::90da5ffb-432f-4dac-8c73-39260ff5493e-vm-5952003d-f95c-4ae0-bf9b-b5a80b210935 |
| ad435ff1-617b-468a-b5d3-736fa0e278b0 | 2021-10-28T06:05:53.059Z | 2021-10-28T07:16:16.715Z | VirtualMachine:::868aa03d-4145-4cb1-808b-e10c4f7a3741-vm-72277, VirtualMachine:::868aa03d-4145-4cb1-808b-e10c4f7a3741-vm-72279 |




### rubrik-gps-vm-recover-files
***
Recovers files from a snapshot backup, back into a system.

Note: To know about the recovery status, use the "rubrik-gps-async-result" command.

#### Base Command

`rubrik-gps-vm-recover-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | ID of the cluster where the snapshot resides.<br/><br/>Note: Users can get the cluster ID by executing the "rubrik-gps-cluster-list" command. | Required | 
| snapshot_id | ID of the snapshot from which to recover files.<br/><br/>Note: Users can get the snapshot ID by executing the "rubrik-polaris-vm-object-snapshot-list" command. | Required | 
| paths_to_recover | Comma separated paths of files and directories that will be recovered from the snapshot.<br/><br/>Note: Users can get the list of paths in a snapshot by executing the "rubrik-gps-snapshot-files-list" command. | Required | 
| restore_path | Path on the destination object on which recovery will be done. | Required | 
| destination_object_id | ID of the object where the files will be restored into. If not provided, Rubrik will use the snapshots object.<br/><br/>Note: Users can get the object ID by executing the "rubrik-polaris-vm-objects-list" command. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.GPSVMRecoverFiles.id | String | Recover files request ID. | 


#### Command Example
```!rubrik-gps-vm-recover-files cluster_id="052bf7af-93a3-44e9-a7d7-bc8dad4d6b43" snapshot_id="e2a0ffa8-82a3-518b-8532-0608a0e7380f" path_to_recover="/bin,/boot" restore_path="/tmp/backup1"```

#### Human Readable Output
### GPS VM Recover Files
|Recover Files Request ID|
|---|
| dummy_id |


### rubrik-sonar-user-access-list

***
Retrieve the user access information.

#### Base Command

`rubrik-sonar-user-access-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_name | The name of the user to search for. | Optional | 
| user_email | The email or the UPN of the user to search for. | Optional | 
| search_time_period | Specify the search time period to look for user access.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2023, 01 Mar 2023 04:45:33, 2023-04-17T14:05:44Z. Default is 7 days. | Optional | 
| risk_levels | The comma-separated list of risk levels.<br/><br/>Supported values are: UNKNOWN_RISK, HIGH_RISK, MEDIUM_RISK, LOW_RISK, NO_RISK.<br/><br/>Note: For any other values, whether the obtained result is filtered or not, is not confirmed. | Optional | 
| group_id | Specify the group ID to filter with. | Optional | 
| include_whitelisted_results | The boolean indicates to include the whitelisted results.<br/><br/>Possible values are: "True", "False". Default is False. | Optional | 
| principal_summary_category | Specify the principal summary category to filter with.<br/><br/>Supported values are: PRINCIPAL_SUMMARY_CATEGORY_UNSPECIFIED, USERS_WITH_SENSITIVE_ACCESS, NEW_USERS_WITH_SENSITIVE_ACCESS, USERS_WITH_RISK_LEVEL_INCREASE. Default is USERS_WITH_SENSITIVE_ACCESS.<br/><br/>Note: For any other values, whether the obtained result is filtered or not, is not confirmed. | Optional | 
| limit | Number of results to retrieve in the response. The maximum allowed size is 1000. Default is 50. | Optional | 
| page_number | Specify the page number to get the particular page of results in the response. Default is 1.<br/><br/>Note: This argument is only applicable when provided with the "user_email" argument. | Optional | 
| sort_by | Specify the field to use for sorting the response.<br/><br/>Supported values are: RISK_LEVEL, RISK_SENSITIVE_FILES, RISK_SENSITIVE_HITS, TOTAL_SENSITIVE_HITS, TOTAL_SENSITIVE_FILES, SID, TOTAL_SENSITIVE_OBJECTS. Default is RISK_LEVEL.<br/><br/>Note: For any other values, whether the obtained result is filtered or not, is not confirmed. | Optional | 
| sort_order | Specify the order to sort the data in.<br/><br/>Possible values are: "ASC", "DESC". Default is DESC. | Optional | 
| next_page_token | The next page cursor to retrieve the next set of results. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.UserAccess.principalId | String | The ID of the user. | 
| RubrikPolaris.UserAccess.fullName | String | The full name of the user. | 
| RubrikPolaris.UserAccess.upn | String | The user principal name. | 
| RubrikPolaris.UserAccess.riskLevel | String | The risk level of the user. | 
| RubrikPolaris.UserAccess.sensitiveFiles.highRiskFileCount.totalCount | Number | The total number of high-risk files. | 
| RubrikPolaris.UserAccess.sensitiveFiles.highRiskFileCount.violatedCount | Number | The number of high-risk files that violate policies. | 
| RubrikPolaris.UserAccess.sensitiveFiles.highRiskFileCount.__typename | String | The high-risk file count field type. | 
| RubrikPolaris.UserAccess.sensitiveFiles.mediumRiskFileCount.totalCount | Number | Total number of medium-risk files. | 
| RubrikPolaris.UserAccess.sensitiveFiles.mediumRiskFileCount.violatedCount | Number | The number of medium-risk files that violate policies. | 
| RubrikPolaris.UserAccess.sensitiveFiles.mediumRiskFileCount.__typename | String | The type of the medium risk file count field. | 
| RubrikPolaris.UserAccess.sensitiveFiles.lowRiskFileCount.totalCount | Number | The total number of low-risk files. | 
| RubrikPolaris.UserAccess.sensitiveFiles.lowRiskFileCount.violatedCount | Number | The number of low-risk files that violate policies. | 
| RubrikPolaris.UserAccess.sensitiveFiles.lowRiskFileCount.__typename | String | The type of the low-risk file count field. | 
| RubrikPolaris.UserAccess.sensitiveFiles.__typename | String | The type of the sensitive files field. | 
| RubrikPolaris.UserAccess.totalSensitiveHits.totalHits | Number | The total number of sensitive hits. | 
| RubrikPolaris.UserAccess.totalSensitiveHits.violatedHits | Number | The number of sensitive hits that violate policies. | 
| RubrikPolaris.UserAccess.totalSensitiveHits.__typename | String | The type of the total sensitive hits field. | 
| RubrikPolaris.UserAccess.sensitiveObjectCount.totalCount | Number | The total number of sensitive objects. | 
| RubrikPolaris.UserAccess.sensitiveObjectCount.violatedCount | Number | The Number of sensitive objects that violate policies. | 
| RubrikPolaris.UserAccess.sensitiveObjectCount.__typename | String | The type of the sensitive object count field. | 
| RubrikPolaris.UserAccess.numDescendants | Number | The number of descendant users associated with this user. | 
| RubrikPolaris.UserAccess.domainName | String | The domain name associated with this user. | 
| RubrikPolaris.UserAccess.__typename | String | The type of the User Access field. | 
| RubrikPolaris.PageToken.UserAccess.name | String | Name of the command. | 
| RubrikPolaris.PageToken.UserAccess.startCursor | String | The start cursor for the current page. | 
| RubrikPolaris.PageToken.UserAccess.endCursor | String | The end cursor for the current page. | 
| RubrikPolaris.PageToken.UserAccess.hasNextPage | Boolean | Whether the result has the next page or not. | 
| RubrikPolaris.PageToken.UserAccess.hasPreviousPage | Boolean | Whether the result has the previous page or not. | 
| RubrikPolaris.PageToken.UserAccess.next_upn_page_number | String | The next UPN page number. | 
| RubrikPolaris.PageToken.UserAccess.has_next_upn_page | Boolean | Whether the result has the next UPN page or not. | 

#### Command example
```!rubrik-sonar-user-access-list user_name="Demo Rubrik" user_email="demo@rubrik.com" limit="1"```
#### Context Example
```json
{
    "RubrikPolaris": {
        "PageToken": {
            "UserAccess": {
                "endCursor": "cursor_1",
                "hasNextPage": false,
                "hasPreviousPage": false,
                "has_next_upn_page": false,
                "name": "rubrik-sonar-user-access-list",
                "next_upn_page_number": 1,
                "startCursor": "cursor_1"
            }
        },
        "UserAccess": {
            "__typename": "PrincipalSummary",
            "domainName": "rubrik.com",
            "fullName": "Demo Rubrik",
            "numDescendants": 0,
            "principalId": "S-1-0-01-0000000000-0000000000-000000000-0001",
            "riskLevel": "HIGH_RISK",
            "sensitiveFiles": {
                "__typename": "SensitiveFiles",
                "highRiskFileCount": {
                    "__typename": "SummaryCount",
                    "totalCount": 0,
                    "violatedCount": 124
                },
                "lowRiskFileCount": {
                    "__typename": "SummaryCount",
                    "totalCount": 0,
                    "violatedCount": 0
                },
                "mediumRiskFileCount": {
                    "__typename": "SummaryCount",
                    "totalCount": 0,
                    "violatedCount": 0
                }
            },
            "sensitiveObjectCount": {
                "__typename": "SummaryCount",
                "totalCount": 0,
                "violatedCount": 1
            },
            "totalSensitiveHits": {
                "__typename": "SummaryHits",
                "totalHits": 0,
                "violatedHits": 86972
            },
            "upn": "demo@rubrik.com"
        }
    }
}
```

#### Human Readable Output

>### User Access (Showing Records 1-1 out of 1)
>|User ID|User Full Name|User Principal Name|Risk Level|Total Sensitive Objects|Total Sensitive Files|Total Sensitive Hits|
>|---|---|---|---|---|---|---|
>| [S-1-0-01-0000000000-0000000000-000000000-0001](https://rubrik-test.my.rubrik.com/sonar/user_intelligence?redirected_user_id=S-1-0-01-0000000000-0000000000-000000000-0001) | Demo Rubrik | demo@rubrik\.com | HIGH_RISK | 1 | 124 | 86972 |
>
>Note: To retrieve the next set of results, use **next_page_token** = "cursor_2".<br/>
>If **next_page_token** is provided, then it will reset the record numbers. For the initial use of **next_page_token**, please avoid specifying the **page_number**.


### rubrik-sonar-user-access-get

***
Retrieve the user access information based on the provided user ID.

#### Base Command

`rubrik-sonar-user-access-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | Specify the user_id to retrieve the user access information.<br/><br/>Note: Users can get the list of the user IDs by executing the "rubrik-sonar-user-access-list" command. | Required | 
| search_time_period | Specify the search time period to look for user access. Default is 7 days.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2023, 01 Mar 2023 04:45:33, 2023-04-17T14:05:44Z. | Optional | 
| historical_delta_days | Specify the number of days in the past to collect delta for the sensitive hits. Default is 7. | Optional | 
| include_whitelisted_results | The boolean indicates to include the whitelisted results. Default is False.<br/><br/>Possible values are: "True", "False". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.UserAccess.principalId | String | The ID of the user. | 
| RubrikPolaris.UserAccess.fullName | String | The full name of the user. | 
| RubrikPolaris.UserAccess.upn | String | The user principal name. | 
| RubrikPolaris.UserAccess.riskLevel | String | The risk level of the user. | 
| RubrikPolaris.UserAccess.policy_hits_summary.__typename | String | The type of object representing the policy hits summary. | 
| RubrikPolaris.UserAccess.policy_hits_summary.policyId | String | The unique identifier of the policy associated with the hits summary. | 
| RubrikPolaris.UserAccess.policy_hits_summary.policyName | String | The human-readable name of the policy associated with the hits summary. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidAnalyzerHits.__typename | String | The type of object representing the analyzer hits for a specific SID. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidAnalyzerHits.highRiskHits.__typename | String | The type of object representing high-risk hits for the analyzer. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidAnalyzerHits.highRiskHits.totalHits | Number | The total number of high-risk hits detected by the analyzer. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidAnalyzerHits.highRiskHits.violatedHits | Number | The number of high-risk hits that violated security policies. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidAnalyzerHits.lowRiskHits.__typename | String | The type of object representing low-risk hits for the analyzer. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidAnalyzerHits.lowRiskHits.totalHits | Number | The total number of low-risk hits detected by the analyzer. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidAnalyzerHits.lowRiskHits.violatedHits | Number | The number of low-risk hits that violated security policies. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidAnalyzerHits.mediumRiskHits.__typename | String | The type of object representing medium-risk hits for the analyzer. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidAnalyzerHits.mediumRiskHits.totalHits | Number | The total number of medium-risk hits detected by the analyzer. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidAnalyzerHits.mediumRiskHits.violatedHits | Number | The number of medium-risk hits that violated security policies. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidAnalyzerHits.totalHits.__typename | String | The type of object representing the total number of hits for the analyzer. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidAnalyzerHits.totalHits.totalHits | Number | The total number of hits detected by the analyzer \(all risk levels combined\). | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidAnalyzerHits.totalHits.violatedHits | Number | The number of hits detected by the analyzer that violated security policies \(all risk levels combined\). | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaAnalyzerHits.__typename | String | The type of object representing the difference in analyzer hits between the current and previous periods. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaAnalyzerHits.highRiskHits.__typename | String | The type of object representing the difference in high-risk hits for the analyzer between the current and previous periods. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaAnalyzerHits.highRiskHits.totalHits | Number | The difference in the total number of high-risk hits detected by the analyzer between the current and previous periods. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaAnalyzerHits.highRiskHits.violatedHits | Number | The difference in the number of high-risk hits that violated security policies between the current and previous periods. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaAnalyzerHits.lowRiskHits.__typename | String | The type of object representing the difference in low-risk hits for the analyzer between the current and previous periods. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaAnalyzerHits.lowRiskHits.totalHits | Number | The difference in the total number of low-risk hits detected by the analyzer between the current and previous periods. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaAnalyzerHits.lowRiskHits.violatedHits | Number | The difference in the number of low-risk hits that violated security policies between the current and previous periods. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaAnalyzerHits.mediumRiskHits.__typename | String | The type of object representing the difference in medium-risk hits for the analyzer between the current and previous periods. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaAnalyzerHits.mediumRiskHits.totalHits | Number | The difference in the total number of medium-risk hits detected by the analyzer between the current and previous periods. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaAnalyzerHits.mediumRiskHits.violatedHits | Number | The difference in the number of medium-risk hits that violated security policies between the current and previous periods. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaAnalyzerHits.totalHits.__typename | String | The type of object representing the total difference in hits for the analyzer between the current and previous periods \(all risk levels combined\). | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaAnalyzerHits.totalHits.totalHits | Number | The total difference in the number of hits detected by the analyzer between the current and previous periods \(all risk levels combined\). | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaAnalyzerHits.totalHits.violatedHits | Number | The difference in the number of hits detected by the analyzer that violated security policies between the current and previous periods \(all risk levels combined\). | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaRiskHits.__typename | String | The type of object representing the difference in risk hits between the current and previous periods. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaRiskHits.highRiskHits.__typename | String | The type of object representing the difference in high-risk hits between the current and previous periods. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaRiskHits.highRiskHits.totalHits | Number | The difference in the total number of high-risk hits detected between the current and previous periods. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaRiskHits.highRiskHits.violatedHits | Number | The difference in the number of high-risk hits that violated security policies between the current and previous periods. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaRiskHits.lowRiskHits.__typename | String | The type of object representing the difference in low-risk hits between the current and previous periods. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaRiskHits.lowRiskHits.totalHits | Number | The difference in the total number of low-risk hits detected between the current and previous periods. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaRiskHits.lowRiskHits.violatedHits | Number | The difference in the number of low-risk hits that violated security policies between the current and previous periods. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaRiskHits.mediumRiskHits.__typename | String | The type of object representing the difference in medium-risk hits between the current and previous periods. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaRiskHits.mediumRiskHits.totalHits | Number | The difference in the total number of medium-risk hits detected between the current and previous periods. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaRiskHits.mediumRiskHits.violatedHits | Number | The difference in the number of medium-risk hits that violated security policies between the current and previous periods. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaRiskHits.totalHits.__typename | String | The type of object representing the total difference in risk hits between the current and previous periods \(all risk levels combined\). | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaRiskHits.totalHits.totalHits | Number | The total difference in the number of risk hits detected between the current and previous periods \(all risk levels combined\). | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidDeltaRiskHits.totalHits.violatedHits | Number | The difference in the number of risk hits detected that violated security policies between the current and previous periods \(all risk levels combined\). | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidRiskHits.__typename | String | The type of object representing the risk hits for a specific SID. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidRiskHits.highRiskHits.__typename | String | The type of object representing high-risk hits for the risk engine. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidRiskHits.highRiskHits.totalHits | Number | The total number of high-risk hits detected by the risk engine for the specific SID. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidRiskHits.highRiskHits.violatedHits | Number | The number of high-risk hits that violated security policies for the specific SID. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidRiskHits.lowRiskHits.__typename | String | The type of object representing low-risk hits for the risk engine. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidRiskHits.lowRiskHits.totalHits | Number | The total number of low-risk hits detected by the risk engine for the specific SID. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidRiskHits.lowRiskHits.violatedHits | Number | The number of low-risk hits that violated security policies for the specific SID. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidRiskHits.mediumRiskHits.__typename | String | The type of object representing medium-risk hits for the risk engine. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidRiskHits.mediumRiskHits.totalHits | Number | The total number of medium-risk hits detected by the risk engine for the specific SID. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidRiskHits.mediumRiskHits.violatedHits | Number | The number of medium-risk hits that violated security policies for the specific SID. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidRiskHits.totalHits.__typename | String | The type of object representing the total number of risk hits for the specific SID \(all risk levels combined\). | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidRiskHits.totalHits.totalHits | Number | The total number of risk hits detected by the risk engine for the specific SID \(all risk levels combined\). | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidRiskHits.totalHits.violatedHits | Number | The number of risk hits detected by the risk engine that violated security policies for the specific SID \(all risk levels combined\). | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidSensitiveFiles.__typename | String | The type of object representing the sensitive files associated with the specific SID. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidSensitiveFiles.totalFileCount.__typename | String | The type of object representing the total number of sensitive files associated with the specific SID. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidSensitiveFiles.totalFileCount.totalCount | Number | The total number of sensitive files associated with the specific SID, including both compliant and non-compliant files. | 
| RubrikPolaris.UserAccess.policy_hits_summary.sidSensitiveFiles.totalFileCount.violatedCount | Number | The number of sensitive files associated with the specific SID that violate security policies. | 
| RubrikPolaris.UserAccess.riskReasons.accessRiskReasons | Unknown | The reasons why the user's access is considered risky. | 
| RubrikPolaris.UserAccess.riskReasons.insecureReasons | Unknown | The reasons why the user's access is considered insecure. | 
| RubrikPolaris.UserAccess.riskReasons.__typename | String | The type of the risk reasons field. | 
| RubrikPolaris.UserAccess.sensitiveFiles.highRiskFileCount.totalCount | Number | The total number of high-risk files. | 
| RubrikPolaris.UserAccess.sensitiveFiles.highRiskFileCount.violatedCount | Number | The number of high-risk files that violate policies. | 
| RubrikPolaris.UserAccess.sensitiveFiles.highRiskFileCount.__typename | String | The high-risk file count field type. | 
| RubrikPolaris.UserAccess.sensitiveFiles.mediumRiskFileCount.totalCount | Number | Total number of medium-risk files. | 
| RubrikPolaris.UserAccess.sensitiveFiles.mediumRiskFileCount.violatedCount | Number | The number of medium-risk files that violate policies. | 
| RubrikPolaris.UserAccess.sensitiveFiles.mediumRiskFileCount.__typename | String | The type of the medium risk file count field. | 
| RubrikPolaris.UserAccess.sensitiveFiles.lowRiskFileCount.totalCount | Number | The total number of low-risk files. | 
| RubrikPolaris.UserAccess.sensitiveFiles.lowRiskFileCount.violatedCount | Number | The number of low-risk files that violate policies. | 
| RubrikPolaris.UserAccess.sensitiveFiles.lowRiskFileCount.__typename | String | The type of the low-risk file count field. | 
| RubrikPolaris.UserAccess.sensitiveFiles.__typename | String | The type of the sensitive files field. | 
| RubrikPolaris.UserAccess.totalSensitiveHits.totalHits | Number | The total number of sensitive hits. | 
| RubrikPolaris.UserAccess.totalSensitiveHits.violatedHits | Number | The number of sensitive hits that violate policies. | 
| RubrikPolaris.UserAccess.totalSensitiveHits.__typename | String | The type of the total sensitive hits field. | 
| RubrikPolaris.UserAccess.sensitiveObjectCount.totalCount | Number | The total number of sensitive objects. | 
| RubrikPolaris.UserAccess.sensitiveObjectCount.violatedCount | Number | The Number of sensitive objects that violate policies. | 
| RubrikPolaris.UserAccess.sensitiveObjectCount.__typename | String | The type of the sensitive object count field. | 
| RubrikPolaris.UserAccess.numDescendants | Number | The number of descendant users associated with this user. | 
| RubrikPolaris.UserAccess.domainName | String | The domain name associated with this user. | 
| RubrikPolaris.UserAccess.directGroups.name | String | The name of the direct group. | 
| RubrikPolaris.UserAccess.directGroups.sid | String | The security identifier \(SID\) of the direct group. | 
| RubrikPolaris.UserAccess.directGroups.__typename | String | The type of the direct groups field. | 
| RubrikPolaris.UserAccess.__typename | String | The type of the User Access field. | 

#### Command example
```!rubrik-sonar-user-access-get user_id="S-1-0-01-0000000000-0000000000-000000000-0001"```
#### Context Example
```json
{
    "RubrikPolaris": {
        "UserAccess": {
            "__typename": "PrincipalSummary",
            "directGroups": [
                {
                    "__typename": "UserAccessGroup",
                    "name": "Domain Admins",
                    "sid": "S-1-0-01-0000000000-0000000000-000000000-002"
                },
                {
                    "__typename": "UserAccessGroup",
                    "name": "Domain Users",
                    "sid": "S-1-0-01-0000000000-0000000000-000000000-003"
                }
            ],
            "domainName": "rubrik.com",
            "fullName": "DemoRubrik",
            "numDescendants": 0,
            "principalId": "S-1-0-01-0000000000-0000000000-000000000-0001",
            "riskLevel": "HIGH_RISK",
            "policy_hits_summary": [
                {
                    "policyId": "00000000-0000-0000-0000-000000000001",
                    "policyName": "Policy 1",
                    "sidSensitiveFiles": {
                        "totalFileCount": {
                            "totalCount": 164,
                            "violatedCount": 164,
                            "__typename": "SummaryCount"
                        },
                        "__typename": "SensitiveFiles"
                    },
                    "sidAnalyzerHits": {
                        "highRiskHits": {
                            "totalHits": 0,
                            "violatedHits": 0,
                            "__typename": "SummaryHits"
                        },
                        "mediumRiskHits": {
                            "totalHits": 138118,
                            "violatedHits": 138118,
                            "__typename": "SummaryHits"
                        },
                        "lowRiskHits": {
                            "totalHits": 0,
                            "violatedHits": 0,
                            "__typename": "SummaryHits"
                        },
                        "totalHits": {
                            "totalHits": 138118,
                            "violatedHits": 138118,
                            "__typename": "SummaryHits"
                        },
                        "__typename": "SensitiveHits"
                    },
                    "sidDeltaAnalyzerHits": {
                        "highRiskHits": {
                            "totalHits": 0,
                            "violatedHits": 0,
                            "__typename": "SummaryHits"
                        },
                        "mediumRiskHits": {
                            "totalHits": 0,
                            "violatedHits": 0,
                            "__typename": "SummaryHits"
                        },
                        "lowRiskHits": {
                            "totalHits": 0,
                            "violatedHits": 0,
                            "__typename": "SummaryHits"
                        },
                        "totalHits": {
                            "totalHits": 0,
                            "violatedHits": 0,
                            "__typename": "SummaryHits"
                        },
                        "__typename": "SensitiveHits"
                    },
                    "sidRiskHits": {
                        "highRiskHits": {
                            "totalHits": 138118,
                            "violatedHits": 138118,
                            "__typename": "SummaryHits"
                        },
                        "mediumRiskHits": {
                            "totalHits": 0,
                            "violatedHits": 0,
                            "__typename": "SummaryHits"
                        },
                        "lowRiskHits": {
                            "totalHits": 0,
                            "violatedHits": 0,
                            "__typename": "SummaryHits"
                        },
                        "totalHits": {
                            "totalHits": 138118,
                            "violatedHits": 138118,
                            "__typename": "SummaryHits"
                        },
                        "__typename": "SensitiveHits"
                    },
                    "sidDeltaRiskHits": {
                        "highRiskHits": {
                            "totalHits": 0,
                            "violatedHits": 0,
                            "__typename": "SummaryHits"
                        },
                        "mediumRiskHits": {
                            "totalHits": 0,
                            "violatedHits": 0,
                            "__typename": "SummaryHits"
                        },
                        "lowRiskHits": {
                            "totalHits": 0,
                            "violatedHits": 0,
                            "__typename": "SummaryHits"
                        },
                        "totalHits": {
                            "totalHits": 0,
                            "violatedHits": 0,
                            "__typename": "SummaryHits"
                        },
                        "__typename": "SensitiveHits"
                    },
                    "__typename": "PolicyHitsSummary"
                },
                {
                    "policyId": "00000000-0000-0000-0000-000000000002",
                    "policyName": "Policy 2",
                    "sidSensitiveFiles": {
                        "totalFileCount": {
                            "totalCount": 130,
                            "violatedCount": 130,
                            "__typename": "SummaryCount"
                        },
                        "__typename": "SensitiveFiles"
                    },
                    "sidAnalyzerHits": {
                        "highRiskHits": {
                            "totalHits": 0,
                            "violatedHits": 0,
                            "__typename": "SummaryHits"
                        },
                        "mediumRiskHits": {
                            "totalHits": 101434,
                            "violatedHits": 101434,
                            "__typename": "SummaryHits"
                        },
                        "lowRiskHits": {
                            "totalHits": 0,
                            "violatedHits": 0,
                            "__typename": "SummaryHits"
                        },
                        "totalHits": {
                            "totalHits": 101434,
                            "violatedHits": 101434,
                            "__typename": "SummaryHits"
                        },
                        "__typename": "SensitiveHits"
                    },
                    "sidDeltaAnalyzerHits": {
                        "highRiskHits": {
                            "totalHits": 0,
                            "violatedHits": 0,
                            "__typename": "SummaryHits"
                        },
                        "mediumRiskHits": {
                            "totalHits": 0,
                            "violatedHits": 0,
                            "__typename": "SummaryHits"
                        },
                        "lowRiskHits": {
                            "totalHits": 0,
                            "violatedHits": 0,
                            "__typename": "SummaryHits"
                        },
                        "totalHits": {
                            "totalHits": 0,
                            "violatedHits": 0,
                            "__typename": "SummaryHits"
                        },
                        "__typename": "SensitiveHits"
                    },
                    "sidRiskHits": {
                        "highRiskHits": {
                            "totalHits": 101434,
                            "violatedHits": 101434,
                            "__typename": "SummaryHits"
                        },
                        "mediumRiskHits": {
                            "totalHits": 0,
                            "violatedHits": 0,
                            "__typename": "SummaryHits"
                        },
                        "lowRiskHits": {
                            "totalHits": 0,
                            "violatedHits": 0,
                            "__typename": "SummaryHits"
                        },
                        "totalHits": {
                            "totalHits": 101434,
                            "violatedHits": 101434,
                            "__typename": "SummaryHits"
                        },
                        "__typename": "SensitiveHits"
                    },
                    "sidDeltaRiskHits": {
                        "highRiskHits": {
                            "totalHits": 0,
                            "violatedHits": 0,
                            "__typename": "SummaryHits"
                        },
                        "mediumRiskHits": {
                            "totalHits": 0,
                            "violatedHits": 0,
                            "__typename": "SummaryHits"
                        },
                        "lowRiskHits": {
                            "totalHits": 0,
                            "violatedHits": 0,
                            "__typename": "SummaryHits"
                        },
                        "totalHits": {
                            "totalHits": 0,
                            "violatedHits": 0,
                            "__typename": "SummaryHits"
                        },
                        "__typename": "SensitiveHits"
                    },
                    "__typename": "PolicyHitsSummary"
                }
            ],
            "riskReasons": {
                "__typename": "PrincipalRiskReasons",
                "accessRiskReasons": [
                    "MEDIUM_RISK_ANALYZER_HITS",
                    "OPEN_ACCESS"
                ],
                "insecureReasons": [
                    "PASSWORD_NEVER_EXPIRES"
                ]
            },
            "sensitiveFiles": {
                "__typename": "SensitiveFiles",
                "highRiskFileCount": {
                    "__typename": "SummaryCount",
                    "totalCount": 0,
                    "violatedCount": 250
                },
                "lowRiskFileCount": {
                    "__typename": "SummaryCount",
                    "totalCount": 0,
                    "violatedCount": 0
                },
                "mediumRiskFileCount": {
                    "__typename": "SummaryCount",
                    "totalCount": 0,
                    "violatedCount": 0
                }
            },
            "sensitiveObjectCount": {
                "__typename": "SummaryCount",
                "totalCount": 0,
                "violatedCount": 2
            },
            "totalSensitiveHits": {
                "__typename": "SummaryHits",
                "totalHits": 0,
                "violatedHits": 173954
            },
            "upn": "demo@rubrik.com"
        }
    }
}
```

#### Human Readable Output

>### User Access
>|User ID|User Full Name|User Principal Name|Risk Level|Access Risk Reason(s)|Insecure Reason(s)|Groups|Total Sensitive Objects|Total Sensitive Files|Total Sensitive Hits|
>|---|---|---|---|---|---|---|---|---|---|
>| [S-1-0-01-0000000000-0000000000-000000000-0001](https://rubrik-test.my.rubrik.com/sonar/user_intelligence?redirected_user_id=S-1-0-01-0000000000-0000000000-000000000-0001) | DemoRubrik | demo@rubrik\.com | HIGH_RISK | MEDIUM_RISK_ANALYZER_HITS, OPEN_ACCESS | PASSWORD_NEVER_EXPIRES | Domain Admins, Domain Users | 2 | 250 | 173954 |
>
>
>### Sensitive Hits
>|Policy Name|Total Sensitive Files|Total Sensitive Hits|Sensitive Hits Delta|High Risk Hits|Medium Risk Hits|Low Risk Hits|
>|---|---|---|---|---|---|---|
>| Policy 1 | 164 | 138118 | 0 | 0 | 138118 | 0 |
>| Policy 2 | 130 | 101434 | 0 | 0 | 101434 | 0 |


### rubrik-sonar-file-context-list

***
Retrieve the context of the file, folder, or file share for the provided object and the file details.

#### Base Command

`rubrik-sonar-file-context-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | The Object ID or the Snappable ID.<br/><br/>Note: Users can get the list of the object IDs by executing the "rubrik-polaris-object-list" command. | Required | 
| snapshot_id | The Snapshot ID of the object.<br/><br/>Note: Users can get the list of the snapshot IDs by executing the "rubrik-polaris-object-snapshot-list" command. | Required | 
| file_name | Specify the name of the file, folder, or file share object. | Optional | 
| file_path | Specify the standard file path to filter with. | Optional | 
| user_id | Specify the user ID to filter with.<br/><br/>Note: Users can get the list of the user IDs by executing the "rubrik-sonar-user-access-list" command. | Optional | 
| include_whitelisted_results | The boolean indicates to include the whitelisted results.<br/><br/>Possible values are: "True", "False". Default is False. | Optional | 
| limit | Number of results to retrieve in the response. The maximum allowed size is 1000. Default is 50. | Optional | 
| sort_by | Specify the field to use for sorting the response.<br/><br/>Supported values are: HITS, NAME, DAILY_CHANGE, LAST_ACCESS_TIME, OPEN_ACCESS_TYPE, FILES_WITH_HITS, FILES_WITH_OPEN_ACCESS_HITS, STALE_FILES_WITH_HITS, CLUSTER, OBJECT_NAME, OBJECT_LOCATION, SNAPSHOT_TIME, NUM_ACTIVITIES, NUM_ACTIVITIES_DELTA, NATIVE_PATH. Default is HITS.<br/><br/>Note: For any other values, whether the obtained result is filtered or not, is not confirmed. | Optional | 
| sort_order | Specify the order to sort the data in.<br/><br/>Possible values are: "ASC", "DESC". Default is DESC. | Optional | 
| next_page_token | The next page cursor to retrieve the next set of results. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.FileContext.nativePath | String | The native path of the file. | 
| RubrikPolaris.FileContext.stdPath | String | The standardized path of the file. | 
| RubrikPolaris.FileContext.filename | String | The filename. | 
| RubrikPolaris.FileContext.mode | String | The file mode. | 
| RubrikPolaris.FileContext.size | Number | The file size in bytes. | 
| RubrikPolaris.FileContext.lastAccessTime | Number | The last access time of the file in milliseconds since the epoch. | 
| RubrikPolaris.FileContext.lastModifiedTime | Number | The last modified time of the file in milliseconds since the epoch. | 
| RubrikPolaris.FileContext.directory | String | The value of Directory. | 
| RubrikPolaris.FileContext.numDescendantFiles | Number | The number of descendant files of the file. | 
| RubrikPolaris.FileContext.numDescendantErrorFiles | Number | The number of descendant files of the file that could not be processed. | 
| RubrikPolaris.FileContext.numDescendantSkippedExtFiles | Number | The number of descendant files of the file that were skipped because of their file extension. | 
| RubrikPolaris.FileContext.numDescendantSkippedSizeFiles | Number | The number of descendant files of the file that were skipped because of their file size. | 
| RubrikPolaris.FileContext.errorCode | String | The error code, if any, for the file. | 
| RubrikPolaris.FileContext.hits.totalHits | Number | The total number of hits for the file. | 
| RubrikPolaris.FileContext.hits.violations | Number | The number of violations for the file. | 
| RubrikPolaris.FileContext.hits.violationsDelta | Number | The change in the number of violations for the file since the last scan. | 
| RubrikPolaris.FileContext.hits.totalHitsDelta | Number | The change in the total number of hits for the file since the last scan. | 
| RubrikPolaris.FileContext.hits.__typename | String | The type of the hits field. | 
| RubrikPolaris.FileContext.filesWithHits.totalHits | Number | The total number of files with hits. | 
| RubrikPolaris.FileContext.filesWithHits.violations | Number | The number of files with violations. | 
| RubrikPolaris.FileContext.filesWithHits.__typename | String | The type of the files with hits field. | 
| RubrikPolaris.FileContext.openAccessFilesWithHits.totalHits | Number | The total number of open access files with hits. | 
| RubrikPolaris.FileContext.openAccessFilesWithHits.violations | Number | The number of open access files with violations. | 
| RubrikPolaris.FileContext.openAccessFilesWithHits.__typename | String | The type of the open access files with hits field. | 
| RubrikPolaris.FileContext.staleFilesWithHits.totalHits | Number | The total number of stale files with hits. | 
| RubrikPolaris.FileContext.staleFilesWithHits.violations | Number | The number of stale files with violations. | 
| RubrikPolaris.FileContext.staleFilesWithHits.__typename | String | The type of the stale files with hits field. | 
| RubrikPolaris.FileContext.analyzerGroupResults.analyzerGroup.groupType | String | The type of the analyzer group. | 
| RubrikPolaris.FileContext.analyzerGroupResults.analyzerGroup.id | String | The ID of the analyzer group. | 
| RubrikPolaris.FileContext.analyzerGroupResults.analyzerGroup.name | String | The name of the analyzer group. | 
| RubrikPolaris.FileContext.analyzerGroupResults.analyzerGroup.__typename | String | The type of the analyzer group field. | 
| RubrikPolaris.FileContext.analyzerGroupResults.analyzerResults.hits.totalHits | Number | The total number of hits for the analyzer results. | 
| RubrikPolaris.FileContext.analyzerGroupResults.analyzerResults.hits.violations | Number | The number of violations for the analyzer results. | 
| RubrikPolaris.FileContext.analyzerGroupResults.analyzerResults.hits.__typename | String | The type of the hits field. | 
| RubrikPolaris.FileContext.analyzerGroupResults.analyzerResults.analyzer.id | String | The ID of the analyzer. | 
| RubrikPolaris.FileContext.analyzerGroupResults.analyzerResults.analyzer.name | String | The name of the analyzer. | 
| RubrikPolaris.FileContext.analyzerGroupResults.analyzerResults.analyzer.analyzerType | String | The type of the analyzer. | 
| RubrikPolaris.FileContext.analyzerGroupResults.analyzerResults.analyzer.__typename | String | The type of the analyzer field. | 
| RubrikPolaris.FileContext.analyzerGroupResults.analyzerResults.__typename | String | The type of the analyzer results field. | 
| RubrikPolaris.FileContext.analyzerGroupResults.hits.totalHits | Number | The total number of hits for the analyzer group results. | 
| RubrikPolaris.FileContext.analyzerGroupResults.hits.violations | Number | The number of violations for the analyzer group results. | 
| RubrikPolaris.FileContext.analyzerGroupResults.hits.violationsDelta | Number | The change in the number of violations for the analyzer group results since the last scan. | 
| RubrikPolaris.FileContext.analyzerGroupResults.hits.totalHitsDelta | Number | The change in the total number of hits for the analyzer group results since the last scan. | 
| RubrikPolaris.FileContext.analyzerGroupResults.hits.__typename | String | The type of the hits field. | 
| RubrikPolaris.FileContext.analyzerGroupResults.__typename | String | The type of the analyzer group results field. | 
| RubrikPolaris.FileContext.sensitiveFiles.highRiskFileCount.totalCount | Number | The total number of high-risk files for the policy object. | 
| RubrikPolaris.FileContext.sensitiveFiles.highRiskFileCount.violatedCount | Number | The number of high-risk files for the policy object that violates policies. | 
| RubrikPolaris.FileContext.sensitiveFiles.highRiskFileCount.__typename | String | The type of the high-risk file count field. | 
| RubrikPolaris.FileContext.sensitiveFiles.mediumRiskFileCount.totalCount | Number | Total number of medium-risk files for the policy object. | 
| RubrikPolaris.FileContext.sensitiveFiles.mediumRiskFileCount.violatedCount | Number | The number of medium-risk files for the policy object that violates policies. | 
| RubrikPolaris.FileContext.sensitiveFiles.mediumRiskFileCount.__typename | String | The type of the medium risk file count field. | 
| RubrikPolaris.FileContext.sensitiveFiles.lowRiskFileCount.totalCount | Number | Total number of low-risk files for the policy object. | 
| RubrikPolaris.FileContext.sensitiveFiles.lowRiskFileCount.violatedCount | Number | The number of low-risk files for the policy object that violates policies. | 
| RubrikPolaris.FileContext.sensitiveFiles.lowRiskFileCount.__typename | String | The type of the low-risk file count field. | 
| RubrikPolaris.FileContext.sensitiveFiles.__typename | String | The type of the sensitive files field. | 
| RubrikPolaris.FileContext.openAccessType | String | The open access type for the file. | 
| RubrikPolaris.FileContext.stalenessType | String | The staleness type for the file. | 
| RubrikPolaris.FileContext.numActivities | Number | The number of activities for the file. | 
| RubrikPolaris.FileContext.numActivitiesDelta | Number | The change in the number of activities for the file since the last time it was checked. | 
| RubrikPolaris.FileContext.__typename | String | The type of the file context field. | 
| RubrikPolaris.PageToken.FileContext.name | String | Name of the command. | 
| RubrikPolaris.PageToken.FileContext.endCursor | String | The end cursor for the current page. | 
| RubrikPolaris.PageToken.FileContext.hasNextPage | Boolean | Whether the result has the next page or not. | 

#### Command example
```!rubrik-sonar-file-context-list object_id="1" snapshot_id="1" limit="2"```
#### Context Example
```json
{
    "RubrikPolaris": {
        "FileContext": [
            {
                "__typename": "FileResult",
                "analyzerGroupResults": [
                    {
                        "__typename": "AnalyzerGroupResult",
                        "analyzerGroup": {
                            "__typename": "AnalyzerGroup",
                            "groupType": "CUSTOM",
                            "id": "00000000-0000-0000-0000-000000000001",
                            "name": "UK PII"
                        },
                        "analyzerResults": [
                            {
                                "__typename": "AnalyzerResult",
                                "analyzer": {
                                    "__typename": "Analyzer",
                                    "analyzerType": "UK_DL",
                                    "id": "00000000-0000-0000-0000-000000000001",
                                    "name": "UK DL"
                                },
                                "hits": {
                                    "__typename": "Hits",
                                    "totalHits": 0,
                                    "violations": 2000
                                }
                            }
                        ],
                        "hits": {
                            "__typename": "Hits",
                            "totalHits": 0,
                            "totalHitsDelta": 0,
                            "violations": 2000,
                            "violationsDelta": 0
                        }
                    }
                ],
                "directory": "/C:/File Shares",
                "errorCode": "NOERROR",
                "filename": "uk_drivers_license_number.xlsx",
                "filesWithHits": {
                    "__typename": "Hits",
                    "totalHits": 0,
                    "violations": 1
                },
                "hits": {
                    "__typename": "Hits",
                    "totalHits": 0,
                    "totalHitsDelta": 0,
                    "violations": 2000,
                    "violationsDelta": 0
                },
                "lastAccessTime": 1648099578,
                "lastModifiedTime": 1648099578,
                "mode": "FILE",
                "nativePath": "/C:/File Shares/uk_drivers_license_number.xlsx",
                "numActivities": 0,
                "numActivitiesDelta": 0,
                "numDescendantErrorFiles": 0,
                "numDescendantFiles": 0,
                "numDescendantSkippedExtFiles": 0,
                "numDescendantSkippedSizeFiles": 0,
                "openAccessFilesWithHits": {
                    "__typename": "Hits",
                    "totalHits": 0,
                    "violations": 1
                },
                "openAccessType": "INHERITED",
                "sensitiveFiles": {
                    "__typename": "SensitiveFiles",
                    "highRiskFileCount": {
                        "__typename": "SummaryCount",
                        "totalCount": 0,
                        "violatedCount": 1
                    },
                    "lowRiskFileCount": {
                        "__typename": "SummaryCount",
                        "totalCount": 0,
                        "violatedCount": 0
                    },
                    "mediumRiskFileCount": {
                        "__typename": "SummaryCount",
                        "totalCount": 0,
                        "violatedCount": 0
                    }
                },
                "size": 85708,
                "staleFilesWithHits": {
                    "__typename": "Hits",
                    "totalHits": 0,
                    "violations": 1
                },
                "stalenessType": "IS_STALE",
                "stdPath": "/C:/File Shares/uk_drivers_license_number.xlsx"
            },
            {
                "__typename": "FileResult",
                "analyzerGroupResults": [
                    {
                        "__typename": "AnalyzerGroupResult",
                        "analyzerGroup": {
                            "__typename": "AnalyzerGroup",
                            "groupType": "CUSTOM",
                            "id": "00000000-0000-0000-0000-000000000001",
                            "name": "UK PII"
                        },
                        "analyzerResults": [
                            {
                                "__typename": "AnalyzerResult",
                                "analyzer": {
                                    "__typename": "Analyzer",
                                    "analyzerType": "UK_NINO",
                                    "id": "00000000-0000-0000-0000-000000000001",
                                    "name": "UK NINO"
                                },
                                "hits": {
                                    "__typename": "Hits",
                                    "totalHits": 0,
                                    "violations": 1712
                                }
                            }
                        ],
                        "hits": {
                            "__typename": "Hits",
                            "totalHits": 0,
                            "totalHitsDelta": 0,
                            "violations": 1712,
                            "violationsDelta": 0
                        }
                    }
                ],
                "directory": "/C:/File Shares",
                "errorCode": "NOERROR",
                "filename": "uk_national_insurance_number.csv",
                "filesWithHits": {
                    "__typename": "Hits",
                    "totalHits": 0,
                    "violations": 1
                },
                "hits": {
                    "__typename": "Hits",
                    "totalHits": 0,
                    "totalHitsDelta": 0,
                    "violations": 1712,
                    "violationsDelta": 0
                },
                "lastAccessTime": 1648099580,
                "lastModifiedTime": 1648099580,
                "mode": "FILE",
                "nativePath": "/C:/File Shares/uk_national_insurance_number.csv",
                "numActivities": 0,
                "numActivitiesDelta": 0,
                "numDescendantErrorFiles": 0,
                "numDescendantFiles": 0,
                "numDescendantSkippedExtFiles": 0,
                "numDescendantSkippedSizeFiles": 0,
                "openAccessFilesWithHits": {
                    "__typename": "Hits",
                    "totalHits": 0,
                    "violations": 1
                },
                "openAccessType": "INHERITED",
                "sensitiveFiles": {
                    "__typename": "SensitiveFiles",
                    "highRiskFileCount": {
                        "__typename": "SummaryCount",
                        "totalCount": 0,
                        "violatedCount": 1
                    },
                    "lowRiskFileCount": {
                        "__typename": "SummaryCount",
                        "totalCount": 0,
                        "violatedCount": 0
                    },
                    "mediumRiskFileCount": {
                        "__typename": "SummaryCount",
                        "totalCount": 0,
                        "violatedCount": 0
                    }
                },
                "size": 120064,
                "staleFilesWithHits": {
                    "__typename": "Hits",
                    "totalHits": 0,
                    "violations": 1
                },
                "stalenessType": "IS_STALE",
                "stdPath": "/C:/File Shares/uk_national_insurance_number.csv"
            }
        ],
        "PageToken": {
            "FileContext": {
                "endCursor": "cursor_2",
                "hasNextPage": true,
                "name": "rubrik-sonar-file-context-list"
            }
        }
    }
}
```

#### Human Readable Output

>### File Context
>|File Name|File Size in Bytes|Total Sensitive Hits|Daily Hits Change|File Path|Access Type|Last Access Time|Last Modified Time|
>|---|---|---|---|---|---|---|---|
>| uk_drivers_license_number.xlsx | 85708 | 2000 | 0 | /C:/File Shares/uk_drivers_license_number.xlsx | INHERITED | 2022-03-24T05:26:18Z | 2022-03-24T05:26:18Z |
>| uk_national_insurance_number.csv | 120064 | 1712 | 0 | /C:/File Shares/uk_national_insurance_number.csv | INHERITED | 2022-03-24T05:26:20Z | 2022-03-24T05:26:20Z |
>
>Note: To retrieve the next set of results use, "next_page_token" = cursor_2


### rubrik-radar-suspicious-file-list

***
Retrieve the suspicious list of files for a snapshot ID with detected file anomalies.

#### Base Command

`rubrik-radar-suspicious-file-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| snapshot_id | The Snapshot ID of the object or Activity Series ID.<br/><br/>Note: Users can get the list of the snapshot IDs by executing the "rubrik-polaris-object-snapshot-list" command. For the Activity Series ID, the users can execute the "rubrik-event-list" command with the "activity_type" argument set to "ANOMALY". | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RubrikPolaris.SuspiciousFile.id | String | The anomaly result ID. | 
| RubrikPolaris.SuspiciousFile.snapshotFid | String | The snapshot ID. | 
| RubrikPolaris.SuspiciousFile.cluster.id | String | The cluster ID. | 
| RubrikPolaris.SuspiciousFile.cluster.defaultAddress | String | The default address of the cluster. | 
| RubrikPolaris.SuspiciousFile.cluster.systemStatusAffectedNodes.ipAddress | String | The IP address of the affected node. | 
| RubrikPolaris.SuspiciousFile.cluster.name | String | The cluster name. | 
| RubrikPolaris.SuspiciousFile.cluster.version | String | The cluster version. | 
| RubrikPolaris.SuspiciousFile.cluster.status | String | The cluster status. | 
| RubrikPolaris.SuspiciousFile.cluster.__typename | String | The type name of the cluster response. | 
| RubrikPolaris.SuspiciousFile.cdmId | String | The snapshot CDM ID. | 
| RubrikPolaris.SuspiciousFile.managedId | String | The managed object ID. | 
| RubrikPolaris.SuspiciousFile.anomalyProbability | Number | The probability of the anomaly. | 
| RubrikPolaris.SuspiciousFile.workloadId | String | The workload ID. | 
| RubrikPolaris.SuspiciousFile.location | String | The location of the anomaly. | 
| RubrikPolaris.SuspiciousFile.isAnomaly | Boolean | Indicates if the file is an anomaly. | 
| RubrikPolaris.SuspiciousFile.objectType | String | The object type. | 
| RubrikPolaris.SuspiciousFile.snappableNew.objectType | String | The object type of the snapshot. | 
| RubrikPolaris.SuspiciousFile.severity | String | The severity of the anomaly. | 
| RubrikPolaris.SuspiciousFile.detectionTime | Date | The detection time of the anomaly. | 
| RubrikPolaris.SuspiciousFile.snapshotDate | Date | The snapshot date of the anomaly. | 
| RubrikPolaris.SuspiciousFile.encryption | String | The encryption standard of the anomaly. | 
| RubrikPolaris.SuspiciousFile.anomalyInfo.strainAnalysisInfo.strainId | String | The ID of the Ransomware Strain. | 
| RubrikPolaris.SuspiciousFile.anomalyInfo.strainAnalysisInfo.totalAffectedFiles | Number | The total number of affected files. | 
| RubrikPolaris.SuspiciousFile.anomalyInfo.strainAnalysisInfo.totalRansomwareNotes | Number | The total number of ransomware notes. | 
| RubrikPolaris.SuspiciousFile.anomalyInfo.strainAnalysisInfo.sampleAffectedFilesInfo.filePath | String | The path of the affected file. | 
| RubrikPolaris.SuspiciousFile.anomalyInfo.strainAnalysisInfo.sampleAffectedFilesInfo.lastModified | Date | The last modified time of the affected file. | 
| RubrikPolaris.SuspiciousFile.anomalyInfo.strainAnalysisInfo.sampleAffectedFilesInfo.fileSizeBytes | Number | The size of the affected file in bytes. | 
| RubrikPolaris.SuspiciousFile.anomalyInfo.strainAnalysisInfo.sampleAffectedFilesInfo.__typename | String | The type name of the affected file response. | 
| RubrikPolaris.SuspiciousFile.anomalyInfo.strainAnalysisInfo.sampleRansomwareNoteFilesInfo.filePath | String | The path of the ransomware note file. | 
| RubrikPolaris.SuspiciousFile.anomalyInfo.strainAnalysisInfo.sampleRansomwareNoteFilesInfo.lastModified | Date | The last modified time of the ransomware note file. | 
| RubrikPolaris.SuspiciousFile.anomalyInfo.strainAnalysisInfo.sampleRansomwareNoteFilesInfo.fileSizeBytes | Number | The size of the ransomware note file in bytes. | 
| RubrikPolaris.SuspiciousFile.anomalyInfo.strainAnalysisInfo.sampleRansomwareNoteFilesInfo.__typename | String | The type name of the ransomware note file response. | 
| RubrikPolaris.SuspiciousFile.anomalyInfo.strainAnalysisInfo.__typename | String | The type name of the strain analysis response. | 
| RubrikPolaris.SuspiciousFile.anomalyInfo.__typename | String | The type name of the anomaly response. | 
| RubrikPolaris.SuspiciousFile.__typename | String | The type name of the suspicious file response. | 

#### Command example
```!rubrik-radar-suspicious-file-list snapshot_id="00000000-0000-0000-0000-000000000001"```
#### Context Example
```json
{
    "RubrikPolaris": {
      "SuspiciousFile": {
        "id": "00000000-0000-0000-0000-000000000001:::VirtualMachine:::00000000-0000-0000-0000-000000000001-vm-206:::00000000-0000-0000-0000-000000000001",
        "snapshotFid": "00000000-0000-0000-0000-000000000001",
        "cluster": {
          "id": "00000000-0000-0000-0000-000000000001",
          "defaultAddress": "cluster.rubrik",
          "systemStatusAffectedNodes": [
            {
              "ipAddress": "0.0.0.0"
            }
          ],
          "name": "Cluster_B",
          "version": "8.1.3",
          "status": "Connected",
          "__typename": "Cluster"
        },
        "snappableNew": {
          "objectType": "VmwareVirtualMachine"
        },
        "cdmId": "00000000-0000-0000-0000-000000000001",
        "managedId": "VirtualMachine:::00000000-0000-0000-0000-000000000001-vm-206",
        "anomalyProbability": 0.949999988079071,
        "workloadId": "00000000-0000-0000-0000-000000000001-vm-206",
        "location": "instance.rubrik",
        "isAnomaly": true,
        "severity": "Critical",
        "detectionTime": "2024-02-05T18:49:03.000Z",
        "snapshotDate": "2024-02-05T16:59:30.000Z",
        "encryption": "HIGH",
        "anomalyInfo": {
          "strainAnalysisInfo": [
            {
              "strainId": "LockBit",
              "totalAffectedFiles": 1,
              "totalRansomwareNotes": 1,
              "sampleAffectedFilesInfo": [
                {
                  "filePath": "/C:/Shares/Restore-My-Files.txt.lockbit",
                  "lastModified": "2024-02-05T16:00:44.000Z",
                  "fileSizeBytes": 2512,
                  "__typename": "SuspiciousFileInfo"
                }
              ],
              "sampleRansomwareNoteFilesInfo": [
                {
                  "filePath": "/C:/Users/Public/Desktop/Restore-My-Files.txt",
                  "lastModified": "2024-02-08T02:00:03.000Z",
                  "fileSizeBytes": 2484,
                  "__typename": "SuspiciousFileInfo"
                }
              ],
              "__typename": "StrainInfo"
            }
          ],
          "__typename": "AnomalyInfo"
        },
        "__typename": "GetAnomalyDetailsReply"
      }
    }
}
```

#### Human Readable Output

>### Anomaly Information
>|Anomaly ID|Is Anomaly|Anomaly Probability|Severity|Encryption|Anomaly Type|Total Suspicious Files|Total Ransomware Note|Detection Time|Snapshot Time|
>|---|---|---|---|---|---|---|---|---|---|
>| 00000000-0000-0000-0000-000000000001:::VirtualMachine:::00000000-0000-0000-0000-000000000001-vm-206:::00000000-0000-0000-0000-000000000001 | true | 0.949999988079071 | Critical | HIGH | LockBit | 1 | 1 | 2024-02-05T18:49:03.000Z | 2024-02-05T16:59:30.000Z |
>
>
>### Suspicious Files
>|File Path|Suspicious Activity|File Size in Bytes|Last Modified Time|
>|---|---|---|---|
>| /C:/Shares/Restore-My-Files.txt.lockbit | Ransomware Encryption | 2512 | 2024-02-05T16:00:44.000Z |
>| /C:/Users/Public/Desktop/Restore-My-Files.txt | Ransomware Note | 2484 | 2024-02-08T02:00:03.000Z |


### ip

***
Retrieve the sensitive information available for the given IP address(es).

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address\(es\) for which to retrieve sensitive information. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| IP.Address | String | IP address. | 
| IP.Relationships.EntityA | String | The source of the relationship. | 
| IP.Relationships.EntityB | String | The destination of the relationship. | 
| IP.Relationships.Relationship | String | The name of the relationship. | 
| IP.Relationships.EntityAType | String | The type of the source of the relationship. | 
| IP.Relationships.EntityBType | String | The type of the destination of the relationship. | 
| IP.ASN | String | The autonomous system name for the IP address, for example: "AS8948". | 
| IP.Hostname | String | The hostname that is mapped to this IP address. | 
| IP.Geo.Location | String | The geolocation where the IP address is located, in the format: latitude:longitude. | 
| IP.Geo.Country | String | The country in which the IP address is located. | 
| IP.Geo.Description | String | Additional information about the location. | 
| IP.DetectionEngines | Number | The total number of engines that checked the indicator. | 
| IP.PositiveDetections | Number | The number of engines that positively detected the indicator as malicious. | 
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. | 
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. | 
| IP.Tags | Unknown | Tags of the IP address. | 
| IP.FeedRelatedIndicators.value | String | Indicators that are associated with the IP address. | 
| IP.FeedRelatedIndicators.type | String | The type of the indicators that are associated with the IP address. | 
| IP.FeedRelatedIndicators.description | String | The description of the indicators that are associated with the IP address. | 
| IP.MalwareFamily | String | The malware family associated with the IP address. | 
| IP.Organization.Name | String | The organization of the IP address. | 
| IP.Organization.Type | String | The organization type of the IP address. | 
| IP.ASOwner | String | The autonomous system owner of the IP address. | 
| IP.Region | String | The region in which the IP address is located. | 
| IP.Port | String | Ports that are associated with the IP address. | 
| IP.Internal | Boolean | Whether the IP address is internal or external. | 
| IP.UpdatedDate | Date | The date that the IP address was last updated. | 
| IP.Registrar.Abuse.Name | String | The name of the contact for reporting abuse. | 
| IP.Registrar.Abuse.Address | String | The address of the contact for reporting abuse. | 
| IP.Registrar.Abuse.Country | String | The country of the contact for reporting abuse. | 
| IP.Registrar.Abuse.Network | String | The network of the contact for reporting abuse. | 
| IP.Registrar.Abuse.Phone | String | The phone number of the contact for reporting abuse. | 
| IP.Registrar.Abuse.Email | String | The email address of the contact for reporting abuse. | 
| IP.Campaign | String | The campaign associated with the IP address. | 
| IP.TrafficLightProtocol | String | The Traffic Light Protocol \(TLP\) color that is suitable for the IP address. | 
| IP.CommunityNotes.note | String | Notes on the IP address that were given by the community. | 
| IP.CommunityNotes.timestamp | Date | The time in which the note was published. | 
| IP.Publications.source | String | The source in which the article was published. | 
| IP.Publications.title | String | The name of the article. | 
| IP.Publications.link | String | A link to the original article. | 
| IP.Publications.timestamp | Date | The time in which the article was published. | 
| IP.ThreatTypes.threatcategory | String | The threat category associated to this indicator by the source vendor. For example, Phishing, Control, TOR, etc. | 
| IP.ThreatTypes.threatcategoryconfidence | String | The confidence level provided by the vendor for the threat type category For example, a confidence of 90 for the threat type category 'malware' means that the vendor rates that this is 90% confidence of being a malware. | 
| RubrikPolaris.IP.ip | String | IP address of the object. | 
| RubrikPolaris.IP.generalInfo.fid | String | The foreign ID of the object. | 
| RubrikPolaris.IP.generalInfo.name | String | The name of the object. | 
| RubrikPolaris.IP.generalInfo.objectType | String | The type of the object. | 
| RubrikPolaris.IP.generalInfo.protectionStatus | String | The protection status of the object. | 
| RubrikPolaris.IP.generalInfo.lastSnapshot | Date | The timestamp of the last snapshot of the object. | 
| RubrikPolaris.IP.generalInfo.redirectLink | String | The link to the object in the Rubrik UI. | 
| RubrikPolaris.IP.sensitiveInfo.riskLevel | String | The risk level of the object. | 
| RubrikPolaris.IP.sensitiveInfo.sensitiveFiles.mediumCount | String | The number of sensitive files of medium risk level. | 
| RubrikPolaris.IP.sensitiveInfo.sensitiveHits | Number | The number of sensitive files. | 
| RubrikPolaris.IP.sensitiveInfo.openAccessFiles | Number | The number of open access files. | 
| RubrikPolaris.IP.sensitiveInfo.staleFiles | Number | The number of stale files. | 
| RubrikPolaris.IP.sensitiveInfo.redirectLink | String | The link to the sensitive information in the Rubrik UI. | 
| RubrikPolaris.IP.sensitiveInfo.policyNames | String | The names of the policies associated with the object. | 
| RubrikPolaris.IP.anomalyInfo.severity | String | The severity of the anomaly. | 
| RubrikPolaris.IP.anomalyInfo.detectionTime | Date | The timestamp of the anomaly detection. | 
| RubrikPolaris.IP.anomalyInfo.createdFileCount | String | The number of created files. | 
| RubrikPolaris.IP.anomalyInfo.deletedFileCount | String | The number of deleted files. | 
| RubrikPolaris.IP.anomalyInfo.modifiedFileCount | String | The number of modified files. | 
| RubrikPolaris.IP.anomalyInfo.suspiciousFileCount | String | The number of suspicious files. | 
| RubrikPolaris.IP.anomalyInfo.redirectLink | String | The link to the anomaly information in the Rubrik UI. | 
| RubrikPolaris.IP.threatHuntInfo.latestThreatHunt.huntId | String | The ID of the latest threat hunt. | 
| RubrikPolaris.IP.threatHuntInfo.latestThreatHunt.huntStartTime | Date | The timestamp of the latest threat hunt. | 
| RubrikPolaris.IP.threatHuntInfo.latestThreatHunt.isMalicious | String | Whether the latest threat hunt is malicious. | 
| RubrikPolaris.IP.threatHuntInfo.latestMaliciousThreatHunt.huntId | String | The ID of the latest malicious threat hunt. | 
| RubrikPolaris.IP.threatHuntInfo.latestMaliciousThreatHunt.huntStartTime | Date | The timestamp of the latest malicious threat hunt. | 
| RubrikPolaris.IP.threatHuntInfo.latestMaliciousThreatHunt.isMalicious | String | Whether the latest malicious threat hunt is malicious. | 
| RubrikPolaris.IP.threatHuntInfo.redirectLink | String | The link to the threat hunt information in the Rubrik UI. | 
| RubrikPolaris.IP.threatMonitoringInfo.latestThreatMonitoring.snapshotFid | String | The foreign ID of the latest threat monitoring snapshot. | 
| RubrikPolaris.IP.threatMonitoringInfo.latestThreatMonitoring.monitoringScanTime | Date | The timestamp of the latest threat monitoring scan. | 
| RubrikPolaris.IP.threatMonitoringInfo.latestThreatMonitoring.isMalicious | String | Whether the latest threat monitoring snapshot is malicious. | 
| RubrikPolaris.IP.threatMonitoringInfo.latestMaliciousThreatMonitoring.snapshotFid | String | The foreign ID of the latest malicious threat monitoring snapshot. | 
| RubrikPolaris.IP.threatMonitoringInfo.latestMaliciousThreatMonitoring.monitoringScanTime | Date | The timestamp of the latest malicious threat monitoring scan. | 
| RubrikPolaris.IP.threatMonitoringInfo.latestMaliciousThreatMonitoring.isMalicious | String | Whether the latest malicious threat monitoring snapshot is malicious. | 
| RubrikPolaris.IP.threatMonitoringInfo.redirectLink | String | The link to the threat monitoring information in the Rubrik UI. | 

#### Command example
```!ip ip="0.0.0.1"```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "0.0.0.1",
        "Reliability": "A - Completely reliable",
        "Score": 2,
        "Type": "ip",
        "Vendor": "Rubrik Security Cloud"
    },
    "IP": {
        "Address": "0.0.0.1",
        "UpdatedDate": "2024-10-21T08:51:52Z"
    },
    "RubrikPolaris": {
        "IP": {
            "ip": "0.0.0.1",
            "generalInfo": {
                "fid": "12345678-1234-1234-1234-123456789012",
                "name": "DEMO-RADAR",
                "objectType": "Vsphere Virtual Machine",
                "protectionStatus": "Protected",
                "lastSnapshot": "2024-10-18T06:02:25Z",
                "redirectLink": "https://rubrik-test.my.rubrik.com/inventory_hierarchy/vsphere/12345678-1234-1234-1234-123456789012/overview"
            },
            "sensitiveInfo": {
                "riskLevel": "Medium",
                "sensitiveFiles": {
                    "mediumCount": "11"
                },
                "sensitiveHits": 2910,
                "openAccessFiles": 6,
                "staleFiles": 11,
                "redirectLink": "https://rubrik-test.my.rubrik.com/sonar/objects/detail/12345678-1234-1234-1234-123456789012/12345678-1234-1234-1234-123456789012/browse",
                "policyNames": [
                    "U.S. PII"
                ]
            },
            "anomalyInfo": {
                "severity": "Critical",
                "detectionTime": "2024-10-14T17:57:06Z",
                "createdFileCount": "4487",
                "deletedFileCount": "4477",
                "modifiedFileCount": "32",
                "suspiciousFileCount": "4476",
                "redirectLink": "https://rubrik-test.my.rubrik.com/radar/investigations/vsphere/12345678-1234-1234-1234-123456789012/snapshot/77dc1474-a654-5f20-bcac-348a0f83cd3a/summary"
            },
            "threatHuntInfo": {
                "latestThreatHunt": {
                    "huntId": "12345678-1234-1234-1234-123456789012",
                    "huntStartTime": "2024-10-11T09:23:26Z",
                    "isMalicious": "Matches Found"
                },
                "latestMaliciousThreatHunt": {
                    "huntId": "12345678-1234-1234-1234-123456789012",
                    "huntStartTime": "2024-10-11T09:23:26Z",
                    "isMalicious": "Matches Found"
                },
                "redirectLink": "https://rubrik-test.my.rubrik.com/radar/investigations/threat_hunts/12345678-1234-1234-1234-123456789012/details"
            },
            "threatMonitoringInfo": {
                "latestThreatMonitoring": {
                    "snapshotFid": "12345678-1234-1234-1234-123456789012",
                    "monitoringScanTime": "2024-10-18T05:51:31Z",
                    "isMalicious": "No Matches"
                },
                "latestMaliciousThreatMonitoring": {
                    "snapshotFid": "12345678-1234-1234-1234-123456789012",
                    "monitoringScanTime": "2024-10-14T04:41:15Z",
                    "isMalicious": "Matches Found"
                },
                "redirectLink": "https://rubrik-test.my.rubrik.com/radar/threat_monitoring/12345678-1234-1234-1234-123456789012/Cluster_B/8b4fe6f6-cc87-4354-a125-b65e23cf8c90"
            }
        }
    }
}
```

#### Human Readable Output

>### General Information for the given medium risk IP: 0.0.0.1
>|Fid|Last Snapshot|Name|Object Type|Protection Status|Redirect Link|
>|---|---|---|---|---|---|
>| 12345678-1234-1234-1234-123456789012 | 2024-10-18T06:02:25Z | DEMO-RADAR | Vsphere Virtual Machine | Protected | [https://rubrik-test.my.rubrik.com/inventory_hierarchy/vsphere/12345678-1234-1234-1234-123456789012/overview](https://rubrik-test.my.rubrik.com/inventory_hierarchy/vsphere/12345678-1234-1234-1234-123456789012/overview) |
>
>### Sensitive Information
>|Open Access Files|Policy Names|Redirect Link|Risk Level|Sensitive Files|Sensitive Hits|Stale Files|
>|---|---|---|---|---|---|---|
>| 6 | U.S. PII | [https://rubrik-test.my.rubrik.com/sonar/objects/detail/12345678-1234-1234-1234-123456789012/12345678-1234-1234-1234-123456789012/browse](https://rubrik-test.my.rubrik.com/sonar/objects/detail/12345678-1234-1234-1234-123456789012/12345678-1234-1234-1234-123456789012/browse) | Medium | mediumCount: 11 | 2910 | 11 |
>
>### Anomaly Information
>|Created File Count|Deleted File Count|Detection Time|Modified File Count|Redirect Link|Severity|Suspicious File Count|
>|---|---|---|---|---|---|---|
>| 4487 | 4477 | 2024-10-14T17:57:06Z | 32 | [https://rubrik-test.my.rubrik.com/radar/investigations/vsphere/12345678-1234-1234-1234-123456789012/snapshot/77dc1474-a654-5f20-bcac-348a0f83cd3a/summary](https://rubrik-test.my.rubrik.com/radar/investigations/vsphere/12345678-1234-1234-1234-123456789012/snapshot/77dc1474-a654-5f20-bcac-348a0f83cd3a/summary) | Critical | 4476 |
>
>### Threat Hunt Information
>|Latest Malicious Threat Hunt|Latest Threat Hunt|Redirect Link|
>|---|---|---|
>| huntId: 12345678-1234-1234-1234-123456789012<br/>huntStartTime: 2024-10-11T09:23:26Z<br/>isMalicious: Matches Found | huntId: 12345678-1234-1234-1234-123456789012<br/>huntStartTime: 2024-10-11T09:23:26Z<br/>isMalicious: Matches Found | [https://rubrik-test.my.rubrik.com/radar/investigations/threat_hunts/12345678-1234-1234-1234-123456789012/details](https://rubrik-test.my.rubrik.com/radar/investigations/threat_hunts/12345678-1234-1234-1234-123456789012/details) |
>
>### Threat Monitoring Information
>|Latest Malicious Threat Monitoring|Latest Threat Monitoring|Redirect Link|
>|---|---|---|
>| snapshotFid: 12345678-1234-1234-1234-123456789012<br/>monitoringScanTime: 2024-10-14T04:41:15Z<br/>isMalicious: Matches Found | snapshotFid: 12345678-1234-1234-1234-123456789012<br/>monitoringScanTime: 2024-10-18T05:51:31Z<br/>isMalicious: No Matches | [https://rubrik-test.my.rubrik.com/radar/threat_monitoring/12345678-1234-1234-1234-123456789012/Cluster_B/8b4fe6f6-cc87-4354-a125-b65e23cf8c90](https://rubrik-test.my.rubrik.com/radar/threat_monitoring/12345678-1234-1234-1234-123456789012/Cluster_B/8b4fe6f6-cc87-4354-a125-b65e23cf8c90) |


### domain

***
Retrieve the sensitive information available for the given domain(s).

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain(s) for which to retrieve sensitive information. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| Domain.Relationships.EntityA | string | The source of the relationship. | 
| Domain.Relationships.EntityB | string | The destination of the relationship. | 
| Domain.Relationships.Relationship | string | The name of the relationship. | 
| Domain.Relationships.EntityAType | string | The type of the source of the relationship. | 
| Domain.Relationships.EntityBType | string | The type of the destination of the relationship. | 
| Domain.DNS | String | A list of IP objects resolved by DNS. | 
| Domain.DetectionEngines | Number | The total number of engines that checked the indicator. | 
| Domain.PositiveDetections | Number | The number of engines that positively detected the indicator as malicious. | 
| Domain.CreationDate | Date | The date that the domain was created. | 
| Domain.UpdatedDate | String | The date that the domain was last updated. | 
| Domain.ExpirationDate | Date | The expiration date of the domain. | 
| Domain.DomainStatus | Datte | The status of the domain. | 
| Domain.NameServers | Unknown | \(List&lt;String&gt;\) Name servers of the domain. | 
| Domain.Organization | String | The organization of the domain. | 
| Domain.Subdomains | Unknown | \(List&lt;String&gt;\) Subdomains of the domain. | 
| Domain.Admin.Country | String | The country of the domain administrator. | 
| Domain.Admin.Email | String | The email address of the domain administrator. | 
| Domain.Admin.Name | String | The name of the domain administrator. | 
| Domain.Admin.Phone | String | The phone number of the domain administrator. | 
| Domain.Registrant.Country | String | The country of the registrant. | 
| Domain.Registrant.Email | String | The email address of the registrant. | 
| Domain.Registrant.Name | String | The name of the registrant. | 
| Domain.Registrant.Phone | String | The phone number for receiving abuse reports. | 
| Domain.Tags | Unknown | Tags of the domain. | 
| Domain.FeedRelatedIndicators.value | String | Indicators that are associated with the domain. | 
| Domain.FeedRelatedIndicators.type | String | The type of the indicators that are associated with the domain. | 
| Domain.FeedRelatedIndicators.description | String | The description of the indicators that are associated with the domain. | 
| Domain.MalwareFamily | String | The malware family associated with the domain. | 
| Domain.WHOIS.DomainStatus | String | The status of the domain. | 
| Domain.WHOIS.NameServers | String | \(List&lt;String&gt;\) Name servers of the domain. | 
| Domain.WHOIS.CreationDate | Date | The date that the domain was created. | 
| Domain.WHOIS.UpdatedDate | Date | The date that the domain was last updated. | 
| Domain.WHOIS.ExpirationDate | Date | The expiration date of the domain. | 
| Domain.WHOIS.Registrant.Name | String | The name of the registrant. | 
| Domain.WHOIS.Registrant.Email | String | The email address of the registrant. | 
| Domain.WHOIS.Registrant.Phone | String | The phone number of the registrant. | 
| Domain.WHOIS.Registrar.Name | String | The name of the registrar, for example: "GoDaddy". | 
| Domain.WHOIS.Registrar.AbuseEmail | String | The email address of the contact for reporting abuse. | 
| Domain.WHOIS.Registrar.AbusePhone | String | The phone number of contact for reporting abuse. | 
| Domain.WHOIS.Admin.Name | String | The name of the domain administrator. | 
| Domain.WHOIS.Admin.Email | String | The email address of the domain administrator. | 
| Domain.WHOIS.Admin.Phone | String | The phone number of the domain administrator. | 
| Domain.WHOIS/History | String | List of Whois objects. | 
| Domain.Malicious.Vendor | String | The vendor reporting the domain as malicious. | 
| Domain.Malicious.Description | String | A description explaining why the domain was reported as malicious. | 
| Domain.DomainIDNName | String | The internationalized domain name \(IDN\) of the domain. | 
| Domain.Port | String | Ports that are associated with the domain. | 
| Domain.Internal | Bool | Whether or not the domain is internal or external. | 
| Domain.Category | String | The category associated with the indicator. | 
| Domain.Campaign | String | The campaign associated with the domain. | 
| Domain.TrafficLightProtocol | String | The Traffic Light Protocol \(TLP\) color that is suitable for the domain. | 
| Domain.ThreatTypes.threatcategory | String | The threat category associated to this indicator by the source vendor. For example, Phishing, Control, TOR, etc. | 
| Domain.ThreatTypes.threatcategoryconfidence | String | Threat Category Confidence is the confidence level provided by the vendor for the threat type category For example a confidence of 90 for threat type category 'malware' means that the vendor rates that this is 90% confidence of being a malware. | 
| Domain.Geo.Location | String | The geolocation where the domain address is located, in the format: latitude:longitude. | 
| Domain.Geo.Country | String | The country in which the domain address is located. | 
| Domain.Geo.Description | String | Additional information about the location. | 
| Domain.Tech.Country | String | The country of the domain technical contact. | 
| Domain.Tech.Name | String | The name of the domain technical contact. | 
| Domain.Tech.Organization | String | The organization of the domain technical contact. | 
| Domain.Tech.Email | String | The email address of the domain technical contact. | 
| Domain.CommunityNotes.note | String | Notes on the domain that were given by the community. | 
| Domain.CommunityNotes.timestamp | Date | The time in which the note was published. | 
| Domain.Publications.source | String | The source in which the article was published. | 
| Domain.Publications.title | String | The name of the article. | 
| Domain.Publications.link | String | A link to the original article. | 
| Domain.Publications.timestamp | Date | The time in which the article was published. | 
| Domain.Billing | String | The billing address of the domain. | 
| RubrikPolaris.Domain.domain | String | The domain of the object. | 
| RubrikPolaris.Domain.generalInfo.fid | String | The foreign ID of the object. | 
| RubrikPolaris.Domain.generalInfo.name | String | The name of the object. | 
| RubrikPolaris.Domain.generalInfo.objectType | String | The type of the object. | 
| RubrikPolaris.Domain.generalInfo.protectionStatus | String | The protection status of the object. | 
| RubrikPolaris.Domain.generalInfo.lastSnapshot | Date | The timestamp of the last snapshot of the object. | 
| RubrikPolaris.Domain.generalInfo.redirectLink | String | The link to the object in the Rubrik UI. | 
| RubrikPolaris.Domain.sensitiveInfo.riskLevel | String | The risk level of the object. | 
| RubrikPolaris.Domain.sensitiveInfo.sensitiveFiles.mediumCount | String | The number of sensitive files of medium risk level. | 
| RubrikPolaris.Domain.sensitiveInfo.sensitiveHits | Number | The number of sensitive files. | 
| RubrikPolaris.Domain.sensitiveInfo.openAccessFiles | Number | The number of open access files. | 
| RubrikPolaris.Domain.sensitiveInfo.staleFiles | Number | The number of stale files. | 
| RubrikPolaris.Domain.sensitiveInfo.redirectLink | String | The link to the sensitive information in the Rubrik UI. | 
| RubrikPolaris.Domain.sensitiveInfo.policyNames | String | The names of the policies associated with the object. | 
| RubrikPolaris.Domain.anomalyInfo.severity | String | The severity of the anomaly. | 
| RubrikPolaris.Domain.anomalyInfo.detectionTime | Date | The timestamp of the anomaly detection. | 
| RubrikPolaris.Domain.anomalyInfo.createdFileCount | String | The number of created files. | 
| RubrikPolaris.Domain.anomalyInfo.deletedFileCount | String | The number of deleted files. | 
| RubrikPolaris.Domain.anomalyInfo.modifiedFileCount | String | The number of modified files. | 
| RubrikPolaris.Domain.anomalyInfo.suspiciousFileCount | String | The number of suspicious files. | 
| RubrikPolaris.Domain.anomalyInfo.redirectLink | String | The link to the anomaly information in the Rubrik UI. | 
| RubrikPolaris.Domain.threatHuntInfo.latestThreatHunt.huntId | String | The ID of the latest threat hunt. | 
| RubrikPolaris.Domain.threatHuntInfo.latestThreatHunt.huntStartTime | Date | The timestamp of the latest threat hunt. | 
| RubrikPolaris.Domain.threatHuntInfo.latestThreatHunt.isMalicious | String | Whether the latest threat hunt is malicious. | 
| RubrikPolaris.Domain.threatHuntInfo.latestMaliciousThreatHunt.huntId | String | The ID of the latest malicious threat hunt. | 
| RubrikPolaris.Domain.threatHuntInfo.latestMaliciousThreatHunt.huntStartTime | Date | The timestamp of the latest malicious threat hunt. | 
| RubrikPolaris.Domain.threatHuntInfo.latestMaliciousThreatHunt.isMalicious | String | Whether the latest malicious threat hunt is malicious. | 
| RubrikPolaris.Domain.threatHuntInfo.redirectLink | String | The link to the threat hunt information in the Rubrik UI. | 
| RubrikPolaris.Domain.threatMonitoringInfo.latestThreatMonitoring.snapshotFid | String | The foreign ID of the latest threat monitoring snapshot. | 
| RubrikPolaris.Domain.threatMonitoringInfo.latestThreatMonitoring.monitoringScanTime | Date | The timestamp of the latest threat monitoring scan. | 
| RubrikPolaris.Domain.threatMonitoringInfo.latestThreatMonitoring.isMalicious | String | Whether the latest threat monitoring snapshot is malicious. | 
| RubrikPolaris.Domain.threatMonitoringInfo.latestMaliciousThreatMonitoring.snapshotFid | String | The foreign ID of the latest malicious threat monitoring snapshot. | 
| RubrikPolaris.Domain.threatMonitoringInfo.latestMaliciousThreatMonitoring.monitoringScanTime | Date | The timestamp of the latest malicious threat monitoring scan. | 
| RubrikPolaris.Domain.threatMonitoringInfo.latestMaliciousThreatMonitoring.isMalicious | String | Whether the latest malicious threat monitoring snapshot is malicious. | 
| RubrikPolaris.Domain.threatMonitoringInfo.redirectLink | String | The link to the threat monitoring information in the Rubrik UI. | 

#### Command example
```!domain domain="DEMO-RADAR" using-brand=RubrikPolaris```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "DEMO-RADAR",
        "Reliability": "A - Completely reliable",
        "Score": 2,
        "Type": "domain",
        "Vendor": "Rubrik Security Cloud"
    },
    "Domain": {
        "Name": "DEMO-RADAR",
        "UpdatedDate": "2024-11-05T04:34:47Z",
        "WHOIS": {
            "UpdatedDate": "2024-11-05T04:34:47Z"
        }
    },
    "RubrikPolaris": {
        "Domain": {
            "domain": "DEMO-RADAR",
            "generalInfo": {
                "fid": "12345678-1234-1234-1234-123456789012",
                "name": "DEMO-RADAR",
                "objectType": "Vsphere Virtual Machine",
                "protectionStatus": "Protected",
                "lastSnapshot": "2024-10-18T06:02:25Z",
                "redirectLink": "https://rubrik-test.my.rubrik.com/inventory_hierarchy/vsphere/12345678-1234-1234-1234-123456789012/overview"
            },
            "anomalyInfo": {
                "severity": "Critical",
                "detectionTime": "2024-10-14T17:57:06Z",
                "createdFileCount": "4487",
                "deletedFileCount": "4477",
                "modifiedFileCount": "32",
                "suspiciousFileCount": "4476",
                "redirectLink": "https://rubrik-test.my.rubrik.com/radar/investigations/vsphere/12345678-1234-1234-1234-123456789012/snapshot/77dc1474-a654-5f20-bcac-348a0f83cd3a/summary"
            },
            "sensitiveInfo": {
                "riskLevel": "Medium",
                "sensitiveFiles": {
                    "mediumCount": "11"
                },
                "sensitiveHits": 2910,
                "openAccessFiles": 6,
                "staleFiles": 11,
                "redirectLink": "https://rubrik-test.my.rubrik.com/sonar/objects/detail/12345678-1234-1234-1234-123456789012/12345678-1234-1234-1234-123456789012/browse",
                "policyNames": [
                    "U.S. PII"
                ]
            },
            "threatHuntInfo": {
                "latestThreatHunt": {
                    "huntId": "12345678-1234-1234-1234-123456789012",
                    "huntStartTime": "2024-10-11T09:23:26Z",
                    "isMalicious": "Matches Found"
                },
                "latestMaliciousThreatHunt": {
                    "huntId": "12345678-1234-1234-1234-123456789012",
                    "huntStartTime": "2024-10-11T09:23:26Z",
                    "isMalicious": "Matches Found"
                },
                "redirectLink": "https://rubrik-test.my.rubrik.com/radar/investigations/threat_hunts/12345678-1234-1234-1234-123456789012/details"
            },
            "threatMonitoringInfo": {
                "latestThreatMonitoring": {
                    "snapshotFid": "12345678-1234-1234-1234-123456789012",
                    "monitoringScanTime": "2024-10-18T05:51:31Z",
                    "isMalicious": "No Matches"
                },
                "latestMaliciousThreatMonitoring": {
                    "snapshotFid": "12345678-1234-1234-1234-123456789012",
                    "monitoringScanTime": "2024-10-14T04:41:15Z",
                    "isMalicious": "Matches Found"
                },
                "redirectLink": "https://rubrik-test.my.rubrik.com/radar/threat_monitoring/12345678-1234-1234-1234-123456789012/Cluster_B/8b4fe6f6-cc87-4354-a125-b65e23cf8c90"
            }
        }
    }
}
```

#### Human Readable Output

>### General Information for the given medium risk domain: DEMO-RADAR
>|Fid|Last Snapshot|Name|Object Type|Protection Status|Redirect Link|
>|---|---|---|---|---|---|
>| 12345678-1234-1234-1234-123456789012 | 2024-10-18T06:02:25Z | DEMO-RADAR | Vsphere Virtual Machine | Protected | [https://rubrik-test.my.rubrik.com/inventory_hierarchy/vsphere/12345678-1234-1234-1234-123456789012/overview](https://rubrik-test.my.rubrik.com/inventory_hierarchy/vsphere/12345678-1234-1234-1234-123456789012/overview) |
>
### Sensitive Information
>|Open Access Files|Policy Names|Redirect Link|Risk Level|Sensitive Files|Sensitive Hits|Stale Files|
>|---|---|---|---|---|---|---|
>| 6 | U.S. PII | [https://rubrik-test.my.rubrik.com/sonar/objects/detail/12345678-1234-1234-1234-123456789012/12345678-1234-1234-1234-123456789012/browse](https://rubrik-test.my.rubrik.com/sonar/objects/detail/12345678-1234-1234-1234-123456789012/12345678-1234-1234-1234-123456789012/browse) | Medium | mediumCount: 11 | 2910 | 11 |
>
>### Anomaly Information
>|Created File Count|Deleted File Count|Detection Time|Modified File Count|Redirect Link|Severity|Suspicious File Count|
>|---|---|---|---|---|---|---|
>| 4487 | 4477 | 2024-10-14T17:57:06Z | 32 | [https://rubrik-test.my.rubrik.com/radar/investigations/vsphere/12345678-1234-1234-1234-123456789012/snapshot/77dc1474-a654-5f20-bcac-348a0f83cd3a/summary](https://rubrik-test.my.rubrik.com/radar/investigations/vsphere/12345678-1234-1234-1234-123456789012/snapshot/77dc1474-a654-5f20-bcac-348a0f83cd3a/summary) | Critical | 4476 |
>
>### Threat Hunt Information
>|Latest Malicious Threat Hunt|Latest Threat Hunt|Redirect Link|
>|---|---|---|
>| huntId: 12345678-1234-1234-1234-123456789012<br>huntStartTime: 2024-10-11T09:23:26Z<br>isMalicious: Matches Found | huntId: 12345678-1234-1234-1234-123456789012<br>huntStartTime: 2024-10-11T09:23:26Z<br>isMalicious: Matches Found | [https://rubrik-test.my.rubrik.com/radar/investigations/threat_hunts/12345678-1234-1234-1234-123456789012/details](https://rubrik-test.my.rubrik.com/radar/investigations/threat_hunts/12345678-1234-1234-1234-123456789012/details) |
>
>### Threat Monitoring Information
>|Latest Malicious Threat Monitoring|Latest Threat Monitoring|Redirect Link|
>|---|---|---|
>| snapshotFid: 12345678-1234-1234-1234-123456789012<br>monitoringScanTime: 2024-10-14T04:41:15Z<br>isMalicious: Matches Found | snapshotFid: 12345678-1234-1234-1234-123456789012<br>monitoringScanTime: 2024-10-18T05:51:31Z<br>isMalicious: No Matches | [https://rubrik-test.my.rubrik.com/radar/threat_monitoring/12345678-1234-1234-1234-123456789012/Cluster_B/8b4fe6f6-cc87-4354-a125-b65e23cf8c90](https://rubrik-test.my.rubrik.com/radar/threat_monitoring/12345678-1234-1234-1234-123456789012/Cluster_B/8b4fe6f6-cc87-4354-a125-b65e23cf8c90) |

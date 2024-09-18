# McAfee ePO

<~XSIAM>

## Log Ingestion Configuration 
Follow the steps below to configure ingestion of McAfee ePO event records into Cortex XSIAM.

### Configuration on McAfee ePO

#### Create a Custom Database View 

Connect to the McAfee ePO's underlying MS SQL Server database and create a custom view as described [here](https://learn.microsoft.com/en-us/sql/relational-databases/views/create-views?view=sql-server-ver16) based on the following ePO's database tables/views:  
- `dbo.EPOEvents`
- `dbo.EPOComputerProperties`
- `dbo.EPOLeafNode`
- `dbo.EPESystems`
- `dbo.EPExtendedEvent`
- `dbo.JTIClientEventInfoView`
- `dbo.JTIClientRulesView`
- `dbo.WP_EventInfo`
  
Use the sample SQL query below as a reference for creating the custom view, and customize it as necessary.  
This query retrieves event records from the `EPOEvents` view from within the last hour, and joins it with various other tables and views for enriching the returned fieldset. 

##### Custom View SQL Query Sample
```
  SELECT TOP (100) PERCENT
      dbo.EPOEvents.ThreatType,
      dbo.EPOEvents.TargetUserName,
      dbo.EPOEvents.TargetProcessName,
      dbo.EPOEvents.TargetPort,
      dbo.EPOEvents.TargetProtocol,
      dbo.EPOEvents.TargetMAC,
      dbo.EPOEvents.TargetIPV4,
      dbo.EPOEvents.TargetIPV6,
      dbo.EPOEvents.TargetHostName,
      dbo.EPOEvents.TargetFileName,
      dbo.EPOEvents.SourceUserName,
      dbo.EPOEvents.SourceURL,
      dbo.EPOEvents.SourceHostName,
      dbo.EPOEvents.SourceIPV6,
      dbo.EPOEvents.SourceIPV4,
      dbo.EPOEvents.SourceMAC,
      dbo.EPOEvents.SourceProcessName,
      dbo.EPOEvents.ThreatSeverity,
      dbo.EPOEvents.ThreatHandled,
      dbo.EPOEvents.ThreatName,
      dbo.EPOEvents.ServerID,
      dbo.EPOEvents.EventTimeLocal,
      dbo.EPOEvents.ReceivedUTC,
      dbo.EPOEvents.ThreatEventID,
      dbo.EPOEvents.DetectedUTC,
      dbo.EPOEvents.ThreatCategory,
      dbo.EPOEvents.AnalyzerEngineVersion,
      dbo.EPOEvents.AnalyzerVersion,
      dbo.EPOEvents.AnalyzerName,
      dbo.EPOEvents.AnalyzerMAC,
      dbo.EPOEvents.AnalyzerIPV4,
      dbo.EPOEvents.AnalyzerIPV6,
      dbo.EPOEvents.AnalyzerHostName,
      dbo.EPOEvents.AnalyzerDATVersion,
      dbo.EPOEvents.AnalyzerDetectionMethod,
      dbo.EPOEvents.AgentGUID,
      dbo.EPOComputerProperties.IPAddress,
      dbo.EPOComputerProperties.IPHostName,
      dbo.EPOComputerProperties.OSType,
      dbo.EPOComputerProperties.OSPlatform,
      dbo.EPOEvents.ThreatActionTaken,
      dbo.JTIClientEventInfoView.RuleID,
      dbo.JTIClientEventInfoView.ObjectType,
      dbo.JTIClientEventInfoView.FileSHA1Hash,
      dbo.JTIClientEventInfoView.Reputation,
      dbo.JTIClientEventInfoView.FileMD5Hash,
      dbo.JTIClientEventInfoView.FileCompany,
      dbo.JTIClientEventInfoView.CertSHA1Hash,
      dbo.JTIClientEventInfoView.CertName,
      dbo.JTIClientEventInfoView.CertCompany,
      dbo.JTIClientEventInfoView.CertPKSHA1Hash,
      dbo.JTIClientEventInfoView.ContentVersion,
      dbo.JTIClientEventInfoView.DetectionType,
      dbo.JTIClientEventInfoView.RPSensitivityLevel,
      dbo.EPExtendedEvent.AMCoreContentVersion,
      dbo.EPExtendedEvent.AnalyzerContentCreationDate,
      dbo.EPExtendedEvent.AnalyzerContentVersion,
      dbo.EPExtendedEvent.AnalyzerGTIQuery,
      dbo.EPExtendedEvent.AnalyzerRegInfo,
      dbo.EPExtendedEvent.AnalyzerRuleID,
      dbo.EPExtendedEvent.AnalyzerRuleName,
      dbo.EPExtendedEvent.AnalyzerTechnologyVersion,
      dbo.EPExtendedEvent.SourcePort,
      dbo.EPExtendedEvent.SourceHash,
      dbo.EPExtendedEvent.SourceFilePath,
      dbo.EPExtendedEvent.TargetHash,
      dbo.EPExtendedEvent.TargetName,
      dbo.EPExtendedEvent.TargetModifyTime,
      dbo.EPExtendedEvent.TargetPath,
      dbo.EPExtendedEvent.TaskName,
      dbo.EPExtendedEvent.TargetURL,
      dbo.EPExtendedEvent.TargetSigner,
      dbo.EPExtendedEvent.TargetSigned,
      dbo.EPExtendedEvent.SourceProcessHash,
      dbo.EPExtendedEvent.SourceParentProcessName,
      dbo.EPOLeafNode.LastCommSecure,
      dbo.EPOLeafNode.LastUpdate,
      dbo.EPOLeafNode.SequenceErrorCountLastUpdate,
      dbo.EPOLeafNode.ManagedState,
      dbo.EPOLeafNode.NodeName,
      dbo.EPOLeafNode.Tags,
      dbo.WP_EventInfo.URL,
      dbo.WP_EventInfo.ReasonID,
      dbo.WP_EventInfo.RatingID,
      dbo.WP_EventInfo.ObserverMode,
      dbo.WP_EventInfo.ListID,
      dbo.WP_EventInfo.ExploitRatingID,
      dbo.WP_EventInfo.SpamRatingID,
      dbo.WP_EventInfo.PhishingRatingID,
      dbo.WP_EventInfo.DomainName,
      dbo.WP_EventInfo.DownloadRatingID,
      dbo.WP_EventInfo.Count,
      dbo.WP_EventInfo.ContentID,
      dbo.WP_EventInfo.ActionID,
      dbo.JTIClientRulesView.Name,
      dbo.JTIClientRulesView.Description,
      dbo.EPESystems.Version,
      dbo.EPESystems.UninitializedUsers,
      dbo.EPESystems.State,
      dbo.EPESystems.PbfsSizeMb,
      dbo.EPESystems.PbfsFreeSpaceBytes,
      dbo.EPESystems.RecoveryPartitionStatus,
      dbo.EPESystems.ModelIdentifier,
      dbo.EPESystems.PrebootPartitionStatus,
      dbo.EPESystems.AutobootTPMState,
      dbo.EPESystems.SGXState,
      dbo.EPESystems.AOACState,
      dbo.EPESystems.FirmwareType,
      dbo.EPESystems.FipsMode,
      dbo.EPESystems.EncryptionProvider,
      dbo.EPESystems.EpoTransfer,
      dbo.EPESystems.AutobootEnabled,
      dbo.EPESystems.Algorithm,
      dbo.EPESystems.TPMSpec,
      dbo.EPOEvents.AutoID
  FROM dbo.EPOEvents
      LEFT OUTER JOIN dbo.WP_EventInfo
          ON dbo.EPOEvents.AutoID = dbo.WP_EventInfo.EventAutoID
      LEFT OUTER JOIN dbo.EPExtendedEvent
          ON dbo.EPOEvents.AutoID = dbo.EPExtendedEvent.EventAutoID
      LEFT OUTER JOIN dbo.EPOLeafNode
          ON dbo.EPOEvents.AgentGUID = dbo.EPOLeafNode.AgentGUID
      LEFT OUTER JOIN dbo.EPESystems
          ON dbo.EPOLeafNode.AutoID = dbo.EPESystems.EPOLeafNodeId
      LEFT OUTER JOIN dbo.EPOComputerProperties
          ON dbo.EPOLeafNode.AutoID = dbo.EPOComputerProperties.ParentID
      LEFT OUTER JOIN dbo.JTIClientEventInfoView
          ON dbo.EPOEvents.AutoID = dbo.JTIClientEventInfoView.EventID
      LEFT OUTER JOIN dbo.JTIClientRulesView
          ON dbo.JTIClientEventInfoView.RuleID = dbo.JTIClientRulesView.RuleID
            AND dbo.JTIClientRulesView.LangID = 'en'
  -- customize time interval as needed             
  WHERE (dbo.EPOEvents.ReceivedUTC >= DATEADD(HOUR, -1, GETUTCDATE()))
  ORDER BY dbo.EPOEvents.ReceivedUTC DESC
  ```

### Configuration on Cortex XSIAM 

#### Configure a Broker VM on Cortex XSIAM
If you do not yet have a Broker VM configured, follow the instructions [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Set-up-and-configure-Broker-VM). 


#### Configure a Database Collector

Activate a database collector as described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Activate-the-Database-Collector).

* When configuring the *Database Query* section, set the following parameters:
   | Parameter         | Value    
   | :---              | :---                    
   | `Rising Column`   | Enter *AutoID*.  
   | `Retrieval Value` | Enter *0* for initializing the first retrieval to select all records within the view's defined time interval. For example, if the view is defined to select records from within the last hour (as in the sample SQL query above), the first retrieval would include all records from within the last hour. After the first initialization retrieval, the subsequent continuous polling would select only new records added from that point forward. Alternatively, set this value to the last known *EPOEvents.AutoID* value.
   | `Unique IDs`      | Leave this parameter blank, as the *AutoID* rising column values are unique. 
   | `Collect Every`   | Select the requested polling time interval. This interval must be shorter than the time interval defined on the custom view SQL query (1 hour on the sample query above). 
   | `Vendor`          | Enter *McAfee*. 
   | `Product`         | Enter *ePO*. 
   
* Under the SQL Query editor, enter the following query, replacing <CUSTOM_VIEW_NAME> with the actual custom view name created on the McAfee ePO database: 
   ```SQL
      SELECT * FROM <CUSTOM_VIEW_NAME>
      WHERE AutoID > ?
      ORDER BY AutoID ASC
  ```

</~XSIAM>
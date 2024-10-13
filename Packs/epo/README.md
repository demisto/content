# McAfee ePO

<~XSIAM>

## Log Ingestion Configuration 
Follow the steps below to configure ingestion of McAfee ePO event records into Cortex XSIAM.

### Configuration on McAfee ePO

#### Create a Custom Database View 

Connect to the McAfee ePO's underlying MS SQL Server database and create a custom view as described [here](https://learn.microsoft.com/en-us/sql/relational-databases/views/create-views?view=sql-server-ver16) based on the following ePO's database views:  
- `dbo.EPOEvents`
- `dbo.EPOComputerProperties`
- `dbo.EPOLeafNode`
- `dbo.EPExtendedEvent`
- `dbo.JTIClientEventInfoView`
  
Use the sample SQL query below as a reference for creating the custom view, and customize the *where* condition as necessary to meet your environment requirements.    
This query retrieves event records from the `EPOEvents` view from within the last hour, and joins it with various additional views for enriching the returned fieldset. 

##### Custom View SQL Query Sample
```
SELECT 
  dbo.EPExtendedEvent.AnalyzerContentVersion,
  dbo.EPExtendedEvent.AnalyzerRuleID,
  dbo.EPExtendedEvent.AnalyzerRuleName,
  dbo.EPExtendedEvent.SourceFilePath,
  dbo.EPExtendedEvent.SourceHash,
  dbo.EPExtendedEvent.SourceParentProcessName,
  dbo.EPExtendedEvent.SourcePort,
  dbo.EPExtendedEvent.SourceProcessHash,
  dbo.EPExtendedEvent.TargetHash,
  dbo.EPExtendedEvent.TargetModifyTime,
  dbo.EPExtendedEvent.TargetName,
  dbo.EPExtendedEvent.TargetPath,
  dbo.EPExtendedEvent.TargetSigned,
  dbo.EPExtendedEvent.TargetSigner,
  dbo.EPExtendedEvent.TargetURL,
  dbo.EPOComputerProperties.IPAddress,
  dbo.EPOComputerProperties.IPHostName,
  dbo.EPOComputerProperties.OSPlatform,
  dbo.EPOComputerProperties.OSType,
  dbo.EPOEvents.AgentGUID,
  dbo.EPOEvents.AnalyzerDATVersion,
  dbo.EPOEvents.AnalyzerDetectionMethod,
  dbo.EPOEvents.AnalyzerEngineVersion,
  dbo.EPOEvents.AnalyzerHostName,
  dbo.EPOEvents.AnalyzerIPV4,
  dbo.EPOEvents.AnalyzerIPV6,
  dbo.EPOEvents.AnalyzerMAC,
  dbo.EPOEvents.AnalyzerName,
  dbo.EPOEvents.AnalyzerVersion,
  dbo.EPOEvents.AutoID,
  dbo.EPOEvents.DetectedUTC,
  dbo.EPOEvents.EventTimeLocal,
  dbo.EPOEvents.ReceivedUTC,
  dbo.EPOEvents.ServerID,
  dbo.EPOEvents.SourceHostName,
  dbo.EPOEvents.SourceIPV4,
  dbo.EPOEvents.SourceIPV6,
  dbo.EPOEvents.SourceMAC,
  dbo.EPOEvents.SourceProcessName,
  dbo.EPOEvents.SourceURL,
  dbo.EPOEvents.SourceUserName,
  dbo.EPOEvents.TargetFileName,
  dbo.EPOEvents.TargetHostName,
  dbo.EPOEvents.TargetIPV4,
  dbo.EPOEvents.TargetIPV6,
  dbo.EPOEvents.TargetMAC,
  dbo.EPOEvents.TargetPort,
  dbo.EPOEvents.TargetProcessName,
  dbo.EPOEvents.TargetProtocol,
  dbo.EPOEvents.TargetUserName,
  dbo.EPOEvents.ThreatActionTaken,
  dbo.EPOEvents.ThreatCategory,
  dbo.EPOEvents.ThreatEventID,
  dbo.EPOEvents.ThreatHandled,
  dbo.EPOEvents.ThreatName,
  dbo.EPOEvents.ThreatSeverity,
  dbo.EPOEvents.ThreatType,
  dbo.EPOLeafNode.NodeName,
  dbo.JTIClientEventInfoView.FileMD5Hash
FROM 
  dbo.EPOEvents 
  LEFT OUTER JOIN dbo.EPExtendedEvent ON dbo.EPOEvents.AutoID = dbo.EPExtendedEvent.EventAutoID 
  LEFT OUTER JOIN dbo.EPOLeafNode ON dbo.EPOEvents.AgentGUID = dbo.EPOLeafNode.AgentGUID 
  LEFT OUTER JOIN dbo.EPOComputerProperties ON dbo.EPOLeafNode.AutoID = dbo.EPOComputerProperties.ParentID 
  LEFT OUTER JOIN dbo.JTIClientEventInfoView ON dbo.EPOEvents.AutoID = dbo.JTIClientEventInfoView.EventID 
WHERE dbo.EPOEvents.ReceivedUTC >= DATEADD(HOUR, -1, GETUTCDATE())   -- customize time interval as needed to meet your environment requirements
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
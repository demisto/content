# LenelS2 NetBox

<~XSIAM>

## Log Ingestion Configuration 
Follow the steps below to configure ingestion of LenelS2 NetBox event records into Cortex XSIAM.

### Configuration on LenelS2 NetBox

#### Create a Custom Database View 

Connect to the LenelS2 NetBox's underlying MS SQL Server database and create a custom view as described [here](https://learn.microsoft.com/en-us/sql/relational-databases/views/create-views?view=sql-server-ver16) 
  
Use the sample SQL query below as a reference for creating the custom view, and customize the *where* condition as necessary to meet your environment requirements.    
This query retrieves event records from the `s2logaccesshistory` view from within the last hour, and joins it with various additional views for enriching the returned fieldset. 


##### Custom View SQL Query Sample
```
SELECT 
 report.dttm,
 report.type,
 report.typecode,
 report.logkey,
 report.reason,
 report.reasoncode,
 report.firstname,
 report.lastname,
 report.personid,
 report.personkey,
 report.portalkey,
 report.portalname,
 report.readerkey,
 report.readername,
 report.partitionkey,
 report.readerpartitionname
FROM 
  report
WHERE report.s2logaccesshistory.dttm >= DATEADD(HOUR, -1, GETUTCDATE())   -- customize time interval as needed to meet your environment requirements
  ```

### Configuration on Cortex XSIAM 

#### Configure a Broker VM on Cortex XSIAM
If you do not yet have a Broker VM configured, follow the instructions [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Set-up-and-configure-Broker-VM). 


#### Configure a Database Collector

Activate a database collector as described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Activate-Database-Collector).

* When configuring the *Database Query* section, set the following parameters:
   | Parameter         | Value    
   | :---              | :---                    
   | `Rising Column`   | Enter *AutoID*.  
   | `Retrieval Value` | Enter *0* for initializing the first retrieval to select all records within the view's defined time interval. For example, if the view is defined to select records from within the last hour (as in the sample SQL query above), the first retrieval would include all records from within the last hour. After the first initialization retrieval, the subsequent continuous polling would select only new records added from that point forward. Alternatively, set this value to the last known *EPOEvents.AutoID* value.
   | `Unique IDs`      | Leave this parameter blank, as the *AutoID* rising column values are unique. 
   | `Collect Every`   | Select the requested polling time interval. This interval must be shorter than the time interval defined on the custom view SQL query (1 hour on the sample query above). 
   | `Vendor`          | Enter *LenelS2*. 
   | `Product`         | Enter *NetBox*. 
  
   
* Under the SQL Query editor, enter the following query, replacing <CUSTOM_VIEW_NAME> with the actual custom view name created on the LenelS2 NetBox database: 
   ```SQL
      SELECT * FROM <CUSTOM_VIEW_NAME>
      WHERE logkey > ?
      ORDER BY logkey ASC
  ```

</~XSIAM>
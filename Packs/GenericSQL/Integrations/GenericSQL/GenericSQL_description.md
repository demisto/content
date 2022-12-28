## Default ports
If the port value is empty, a default port will be selected according to the database type.
- MySQL: 3306
- PostgreSQL: 5432
- Microsoft SQL Server: 1433
- Oracle: 1521


## Connection Arguments
Specify arguments for the configuration of an instance name-value pairs, for example:
```
charset=utf8
```
Separate pairs using __&amp;__ character, for example:
```
charset=utf8&read_timeout=10
```

## Connection Pooling
By default, the integration does not pool database connections. Thus, a connection is created and closed for each command run by the integration. When connection pooling is enabled, each Docker container will maintain a single connection open for time specified in the the _Connection Pool Time to Live_ parameter (default: 600 seconds). After the time to live expires, and upon execution of a new command, the database connection will close and a new connection will be created. 

**Note**: when pooling is enabled, the number of active open database connections will equal the number of active running **demisto/genericsql** Docker containers.  

## Bind Variables 
There are two options to use to bind variables:
1. Use both bind variable names and values, for example:
    SELECT * from Table Where ID=:x" bind_variables_names=x bind_variables_values=123
2. Use only bind variable values, for example:
    INSERT into Table(ID, Name) VALUES (%s, %s)" bind_variables_values= "123, Ben”

## Fetch Incidents
There are two options to fetch incidents, determined by 'Fetch by' configuration:
1. **ID and timestamp** - when ID is unique but not necessarily ascending and timestamp is not unique.
   Fill in 'Column name for fetching' with your exact timestamp column name, and fill in 'ID column name' with your exact ID column name.
2. **Unique ascending ID or unique timestamp** - when fetching by either ID or timestamp.
   Fill only the 'Column name for fetching' with the exact column name to fetch (ID column or timestamp column).

#### Fetch events query
The Generic SQL query or procedure to fetch according to.
When using queries, only simple queries are supported, therefor, it is highly recommended to use procedures.
1. **Queries examples**: 
   Use only 'select' and 'from' keywords.
   1. Supported:
      1. select id, header_name from table_name -- ok when fetching by id and id is the exact column name.
      2. select * from table_name -- all columns, should include timestamp or id column.
   2. Unsupported:
      1. select header_name from table_name -- no select id or timestamp column, can't execute the fetch

Procedure examples for different SQL DBs:
2. **MySQL** 
    1. Example: "CREATE PROCEDURE *PROCEDURE_NAME*(IN ts DATETIME, IN l INT)
BEGIN
    SELECT * FROM TABLE_NAME
    WHERE timestamp >= ts order by timestamp asc limit l;
END"
    2. Make sure to add as parameters the fetch parameter and the limit.
    3. The procedure should contain conditions on the fetch parameter: (In the example provided, 'ts' is a fetch timestamp parameter)
       1. timestamp >= ts or timestamp > ts if timestamp is unique.
       2. order by timestamp (asc).
    4. Run ***sql-command*** with your new procedure provided in the query argument, in order to create your procedure.
    5. After creating the procedure, fill in 'Fetch events query' the value: 'call *PROCEDURE_NAME*' with your procedure name. 
    6. Fetch parameters, ts (timestamp) or id and l (limit), will be added by the fetch mechanism.
3. **MSSQL**
   1. Example: "CREATE PROCEDURE *PROCEDURE_NAME* @timestamp DATETIME
   AS
   SELECT * FROM TABLE_NAME WHERE timestamp >= @timestamp order by timestamp"
   2. Make sure to add as parameters the fetch parameter.
   3. The procedure should contain conditions on the fetch parameter: (In the example provided, 'timestamp' is a fetch parameter)
      1. timestamp >= @timestamp or timestamp > @timestamp if timestamp is unique.
      2. order by timestamp (asc).
   4. The fetch parameter should be the same as the column name, the limit is handled outside the query.
   5. Run ***sql-command*** with your new procedure provided in the query argument, in order to create your procedure.
   6. After creating the procedure, fill in 'Fetch events query' the value: 'EXEC *PROCEDURE_NAME*' with your procedure name.
   7. Fetch parameters, ts (timestamp) or id and l (limit), will be added by the fetch mechanism.
3. Others SQL DBs are not supported by the fetch incidents currently.

**Fetch Incidents query Notes**
1. When 'Fetch by' is 'Unique sequence ID or unique timestamp', make sure to create the procedure with '>' and not '>=' in the condition on the timestamp field.
2. When 'Fetch by' is 'ID and timestamp', handling the ID occurs internally and has no reference in the query.

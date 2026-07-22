## Default ports

If the port value is empty, a default port will be selected according to the database type.

- MySQL: 3306
- PostgreSQL: 5432
- Microsoft SQL Server: 1433
- Oracle: 1521
- Trino: 8080
- Teradata: 1025

## Connection Arguments

Specify arguments for the configuration of an instance name-value pairs, for example:

```charset=utf8```

Separate pairs using __&amp;__ character, for example:

```charset=utf8&read_timeout=10```

## Connection Pooling

By default, the integration does not pool database connections. Thus, a connection is created and closed for each command run by the integration. When connection pooling is enabled, each Docker container will maintain a single connection open for the time specified in the the _Connection Pool Time to Live_ parameter (default: 600 seconds). After the time to live expires, and upon execution of a new command, the database connection will close and a new connection will be created.

__Note__: When pooling is enabled, the number of active open database connections will equal the number of active running __demisto/genericsql__ Docker containers.  

## Bind Variables

There are two options to use to bind variables:

1. Use both bind variable names and values, for example:
    SELECT * from Table Where ID=:x" bind_variables_names=x bind_variables_values=123
2. Use only bind variable values, for example:
    INSERT into Table(ID, Name) VALUES (%s, %s)" bind_variables_values= "123, Ben”

## Fetch Incidents

There are two options to fetch incidents, determined by the 'Fetch by' configuration:

- __ID and timestamp__ - When the ID is unique but not necessarily ascending and timestamp is not unique.

   Fill in 'Fetch Column' with your exact timestamp column name, and fill in the 'ID column name' with your exact ID column name.
- __Unique ascending ID or Unique timestamp__ - When fetching by either ID or timestamp.

   Fill only the 'Fetch Column' with the exact column name to fetch (ID column or timestamp column).

### Fetch events query

The Generic SQL query or procedure to fetch according to.
When using queries, there are two requirements, and the third one depends on the database.

   1. 'fetch column' > or >= :'fetch column'
   2. Order by (asc) 'fetch column'
   3. (Optional) limit :limit (It's possible if the database supports it)

#### Queries examples

- Supported:
    1. Select ID, header_name from table_name where id >:id order by id -- ok when fetching by ID and ID is the exact fetch column.
    2. Select * from table_name where timestamp >=:timestamp order by timestamp limit :limit -- ok when fetching by timestamp and timestamp is the exact fetch column and database supports for limit.
- Unsupported:
    1. Select header_name from table_name -- no select ID or timestamp column, can't execute the fetch.
    2. Select alert_id from table_name -- missing condition 'where alert_id >:alert_id order by alert_id', can't execute the fetch.

The following are procedure examples for different SQL databases:

##### MySQL

Example: "CREATE PROCEDURE _PROCEDURE_NAME_(IN ts DATETIME, IN l INT)
BEGIN
    SELECT * FROM TABLE_NAME
    WHERE timestamp >= ts order by timestamp asc limit l;
END"

1. Make sure to add as parameters the fetch parameter and the limit.
2. The procedure should contain conditions on the fetch parameter: (In the example provided, 'ts' is a fetch timestamp parameter)
    - timestamp >= ts or timestamp > ts if timestamp is unique.
    - order by timestamp (asc).
3. Run ___sql-command___ with your new procedure provided in the query argument in order to create your procedure.
4. After creating the procedure, fill in 'Fetch events query' the value: 'call _PROCEDURE_NAME_' with your procedure name.
5. Fetch parameters, ts (timestamp) or ID and l (limit), will be added by the fetch mechanism.

##### MSSQL

Example: "CREATE PROCEDURE _PROCEDURE_NAME_ @timestamp DATETIME
   AS
   SELECT * FROM TABLE_NAME WHERE timestamp >= @timestamp order by timestamp"

1. Make sure to add as parameters the fetch parameter.
2. The procedure should contain conditions on the fetch parameter: (In the example provided, 'timestamp' is a fetch parameter)
    - timestamp >= @timestamp or timestamp > @timestamp if timestamp is unique.
    - order by timestamp (asc).
3. The fetch parameter should be the same as the column name, the limit is handled outside the query.
4. Run ___sql-command___ with your new procedure provided in the query argument, in order to create your procedure.
5. After creating the procedure, fill in 'Fetch events query' the value: 'EXEC _PROCEDURE_NAME_' with your procedure name.
6. Fetch parameters, ts (timestamp) or id and l (limit), will be added by the fetch mechanism.

Note: Other SQL databases are currently not supported by the fetch incidents.

##### Fetch Incidents query Notes

1. When 'Fetch by' is 'Unique ascending ID' or 'Unique timestamp', make sure to create the procedure with '>' and not '>=' in the condition on the timestamp/id field.
2. When 'Fetch by' is 'ID and timestamp', handling the ID occurs internally and has no reference in the query.

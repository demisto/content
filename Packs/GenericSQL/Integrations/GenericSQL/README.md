Generic SQL integration for the Databases: MySQL, PostgreSQL, Microsoft SQL Server and Oracle.

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
    3. The procedure should contain conditions on the fetch parameter. In the example provided, 'ts' is a fetch timestamp parameter.
    4. Run ***sql-command*** with your new procedure provided in the query argument, in order to create your procedure.
    5. After creating the procedure, fill in 'Fetch events query' the value: 'call *PROCEDURE_NAME*' with your procedure name. 
    6. Fetch parameters, ts (timestamp) or id and l (limit), will be added by the fetch mechanism.
3. **MSSQL**
   1. Example: "CREATE PROCEDURE *PROCEDURE_NAME* @timestamp DATETIME
   AS
   SELECT * FROM TABLE_NAME WHERE timestamp >= @timestamp order by timestamp"
   2. Make sure to add as parameters the fetch parameter.
   3. The procedure should contain conditions on the fetch parameter. In the example provided, 'timestamp' is a fetch parameter.
   4. The fetch parameter should be the same as the column name, the limit is handled outside the query.
   5. Run ***sql-command*** with your new procedure provided in the query argument, in order to create your procedure.
   6. After creating the procedure, fill in 'Fetch events query' the value: 'EXEC *PROCEDURE_NAME*' with your procedure name.
   7. Fetch parameters, ts (timestamp) or id and l (limit), will be added by the fetch mechanism.
3. Others SQL DBs are not supported by the fetch incidents currently.

**Fetch Incidents query Notes**
1. When 'Fetch by' is 'Unique sequence ID or unique timestamp', make sure to create the procedure with '>' and not '>=' in the condition on the timestamp field.
2. When 'Fetch by' is 'ID and timestamp', handling the ID occurs internally and has no reference in the query.


#### Fetch events query
The Generic SQL query/procedure.
Only simple queries are supported, which means 'select * from table_name'.
It's highly recommended to use procedures.
Procedures (examples):
1. MySQL - "CREATE PROCEDURE *PROCEDURE_NAME*(
    IN ts DATETIME, IN l INT
)
BEGIN
    SELECT * 
     FROM TABLE_NAME
    WHERE timestamp >= ts order by timestamp asc limit l;
END"
   (Notes: The procedure should contain conditions on the fetch parameter, ts here is the dynamic parameter for the fetch cycles.
When using MySQL DB, the procedure should contain also the limit inside.
After creating the procedure, we'll execute this query like this: 'call Procedure_name', 
when both parameters, ts or id and l-limit, will be added by the fetch)
2. MSSQL - "CREATE PROCEDURE *PROCEDURE_NAME* @timestamp DATETIME
AS
SELECT * FROM TABLE_NAME WHERE timestamp >= @timestamp order by timestamp"
   (Notes: The procedure should contain conditions on the fetch parameter, timestamp here is the dynamic parameter for the fetch cycles.
When using MSSQL DB: the parameter name should be the same as the column name,
the limit is handled outside the query.
After creating the procedure, we'll execute this query like this: 'EXEC Procedure_name', 
when both parameters, timestamp or id and l-limit, will be added by the fetch)
3. When 'Fetch parameters' == ID and timestamp, The handling of the ID occurs internally and has no reference in the query.
4. When 'Fetch parameters' == Unique sequence ID or unique timestamp, create the procedure with '>' and not '>=' 

## Configure Generic SQL on Cortex XSOAR

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Generic SQL.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __SQL DB__
    * __Database host__
    * __Port__
    * __Database Name__
    * __Username__
    * __Connection Arguments (ex: arg1=val1&arg2=val2)__
4. Click __Test__ to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
The two commands are the same, they can get the same arguments and will provide the same outputs.
1. query
2. sql-command

### 1. query
Running a sql query

##### Required Permissions
Permissions to the database are needed

##### Base Command

`query`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Number of results you would like to get back | Optional | 
| query | The sql query | Required | 
| skip | Number of results you would like to skip on | Optional | 
| bind_variables_names | e.g: "foo","bar","alpha" | Optional | 
| bind_variables_values | e.g: 7,"foo",3 | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!query query="select * from TestTable" limit=10 skip=0```

##### Context Example
```
{
    "GenericSQL": {
        "GenericSQL": {
            "Query": "select * from TestTable", 
            "Headers": ["LastName", "ID", "FirstName"],
            "InstanceName": "MySQL_new_schema", 
            "Result": [
                {
                    "LastName": "Grace", 
                    "ID": 22222, 
                    "FirstName": "Bob"
                }, 
                {
                    "LastName": "Jacob", 
                    "ID": 33333, 
                    "FirstName": "Liya"
                }, 
                {
                    "LastName": "James", 
                    "ID": 44444, 
                    "FirstName": "Chris"
                }, 
                {
                    "LastName": "Zohar", 
                    "ID": 55555, 
                    "FirstName": "Tamar"
                }
            ]
        }
    }
}
```

##### Human Readable Output
> ### Query result:
> |ID|LastName|FirstName|
> |---|---|---|
> | 22222 | Grace | Bob |
> | 33333 | Jacob | Liya |
> | 44444 | James | Chris |
> | 55555 | Zohar | Tamar |

##### Command Example
```!query query="INSERT into TestTable(ID, LastName, FirstName) VALUES (11111, :x , :y)" bind_variables_names=x,y bind_variables_values="test,playbook"```

##### Context Example
```
{}
```

##### Human Readable Output
Command executed

##### Command Example
```!query query="delete from TestTable where ID=11111"```

##### Context Example
```
{}
```

##### Human Readable Output
Command executed

### 2. sql-command
---
Running a sql query

##### Base Command

`sql-command`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Number of results you would like to get back | Optional | 
| query | The sql query | Required | 
| skip | Number of results you would like to skip on | Optional | 
| bind_variables_names | e.g: "foo","bar","alpha" | Optional | 
| bind_variables_values | e.g: 7,"foo",3 | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!sql-command query="select * from TestTable" limit=10 skip=0```

##### Context Example
```
{
    "GenericSQL": {
        "GenericSQL": {
            "Query": "select * from TestTable", 
            "Headers": ["LastName", "ID", "FirstName"],
            "InstanceName": "MySQL_new_schema", 
            "Result": [
                {
                    "LastName": "Grace", 
                    "ID": 22222, 
                    "FirstName": "Bob"
                }, 
                {
                    "LastName": "Jacob", 
                    "ID": 33333, 
                    "FirstName": "Liya"
                }, 
                {
                    "LastName": "James", 
                    "ID": 44444, 
                    "FirstName": "Chris"
                }, 
                {
                    "LastName": "Zohar", 
                    "ID": 55555, 
                    "FirstName": "Tamar"
                }
            ]
        }
    }
}
```

##### Human Readable Output
> ### Query result:
> |ID|LastName|FirstName|
> |---|---|---|
> | 22222 | Grace | Bob |
> | 33333 | Jacob | Liya |
> | 44444 | James | Chris |
> | 55555 | Zohar | Tamar |

##### Command Example
```!sql-command query="INSERT into TestTable(ID, LastName, FirstName) VALUES (11111, :x , :y)" bind_variables_names=x,y bind_variables_values="test,playbook"```

##### Context Example
```
{}
```

##### Human Readable Output
Command executed

##### Command Example
```!sql-command query="delete from TestTable where ID=11111"```

##### Context Example
```
{}
```

##### Human Readable Output
Command executed

## Troubleshooting

### General Test Connection Error
In cases where you receive an error that is not clear when you **Test** the integration instance you can get detailed logs.
1. Save the configured instance even though the **Test** doesn't work.
2. In the playground, run the `!sql-command` with `debug-mode=true`. For example:
  ```
  !sql-command query="some simple query" debug-mode=true
  ```
A log file will be generated in the Playground. Examine the log file for further details that explain why the integration is failing.

### Microsoft SQL Server
We provide two options for connecting to Microsoft SQL Server:
* **Microsoft SQL Server**: Uses the open source FreeTDS driver to communicate with Microsoft SQL Server. This driver supports authentication via domain logins (`DOMAIN\username`) with a password. If you do not require a domain login for authentication, we recommend using the `Microsoft SQL Server - MS ODBC Driver`.
* **Microsoft SQL Server - MS ODBC Driver**: Official driver from Microsoft for Linux.

**Note:** Kerberos authentication is not supported.

If you experience any issues communicating with your Microsoft SQL Sever, try using both options as we've seen cases where one option works while the other doesn't.


When configuring *SQL Server*, if you receive an error of the form:
```
('08S01', '[08S01] [FreeTDS][SQL Server]Unable to connect: Adaptive Server is unavailable or does not exist (20009) (SQLDriverConnect)')
(Background on this error at: http://sqlalche.me/e/13/e3q8) 
``` 
It means there is a communication problem from the Generic SQL docker to the SQL Server. It usually means the dns hostname of the sql server is not resolving. You can try using an IP instead of the DNS. You can further test the from docker by running the following command on the Cortex XSOAR machine: 
```
echo "select @@version" | sudo docker run --rm -i  demisto/genericsql:1.1.0.9726 tsql -H <sql_server_host> -p <sql_port_number> -U <user> -P <password> -D <db_to_connect> -v -o v
```

**Autocommit**: If you are seeing that insert/update operations are NOT being performed and no error is received, it could be a case that autocommit is not enabled on the connection and the transacation is rolledback. To enable autocommit, add the following to the connection arguments instance configuration option:
```
autocommit=True
```

### Oracle
If you require connecting to Oracle via a **SERVICE_NAME**, leave the `Database Name` parameter empty and add to the `Connection Arguments` the following:
```
service_name=<SERVICE_NAME>
```
For example:
```
service_name=XEXDB
```

## Possible Errors:
* The bind variables lists are not is the same length
* Command is not an existing Generic SQL command

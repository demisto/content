Generic SQL integration for the Databases: MySQL, PostgreSQL, Microsoft SQL Server, Oracle, Teradata and Trino.

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

```
charset=utf8
```

Separate pairs using __&amp;__ character, for example:

```
charset=utf8&read_timeout=10
```

## Connection Pooling

By default, the integration does not pool database connections. Thus, a connection is created and closed for each command run by the integration. When connection pooling is enabled, each Docker container will maintain a single connection open for the time specified in the the _Connection Pool Time to Live_ parameter (default: 600 seconds). After the time to live expires, and upon execution of a new command, the database connection will close and a new connection will be created.

__Note__: When pooling is enabled, the number of active open database connections will equal the number of active running __demisto/genericsql__ Docker containers.  

## Bind Variables

There are two options to use to bind variables:

- Use both bind variable names and values, for example:
    SELECT * from Table Where ID=:x" bind_variables_names=x bind_variables_values=123
- Use only bind variable values, for example:
    INSERT into Table(ID, Name) VALUES (%s, %s)" bind_variables_values= "123, Ben”

## Fetch Incidents

There are two options to fetch incidents, determined by 'Fetch by' configuration:

- __ID and timestamp__ - when ID is unique but not necessarily ascending and timestamp is not unique.

   Fill in 'Fetch Column' with your exact timestamp column name, and fill in 'ID column name' with your exact ID column name.
- __Unique ascending ID or Unique timestamp__ - when fetching by either ID or timestamp.

   Fill only the 'Fetch Column' with the exact column name to fetch (ID column or timestamp column).

### Fetch events query

The Generic SQL query or procedure to fetch according to.
When using queries, there are two requirements, and the third one depends on the database.

   1. 'fetch column' > or >= :'fetch column'
   2. order by (asc) 'fetch column'
   3. (Optional) limit :limit (It's possible if the DB supports it)

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

## Configure Generic SQL on Cortex XSOAR

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Generic SQL.
3. Click __Add instance__ to create and configure a new integration instance.
    - __Name__: a textual name for the integration instance.
    - __SQL DB__
    - __Database host__
    - __Port__
    - __Database Name__
    - __Username__
    - __Connection Arguments (ex: arg1=val1&arg2=val2)__
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

| __Argument Name__ | __Description__ | __Required__ |
| --- | --- | --- |
| limit | Number of results you would like to get back | Optional |
| query | The SQL query | Required |
| skip | Number of results you would like to skip on | Optional |
| bind_variables_names | e.g.: "foo","bar","alpha" | Optional |
| bind_variables_values | e.g.: 7,"foo",3 | Optional |

##### Context Output

There is no context output for this command.

##### Command Example

```!query query="select * from TestTable" limit=10 skip=0```

##### Context Example

```json
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
>
> ### Query result
>
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

| __Argument Name__ | __Description__ | __Required__ |
| --- | --- | --- |
| limit | Number of results you would like to get back | Optional |
| query | The SQL query | Required |
| skip | Number of results you would like to skip on | Optional |
| bind_variables_names | e.g.: "foo","bar","alpha" | Optional |
| bind_variables_values | e.g.: 7,"foo",3 | Optional |

##### Context Output

There is no context output for this command.

##### Command Example

```!sql-command query="select * from TestTable" limit=10 skip=0```

##### Context Example

```json
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
>
> ### Query result
>
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

In cases where you receive an error that is not clear when you __Test__ the integration instance you can get detailed logs.

1. Save the configured instance even though the __Test__ doesn't work.
2. In the playground, run the `!sql-command` with `debug-mode=true`. For example:

  ```
  !sql-command query="some simple query" debug-mode=true
  ```

A log file will be generated in the Playground. Examine the log file for further details that explain why the integration is failing.

### Microsoft SQL Server

We provide two options for connecting to Microsoft SQL Server:

- __Microsoft SQL Server__: Uses the open source FreeTDS driver to communicate with Microsoft SQL Server. This driver supports authentication via domain logins (`DOMAIN\username`) with a password. If you do not require a domain login for authentication, we recommend using the `Microsoft SQL Server - MS ODBC Driver`.
- __Microsoft SQL Server - MS ODBC Driver__: Official driver from Microsoft for Linux.

__Note:__ Kerberos authentication is not supported.

If you experience any issues communicating with your Microsoft SQL Sever, try using both options as we've seen cases where one option works while the other doesn't.

When configuring _SQL Server_, if you receive an error of the form:

```
('08S01', '[08S01] [FreeTDS][SQL Server]Unable to connect: Adaptive Server is unavailable or does not exist (20009) (SQLDriverConnect)')
(Background on this error at: http://sqlalche.me/e/13/e3q8) 
```

It means there is a communication problem from the Generic SQL Docker to the SQL Server. It usually means the dns hostname of the SQL Server is not resolving. You can try using an IP instead of the DNS. You can further test from Docker by running the following command on the Cortex XSOAR machine:

```
echo "select @@version" | sudo docker run --rm -i  demisto/genericsql:1.1.0.9726 tsql -H <sql_server_host> -p <sql_port_number> -U <user> -P <password> -D <db_to_connect> -v -o v
```

__Autocommit__: If you are seeing that insert/update operations are NOT being performed and no error is received, it could be a case that autocommit is not enabled on the connection and the transaction is rolledback. To enable autocommit, add the following to the connection arguments instance configuration option:

```
autocommit=True
```

### Oracle

If you require connecting to Oracle via a __SERVICE_NAME__, leave the `Database Name` parameter empty and add to the `Connection Arguments` the following:

```
service_name=<SERVICE_NAME>
```

For example:

```
service_name=XEXDB
```

## Possible Errors

- The bind variables lists are not the same length.
- Command is not an existing Generic SQL command.

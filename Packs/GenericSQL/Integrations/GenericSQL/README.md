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

## Configure Generic SQL on Demisto

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
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
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
```!query query="INSERT into TestTable(ID, LastName, FirstName) VALUES (11211, :x , :y)" bind_variables_names=x,y bind_variables_values="test,playbook"```

##### Context Example
```
{}
```

##### Human Readable Output
Command executed

##### Command Example
```!query query="delete from TestTable where ID=11211"```

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
```!sql-command query="INSERT into TestTable(ID, LastName, FirstName) VALUES (11211, :x , :y)" bind_variables_names=x,y bind_variables_values="test,playbook"```

##### Context Example
```
{}
```

##### Human Readable Output
Command executed

##### Command Example
```!sql-command query="delete from TestTable where ID=11211"```

##### Context Example
```
{}
```

##### Human Readable Output
Command executed


## Possible Errors:
* The bind variables lists are not is the same length
* command is not an existing Generic SQL command'

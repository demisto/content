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

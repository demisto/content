## Default ports
If the port value is empty, a default port will be selected according to the database type.
MySQL: 3306
PostgreSQL: 5432
Microsoft SQL Server: 1433
Oracle: 1521


## Connection Arguments
When choosing the configuration of an instance, for example:
charset=utf8


## Bind Variables 
There are two options to use to bind variables:
1. Use both bind variable names and values, for example:
    SELECT * from Table Where ID=:x" bind_variables_names=x bind_variables_values=123
2. Use only bind variable values, for example:
    INSERT into Table(ID, Name) VALUES (%s, %s)" bind_variables_values= "123, Ben”

## Generic SQL
Support the databases - mysql, PostgreSQL, Microsoft SQL and Oracle.

### Default ports
In case the port value is empty a default port wiil be chosen according to the database type:
MySQL - port 3306
PostgreSQL - port 5432
Microsoft SQL Server - port 1433
Oracle - port 1521


### Connection Arguments
When choosing the configuration of an instance, e.g:
charset=utf8


##Bind Variables 
There are 2 options to use bind variables:
1. Use both bind variables names and values, e.g.:
    SELECT * from Table Where ID=:x" bind_variables_names=x bind_variables_values=123
2. Use only bind variables values, e.g.:
    INSERT into Table(ID, Name) VALUES (%s, %s)" bind_variables_values= "123, Ben”

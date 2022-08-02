## DB2 Integration
This integration helps in executing raw queries with the help of command `query` parameter.

## Default Port
If the `port` value is empty, a default port `50000` will be used.

## Connection Arguments
Specify arguments for the configuration of an instance name-value pairs, for example:

```
ATTR_CASE=CASE_NATURAL&SQL_ATTR_CURSOR_TYPE=SQL_CURSOR_FORWARD_ONLY
```

## Bind Variables 
There are two options to use to bind variables:

1. Use both bind variable names and values, for example:
```
"SELECT * from Table Where ID=:x" bind_variables_names="x" bind_variables_values="123"
```
2. Use only bind variable values, for example:
```
"INSERT into Table(ID, Name) VALUES (?, ?)" bind_variables_values= "123, Ben”
```

**Note:** Make sure only values are used as in `bind_variables_name` and `bind_variables_values`, not the table column name.
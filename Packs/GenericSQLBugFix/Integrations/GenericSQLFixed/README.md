Use the Generic SQL integration to run SQL queries on the following databases: MySQL, PostgreSQL, Microsoft SQL Server, and Oracle.
This integration was integrated and tested with version xx of Generic SQL_fixed
## Configure Generic SQL_fixed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Generic SQL_fixed.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | SQL DB |  | True |
    | Database host |  | True |
    | Port |  | False |
    | Database Name |  | False |
    | Username |  | True |
    | Connection Arguments (ex: arg1=val1&amp;arg2=val2) |  | False |
    | Use an SSL connection |  | False |
    | Use Connection Pooling |  | False |
    | Connection Pool Time to Live (seconds) | After this time the connection pool will be refreshed | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### sql-command
***
Running a sql query


#### Base Command

`sql-command`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The SQL query to run. | Required | 
| limit | The maximum number of results to return. Default is 50. | Optional | 
| skip | The offset at which to start the results. The default is 0. Default is 0. | Optional | 
| bind_variables_names | A comma-separated list of names, for example: "foo","bar","alpha". | Optional | 
| bind_variables_values | A comma-separated list of value, for example: 7,"foo",3. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



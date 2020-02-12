 # Integration Instructions

## Overview

An integration to run Oracle Database Queries. You can use this integration with Oracle 11.2, 12, 18 and 19 Executing both SQL and PL/SQL statements.

The integration does use Oracle's Easy Connect Syntax for the Connection String. For more information:

https://www.oracle.com/technetwork/database/enterprise-edition/oraclenetservices-neteasyconnect-133058.pdf
## Use Cases:

* Query an Oracle for Incident Response Investigation


## Configure Oracle on Demisto

1. Go to __Settings__ > __Integrations__ > __Servers & Services__ 

2. Locate __Oracle Database__ by searching for it using the search box on the top of the page.

3. Click __Add instance__ to create and configure a new integration. You should configure the following settings:

__Database Server__:
This is the server address of the Oracle Database Server (The host on which the the database service is hosted): `dbhost.example.com` as an example.

__Username and Password__:
The credentials entered here are used to run SQL queries against the Oracle Database based on the granted role and schema, granted to these credentials.
You can check your assigned roles and priviliges by running this query from the Demisto Console:

`!oracle-query query="SELECT * FROM USER_ROLE_PRIVS" limit="10"` , below is an example output:

**Oracle DB - Results for the Search Query**

|       |  |
| ----------- | ----------- |
| ADMIN_OPTION      | NO       |
| COMMON   | NO        |
| DEFAULT_ROLE      | YES       |
| DELEGATE_OPTION   | NO        |
| GRANTED_ROLE      | RESOURCE       |
| INHERITED   | NO        |
| OS_GRANTED      | NO       |
| USERNAME   | HR        |
|  |  |

`!oracle-query query="SELECT * FROM USER_ROLE_PRIVS" limit="10"` , below is an example output:

**Oracle DB - Results for the Search Query**

| ADMIN_OPTION | COMMON | INHERITED | PRIVILEGE | USERNAME |
| ----------- | ----------- | ----------- | ----------- | ----------- |
| NO |	NO | NO | UNLIMITED TABLESPACE | HR |
| NO |	NO | NO | ALTER SESSION	| HR |
| NO |	NO | NO | CREATE SESSION	| HR |
| NO |	NO | NO | CREATE SYNONYM	| HR |
| NO |	NO | NO | CREATE DATABASE LINK	| HR |
| NO |	NO | NO | CREATE SEQUENCE	| HR |
| NO |	NO | NO | CREATE VIEW	| HR |

__Service Name__:  
A service name is a feature in which a database can register itself with the listener. The Easy Connect syntax used by this integration supports Oracle Database service names. It cannot be used with the older System Identifiers (SID). 


__Port Number__:
Port 1521 is used if no port number is specified in the connection string.

##Commands

You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. oracle-query-json
2. oracle-query
###1. oracle-query
####Input

| **Argument**|**Description** |
| :------:|:------:|
| query |	The SQL Query , Example: "select *  from HR.EMPLOYEES |
| limit |	A limit for the returned number of rows, if default it's 10 and the max is 15, we don't think you need more than that for an investigation use case |

#####Context Output
| **Path** |**Type**  | **Description**  |
| :------:|:------:|:------:|
| Oracle.Query | String | The query output, each row is an output dictionary |

###2. oracle-query-json
####Input
| **Argument** |**Description**  |
| :------:|:------:|
| query |	The SQL Query with the JSON_OBJECT Oracle Function, Example "select JSON_OBJECT('ID' is EMPLOYEE_ID , 'FirstName' is FIRST_NAME,'LastName' is LAST_NAME) from HR.EMPLOYEES" |
| limit |	A limit for the returned number of rows, if default it's 10 and the max is 15, we don't think you need more than that for an investigation use case |

#####Context Output
| **Path|Type**  | **Description**  |
| :------:|:------:|:------:|
| Oracle.Query | String | The query output, each row is an output dictionary |

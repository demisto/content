### Successfully searched provided values in the test_data_table data table
|Value|Found In Columns|Not Found In Columns|Overall Status|
|---|---|---|---|
| 1 | column_1 | column_2 | Found |
| 20 |  | column_1, column_2 | Not Found |
| ^\[a\-zA\-Z\]\+$ | column_2 | column_1 | Found |
| 3 | column_1 | column_2 | Found |

The command can search the up to 1000 rows in single execution. To search the next set of data table rows, execute the command with the page token as `dummy_page_token`
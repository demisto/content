## [Unreleased]
Fixed an issue in which the **ServiceNow ticket column to be set as the incident name** parameter was not initialized with the default value as expected.

## [20.5.2] - 2020-05-26
  - Fixed the timestamp field parameter description.
  - Added the *incident_name* parameter, to allow the user to choose the column from ServiceNow on which the fetched incidents will be named.
  - Fixed an issue where system proxy settings were always being used.
  - Fixed an issue where ***fetch-incidents*** command with attachments did not work as expected.


## [20.5.0] - 2020-05-12
  - Added 5 commands:
    - ***servicenow-query-items***
    - ***servicenow-get-item-details***
    - ***servicenow-create-item-order***
    - ***servicenow-add-tag***
    - ***servicenow-document-route-to-queue***
  - Improved documentation regarding the usage of the ***impact*** and the ***urgency*** arguments for the commands:
    - ***servicenow-update-ticket***
    - ***servicenow-create-ticket***
  - Added the *system_params* argument to the ***servicenow-query-table***, ***servicenow-query-tickets*** commands.

## [20.4.1] - 2020-04-29
  - Added the *additional_fields* argument to the following commands:
    - ***servicenow-get-ticket***
    - ***servicenow-update-ticket***
    - ***servicenow-create-ticket***
    - ***servicenow-query-tickets***
  - Added support for the *sc_req_item* table in the get, create, update, and delete ticket commands.
  - Added the *approval* argument for the create and update ticket commands.
  - Added the *custom_field* argument to the ***servicenow-get-ticket*** command.
  - Disabled auto-extract for War Room entries of the CRUD tickets and records commands.

## [Unreleased]
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
  - Disabled auto-extract for war-room entries of the CRUD tickets and records commands.

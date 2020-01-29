## [Unreleased]


## [20.1.2] - 2020-01-22
Fixed an issue where trying to download a filter-pcap with the necessary arguments did not return the correct results.

## [20.1.0] - 2020-01-07
  - Fixed an issue when trying to download a threat-pcap without the necessary arguments.
  - Improved the error message when trying to download PCAPs from a Panorama instance.
  - Fixed an issue in the ***panorama-list-pcaps*** command when there are no PCAPs in PAN-OS.
  - You can now specify multiple values (list) for the *source*, *destination*, and *application* arguments in the following commands. 
    - ***panorama-create-rule***
    - ***panorama-custom-block-rule***
    - ***panorama-edit-rule***
  - Added 4 commands.
    - ***panorama-list-static-routes***
    - ***panorama-get-static-route***
    - ***panorama-add-static-route***
    - ***panorama-delete-static-route***

## [19.12.0] - 2019-12-10
  - Fixed an issue where the status log queries that returned zero results did not update to *Completed*.
  - Added 2 commands.
    - ***panorama-get-url-category-from-cloud***
    - ***panorama-get-url-category-from-host***
  - Added support to get, create, and edit custom URL category objects, including using the categories attribute in PAN-OS v9.x and above.


## [19.11.1] - 2019-11-26
  - Added support for a list of *job_id* in the ***panorama-query-logs*** and ***panorama-check-logs-status*** commands.
  - Added the *ip* argument in the ***panorama-query-logs*** command.


## [19.11.0] - 2019-11-12
  - Fixed an issue where the ***panorama-custom-block-rule*** failed when trying to block an EDL or an address group object.
  - Changed the *url* argument from equals to contains in the ***panorama-log-query*** command.
  - Improved descriptions in the ***panorama-move-rule*** command.

## [19.10.2] - 2019-10-29
Added the ***panorama-security-policy-match*** command.

## [19.9.1] - 2019-09-18
- Added the *tag* argument to several commands.
    - List commands - filter by a tag.
    - Create and edit commands
    - Added the context output Tags to all list, create, edit, and get commands.
  - Added support in the ***panorama-query-logs*** command to supply a list of arguments, which are separated using the "OR" operator.
  - Improved error messaging when trying to configure a *device-group* that does not exist.
  
## [19.9.0] - 2019-09-04
  - Added 3 commands.
    - ***panorama-query-logs***
    - ***panorama-check-logs-status***
    - ***panorama-get-logs***
  - Added the **Panorama Query Logs** playbook.
  - Added *log-forwarding* as an option for the *element_to_change* argument in the ***panorama-edit-rule*** command.
  - Added support for Shared objects and Rules in Panorama instances.
  - Added the device-group argument to all relevant commands.
  

## [19.8.2] - 2019-08-22
  - Improved error handling in cases of trying to refresh an EDL object on a Panorama instance.

## [19.8.0] - 2019-08-06
  - Improved error handling for URL filtering licensing.
  - Improved error handling when trying to edit an uncommitted Custom URL category.
  - Added the ***panorama-list-rules*** command.
  - Added *edl* as an option for the *object_type* argument in the ***panorama-custom-block-rule*** command.

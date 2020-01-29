## [Unreleased]


## [19.11.0] - 2019-11-12
Bug fixes for uptycs-set-asset-tag command and addition of ancestor list to process parent-child lineage functionality. 
 - Fixed an issue where users could not set an asset tag with a key that already exists by adding a new column, ancestor_list, to the process_events table in osquery.  This simplifies computing of the parent-child lineage of processes.

## [19.8.0] - 2019-08-06
#### New Integration
Use the Uptycs integration to fetch data from the Uptycs database.

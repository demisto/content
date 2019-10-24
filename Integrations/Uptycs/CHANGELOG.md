## [Unreleased]
#### Bug fixes for uptycs-set-asset-tag command and addition of ancestor list to process parent-child lineage functionality. 
There was an issue where the user could not set an asset tag with a key that already exists.  This has been corrected.  A new column, ancestor_list, has been added to process_events table in osquery.  This make parent-child lineage of processes easier to compute.  This functionality is now available.

## [19.8.0] - 2019-08-06
#### New Integration
Use the Uptycs integration to fetch data from the Uptycs database.

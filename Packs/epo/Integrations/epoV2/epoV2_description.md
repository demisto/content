#### *McAfee ePO Integration v2*
This integration was integrated and tested with McAfee ePO v5.3.2 and v5.10.0 .

## Permissions
McAfee ePO has a highly flexible and powerful permissions system. The permissions required for the user that uses this integration depend on which operations they need to perform. The API user should have the same permissions a regular user would have in order to access the data via the UI. It is possible to view the exact permissions needed for a specific command by running the `!epo-help` command. The `!epo-help` command's output will include help information for the specific command including required permissions. 
More info about McAfee ePO's permissions model is available [here](https://docs.mcafee.com/bundle/epolicy-orchestrator-5.10.0-product-guide/page/GUID-1AEFA219-0726-4090-A8C2-BCAA1CAA7B37.html).

Example `!epo-help` outputs with permission information: 
* `!epo-help command="repository.findPackages"`:
![](../../doc_files/epo-help-find-pkg.png)
* `!epo-help command="repository.deletePackage"`:
![](../../doc_files/epo-help-delete-pkg.png)
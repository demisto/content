In a Multi-Tenant environment, the main account collects data from each host. Using this pack, the data is displayed in the pack's dashboards.

If you are using a none default partition in your hosts and wish to monitor it using this pack, you will need to add the following configuration:
| Key | Value |
| --- | --- |
| server.disk.partition | Path and name of the partition. |

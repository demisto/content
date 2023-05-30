# XSOAR EDL Checker

This integration checks an external dynamic list provided by the [XSOAR Generic Indicators Export Service](https://xsoar.pan.dev/docs/reference/integrations/edl), to validate it is responding as required.

Only supports lists hosted off the XSOAR server, and requires the following server configuration be set from Settings -> About -> Troubleshooting

instance.execute.external = true 

## Setup

Configure an instance and provide the name of the instance name from the XSOAR Generic Indicators Export Service.

If you configured the integration instance to support basic auth, provide or select the credentials to be used.

## Using it

Run the **xsoaredlchecker-get-edl** command from the command line or playbook to check the EDLs.   

This will check all instances, then you can do some magic in the playbook to see if anything isn't OK and notify!
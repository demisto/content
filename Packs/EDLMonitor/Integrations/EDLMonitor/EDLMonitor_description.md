## EDL logger
-BE SURE to set the integration to "fetch" to allow it to monitor the EDLs in the background
-EDLs will be emailed to the user emailTo provided to log the current content of the EDL at the incidentFetchInterval configured
-While the EDL contents are timestamped and attached in zip files, due to the nature of the files, zipping will likely not save much space

Note: If you are a hosted customer, you may need to set the below server config:
instance.execute.external = true [Reference](https://xsoar.pan.dev/docs/reference/integrations/edl)
and configure the EDL to the below format:
{base_url}/instance/execute/{edl_name}

This is only tested with Gmail using smtp.gmail.com as the server, and you will need to enable 2FA for your google account and create an app password as the regular credentials will no longer work due to new Google security settings.  See https://support.google.com/accounts/answer/185833?hl=en&authuser=2 for details
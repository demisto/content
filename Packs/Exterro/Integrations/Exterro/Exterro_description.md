To use the Exterro FTK integration, configure the domain or the IP address of the FTKC instance and the EnterpriseApiKey. To get the EnterpriseApiKey, follow these steps:
1. Open the FTKC UI
2. Log in to the FTKC
3. Go to "http(s): //< ftkc-instance-ip >: < port >/api/security/1000/getenterpriseapiguid" (specify FTKC IP and port), which returns an XML like TOKEN_STRING, where in place of TOKEN_STRING is your EnterpriseAPIKey.
